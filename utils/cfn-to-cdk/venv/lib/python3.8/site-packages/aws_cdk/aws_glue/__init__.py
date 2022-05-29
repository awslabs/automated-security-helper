'''
# AWS Glue Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_glue as glue
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-glue-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Glue](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Glue.html).

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
class CfnClassifier(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnClassifier",
):
    '''A CloudFormation ``AWS::Glue::Classifier``.

    The ``AWS::Glue::Classifier`` resource creates an AWS Glue classifier that categorizes data sources and specifies schemas. For more information, see `Adding Classifiers to a Crawler <https://docs.aws.amazon.com/glue/latest/dg/add-classifier.html>`_ and `Classifier Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-crawler-classifiers.html#aws-glue-api-crawler-classifiers-Classifier>`_ in the *AWS Glue Developer Guide* .

    :cloudformationResource: AWS::Glue::Classifier
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        cfn_classifier = glue.CfnClassifier(self, "MyCfnClassifier",
            csv_classifier=glue.CfnClassifier.CsvClassifierProperty(
                allow_single_column=False,
                contains_header="containsHeader",
                delimiter="delimiter",
                disable_value_trimming=False,
                header=["header"],
                name="name",
                quote_symbol="quoteSymbol"
            ),
            grok_classifier=glue.CfnClassifier.GrokClassifierProperty(
                classification="classification",
                grok_pattern="grokPattern",
        
                # the properties below are optional
                custom_patterns="customPatterns",
                name="name"
            ),
            json_classifier=glue.CfnClassifier.JsonClassifierProperty(
                json_path="jsonPath",
        
                # the properties below are optional
                name="name"
            ),
            xml_classifier=glue.CfnClassifier.XMLClassifierProperty(
                classification="classification",
                row_tag="rowTag",
        
                # the properties below are optional
                name="name"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        csv_classifier: typing.Optional[typing.Union["CfnClassifier.CsvClassifierProperty", _IResolvable_da3f097b]] = None,
        grok_classifier: typing.Optional[typing.Union["CfnClassifier.GrokClassifierProperty", _IResolvable_da3f097b]] = None,
        json_classifier: typing.Optional[typing.Union["CfnClassifier.JsonClassifierProperty", _IResolvable_da3f097b]] = None,
        xml_classifier: typing.Optional[typing.Union["CfnClassifier.XMLClassifierProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Glue::Classifier``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param csv_classifier: A classifier for comma-separated values (CSV).
        :param grok_classifier: A classifier that uses ``grok`` .
        :param json_classifier: A classifier for JSON content.
        :param xml_classifier: A classifier for XML content.
        '''
        props = CfnClassifierProps(
            csv_classifier=csv_classifier,
            grok_classifier=grok_classifier,
            json_classifier=json_classifier,
            xml_classifier=xml_classifier,
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
    @jsii.member(jsii_name="csvClassifier")
    def csv_classifier(
        self,
    ) -> typing.Optional[typing.Union["CfnClassifier.CsvClassifierProperty", _IResolvable_da3f097b]]:
        '''A classifier for comma-separated values (CSV).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html#cfn-glue-classifier-csvclassifier
        '''
        return typing.cast(typing.Optional[typing.Union["CfnClassifier.CsvClassifierProperty", _IResolvable_da3f097b]], jsii.get(self, "csvClassifier"))

    @csv_classifier.setter
    def csv_classifier(
        self,
        value: typing.Optional[typing.Union["CfnClassifier.CsvClassifierProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "csvClassifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grokClassifier")
    def grok_classifier(
        self,
    ) -> typing.Optional[typing.Union["CfnClassifier.GrokClassifierProperty", _IResolvable_da3f097b]]:
        '''A classifier that uses ``grok`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html#cfn-glue-classifier-grokclassifier
        '''
        return typing.cast(typing.Optional[typing.Union["CfnClassifier.GrokClassifierProperty", _IResolvable_da3f097b]], jsii.get(self, "grokClassifier"))

    @grok_classifier.setter
    def grok_classifier(
        self,
        value: typing.Optional[typing.Union["CfnClassifier.GrokClassifierProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "grokClassifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="jsonClassifier")
    def json_classifier(
        self,
    ) -> typing.Optional[typing.Union["CfnClassifier.JsonClassifierProperty", _IResolvable_da3f097b]]:
        '''A classifier for JSON content.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html#cfn-glue-classifier-jsonclassifier
        '''
        return typing.cast(typing.Optional[typing.Union["CfnClassifier.JsonClassifierProperty", _IResolvable_da3f097b]], jsii.get(self, "jsonClassifier"))

    @json_classifier.setter
    def json_classifier(
        self,
        value: typing.Optional[typing.Union["CfnClassifier.JsonClassifierProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "jsonClassifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="xmlClassifier")
    def xml_classifier(
        self,
    ) -> typing.Optional[typing.Union["CfnClassifier.XMLClassifierProperty", _IResolvable_da3f097b]]:
        '''A classifier for XML content.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html#cfn-glue-classifier-xmlclassifier
        '''
        return typing.cast(typing.Optional[typing.Union["CfnClassifier.XMLClassifierProperty", _IResolvable_da3f097b]], jsii.get(self, "xmlClassifier"))

    @xml_classifier.setter
    def xml_classifier(
        self,
        value: typing.Optional[typing.Union["CfnClassifier.XMLClassifierProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "xmlClassifier", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnClassifier.CsvClassifierProperty",
        jsii_struct_bases=[],
        name_mapping={
            "allow_single_column": "allowSingleColumn",
            "contains_header": "containsHeader",
            "delimiter": "delimiter",
            "disable_value_trimming": "disableValueTrimming",
            "header": "header",
            "name": "name",
            "quote_symbol": "quoteSymbol",
        },
    )
    class CsvClassifierProperty:
        def __init__(
            self,
            *,
            allow_single_column: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            contains_header: typing.Optional[builtins.str] = None,
            delimiter: typing.Optional[builtins.str] = None,
            disable_value_trimming: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            header: typing.Optional[typing.Sequence[builtins.str]] = None,
            name: typing.Optional[builtins.str] = None,
            quote_symbol: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A classifier for custom ``CSV`` content.

            :param allow_single_column: Enables the processing of files that contain only one column.
            :param contains_header: Indicates whether the CSV file contains a header.
            :param delimiter: A custom symbol to denote what separates each column entry in the row.
            :param disable_value_trimming: Specifies not to trim values before identifying the type of column values. The default value is ``true`` .
            :param header: A list of strings representing column names.
            :param name: The name of the classifier.
            :param quote_symbol: A custom symbol to denote what combines content into a single column value. It must be different from the column delimiter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-csvclassifier.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                csv_classifier_property = glue.CfnClassifier.CsvClassifierProperty(
                    allow_single_column=False,
                    contains_header="containsHeader",
                    delimiter="delimiter",
                    disable_value_trimming=False,
                    header=["header"],
                    name="name",
                    quote_symbol="quoteSymbol"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if allow_single_column is not None:
                self._values["allow_single_column"] = allow_single_column
            if contains_header is not None:
                self._values["contains_header"] = contains_header
            if delimiter is not None:
                self._values["delimiter"] = delimiter
            if disable_value_trimming is not None:
                self._values["disable_value_trimming"] = disable_value_trimming
            if header is not None:
                self._values["header"] = header
            if name is not None:
                self._values["name"] = name
            if quote_symbol is not None:
                self._values["quote_symbol"] = quote_symbol

        @builtins.property
        def allow_single_column(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables the processing of files that contain only one column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-csvclassifier.html#cfn-glue-classifier-csvclassifier-allowsinglecolumn
            '''
            result = self._values.get("allow_single_column")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def contains_header(self) -> typing.Optional[builtins.str]:
            '''Indicates whether the CSV file contains a header.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-csvclassifier.html#cfn-glue-classifier-csvclassifier-containsheader
            '''
            result = self._values.get("contains_header")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def delimiter(self) -> typing.Optional[builtins.str]:
            '''A custom symbol to denote what separates each column entry in the row.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-csvclassifier.html#cfn-glue-classifier-csvclassifier-delimiter
            '''
            result = self._values.get("delimiter")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def disable_value_trimming(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies not to trim values before identifying the type of column values.

            The default value is ``true`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-csvclassifier.html#cfn-glue-classifier-csvclassifier-disablevaluetrimming
            '''
            result = self._values.get("disable_value_trimming")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def header(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of strings representing column names.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-csvclassifier.html#cfn-glue-classifier-csvclassifier-header
            '''
            result = self._values.get("header")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the classifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-csvclassifier.html#cfn-glue-classifier-csvclassifier-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def quote_symbol(self) -> typing.Optional[builtins.str]:
            '''A custom symbol to denote what combines content into a single column value.

            It must be different from the column delimiter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-csvclassifier.html#cfn-glue-classifier-csvclassifier-quotesymbol
            '''
            result = self._values.get("quote_symbol")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CsvClassifierProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnClassifier.GrokClassifierProperty",
        jsii_struct_bases=[],
        name_mapping={
            "classification": "classification",
            "grok_pattern": "grokPattern",
            "custom_patterns": "customPatterns",
            "name": "name",
        },
    )
    class GrokClassifierProperty:
        def __init__(
            self,
            *,
            classification: builtins.str,
            grok_pattern: builtins.str,
            custom_patterns: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A classifier that uses ``grok`` patterns.

            :param classification: An identifier of the data format that the classifier matches, such as Twitter, JSON, Omniture logs, and so on.
            :param grok_pattern: The grok pattern applied to a data store by this classifier. For more information, see built-in patterns in `Writing Custom Classifiers <https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html>`_ .
            :param custom_patterns: Optional custom grok patterns defined by this classifier. For more information, see custom patterns in `Writing Custom Classifiers <https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html>`_ .
            :param name: The name of the classifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-grokclassifier.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                grok_classifier_property = glue.CfnClassifier.GrokClassifierProperty(
                    classification="classification",
                    grok_pattern="grokPattern",
                
                    # the properties below are optional
                    custom_patterns="customPatterns",
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "classification": classification,
                "grok_pattern": grok_pattern,
            }
            if custom_patterns is not None:
                self._values["custom_patterns"] = custom_patterns
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def classification(self) -> builtins.str:
            '''An identifier of the data format that the classifier matches, such as Twitter, JSON, Omniture logs, and so on.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-grokclassifier.html#cfn-glue-classifier-grokclassifier-classification
            '''
            result = self._values.get("classification")
            assert result is not None, "Required property 'classification' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def grok_pattern(self) -> builtins.str:
            '''The grok pattern applied to a data store by this classifier.

            For more information, see built-in patterns in `Writing Custom Classifiers <https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-grokclassifier.html#cfn-glue-classifier-grokclassifier-grokpattern
            '''
            result = self._values.get("grok_pattern")
            assert result is not None, "Required property 'grok_pattern' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def custom_patterns(self) -> typing.Optional[builtins.str]:
            '''Optional custom grok patterns defined by this classifier.

            For more information, see custom patterns in `Writing Custom Classifiers <https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-grokclassifier.html#cfn-glue-classifier-grokclassifier-custompatterns
            '''
            result = self._values.get("custom_patterns")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the classifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-grokclassifier.html#cfn-glue-classifier-grokclassifier-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GrokClassifierProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnClassifier.JsonClassifierProperty",
        jsii_struct_bases=[],
        name_mapping={"json_path": "jsonPath", "name": "name"},
    )
    class JsonClassifierProperty:
        def __init__(
            self,
            *,
            json_path: builtins.str,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A classifier for ``JSON`` content.

            :param json_path: A ``JsonPath`` string defining the JSON data for the classifier to classify. AWS Glue supports a subset of ``JsonPath`` , as described in `Writing JsonPath Custom Classifiers <https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html#custom-classifier-json>`_ .
            :param name: The name of the classifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-jsonclassifier.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                json_classifier_property = glue.CfnClassifier.JsonClassifierProperty(
                    json_path="jsonPath",
                
                    # the properties below are optional
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "json_path": json_path,
            }
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def json_path(self) -> builtins.str:
            '''A ``JsonPath`` string defining the JSON data for the classifier to classify.

            AWS Glue supports a subset of ``JsonPath`` , as described in `Writing JsonPath Custom Classifiers <https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html#custom-classifier-json>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-jsonclassifier.html#cfn-glue-classifier-jsonclassifier-jsonpath
            '''
            result = self._values.get("json_path")
            assert result is not None, "Required property 'json_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the classifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-jsonclassifier.html#cfn-glue-classifier-jsonclassifier-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JsonClassifierProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnClassifier.XMLClassifierProperty",
        jsii_struct_bases=[],
        name_mapping={
            "classification": "classification",
            "row_tag": "rowTag",
            "name": "name",
        },
    )
    class XMLClassifierProperty:
        def __init__(
            self,
            *,
            classification: builtins.str,
            row_tag: builtins.str,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A classifier for ``XML`` content.

            :param classification: An identifier of the data format that the classifier matches.
            :param row_tag: The XML tag designating the element that contains each record in an XML document being parsed. This can't identify a self-closing element (closed by ``/>`` ). An empty row element that contains only attributes can be parsed as long as it ends with a closing tag (for example, ``<row item_a="A" item_b="B"></row>`` is okay, but ``<row item_a="A" item_b="B" />`` is not).
            :param name: The name of the classifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-xmlclassifier.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                x_mLClassifier_property = glue.CfnClassifier.XMLClassifierProperty(
                    classification="classification",
                    row_tag="rowTag",
                
                    # the properties below are optional
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "classification": classification,
                "row_tag": row_tag,
            }
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def classification(self) -> builtins.str:
            '''An identifier of the data format that the classifier matches.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-xmlclassifier.html#cfn-glue-classifier-xmlclassifier-classification
            '''
            result = self._values.get("classification")
            assert result is not None, "Required property 'classification' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def row_tag(self) -> builtins.str:
            '''The XML tag designating the element that contains each record in an XML document being parsed.

            This can't identify a self-closing element (closed by ``/>`` ). An empty row element that contains only attributes can be parsed as long as it ends with a closing tag (for example, ``<row item_a="A" item_b="B"></row>`` is okay, but ``<row item_a="A" item_b="B" />`` is not).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-xmlclassifier.html#cfn-glue-classifier-xmlclassifier-rowtag
            '''
            result = self._values.get("row_tag")
            assert result is not None, "Required property 'row_tag' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the classifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-classifier-xmlclassifier.html#cfn-glue-classifier-xmlclassifier-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "XMLClassifierProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnClassifierProps",
    jsii_struct_bases=[],
    name_mapping={
        "csv_classifier": "csvClassifier",
        "grok_classifier": "grokClassifier",
        "json_classifier": "jsonClassifier",
        "xml_classifier": "xmlClassifier",
    },
)
class CfnClassifierProps:
    def __init__(
        self,
        *,
        csv_classifier: typing.Optional[typing.Union[CfnClassifier.CsvClassifierProperty, _IResolvable_da3f097b]] = None,
        grok_classifier: typing.Optional[typing.Union[CfnClassifier.GrokClassifierProperty, _IResolvable_da3f097b]] = None,
        json_classifier: typing.Optional[typing.Union[CfnClassifier.JsonClassifierProperty, _IResolvable_da3f097b]] = None,
        xml_classifier: typing.Optional[typing.Union[CfnClassifier.XMLClassifierProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnClassifier``.

        :param csv_classifier: A classifier for comma-separated values (CSV).
        :param grok_classifier: A classifier that uses ``grok`` .
        :param json_classifier: A classifier for JSON content.
        :param xml_classifier: A classifier for XML content.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            cfn_classifier_props = glue.CfnClassifierProps(
                csv_classifier=glue.CfnClassifier.CsvClassifierProperty(
                    allow_single_column=False,
                    contains_header="containsHeader",
                    delimiter="delimiter",
                    disable_value_trimming=False,
                    header=["header"],
                    name="name",
                    quote_symbol="quoteSymbol"
                ),
                grok_classifier=glue.CfnClassifier.GrokClassifierProperty(
                    classification="classification",
                    grok_pattern="grokPattern",
            
                    # the properties below are optional
                    custom_patterns="customPatterns",
                    name="name"
                ),
                json_classifier=glue.CfnClassifier.JsonClassifierProperty(
                    json_path="jsonPath",
            
                    # the properties below are optional
                    name="name"
                ),
                xml_classifier=glue.CfnClassifier.XMLClassifierProperty(
                    classification="classification",
                    row_tag="rowTag",
            
                    # the properties below are optional
                    name="name"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if csv_classifier is not None:
            self._values["csv_classifier"] = csv_classifier
        if grok_classifier is not None:
            self._values["grok_classifier"] = grok_classifier
        if json_classifier is not None:
            self._values["json_classifier"] = json_classifier
        if xml_classifier is not None:
            self._values["xml_classifier"] = xml_classifier

    @builtins.property
    def csv_classifier(
        self,
    ) -> typing.Optional[typing.Union[CfnClassifier.CsvClassifierProperty, _IResolvable_da3f097b]]:
        '''A classifier for comma-separated values (CSV).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html#cfn-glue-classifier-csvclassifier
        '''
        result = self._values.get("csv_classifier")
        return typing.cast(typing.Optional[typing.Union[CfnClassifier.CsvClassifierProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def grok_classifier(
        self,
    ) -> typing.Optional[typing.Union[CfnClassifier.GrokClassifierProperty, _IResolvable_da3f097b]]:
        '''A classifier that uses ``grok`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html#cfn-glue-classifier-grokclassifier
        '''
        result = self._values.get("grok_classifier")
        return typing.cast(typing.Optional[typing.Union[CfnClassifier.GrokClassifierProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def json_classifier(
        self,
    ) -> typing.Optional[typing.Union[CfnClassifier.JsonClassifierProperty, _IResolvable_da3f097b]]:
        '''A classifier for JSON content.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html#cfn-glue-classifier-jsonclassifier
        '''
        result = self._values.get("json_classifier")
        return typing.cast(typing.Optional[typing.Union[CfnClassifier.JsonClassifierProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def xml_classifier(
        self,
    ) -> typing.Optional[typing.Union[CfnClassifier.XMLClassifierProperty, _IResolvable_da3f097b]]:
        '''A classifier for XML content.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-classifier.html#cfn-glue-classifier-xmlclassifier
        '''
        result = self._values.get("xml_classifier")
        return typing.cast(typing.Optional[typing.Union[CfnClassifier.XMLClassifierProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnClassifierProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnConnection(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnConnection",
):
    '''A CloudFormation ``AWS::Glue::Connection``.

    The ``AWS::Glue::Connection`` resource specifies an AWS Glue connection to a data source. For more information, see `Adding a Connection to Your Data Store <https://docs.aws.amazon.com/glue/latest/dg/populate-add-connection.html>`_ and `Connection Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-catalog-connections.html#aws-glue-api-catalog-connections-Connection>`_ in the *AWS Glue Developer Guide* .

    :cloudformationResource: AWS::Glue::Connection
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-connection.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # connection_properties: Any
        
        cfn_connection = glue.CfnConnection(self, "MyCfnConnection",
            catalog_id="catalogId",
            connection_input=glue.CfnConnection.ConnectionInputProperty(
                connection_type="connectionType",
        
                # the properties below are optional
                connection_properties=connection_properties,
                description="description",
                match_criteria=["matchCriteria"],
                name="name",
                physical_connection_requirements=glue.CfnConnection.PhysicalConnectionRequirementsProperty(
                    availability_zone="availabilityZone",
                    security_group_id_list=["securityGroupIdList"],
                    subnet_id="subnetId"
                )
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        catalog_id: builtins.str,
        connection_input: typing.Union["CfnConnection.ConnectionInputProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::Glue::Connection``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param catalog_id: The ID of the data catalog to create the catalog object in. Currently, this should be the AWS account ID. .. epigraph:: To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId`` .
        :param connection_input: The connection that you want to create.
        '''
        props = CfnConnectionProps(
            catalog_id=catalog_id, connection_input=connection_input
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
    @jsii.member(jsii_name="catalogId")
    def catalog_id(self) -> builtins.str:
        '''The ID of the data catalog to create the catalog object in.

        Currently, this should be the AWS account ID.
        .. epigraph::

           To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-connection.html#cfn-glue-connection-catalogid
        '''
        return typing.cast(builtins.str, jsii.get(self, "catalogId"))

    @catalog_id.setter
    def catalog_id(self, value: builtins.str) -> None:
        jsii.set(self, "catalogId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionInput")
    def connection_input(
        self,
    ) -> typing.Union["CfnConnection.ConnectionInputProperty", _IResolvable_da3f097b]:
        '''The connection that you want to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-connection.html#cfn-glue-connection-connectioninput
        '''
        return typing.cast(typing.Union["CfnConnection.ConnectionInputProperty", _IResolvable_da3f097b], jsii.get(self, "connectionInput"))

    @connection_input.setter
    def connection_input(
        self,
        value: typing.Union["CfnConnection.ConnectionInputProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "connectionInput", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnConnection.ConnectionInputProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connection_type": "connectionType",
            "connection_properties": "connectionProperties",
            "description": "description",
            "match_criteria": "matchCriteria",
            "name": "name",
            "physical_connection_requirements": "physicalConnectionRequirements",
        },
    )
    class ConnectionInputProperty:
        def __init__(
            self,
            *,
            connection_type: builtins.str,
            connection_properties: typing.Any = None,
            description: typing.Optional[builtins.str] = None,
            match_criteria: typing.Optional[typing.Sequence[builtins.str]] = None,
            name: typing.Optional[builtins.str] = None,
            physical_connection_requirements: typing.Optional[typing.Union["CfnConnection.PhysicalConnectionRequirementsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A structure that is used to specify a connection to create or update.

            :param connection_type: The type of the connection. Currently, these types are supported:. - ``JDBC`` - Designates a connection to a database through Java Database Connectivity (JDBC). - ``KAFKA`` - Designates a connection to an Apache Kafka streaming platform. - ``MONGODB`` - Designates a connection to a MongoDB document database. - ``NETWORK`` - Designates a network connection to a data source within an Amazon Virtual Private Cloud environment (Amazon VPC). SFTP is not supported.
            :param connection_properties: These key-value pairs define parameters for the connection.
            :param description: The description of the connection.
            :param match_criteria: A list of criteria that can be used in selecting this connection.
            :param name: The name of the connection.
            :param physical_connection_requirements: A map of physical connection requirements, such as virtual private cloud (VPC) and ``SecurityGroup`` , that are needed to successfully make this connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-connectioninput.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # connection_properties: Any
                
                connection_input_property = glue.CfnConnection.ConnectionInputProperty(
                    connection_type="connectionType",
                
                    # the properties below are optional
                    connection_properties=connection_properties,
                    description="description",
                    match_criteria=["matchCriteria"],
                    name="name",
                    physical_connection_requirements=glue.CfnConnection.PhysicalConnectionRequirementsProperty(
                        availability_zone="availabilityZone",
                        security_group_id_list=["securityGroupIdList"],
                        subnet_id="subnetId"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connection_type": connection_type,
            }
            if connection_properties is not None:
                self._values["connection_properties"] = connection_properties
            if description is not None:
                self._values["description"] = description
            if match_criteria is not None:
                self._values["match_criteria"] = match_criteria
            if name is not None:
                self._values["name"] = name
            if physical_connection_requirements is not None:
                self._values["physical_connection_requirements"] = physical_connection_requirements

        @builtins.property
        def connection_type(self) -> builtins.str:
            '''The type of the connection. Currently, these types are supported:.

            - ``JDBC`` - Designates a connection to a database through Java Database Connectivity (JDBC).
            - ``KAFKA`` - Designates a connection to an Apache Kafka streaming platform.
            - ``MONGODB`` - Designates a connection to a MongoDB document database.
            - ``NETWORK`` - Designates a network connection to a data source within an Amazon Virtual Private Cloud environment (Amazon VPC).

            SFTP is not supported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-connectioninput.html#cfn-glue-connection-connectioninput-connectiontype
            '''
            result = self._values.get("connection_type")
            assert result is not None, "Required property 'connection_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def connection_properties(self) -> typing.Any:
            '''These key-value pairs define parameters for the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-connectioninput.html#cfn-glue-connection-connectioninput-connectionproperties
            '''
            result = self._values.get("connection_properties")
            return typing.cast(typing.Any, result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''The description of the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-connectioninput.html#cfn-glue-connection-connectioninput-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def match_criteria(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of criteria that can be used in selecting this connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-connectioninput.html#cfn-glue-connection-connectioninput-matchcriteria
            '''
            result = self._values.get("match_criteria")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-connectioninput.html#cfn-glue-connection-connectioninput-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def physical_connection_requirements(
            self,
        ) -> typing.Optional[typing.Union["CfnConnection.PhysicalConnectionRequirementsProperty", _IResolvable_da3f097b]]:
            '''A map of physical connection requirements, such as virtual private cloud (VPC) and ``SecurityGroup`` , that are needed to successfully make this connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-connectioninput.html#cfn-glue-connection-connectioninput-physicalconnectionrequirements
            '''
            result = self._values.get("physical_connection_requirements")
            return typing.cast(typing.Optional[typing.Union["CfnConnection.PhysicalConnectionRequirementsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectionInputProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnConnection.PhysicalConnectionRequirementsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "availability_zone": "availabilityZone",
            "security_group_id_list": "securityGroupIdList",
            "subnet_id": "subnetId",
        },
    )
    class PhysicalConnectionRequirementsProperty:
        def __init__(
            self,
            *,
            availability_zone: typing.Optional[builtins.str] = None,
            security_group_id_list: typing.Optional[typing.Sequence[builtins.str]] = None,
            subnet_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the physical requirements for a connection.

            :param availability_zone: The connection's Availability Zone. This field is redundant because the specified subnet implies the Availability Zone to be used. Currently the field must be populated, but it will be deprecated in the future.
            :param security_group_id_list: The security group ID list used by the connection.
            :param subnet_id: The subnet ID used by the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-physicalconnectionrequirements.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                physical_connection_requirements_property = glue.CfnConnection.PhysicalConnectionRequirementsProperty(
                    availability_zone="availabilityZone",
                    security_group_id_list=["securityGroupIdList"],
                    subnet_id="subnetId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if availability_zone is not None:
                self._values["availability_zone"] = availability_zone
            if security_group_id_list is not None:
                self._values["security_group_id_list"] = security_group_id_list
            if subnet_id is not None:
                self._values["subnet_id"] = subnet_id

        @builtins.property
        def availability_zone(self) -> typing.Optional[builtins.str]:
            '''The connection's Availability Zone.

            This field is redundant because the specified subnet implies the Availability Zone to be used. Currently the field must be populated, but it will be deprecated in the future.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-physicalconnectionrequirements.html#cfn-glue-connection-physicalconnectionrequirements-availabilityzone
            '''
            result = self._values.get("availability_zone")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def security_group_id_list(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The security group ID list used by the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-physicalconnectionrequirements.html#cfn-glue-connection-physicalconnectionrequirements-securitygroupidlist
            '''
            result = self._values.get("security_group_id_list")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def subnet_id(self) -> typing.Optional[builtins.str]:
            '''The subnet ID used by the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-connection-physicalconnectionrequirements.html#cfn-glue-connection-physicalconnectionrequirements-subnetid
            '''
            result = self._values.get("subnet_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PhysicalConnectionRequirementsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnConnectionProps",
    jsii_struct_bases=[],
    name_mapping={"catalog_id": "catalogId", "connection_input": "connectionInput"},
)
class CfnConnectionProps:
    def __init__(
        self,
        *,
        catalog_id: builtins.str,
        connection_input: typing.Union[CfnConnection.ConnectionInputProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnConnection``.

        :param catalog_id: The ID of the data catalog to create the catalog object in. Currently, this should be the AWS account ID. .. epigraph:: To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId`` .
        :param connection_input: The connection that you want to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-connection.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # connection_properties: Any
            
            cfn_connection_props = glue.CfnConnectionProps(
                catalog_id="catalogId",
                connection_input=glue.CfnConnection.ConnectionInputProperty(
                    connection_type="connectionType",
            
                    # the properties below are optional
                    connection_properties=connection_properties,
                    description="description",
                    match_criteria=["matchCriteria"],
                    name="name",
                    physical_connection_requirements=glue.CfnConnection.PhysicalConnectionRequirementsProperty(
                        availability_zone="availabilityZone",
                        security_group_id_list=["securityGroupIdList"],
                        subnet_id="subnetId"
                    )
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "catalog_id": catalog_id,
            "connection_input": connection_input,
        }

    @builtins.property
    def catalog_id(self) -> builtins.str:
        '''The ID of the data catalog to create the catalog object in.

        Currently, this should be the AWS account ID.
        .. epigraph::

           To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-connection.html#cfn-glue-connection-catalogid
        '''
        result = self._values.get("catalog_id")
        assert result is not None, "Required property 'catalog_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def connection_input(
        self,
    ) -> typing.Union[CfnConnection.ConnectionInputProperty, _IResolvable_da3f097b]:
        '''The connection that you want to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-connection.html#cfn-glue-connection-connectioninput
        '''
        result = self._values.get("connection_input")
        assert result is not None, "Required property 'connection_input' is missing"
        return typing.cast(typing.Union[CfnConnection.ConnectionInputProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnConnectionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnCrawler(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnCrawler",
):
    '''A CloudFormation ``AWS::Glue::Crawler``.

    The ``AWS::Glue::Crawler`` resource specifies an AWS Glue crawler. For more information, see `Cataloging Tables with a Crawler <https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html>`_ and `Crawler Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-crawler-crawling.html#aws-glue-api-crawler-crawling-Crawler>`_ in the *AWS Glue Developer Guide* .

    :cloudformationResource: AWS::Glue::Crawler
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # tags: Any
        
        cfn_crawler = glue.CfnCrawler(self, "MyCfnCrawler",
            role="role",
            targets=glue.CfnCrawler.TargetsProperty(
                catalog_targets=[glue.CfnCrawler.CatalogTargetProperty(
                    database_name="databaseName",
                    tables=["tables"]
                )],
                dynamo_db_targets=[glue.CfnCrawler.DynamoDBTargetProperty(
                    path="path"
                )],
                jdbc_targets=[glue.CfnCrawler.JdbcTargetProperty(
                    connection_name="connectionName",
                    exclusions=["exclusions"],
                    path="path"
                )],
                mongo_db_targets=[glue.CfnCrawler.MongoDBTargetProperty(
                    connection_name="connectionName",
                    path="path"
                )],
                s3_targets=[glue.CfnCrawler.S3TargetProperty(
                    connection_name="connectionName",
                    dlq_event_queue_arn="dlqEventQueueArn",
                    event_queue_arn="eventQueueArn",
                    exclusions=["exclusions"],
                    path="path",
                    sample_size=123
                )]
            ),
        
            # the properties below are optional
            classifiers=["classifiers"],
            configuration="configuration",
            crawler_security_configuration="crawlerSecurityConfiguration",
            database_name="databaseName",
            description="description",
            name="name",
            recrawl_policy=glue.CfnCrawler.RecrawlPolicyProperty(
                recrawl_behavior="recrawlBehavior"
            ),
            schedule=glue.CfnCrawler.ScheduleProperty(
                schedule_expression="scheduleExpression"
            ),
            schema_change_policy=glue.CfnCrawler.SchemaChangePolicyProperty(
                delete_behavior="deleteBehavior",
                update_behavior="updateBehavior"
            ),
            table_prefix="tablePrefix",
            tags=tags
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        role: builtins.str,
        targets: typing.Union["CfnCrawler.TargetsProperty", _IResolvable_da3f097b],
        classifiers: typing.Optional[typing.Sequence[builtins.str]] = None,
        configuration: typing.Optional[builtins.str] = None,
        crawler_security_configuration: typing.Optional[builtins.str] = None,
        database_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        recrawl_policy: typing.Optional[typing.Union["CfnCrawler.RecrawlPolicyProperty", _IResolvable_da3f097b]] = None,
        schedule: typing.Optional[typing.Union["CfnCrawler.ScheduleProperty", _IResolvable_da3f097b]] = None,
        schema_change_policy: typing.Optional[typing.Union["CfnCrawler.SchemaChangePolicyProperty", _IResolvable_da3f097b]] = None,
        table_prefix: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Glue::Crawler``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param role: The Amazon Resource Name (ARN) of an IAM role that's used to access customer resources, such as Amazon Simple Storage Service (Amazon S3) data.
        :param targets: A collection of targets to crawl.
        :param classifiers: A list of UTF-8 strings that specify the custom classifiers that are associated with the crawler.
        :param configuration: Crawler configuration information. This versioned JSON string allows users to specify aspects of a crawler's behavior. For more information, see `Configuring a Crawler <https://docs.aws.amazon.com/glue/latest/dg/crawler-configuration.html>`_ .
        :param crawler_security_configuration: The name of the ``SecurityConfiguration`` structure to be used by this crawler.
        :param database_name: The name of the database in which the crawler's output is stored.
        :param description: A description of the crawler.
        :param name: The name of the crawler.
        :param recrawl_policy: A policy that specifies whether to crawl the entire dataset again, or to crawl only folders that were added since the last crawler run.
        :param schedule: For scheduled crawlers, the schedule when the crawler runs.
        :param schema_change_policy: The policy that specifies update and delete behaviors for the crawler.
        :param table_prefix: The prefix added to the names of tables that are created.
        :param tags: The tags to use with this crawler.
        '''
        props = CfnCrawlerProps(
            role=role,
            targets=targets,
            classifiers=classifiers,
            configuration=configuration,
            crawler_security_configuration=crawler_security_configuration,
            database_name=database_name,
            description=description,
            name=name,
            recrawl_policy=recrawl_policy,
            schedule=schedule,
            schema_change_policy=schema_change_policy,
            table_prefix=table_prefix,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to use with this crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of an IAM role that's used to access customer resources, such as Amazon Simple Storage Service (Amazon S3) data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-role
        '''
        return typing.cast(builtins.str, jsii.get(self, "role"))

    @role.setter
    def role(self, value: builtins.str) -> None:
        jsii.set(self, "role", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targets")
    def targets(
        self,
    ) -> typing.Union["CfnCrawler.TargetsProperty", _IResolvable_da3f097b]:
        '''A collection of targets to crawl.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-targets
        '''
        return typing.cast(typing.Union["CfnCrawler.TargetsProperty", _IResolvable_da3f097b], jsii.get(self, "targets"))

    @targets.setter
    def targets(
        self,
        value: typing.Union["CfnCrawler.TargetsProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "targets", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="classifiers")
    def classifiers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of UTF-8 strings that specify the custom classifiers that are associated with the crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-classifiers
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "classifiers"))

    @classifiers.setter
    def classifiers(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "classifiers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="configuration")
    def configuration(self) -> typing.Optional[builtins.str]:
        '''Crawler configuration information.

        This versioned JSON string allows users to specify aspects of a crawler's behavior. For more information, see `Configuring a Crawler <https://docs.aws.amazon.com/glue/latest/dg/crawler-configuration.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-configuration
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "configuration"))

    @configuration.setter
    def configuration(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "configuration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="crawlerSecurityConfiguration")
    def crawler_security_configuration(self) -> typing.Optional[builtins.str]:
        '''The name of the ``SecurityConfiguration`` structure to be used by this crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-crawlersecurityconfiguration
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "crawlerSecurityConfiguration"))

    @crawler_security_configuration.setter
    def crawler_security_configuration(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "crawlerSecurityConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="databaseName")
    def database_name(self) -> typing.Optional[builtins.str]:
        '''The name of the database in which the crawler's output is stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-databasename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "databaseName"))

    @database_name.setter
    def database_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "databaseName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="recrawlPolicy")
    def recrawl_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnCrawler.RecrawlPolicyProperty", _IResolvable_da3f097b]]:
        '''A policy that specifies whether to crawl the entire dataset again, or to crawl only folders that were added since the last crawler run.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-recrawlpolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCrawler.RecrawlPolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "recrawlPolicy"))

    @recrawl_policy.setter
    def recrawl_policy(
        self,
        value: typing.Optional[typing.Union["CfnCrawler.RecrawlPolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "recrawlPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schedule")
    def schedule(
        self,
    ) -> typing.Optional[typing.Union["CfnCrawler.ScheduleProperty", _IResolvable_da3f097b]]:
        '''For scheduled crawlers, the schedule when the crawler runs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-schedule
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCrawler.ScheduleProperty", _IResolvable_da3f097b]], jsii.get(self, "schedule"))

    @schedule.setter
    def schedule(
        self,
        value: typing.Optional[typing.Union["CfnCrawler.ScheduleProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "schedule", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schemaChangePolicy")
    def schema_change_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnCrawler.SchemaChangePolicyProperty", _IResolvable_da3f097b]]:
        '''The policy that specifies update and delete behaviors for the crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-schemachangepolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCrawler.SchemaChangePolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "schemaChangePolicy"))

    @schema_change_policy.setter
    def schema_change_policy(
        self,
        value: typing.Optional[typing.Union["CfnCrawler.SchemaChangePolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "schemaChangePolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tablePrefix")
    def table_prefix(self) -> typing.Optional[builtins.str]:
        '''The prefix added to the names of tables that are created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-tableprefix
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "tablePrefix"))

    @table_prefix.setter
    def table_prefix(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "tablePrefix", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.CatalogTargetProperty",
        jsii_struct_bases=[],
        name_mapping={"database_name": "databaseName", "tables": "tables"},
    )
    class CatalogTargetProperty:
        def __init__(
            self,
            *,
            database_name: typing.Optional[builtins.str] = None,
            tables: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Specifies an AWS Glue Data Catalog target.

            :param database_name: The name of the database to be synchronized.
            :param tables: A list of the tables to be synchronized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-catalogtarget.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                catalog_target_property = glue.CfnCrawler.CatalogTargetProperty(
                    database_name="databaseName",
                    tables=["tables"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if database_name is not None:
                self._values["database_name"] = database_name
            if tables is not None:
                self._values["tables"] = tables

        @builtins.property
        def database_name(self) -> typing.Optional[builtins.str]:
            '''The name of the database to be synchronized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-catalogtarget.html#cfn-glue-crawler-catalogtarget-databasename
            '''
            result = self._values.get("database_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tables(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of the tables to be synchronized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-catalogtarget.html#cfn-glue-crawler-catalogtarget-tables
            '''
            result = self._values.get("tables")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CatalogTargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.DynamoDBTargetProperty",
        jsii_struct_bases=[],
        name_mapping={"path": "path"},
    )
    class DynamoDBTargetProperty:
        def __init__(self, *, path: typing.Optional[builtins.str] = None) -> None:
            '''Specifies an Amazon DynamoDB table to crawl.

            :param path: The name of the DynamoDB table to crawl.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-dynamodbtarget.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                dynamo_dBTarget_property = glue.CfnCrawler.DynamoDBTargetProperty(
                    path="path"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if path is not None:
                self._values["path"] = path

        @builtins.property
        def path(self) -> typing.Optional[builtins.str]:
            '''The name of the DynamoDB table to crawl.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-dynamodbtarget.html#cfn-glue-crawler-dynamodbtarget-path
            '''
            result = self._values.get("path")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DynamoDBTargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.JdbcTargetProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connection_name": "connectionName",
            "exclusions": "exclusions",
            "path": "path",
        },
    )
    class JdbcTargetProperty:
        def __init__(
            self,
            *,
            connection_name: typing.Optional[builtins.str] = None,
            exclusions: typing.Optional[typing.Sequence[builtins.str]] = None,
            path: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies a JDBC data store to crawl.

            :param connection_name: The name of the connection to use to connect to the JDBC target.
            :param exclusions: A list of glob patterns used to exclude from the crawl. For more information, see `Catalog Tables with a Crawler <https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html>`_ .
            :param path: The path of the JDBC target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-jdbctarget.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                jdbc_target_property = glue.CfnCrawler.JdbcTargetProperty(
                    connection_name="connectionName",
                    exclusions=["exclusions"],
                    path="path"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if connection_name is not None:
                self._values["connection_name"] = connection_name
            if exclusions is not None:
                self._values["exclusions"] = exclusions
            if path is not None:
                self._values["path"] = path

        @builtins.property
        def connection_name(self) -> typing.Optional[builtins.str]:
            '''The name of the connection to use to connect to the JDBC target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-jdbctarget.html#cfn-glue-crawler-jdbctarget-connectionname
            '''
            result = self._values.get("connection_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def exclusions(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of glob patterns used to exclude from the crawl.

            For more information, see `Catalog Tables with a Crawler <https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-jdbctarget.html#cfn-glue-crawler-jdbctarget-exclusions
            '''
            result = self._values.get("exclusions")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def path(self) -> typing.Optional[builtins.str]:
            '''The path of the JDBC target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-jdbctarget.html#cfn-glue-crawler-jdbctarget-path
            '''
            result = self._values.get("path")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JdbcTargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.MongoDBTargetProperty",
        jsii_struct_bases=[],
        name_mapping={"connection_name": "connectionName", "path": "path"},
    )
    class MongoDBTargetProperty:
        def __init__(
            self,
            *,
            connection_name: typing.Optional[builtins.str] = None,
            path: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an Amazon DocumentDB or MongoDB data store to crawl.

            :param connection_name: The name of the connection to use to connect to the Amazon DocumentDB or MongoDB target.
            :param path: The path of the Amazon DocumentDB or MongoDB target (database/collection).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-mongodbtarget.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                mongo_dBTarget_property = glue.CfnCrawler.MongoDBTargetProperty(
                    connection_name="connectionName",
                    path="path"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if connection_name is not None:
                self._values["connection_name"] = connection_name
            if path is not None:
                self._values["path"] = path

        @builtins.property
        def connection_name(self) -> typing.Optional[builtins.str]:
            '''The name of the connection to use to connect to the Amazon DocumentDB or MongoDB target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-mongodbtarget.html#cfn-glue-crawler-mongodbtarget-connectionname
            '''
            result = self._values.get("connection_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def path(self) -> typing.Optional[builtins.str]:
            '''The path of the Amazon DocumentDB or MongoDB target (database/collection).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-mongodbtarget.html#cfn-glue-crawler-mongodbtarget-path
            '''
            result = self._values.get("path")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MongoDBTargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.RecrawlPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={"recrawl_behavior": "recrawlBehavior"},
    )
    class RecrawlPolicyProperty:
        def __init__(
            self,
            *,
            recrawl_behavior: typing.Optional[builtins.str] = None,
        ) -> None:
            '''When crawling an Amazon S3 data source after the first crawl is complete, specifies whether to crawl the entire dataset again or to crawl only folders that were added since the last crawler run.

            For more information, see `Incremental Crawls in AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/incremental-crawls.html>`_ in the developer guide.

            :param recrawl_behavior: Specifies whether to crawl the entire dataset again or to crawl only folders that were added since the last crawler run. A value of ``CRAWL_EVERYTHING`` specifies crawling the entire dataset again. A value of ``CRAWL_NEW_FOLDERS_ONLY`` specifies crawling only folders that were added since the last crawler run. A value of ``CRAWL_EVENT_MODE`` specifies crawling only the changes identified by Amazon S3 events.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-recrawlpolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                recrawl_policy_property = glue.CfnCrawler.RecrawlPolicyProperty(
                    recrawl_behavior="recrawlBehavior"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if recrawl_behavior is not None:
                self._values["recrawl_behavior"] = recrawl_behavior

        @builtins.property
        def recrawl_behavior(self) -> typing.Optional[builtins.str]:
            '''Specifies whether to crawl the entire dataset again or to crawl only folders that were added since the last crawler run.

            A value of ``CRAWL_EVERYTHING`` specifies crawling the entire dataset again.

            A value of ``CRAWL_NEW_FOLDERS_ONLY`` specifies crawling only folders that were added since the last crawler run.

            A value of ``CRAWL_EVENT_MODE`` specifies crawling only the changes identified by Amazon S3 events.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-recrawlpolicy.html#cfn-glue-crawler-recrawlpolicy-recrawlbehavior
            '''
            result = self._values.get("recrawl_behavior")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RecrawlPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.S3TargetProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connection_name": "connectionName",
            "dlq_event_queue_arn": "dlqEventQueueArn",
            "event_queue_arn": "eventQueueArn",
            "exclusions": "exclusions",
            "path": "path",
            "sample_size": "sampleSize",
        },
    )
    class S3TargetProperty:
        def __init__(
            self,
            *,
            connection_name: typing.Optional[builtins.str] = None,
            dlq_event_queue_arn: typing.Optional[builtins.str] = None,
            event_queue_arn: typing.Optional[builtins.str] = None,
            exclusions: typing.Optional[typing.Sequence[builtins.str]] = None,
            path: typing.Optional[builtins.str] = None,
            sample_size: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies a data store in Amazon Simple Storage Service (Amazon S3).

            :param connection_name: The name of a connection which allows a job or crawler to access data in Amazon S3 within an Amazon Virtual Private Cloud environment (Amazon VPC).
            :param dlq_event_queue_arn: ``CfnCrawler.S3TargetProperty.DlqEventQueueArn``.
            :param event_queue_arn: ``CfnCrawler.S3TargetProperty.EventQueueArn``.
            :param exclusions: A list of glob patterns used to exclude from the crawl. For more information, see `Catalog Tables with a Crawler <https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html>`_ .
            :param path: The path to the Amazon S3 target.
            :param sample_size: Sets the number of files in each leaf folder to be crawled when crawling sample files in a dataset. If not set, all the files are crawled. A valid value is an integer between 1 and 249.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-s3target.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                s3_target_property = glue.CfnCrawler.S3TargetProperty(
                    connection_name="connectionName",
                    dlq_event_queue_arn="dlqEventQueueArn",
                    event_queue_arn="eventQueueArn",
                    exclusions=["exclusions"],
                    path="path",
                    sample_size=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if connection_name is not None:
                self._values["connection_name"] = connection_name
            if dlq_event_queue_arn is not None:
                self._values["dlq_event_queue_arn"] = dlq_event_queue_arn
            if event_queue_arn is not None:
                self._values["event_queue_arn"] = event_queue_arn
            if exclusions is not None:
                self._values["exclusions"] = exclusions
            if path is not None:
                self._values["path"] = path
            if sample_size is not None:
                self._values["sample_size"] = sample_size

        @builtins.property
        def connection_name(self) -> typing.Optional[builtins.str]:
            '''The name of a connection which allows a job or crawler to access data in Amazon S3 within an Amazon Virtual Private Cloud environment (Amazon VPC).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-s3target.html#cfn-glue-crawler-s3target-connectionname
            '''
            result = self._values.get("connection_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dlq_event_queue_arn(self) -> typing.Optional[builtins.str]:
            '''``CfnCrawler.S3TargetProperty.DlqEventQueueArn``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-s3target.html#cfn-glue-crawler-s3target-dlqeventqueuearn
            '''
            result = self._values.get("dlq_event_queue_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def event_queue_arn(self) -> typing.Optional[builtins.str]:
            '''``CfnCrawler.S3TargetProperty.EventQueueArn``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-s3target.html#cfn-glue-crawler-s3target-eventqueuearn
            '''
            result = self._values.get("event_queue_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def exclusions(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of glob patterns used to exclude from the crawl.

            For more information, see `Catalog Tables with a Crawler <https://docs.aws.amazon.com/glue/latest/dg/add-crawler.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-s3target.html#cfn-glue-crawler-s3target-exclusions
            '''
            result = self._values.get("exclusions")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def path(self) -> typing.Optional[builtins.str]:
            '''The path to the Amazon S3 target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-s3target.html#cfn-glue-crawler-s3target-path
            '''
            result = self._values.get("path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sample_size(self) -> typing.Optional[jsii.Number]:
            '''Sets the number of files in each leaf folder to be crawled when crawling sample files in a dataset.

            If not set, all the files are crawled. A valid value is an integer between 1 and 249.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-s3target.html#cfn-glue-crawler-s3target-samplesize
            '''
            result = self._values.get("sample_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3TargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.ScheduleProperty",
        jsii_struct_bases=[],
        name_mapping={"schedule_expression": "scheduleExpression"},
    )
    class ScheduleProperty:
        def __init__(
            self,
            *,
            schedule_expression: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A scheduling object using a ``cron`` statement to schedule an event.

            :param schedule_expression: A ``cron`` expression used to specify the schedule. For more information, see `Time-Based Schedules for Jobs and Crawlers <https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html>`_ . For example, to run something every day at 12:15 UTC, specify ``cron(15 12 * * ? *)`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-schedule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                schedule_property = glue.CfnCrawler.ScheduleProperty(
                    schedule_expression="scheduleExpression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if schedule_expression is not None:
                self._values["schedule_expression"] = schedule_expression

        @builtins.property
        def schedule_expression(self) -> typing.Optional[builtins.str]:
            '''A ``cron`` expression used to specify the schedule.

            For more information, see `Time-Based Schedules for Jobs and Crawlers <https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html>`_ . For example, to run something every day at 12:15 UTC, specify ``cron(15 12 * * ? *)`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-schedule.html#cfn-glue-crawler-schedule-scheduleexpression
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
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.SchemaChangePolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delete_behavior": "deleteBehavior",
            "update_behavior": "updateBehavior",
        },
    )
    class SchemaChangePolicyProperty:
        def __init__(
            self,
            *,
            delete_behavior: typing.Optional[builtins.str] = None,
            update_behavior: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A policy that specifies update and deletion behaviors for the crawler.

            :param delete_behavior: The deletion behavior when the crawler finds a deleted object.
            :param update_behavior: The update behavior when the crawler finds a changed schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-schemachangepolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                schema_change_policy_property = glue.CfnCrawler.SchemaChangePolicyProperty(
                    delete_behavior="deleteBehavior",
                    update_behavior="updateBehavior"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if delete_behavior is not None:
                self._values["delete_behavior"] = delete_behavior
            if update_behavior is not None:
                self._values["update_behavior"] = update_behavior

        @builtins.property
        def delete_behavior(self) -> typing.Optional[builtins.str]:
            '''The deletion behavior when the crawler finds a deleted object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-schemachangepolicy.html#cfn-glue-crawler-schemachangepolicy-deletebehavior
            '''
            result = self._values.get("delete_behavior")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def update_behavior(self) -> typing.Optional[builtins.str]:
            '''The update behavior when the crawler finds a changed schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-schemachangepolicy.html#cfn-glue-crawler-schemachangepolicy-updatebehavior
            '''
            result = self._values.get("update_behavior")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaChangePolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnCrawler.TargetsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "catalog_targets": "catalogTargets",
            "dynamo_db_targets": "dynamoDbTargets",
            "jdbc_targets": "jdbcTargets",
            "mongo_db_targets": "mongoDbTargets",
            "s3_targets": "s3Targets",
        },
    )
    class TargetsProperty:
        def __init__(
            self,
            *,
            catalog_targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCrawler.CatalogTargetProperty", _IResolvable_da3f097b]]]] = None,
            dynamo_db_targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCrawler.DynamoDBTargetProperty", _IResolvable_da3f097b]]]] = None,
            jdbc_targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCrawler.JdbcTargetProperty", _IResolvable_da3f097b]]]] = None,
            mongo_db_targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCrawler.MongoDBTargetProperty", _IResolvable_da3f097b]]]] = None,
            s3_targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCrawler.S3TargetProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies data stores to crawl.

            :param catalog_targets: Specifies AWS Glue Data Catalog targets.
            :param dynamo_db_targets: Specifies Amazon DynamoDB targets.
            :param jdbc_targets: Specifies JDBC targets.
            :param mongo_db_targets: A list of Mongo DB targets.
            :param s3_targets: Specifies Amazon Simple Storage Service (Amazon S3) targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-targets.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                targets_property = glue.CfnCrawler.TargetsProperty(
                    catalog_targets=[glue.CfnCrawler.CatalogTargetProperty(
                        database_name="databaseName",
                        tables=["tables"]
                    )],
                    dynamo_db_targets=[glue.CfnCrawler.DynamoDBTargetProperty(
                        path="path"
                    )],
                    jdbc_targets=[glue.CfnCrawler.JdbcTargetProperty(
                        connection_name="connectionName",
                        exclusions=["exclusions"],
                        path="path"
                    )],
                    mongo_db_targets=[glue.CfnCrawler.MongoDBTargetProperty(
                        connection_name="connectionName",
                        path="path"
                    )],
                    s3_targets=[glue.CfnCrawler.S3TargetProperty(
                        connection_name="connectionName",
                        dlq_event_queue_arn="dlqEventQueueArn",
                        event_queue_arn="eventQueueArn",
                        exclusions=["exclusions"],
                        path="path",
                        sample_size=123
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if catalog_targets is not None:
                self._values["catalog_targets"] = catalog_targets
            if dynamo_db_targets is not None:
                self._values["dynamo_db_targets"] = dynamo_db_targets
            if jdbc_targets is not None:
                self._values["jdbc_targets"] = jdbc_targets
            if mongo_db_targets is not None:
                self._values["mongo_db_targets"] = mongo_db_targets
            if s3_targets is not None:
                self._values["s3_targets"] = s3_targets

        @builtins.property
        def catalog_targets(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.CatalogTargetProperty", _IResolvable_da3f097b]]]]:
            '''Specifies AWS Glue Data Catalog targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-targets.html#cfn-glue-crawler-targets-catalogtargets
            '''
            result = self._values.get("catalog_targets")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.CatalogTargetProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def dynamo_db_targets(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.DynamoDBTargetProperty", _IResolvable_da3f097b]]]]:
            '''Specifies Amazon DynamoDB targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-targets.html#cfn-glue-crawler-targets-dynamodbtargets
            '''
            result = self._values.get("dynamo_db_targets")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.DynamoDBTargetProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def jdbc_targets(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.JdbcTargetProperty", _IResolvable_da3f097b]]]]:
            '''Specifies JDBC targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-targets.html#cfn-glue-crawler-targets-jdbctargets
            '''
            result = self._values.get("jdbc_targets")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.JdbcTargetProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def mongo_db_targets(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.MongoDBTargetProperty", _IResolvable_da3f097b]]]]:
            '''A list of Mongo DB targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-targets.html#cfn-glue-crawler-targets-mongodbtargets
            '''
            result = self._values.get("mongo_db_targets")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.MongoDBTargetProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def s3_targets(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.S3TargetProperty", _IResolvable_da3f097b]]]]:
            '''Specifies Amazon Simple Storage Service (Amazon S3) targets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-crawler-targets.html#cfn-glue-crawler-targets-s3targets
            '''
            result = self._values.get("s3_targets")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCrawler.S3TargetProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnCrawlerProps",
    jsii_struct_bases=[],
    name_mapping={
        "role": "role",
        "targets": "targets",
        "classifiers": "classifiers",
        "configuration": "configuration",
        "crawler_security_configuration": "crawlerSecurityConfiguration",
        "database_name": "databaseName",
        "description": "description",
        "name": "name",
        "recrawl_policy": "recrawlPolicy",
        "schedule": "schedule",
        "schema_change_policy": "schemaChangePolicy",
        "table_prefix": "tablePrefix",
        "tags": "tags",
    },
)
class CfnCrawlerProps:
    def __init__(
        self,
        *,
        role: builtins.str,
        targets: typing.Union[CfnCrawler.TargetsProperty, _IResolvable_da3f097b],
        classifiers: typing.Optional[typing.Sequence[builtins.str]] = None,
        configuration: typing.Optional[builtins.str] = None,
        crawler_security_configuration: typing.Optional[builtins.str] = None,
        database_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        recrawl_policy: typing.Optional[typing.Union[CfnCrawler.RecrawlPolicyProperty, _IResolvable_da3f097b]] = None,
        schedule: typing.Optional[typing.Union[CfnCrawler.ScheduleProperty, _IResolvable_da3f097b]] = None,
        schema_change_policy: typing.Optional[typing.Union[CfnCrawler.SchemaChangePolicyProperty, _IResolvable_da3f097b]] = None,
        table_prefix: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnCrawler``.

        :param role: The Amazon Resource Name (ARN) of an IAM role that's used to access customer resources, such as Amazon Simple Storage Service (Amazon S3) data.
        :param targets: A collection of targets to crawl.
        :param classifiers: A list of UTF-8 strings that specify the custom classifiers that are associated with the crawler.
        :param configuration: Crawler configuration information. This versioned JSON string allows users to specify aspects of a crawler's behavior. For more information, see `Configuring a Crawler <https://docs.aws.amazon.com/glue/latest/dg/crawler-configuration.html>`_ .
        :param crawler_security_configuration: The name of the ``SecurityConfiguration`` structure to be used by this crawler.
        :param database_name: The name of the database in which the crawler's output is stored.
        :param description: A description of the crawler.
        :param name: The name of the crawler.
        :param recrawl_policy: A policy that specifies whether to crawl the entire dataset again, or to crawl only folders that were added since the last crawler run.
        :param schedule: For scheduled crawlers, the schedule when the crawler runs.
        :param schema_change_policy: The policy that specifies update and delete behaviors for the crawler.
        :param table_prefix: The prefix added to the names of tables that are created.
        :param tags: The tags to use with this crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # tags: Any
            
            cfn_crawler_props = glue.CfnCrawlerProps(
                role="role",
                targets=glue.CfnCrawler.TargetsProperty(
                    catalog_targets=[glue.CfnCrawler.CatalogTargetProperty(
                        database_name="databaseName",
                        tables=["tables"]
                    )],
                    dynamo_db_targets=[glue.CfnCrawler.DynamoDBTargetProperty(
                        path="path"
                    )],
                    jdbc_targets=[glue.CfnCrawler.JdbcTargetProperty(
                        connection_name="connectionName",
                        exclusions=["exclusions"],
                        path="path"
                    )],
                    mongo_db_targets=[glue.CfnCrawler.MongoDBTargetProperty(
                        connection_name="connectionName",
                        path="path"
                    )],
                    s3_targets=[glue.CfnCrawler.S3TargetProperty(
                        connection_name="connectionName",
                        dlq_event_queue_arn="dlqEventQueueArn",
                        event_queue_arn="eventQueueArn",
                        exclusions=["exclusions"],
                        path="path",
                        sample_size=123
                    )]
                ),
            
                # the properties below are optional
                classifiers=["classifiers"],
                configuration="configuration",
                crawler_security_configuration="crawlerSecurityConfiguration",
                database_name="databaseName",
                description="description",
                name="name",
                recrawl_policy=glue.CfnCrawler.RecrawlPolicyProperty(
                    recrawl_behavior="recrawlBehavior"
                ),
                schedule=glue.CfnCrawler.ScheduleProperty(
                    schedule_expression="scheduleExpression"
                ),
                schema_change_policy=glue.CfnCrawler.SchemaChangePolicyProperty(
                    delete_behavior="deleteBehavior",
                    update_behavior="updateBehavior"
                ),
                table_prefix="tablePrefix",
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "role": role,
            "targets": targets,
        }
        if classifiers is not None:
            self._values["classifiers"] = classifiers
        if configuration is not None:
            self._values["configuration"] = configuration
        if crawler_security_configuration is not None:
            self._values["crawler_security_configuration"] = crawler_security_configuration
        if database_name is not None:
            self._values["database_name"] = database_name
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if recrawl_policy is not None:
            self._values["recrawl_policy"] = recrawl_policy
        if schedule is not None:
            self._values["schedule"] = schedule
        if schema_change_policy is not None:
            self._values["schema_change_policy"] = schema_change_policy
        if table_prefix is not None:
            self._values["table_prefix"] = table_prefix
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def role(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of an IAM role that's used to access customer resources, such as Amazon Simple Storage Service (Amazon S3) data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-role
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def targets(
        self,
    ) -> typing.Union[CfnCrawler.TargetsProperty, _IResolvable_da3f097b]:
        '''A collection of targets to crawl.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-targets
        '''
        result = self._values.get("targets")
        assert result is not None, "Required property 'targets' is missing"
        return typing.cast(typing.Union[CfnCrawler.TargetsProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def classifiers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of UTF-8 strings that specify the custom classifiers that are associated with the crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-classifiers
        '''
        result = self._values.get("classifiers")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def configuration(self) -> typing.Optional[builtins.str]:
        '''Crawler configuration information.

        This versioned JSON string allows users to specify aspects of a crawler's behavior. For more information, see `Configuring a Crawler <https://docs.aws.amazon.com/glue/latest/dg/crawler-configuration.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-configuration
        '''
        result = self._values.get("configuration")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def crawler_security_configuration(self) -> typing.Optional[builtins.str]:
        '''The name of the ``SecurityConfiguration`` structure to be used by this crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-crawlersecurityconfiguration
        '''
        result = self._values.get("crawler_security_configuration")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def database_name(self) -> typing.Optional[builtins.str]:
        '''The name of the database in which the crawler's output is stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-databasename
        '''
        result = self._values.get("database_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def recrawl_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnCrawler.RecrawlPolicyProperty, _IResolvable_da3f097b]]:
        '''A policy that specifies whether to crawl the entire dataset again, or to crawl only folders that were added since the last crawler run.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-recrawlpolicy
        '''
        result = self._values.get("recrawl_policy")
        return typing.cast(typing.Optional[typing.Union[CfnCrawler.RecrawlPolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def schedule(
        self,
    ) -> typing.Optional[typing.Union[CfnCrawler.ScheduleProperty, _IResolvable_da3f097b]]:
        '''For scheduled crawlers, the schedule when the crawler runs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-schedule
        '''
        result = self._values.get("schedule")
        return typing.cast(typing.Optional[typing.Union[CfnCrawler.ScheduleProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def schema_change_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnCrawler.SchemaChangePolicyProperty, _IResolvable_da3f097b]]:
        '''The policy that specifies update and delete behaviors for the crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-schemachangepolicy
        '''
        result = self._values.get("schema_change_policy")
        return typing.cast(typing.Optional[typing.Union[CfnCrawler.SchemaChangePolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def table_prefix(self) -> typing.Optional[builtins.str]:
        '''The prefix added to the names of tables that are created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-tableprefix
        '''
        result = self._values.get("table_prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''The tags to use with this crawler.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-crawler.html#cfn-glue-crawler-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCrawlerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDataCatalogEncryptionSettings(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnDataCatalogEncryptionSettings",
):
    '''A CloudFormation ``AWS::Glue::DataCatalogEncryptionSettings``.

    Sets the security configuration for a specified catalog. After the configuration has been set, the specified encryption is applied to every catalog write thereafter.

    :cloudformationResource: AWS::Glue::DataCatalogEncryptionSettings
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-datacatalogencryptionsettings.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        cfn_data_catalog_encryption_settings = glue.CfnDataCatalogEncryptionSettings(self, "MyCfnDataCatalogEncryptionSettings",
            catalog_id="catalogId",
            data_catalog_encryption_settings=glue.CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty(
                connection_password_encryption=glue.CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty(
                    kms_key_id="kmsKeyId",
                    return_connection_password_encrypted=False
                ),
                encryption_at_rest=glue.CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty(
                    catalog_encryption_mode="catalogEncryptionMode",
                    sse_aws_kms_key_id="sseAwsKmsKeyId"
                )
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        catalog_id: builtins.str,
        data_catalog_encryption_settings: typing.Union["CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::Glue::DataCatalogEncryptionSettings``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param catalog_id: The ID of the Data Catalog in which the settings are created.
        :param data_catalog_encryption_settings: Contains configuration information for maintaining Data Catalog security.
        '''
        props = CfnDataCatalogEncryptionSettingsProps(
            catalog_id=catalog_id,
            data_catalog_encryption_settings=data_catalog_encryption_settings,
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
    @jsii.member(jsii_name="catalogId")
    def catalog_id(self) -> builtins.str:
        '''The ID of the Data Catalog in which the settings are created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-datacatalogencryptionsettings.html#cfn-glue-datacatalogencryptionsettings-catalogid
        '''
        return typing.cast(builtins.str, jsii.get(self, "catalogId"))

    @catalog_id.setter
    def catalog_id(self, value: builtins.str) -> None:
        jsii.set(self, "catalogId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataCatalogEncryptionSettings")
    def data_catalog_encryption_settings(
        self,
    ) -> typing.Union["CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty", _IResolvable_da3f097b]:
        '''Contains configuration information for maintaining Data Catalog security.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-datacatalogencryptionsettings.html#cfn-glue-datacatalogencryptionsettings-datacatalogencryptionsettings
        '''
        return typing.cast(typing.Union["CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty", _IResolvable_da3f097b], jsii.get(self, "dataCatalogEncryptionSettings"))

    @data_catalog_encryption_settings.setter
    def data_catalog_encryption_settings(
        self,
        value: typing.Union["CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "dataCatalogEncryptionSettings", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "kms_key_id": "kmsKeyId",
            "return_connection_password_encrypted": "returnConnectionPasswordEncrypted",
        },
    )
    class ConnectionPasswordEncryptionProperty:
        def __init__(
            self,
            *,
            kms_key_id: typing.Optional[builtins.str] = None,
            return_connection_password_encrypted: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The data structure used by the Data Catalog to encrypt the password as part of ``CreateConnection`` or ``UpdateConnection`` and store it in the ``ENCRYPTED_PASSWORD`` field in the connection properties.

            You can enable catalog encryption or only password encryption.

            When a ``CreationConnection`` request arrives containing a password, the Data Catalog first encrypts the password using your AWS KMS key. It then encrypts the whole connection object again if catalog encryption is also enabled.

            This encryption requires that you set AWS KMS key permissions to enable or restrict access on the password key according to your security requirements. For example, you might want only administrators to have decrypt permission on the password key.

            :param kms_key_id: An AWS KMS key that is used to encrypt the connection password. If connection password protection is enabled, the caller of ``CreateConnection`` and ``UpdateConnection`` needs at least ``kms:Encrypt`` permission on the specified AWS KMS key, to encrypt passwords before storing them in the Data Catalog. You can set the decrypt permission to enable or restrict access on the password key according to your security requirements.
            :param return_connection_password_encrypted: When the ``ReturnConnectionPasswordEncrypted`` flag is set to "true", passwords remain encrypted in the responses of ``GetConnection`` and ``GetConnections`` . This encryption takes effect independently from catalog encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-connectionpasswordencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                connection_password_encryption_property = glue.CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty(
                    kms_key_id="kmsKeyId",
                    return_connection_password_encrypted=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id
            if return_connection_password_encrypted is not None:
                self._values["return_connection_password_encrypted"] = return_connection_password_encrypted

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''An AWS KMS key that is used to encrypt the connection password.

            If connection password protection is enabled, the caller of ``CreateConnection`` and ``UpdateConnection`` needs at least ``kms:Encrypt`` permission on the specified AWS KMS key, to encrypt passwords before storing them in the Data Catalog. You can set the decrypt permission to enable or restrict access on the password key according to your security requirements.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-connectionpasswordencryption.html#cfn-glue-datacatalogencryptionsettings-connectionpasswordencryption-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def return_connection_password_encrypted(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When the ``ReturnConnectionPasswordEncrypted`` flag is set to "true", passwords remain encrypted in the responses of ``GetConnection`` and ``GetConnections`` .

            This encryption takes effect independently from catalog encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-connectionpasswordencryption.html#cfn-glue-datacatalogencryptionsettings-connectionpasswordencryption-returnconnectionpasswordencrypted
            '''
            result = self._values.get("return_connection_password_encrypted")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectionPasswordEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connection_password_encryption": "connectionPasswordEncryption",
            "encryption_at_rest": "encryptionAtRest",
        },
    )
    class DataCatalogEncryptionSettingsProperty:
        def __init__(
            self,
            *,
            connection_password_encryption: typing.Optional[typing.Union["CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty", _IResolvable_da3f097b]] = None,
            encryption_at_rest: typing.Optional[typing.Union["CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Contains configuration information for maintaining Data Catalog security.

            :param connection_password_encryption: When connection password protection is enabled, the Data Catalog uses a customer-provided key to encrypt the password as part of ``CreateConnection`` or ``UpdateConnection`` and store it in the ``ENCRYPTED_PASSWORD`` field in the connection properties. You can enable catalog encryption or only password encryption.
            :param encryption_at_rest: Specifies the encryption-at-rest configuration for the Data Catalog.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-datacatalogencryptionsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                data_catalog_encryption_settings_property = glue.CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty(
                    connection_password_encryption=glue.CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty(
                        kms_key_id="kmsKeyId",
                        return_connection_password_encrypted=False
                    ),
                    encryption_at_rest=glue.CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty(
                        catalog_encryption_mode="catalogEncryptionMode",
                        sse_aws_kms_key_id="sseAwsKmsKeyId"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if connection_password_encryption is not None:
                self._values["connection_password_encryption"] = connection_password_encryption
            if encryption_at_rest is not None:
                self._values["encryption_at_rest"] = encryption_at_rest

        @builtins.property
        def connection_password_encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty", _IResolvable_da3f097b]]:
            '''When connection password protection is enabled, the Data Catalog uses a customer-provided key to encrypt the password as part of ``CreateConnection`` or ``UpdateConnection`` and store it in the ``ENCRYPTED_PASSWORD`` field in the connection properties.

            You can enable catalog encryption or only password encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-datacatalogencryptionsettings.html#cfn-glue-datacatalogencryptionsettings-datacatalogencryptionsettings-connectionpasswordencryption
            '''
            result = self._values.get("connection_password_encryption")
            return typing.cast(typing.Optional[typing.Union["CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def encryption_at_rest(
            self,
        ) -> typing.Optional[typing.Union["CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty", _IResolvable_da3f097b]]:
            '''Specifies the encryption-at-rest configuration for the Data Catalog.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-datacatalogencryptionsettings.html#cfn-glue-datacatalogencryptionsettings-datacatalogencryptionsettings-encryptionatrest
            '''
            result = self._values.get("encryption_at_rest")
            return typing.cast(typing.Optional[typing.Union["CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataCatalogEncryptionSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty",
        jsii_struct_bases=[],
        name_mapping={
            "catalog_encryption_mode": "catalogEncryptionMode",
            "sse_aws_kms_key_id": "sseAwsKmsKeyId",
        },
    )
    class EncryptionAtRestProperty:
        def __init__(
            self,
            *,
            catalog_encryption_mode: typing.Optional[builtins.str] = None,
            sse_aws_kms_key_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the encryption-at-rest configuration for the Data Catalog.

            :param catalog_encryption_mode: The encryption-at-rest mode for encrypting Data Catalog data.
            :param sse_aws_kms_key_id: The ID of the AWS KMS key to use for encryption at rest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-encryptionatrest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                encryption_at_rest_property = glue.CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty(
                    catalog_encryption_mode="catalogEncryptionMode",
                    sse_aws_kms_key_id="sseAwsKmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if catalog_encryption_mode is not None:
                self._values["catalog_encryption_mode"] = catalog_encryption_mode
            if sse_aws_kms_key_id is not None:
                self._values["sse_aws_kms_key_id"] = sse_aws_kms_key_id

        @builtins.property
        def catalog_encryption_mode(self) -> typing.Optional[builtins.str]:
            '''The encryption-at-rest mode for encrypting Data Catalog data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-encryptionatrest.html#cfn-glue-datacatalogencryptionsettings-encryptionatrest-catalogencryptionmode
            '''
            result = self._values.get("catalog_encryption_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sse_aws_kms_key_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the AWS KMS key to use for encryption at rest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-encryptionatrest.html#cfn-glue-datacatalogencryptionsettings-encryptionatrest-sseawskmskeyid
            '''
            result = self._values.get("sse_aws_kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionAtRestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnDataCatalogEncryptionSettingsProps",
    jsii_struct_bases=[],
    name_mapping={
        "catalog_id": "catalogId",
        "data_catalog_encryption_settings": "dataCatalogEncryptionSettings",
    },
)
class CfnDataCatalogEncryptionSettingsProps:
    def __init__(
        self,
        *,
        catalog_id: builtins.str,
        data_catalog_encryption_settings: typing.Union[CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnDataCatalogEncryptionSettings``.

        :param catalog_id: The ID of the Data Catalog in which the settings are created.
        :param data_catalog_encryption_settings: Contains configuration information for maintaining Data Catalog security.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-datacatalogencryptionsettings.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            cfn_data_catalog_encryption_settings_props = glue.CfnDataCatalogEncryptionSettingsProps(
                catalog_id="catalogId",
                data_catalog_encryption_settings=glue.CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty(
                    connection_password_encryption=glue.CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty(
                        kms_key_id="kmsKeyId",
                        return_connection_password_encrypted=False
                    ),
                    encryption_at_rest=glue.CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty(
                        catalog_encryption_mode="catalogEncryptionMode",
                        sse_aws_kms_key_id="sseAwsKmsKeyId"
                    )
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "catalog_id": catalog_id,
            "data_catalog_encryption_settings": data_catalog_encryption_settings,
        }

    @builtins.property
    def catalog_id(self) -> builtins.str:
        '''The ID of the Data Catalog in which the settings are created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-datacatalogencryptionsettings.html#cfn-glue-datacatalogencryptionsettings-catalogid
        '''
        result = self._values.get("catalog_id")
        assert result is not None, "Required property 'catalog_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def data_catalog_encryption_settings(
        self,
    ) -> typing.Union[CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty, _IResolvable_da3f097b]:
        '''Contains configuration information for maintaining Data Catalog security.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-datacatalogencryptionsettings.html#cfn-glue-datacatalogencryptionsettings-datacatalogencryptionsettings
        '''
        result = self._values.get("data_catalog_encryption_settings")
        assert result is not None, "Required property 'data_catalog_encryption_settings' is missing"
        return typing.cast(typing.Union[CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDataCatalogEncryptionSettingsProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDatabase(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnDatabase",
):
    '''A CloudFormation ``AWS::Glue::Database``.

    The ``AWS::Glue::Database`` resource specifies a logical grouping of tables in AWS Glue . For more information, see `Defining a Database in Your Data Catalog <https://docs.aws.amazon.com/glue/latest/dg/define-database.html>`_ and `Database Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-catalog-databases.html#aws-glue-api-catalog-databases-Database>`_ in the *AWS Glue Developer Guide* .

    :cloudformationResource: AWS::Glue::Database
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-database.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # parameters: Any
        
        cfn_database = glue.CfnDatabase(self, "MyCfnDatabase",
            catalog_id="catalogId",
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                create_table_default_permissions=[glue.CfnDatabase.PrincipalPrivilegesProperty(
                    permissions=["permissions"],
                    principal=glue.CfnDatabase.DataLakePrincipalProperty(
                        data_lake_principal_identifier="dataLakePrincipalIdentifier"
                    )
                )],
                description="description",
                location_uri="locationUri",
                name="name",
                parameters=parameters,
                target_database=glue.CfnDatabase.DatabaseIdentifierProperty(
                    catalog_id="catalogId",
                    database_name="databaseName"
                )
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        catalog_id: builtins.str,
        database_input: typing.Union["CfnDatabase.DatabaseInputProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::Glue::Database``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param catalog_id: The AWS account ID for the account in which to create the catalog object. .. epigraph:: To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId``
        :param database_input: The metadata for the database.
        '''
        props = CfnDatabaseProps(catalog_id=catalog_id, database_input=database_input)

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
    @jsii.member(jsii_name="catalogId")
    def catalog_id(self) -> builtins.str:
        '''The AWS account ID for the account in which to create the catalog object.

        .. epigraph::

           To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-database.html#cfn-glue-database-catalogid
        '''
        return typing.cast(builtins.str, jsii.get(self, "catalogId"))

    @catalog_id.setter
    def catalog_id(self, value: builtins.str) -> None:
        jsii.set(self, "catalogId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="databaseInput")
    def database_input(
        self,
    ) -> typing.Union["CfnDatabase.DatabaseInputProperty", _IResolvable_da3f097b]:
        '''The metadata for the database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-database.html#cfn-glue-database-databaseinput
        '''
        return typing.cast(typing.Union["CfnDatabase.DatabaseInputProperty", _IResolvable_da3f097b], jsii.get(self, "databaseInput"))

    @database_input.setter
    def database_input(
        self,
        value: typing.Union["CfnDatabase.DatabaseInputProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "databaseInput", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnDatabase.DataLakePrincipalProperty",
        jsii_struct_bases=[],
        name_mapping={"data_lake_principal_identifier": "dataLakePrincipalIdentifier"},
    )
    class DataLakePrincipalProperty:
        def __init__(
            self,
            *,
            data_lake_principal_identifier: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The AWS Lake Formation principal.

            :param data_lake_principal_identifier: An identifier for the AWS Lake Formation principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-datalakeprincipal.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                data_lake_principal_property = glue.CfnDatabase.DataLakePrincipalProperty(
                    data_lake_principal_identifier="dataLakePrincipalIdentifier"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if data_lake_principal_identifier is not None:
                self._values["data_lake_principal_identifier"] = data_lake_principal_identifier

        @builtins.property
        def data_lake_principal_identifier(self) -> typing.Optional[builtins.str]:
            '''An identifier for the AWS Lake Formation principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-datalakeprincipal.html#cfn-glue-database-datalakeprincipal-datalakeprincipalidentifier
            '''
            result = self._values.get("data_lake_principal_identifier")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataLakePrincipalProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnDatabase.DatabaseIdentifierProperty",
        jsii_struct_bases=[],
        name_mapping={"catalog_id": "catalogId", "database_name": "databaseName"},
    )
    class DatabaseIdentifierProperty:
        def __init__(
            self,
            *,
            catalog_id: typing.Optional[builtins.str] = None,
            database_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that describes a target database for resource linking.

            :param catalog_id: The ID of the Data Catalog in which the database resides.
            :param database_name: The name of the catalog database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseidentifier.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                database_identifier_property = glue.CfnDatabase.DatabaseIdentifierProperty(
                    catalog_id="catalogId",
                    database_name="databaseName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if catalog_id is not None:
                self._values["catalog_id"] = catalog_id
            if database_name is not None:
                self._values["database_name"] = database_name

        @builtins.property
        def catalog_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the Data Catalog in which the database resides.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseidentifier.html#cfn-glue-database-databaseidentifier-catalogid
            '''
            result = self._values.get("catalog_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def database_name(self) -> typing.Optional[builtins.str]:
            '''The name of the catalog database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseidentifier.html#cfn-glue-database-databaseidentifier-databasename
            '''
            result = self._values.get("database_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatabaseIdentifierProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnDatabase.DatabaseInputProperty",
        jsii_struct_bases=[],
        name_mapping={
            "create_table_default_permissions": "createTableDefaultPermissions",
            "description": "description",
            "location_uri": "locationUri",
            "name": "name",
            "parameters": "parameters",
            "target_database": "targetDatabase",
        },
    )
    class DatabaseInputProperty:
        def __init__(
            self,
            *,
            create_table_default_permissions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDatabase.PrincipalPrivilegesProperty", _IResolvable_da3f097b]]]] = None,
            description: typing.Optional[builtins.str] = None,
            location_uri: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
            parameters: typing.Any = None,
            target_database: typing.Optional[typing.Union["CfnDatabase.DatabaseIdentifierProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The structure used to create or update a database.

            :param create_table_default_permissions: Creates a set of default permissions on the table for principals.
            :param description: A description of the database.
            :param location_uri: The location of the database (for example, an HDFS path).
            :param name: The name of the database. For Hive compatibility, this is folded to lowercase when it is stored.
            :param parameters: These key-value pairs define parameters and properties of the database.
            :param target_database: A ``DatabaseIdentifier`` structure that describes a target database for resource linking.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseinput.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # parameters: Any
                
                database_input_property = glue.CfnDatabase.DatabaseInputProperty(
                    create_table_default_permissions=[glue.CfnDatabase.PrincipalPrivilegesProperty(
                        permissions=["permissions"],
                        principal=glue.CfnDatabase.DataLakePrincipalProperty(
                            data_lake_principal_identifier="dataLakePrincipalIdentifier"
                        )
                    )],
                    description="description",
                    location_uri="locationUri",
                    name="name",
                    parameters=parameters,
                    target_database=glue.CfnDatabase.DatabaseIdentifierProperty(
                        catalog_id="catalogId",
                        database_name="databaseName"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if create_table_default_permissions is not None:
                self._values["create_table_default_permissions"] = create_table_default_permissions
            if description is not None:
                self._values["description"] = description
            if location_uri is not None:
                self._values["location_uri"] = location_uri
            if name is not None:
                self._values["name"] = name
            if parameters is not None:
                self._values["parameters"] = parameters
            if target_database is not None:
                self._values["target_database"] = target_database

        @builtins.property
        def create_table_default_permissions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDatabase.PrincipalPrivilegesProperty", _IResolvable_da3f097b]]]]:
            '''Creates a set of default permissions on the table for principals.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseinput.html#cfn-glue-database-databaseinput-createtabledefaultpermissions
            '''
            result = self._values.get("create_table_default_permissions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDatabase.PrincipalPrivilegesProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A description of the database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseinput.html#cfn-glue-database-databaseinput-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def location_uri(self) -> typing.Optional[builtins.str]:
            '''The location of the database (for example, an HDFS path).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseinput.html#cfn-glue-database-databaseinput-locationuri
            '''
            result = self._values.get("location_uri")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the database.

            For Hive compatibility, this is folded to lowercase when it is stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseinput.html#cfn-glue-database-databaseinput-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''These key-value pairs define parameters and properties of the database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseinput.html#cfn-glue-database-databaseinput-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        @builtins.property
        def target_database(
            self,
        ) -> typing.Optional[typing.Union["CfnDatabase.DatabaseIdentifierProperty", _IResolvable_da3f097b]]:
            '''A ``DatabaseIdentifier`` structure that describes a target database for resource linking.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-databaseinput.html#cfn-glue-database-databaseinput-targetdatabase
            '''
            result = self._values.get("target_database")
            return typing.cast(typing.Optional[typing.Union["CfnDatabase.DatabaseIdentifierProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatabaseInputProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnDatabase.PrincipalPrivilegesProperty",
        jsii_struct_bases=[],
        name_mapping={"permissions": "permissions", "principal": "principal"},
    )
    class PrincipalPrivilegesProperty:
        def __init__(
            self,
            *,
            permissions: typing.Optional[typing.Sequence[builtins.str]] = None,
            principal: typing.Optional[typing.Union["CfnDatabase.DataLakePrincipalProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''the permissions granted to a principal.

            :param permissions: The permissions that are granted to the principal.
            :param principal: The principal who is granted permissions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-principalprivileges.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                principal_privileges_property = glue.CfnDatabase.PrincipalPrivilegesProperty(
                    permissions=["permissions"],
                    principal=glue.CfnDatabase.DataLakePrincipalProperty(
                        data_lake_principal_identifier="dataLakePrincipalIdentifier"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if permissions is not None:
                self._values["permissions"] = permissions
            if principal is not None:
                self._values["principal"] = principal

        @builtins.property
        def permissions(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The permissions that are granted to the principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-principalprivileges.html#cfn-glue-database-principalprivileges-permissions
            '''
            result = self._values.get("permissions")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def principal(
            self,
        ) -> typing.Optional[typing.Union["CfnDatabase.DataLakePrincipalProperty", _IResolvable_da3f097b]]:
            '''The principal who is granted permissions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-database-principalprivileges.html#cfn-glue-database-principalprivileges-principal
            '''
            result = self._values.get("principal")
            return typing.cast(typing.Optional[typing.Union["CfnDatabase.DataLakePrincipalProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PrincipalPrivilegesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnDatabaseProps",
    jsii_struct_bases=[],
    name_mapping={"catalog_id": "catalogId", "database_input": "databaseInput"},
)
class CfnDatabaseProps:
    def __init__(
        self,
        *,
        catalog_id: builtins.str,
        database_input: typing.Union[CfnDatabase.DatabaseInputProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnDatabase``.

        :param catalog_id: The AWS account ID for the account in which to create the catalog object. .. epigraph:: To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId``
        :param database_input: The metadata for the database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-database.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # parameters: Any
            
            cfn_database_props = glue.CfnDatabaseProps(
                catalog_id="catalogId",
                database_input=glue.CfnDatabase.DatabaseInputProperty(
                    create_table_default_permissions=[glue.CfnDatabase.PrincipalPrivilegesProperty(
                        permissions=["permissions"],
                        principal=glue.CfnDatabase.DataLakePrincipalProperty(
                            data_lake_principal_identifier="dataLakePrincipalIdentifier"
                        )
                    )],
                    description="description",
                    location_uri="locationUri",
                    name="name",
                    parameters=parameters,
                    target_database=glue.CfnDatabase.DatabaseIdentifierProperty(
                        catalog_id="catalogId",
                        database_name="databaseName"
                    )
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "catalog_id": catalog_id,
            "database_input": database_input,
        }

    @builtins.property
    def catalog_id(self) -> builtins.str:
        '''The AWS account ID for the account in which to create the catalog object.

        .. epigraph::

           To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-database.html#cfn-glue-database-catalogid
        '''
        result = self._values.get("catalog_id")
        assert result is not None, "Required property 'catalog_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def database_input(
        self,
    ) -> typing.Union[CfnDatabase.DatabaseInputProperty, _IResolvable_da3f097b]:
        '''The metadata for the database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-database.html#cfn-glue-database-databaseinput
        '''
        result = self._values.get("database_input")
        assert result is not None, "Required property 'database_input' is missing"
        return typing.cast(typing.Union[CfnDatabase.DatabaseInputProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDatabaseProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDevEndpoint(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnDevEndpoint",
):
    '''A CloudFormation ``AWS::Glue::DevEndpoint``.

    The ``AWS::Glue::DevEndpoint`` resource specifies a development endpoint where a developer can remotely debug ETL scripts for AWS Glue . For more information, see `DevEndpoint Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-dev-endpoint.html#aws-glue-api-jobs-dev-endpoint-DevEndpoint>`_ in the AWS Glue Developer Guide.

    :cloudformationResource: AWS::Glue::DevEndpoint
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # arguments_: Any
        # tags: Any
        
        cfn_dev_endpoint = glue.CfnDevEndpoint(self, "MyCfnDevEndpoint",
            role_arn="roleArn",
        
            # the properties below are optional
            arguments=arguments_,
            endpoint_name="endpointName",
            extra_jars_s3_path="extraJarsS3Path",
            extra_python_libs_s3_path="extraPythonLibsS3Path",
            glue_version="glueVersion",
            number_of_nodes=123,
            number_of_workers=123,
            public_key="publicKey",
            public_keys=["publicKeys"],
            security_configuration="securityConfiguration",
            security_group_ids=["securityGroupIds"],
            subnet_id="subnetId",
            tags=tags,
            worker_type="workerType"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        role_arn: builtins.str,
        arguments: typing.Any = None,
        endpoint_name: typing.Optional[builtins.str] = None,
        extra_jars_s3_path: typing.Optional[builtins.str] = None,
        extra_python_libs_s3_path: typing.Optional[builtins.str] = None,
        glue_version: typing.Optional[builtins.str] = None,
        number_of_nodes: typing.Optional[jsii.Number] = None,
        number_of_workers: typing.Optional[jsii.Number] = None,
        public_key: typing.Optional[builtins.str] = None,
        public_keys: typing.Optional[typing.Sequence[builtins.str]] = None,
        security_configuration: typing.Optional[builtins.str] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        subnet_id: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
        worker_type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Glue::DevEndpoint``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role used in this ``DevEndpoint`` .
        :param arguments: A map of arguments used to configure the ``DevEndpoint`` . Valid arguments are: - ``"--enable-glue-datacatalog": ""`` - ``"GLUE_PYTHON_VERSION": "3"`` - ``"GLUE_PYTHON_VERSION": "2"`` You can specify a version of Python support for development endpoints by using the ``Arguments`` parameter in the ``CreateDevEndpoint`` or ``UpdateDevEndpoint`` APIs. If no arguments are provided, the version defaults to Python 2.
        :param endpoint_name: The name of the ``DevEndpoint`` .
        :param extra_jars_s3_path: The path to one or more Java ``.jar`` files in an S3 bucket that should be loaded in your ``DevEndpoint`` . .. epigraph:: You can only use pure Java/Scala libraries with a ``DevEndpoint`` .
        :param extra_python_libs_s3_path: The paths to one or more Python libraries in an Amazon S3 bucket that should be loaded in your ``DevEndpoint`` . Multiple values must be complete paths separated by a comma. .. epigraph:: You can only use pure Python libraries with a ``DevEndpoint`` . Libraries that rely on C extensions, such as the `pandas <https://docs.aws.amazon.com/http://pandas.pydata.org/>`_ Python data analysis library, are not currently supported.
        :param glue_version: The AWS Glue version determines the versions of Apache Spark and Python that AWS Glue supports. The Python version indicates the version supported for running your ETL scripts on development endpoints. For more information about the available AWS Glue versions and corresponding Spark and Python versions, see `Glue version <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ in the developer guide. Development endpoints that are created without specifying a Glue version default to Glue 0.9. You can specify a version of Python support for development endpoints by using the ``Arguments`` parameter in the ``CreateDevEndpoint`` or ``UpdateDevEndpoint`` APIs. If no arguments are provided, the version defaults to Python 2.
        :param number_of_nodes: The number of AWS Glue Data Processing Units (DPUs) allocated to this ``DevEndpoint`` .
        :param number_of_workers: The number of workers of a defined ``workerType`` that are allocated to the development endpoint. The maximum number of workers you can define are 299 for ``G.1X`` , and 149 for ``G.2X`` .
        :param public_key: The public key to be used by this ``DevEndpoint`` for authentication. This attribute is provided for backward compatibility because the recommended attribute to use is public keys.
        :param public_keys: A list of public keys to be used by the ``DevEndpoints`` for authentication. Using this attribute is preferred over a single public key because the public keys allow you to have a different private key per client. .. epigraph:: If you previously created an endpoint with a public key, you must remove that key to be able to set a list of public keys. Call the ``UpdateDevEndpoint`` API operation with the public key content in the ``deletePublicKeys`` attribute, and the list of new keys in the ``addPublicKeys`` attribute.
        :param security_configuration: The name of the ``SecurityConfiguration`` structure to be used with this ``DevEndpoint`` .
        :param security_group_ids: A list of security group identifiers used in this ``DevEndpoint`` .
        :param subnet_id: The subnet ID for this ``DevEndpoint`` .
        :param tags: The tags to use with this DevEndpoint.
        :param worker_type: The type of predefined worker that is allocated to the development endpoint. Accepts a value of Standard, G.1X, or G.2X. - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker. - For the ``G.1X`` worker type, each worker maps to 1 DPU (4 vCPU, 16 GB of memory, 64 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs. - For the ``G.2X`` worker type, each worker maps to 2 DPU (8 vCPU, 32 GB of memory, 128 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs. Known issue: when a development endpoint is created with the ``G.2X`` ``WorkerType`` configuration, the Spark drivers for the development endpoint will run on 4 vCPU, 16 GB of memory, and a 64 GB disk.
        '''
        props = CfnDevEndpointProps(
            role_arn=role_arn,
            arguments=arguments,
            endpoint_name=endpoint_name,
            extra_jars_s3_path=extra_jars_s3_path,
            extra_python_libs_s3_path=extra_python_libs_s3_path,
            glue_version=glue_version,
            number_of_nodes=number_of_nodes,
            number_of_workers=number_of_workers,
            public_key=public_key,
            public_keys=public_keys,
            security_configuration=security_configuration,
            security_group_ids=security_group_ids,
            subnet_id=subnet_id,
            tags=tags,
            worker_type=worker_type,
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
        '''The tags to use with this DevEndpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="arguments")
    def arguments(self) -> typing.Any:
        '''A map of arguments used to configure the ``DevEndpoint`` .

        Valid arguments are:

        - ``"--enable-glue-datacatalog": ""``
        - ``"GLUE_PYTHON_VERSION": "3"``
        - ``"GLUE_PYTHON_VERSION": "2"``

        You can specify a version of Python support for development endpoints by using the ``Arguments`` parameter in the ``CreateDevEndpoint`` or ``UpdateDevEndpoint`` APIs. If no arguments are provided, the version defaults to Python 2.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-arguments
        '''
        return typing.cast(typing.Any, jsii.get(self, "arguments"))

    @arguments.setter
    def arguments(self, value: typing.Any) -> None:
        jsii.set(self, "arguments", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role used in this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-rolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="endpointName")
    def endpoint_name(self) -> typing.Optional[builtins.str]:
        '''The name of the ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-endpointname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "endpointName"))

    @endpoint_name.setter
    def endpoint_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "endpointName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="extraJarsS3Path")
    def extra_jars_s3_path(self) -> typing.Optional[builtins.str]:
        '''The path to one or more Java ``.jar`` files in an S3 bucket that should be loaded in your ``DevEndpoint`` .

        .. epigraph::

           You can only use pure Java/Scala libraries with a ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-extrajarss3path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "extraJarsS3Path"))

    @extra_jars_s3_path.setter
    def extra_jars_s3_path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "extraJarsS3Path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="extraPythonLibsS3Path")
    def extra_python_libs_s3_path(self) -> typing.Optional[builtins.str]:
        '''The paths to one or more Python libraries in an Amazon S3 bucket that should be loaded in your ``DevEndpoint`` .

        Multiple values must be complete paths separated by a comma.
        .. epigraph::

           You can only use pure Python libraries with a ``DevEndpoint`` . Libraries that rely on C extensions, such as the `pandas <https://docs.aws.amazon.com/http://pandas.pydata.org/>`_ Python data analysis library, are not currently supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-extrapythonlibss3path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "extraPythonLibsS3Path"))

    @extra_python_libs_s3_path.setter
    def extra_python_libs_s3_path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "extraPythonLibsS3Path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="glueVersion")
    def glue_version(self) -> typing.Optional[builtins.str]:
        '''The AWS Glue version determines the versions of Apache Spark and Python that AWS Glue supports.

        The Python version indicates the version supported for running your ETL scripts on development endpoints.

        For more information about the available AWS Glue versions and corresponding Spark and Python versions, see `Glue version <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ in the developer guide.

        Development endpoints that are created without specifying a Glue version default to Glue 0.9.

        You can specify a version of Python support for development endpoints by using the ``Arguments`` parameter in the ``CreateDevEndpoint`` or ``UpdateDevEndpoint`` APIs. If no arguments are provided, the version defaults to Python 2.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-glueversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "glueVersion"))

    @glue_version.setter
    def glue_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "glueVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="numberOfNodes")
    def number_of_nodes(self) -> typing.Optional[jsii.Number]:
        '''The number of AWS Glue Data Processing Units (DPUs) allocated to this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-numberofnodes
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "numberOfNodes"))

    @number_of_nodes.setter
    def number_of_nodes(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "numberOfNodes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="numberOfWorkers")
    def number_of_workers(self) -> typing.Optional[jsii.Number]:
        '''The number of workers of a defined ``workerType`` that are allocated to the development endpoint.

        The maximum number of workers you can define are 299 for ``G.1X`` , and 149 for ``G.2X`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-numberofworkers
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "numberOfWorkers"))

    @number_of_workers.setter
    def number_of_workers(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "numberOfWorkers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publicKey")
    def public_key(self) -> typing.Optional[builtins.str]:
        '''The public key to be used by this ``DevEndpoint`` for authentication.

        This attribute is provided for backward compatibility because the recommended attribute to use is public keys.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-publickey
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "publicKey"))

    @public_key.setter
    def public_key(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "publicKey", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publicKeys")
    def public_keys(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of public keys to be used by the ``DevEndpoints`` for authentication.

        Using this attribute is preferred over a single public key because the public keys allow you to have a different private key per client.
        .. epigraph::

           If you previously created an endpoint with a public key, you must remove that key to be able to set a list of public keys. Call the ``UpdateDevEndpoint`` API operation with the public key content in the ``deletePublicKeys`` attribute, and the list of new keys in the ``addPublicKeys`` attribute.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-publickeys
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "publicKeys"))

    @public_keys.setter
    def public_keys(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "publicKeys", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityConfiguration")
    def security_configuration(self) -> typing.Optional[builtins.str]:
        '''The name of the ``SecurityConfiguration`` structure to be used with this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-securityconfiguration
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "securityConfiguration"))

    @security_configuration.setter
    def security_configuration(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "securityConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroupIds")
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of security group identifiers used in this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-securitygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "securityGroupIds"))

    @security_group_ids.setter
    def security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "securityGroupIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetId")
    def subnet_id(self) -> typing.Optional[builtins.str]:
        '''The subnet ID for this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-subnetid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "subnetId"))

    @subnet_id.setter
    def subnet_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "subnetId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workerType")
    def worker_type(self) -> typing.Optional[builtins.str]:
        '''The type of predefined worker that is allocated to the development endpoint.

        Accepts a value of Standard, G.1X, or G.2X.

        - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker.
        - For the ``G.1X`` worker type, each worker maps to 1 DPU (4 vCPU, 16 GB of memory, 64 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.
        - For the ``G.2X`` worker type, each worker maps to 2 DPU (8 vCPU, 32 GB of memory, 128 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.

        Known issue: when a development endpoint is created with the ``G.2X`` ``WorkerType`` configuration, the Spark drivers for the development endpoint will run on 4 vCPU, 16 GB of memory, and a 64 GB disk.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-workertype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "workerType"))

    @worker_type.setter
    def worker_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "workerType", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnDevEndpointProps",
    jsii_struct_bases=[],
    name_mapping={
        "role_arn": "roleArn",
        "arguments": "arguments",
        "endpoint_name": "endpointName",
        "extra_jars_s3_path": "extraJarsS3Path",
        "extra_python_libs_s3_path": "extraPythonLibsS3Path",
        "glue_version": "glueVersion",
        "number_of_nodes": "numberOfNodes",
        "number_of_workers": "numberOfWorkers",
        "public_key": "publicKey",
        "public_keys": "publicKeys",
        "security_configuration": "securityConfiguration",
        "security_group_ids": "securityGroupIds",
        "subnet_id": "subnetId",
        "tags": "tags",
        "worker_type": "workerType",
    },
)
class CfnDevEndpointProps:
    def __init__(
        self,
        *,
        role_arn: builtins.str,
        arguments: typing.Any = None,
        endpoint_name: typing.Optional[builtins.str] = None,
        extra_jars_s3_path: typing.Optional[builtins.str] = None,
        extra_python_libs_s3_path: typing.Optional[builtins.str] = None,
        glue_version: typing.Optional[builtins.str] = None,
        number_of_nodes: typing.Optional[jsii.Number] = None,
        number_of_workers: typing.Optional[jsii.Number] = None,
        public_key: typing.Optional[builtins.str] = None,
        public_keys: typing.Optional[typing.Sequence[builtins.str]] = None,
        security_configuration: typing.Optional[builtins.str] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        subnet_id: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
        worker_type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnDevEndpoint``.

        :param role_arn: The Amazon Resource Name (ARN) of the IAM role used in this ``DevEndpoint`` .
        :param arguments: A map of arguments used to configure the ``DevEndpoint`` . Valid arguments are: - ``"--enable-glue-datacatalog": ""`` - ``"GLUE_PYTHON_VERSION": "3"`` - ``"GLUE_PYTHON_VERSION": "2"`` You can specify a version of Python support for development endpoints by using the ``Arguments`` parameter in the ``CreateDevEndpoint`` or ``UpdateDevEndpoint`` APIs. If no arguments are provided, the version defaults to Python 2.
        :param endpoint_name: The name of the ``DevEndpoint`` .
        :param extra_jars_s3_path: The path to one or more Java ``.jar`` files in an S3 bucket that should be loaded in your ``DevEndpoint`` . .. epigraph:: You can only use pure Java/Scala libraries with a ``DevEndpoint`` .
        :param extra_python_libs_s3_path: The paths to one or more Python libraries in an Amazon S3 bucket that should be loaded in your ``DevEndpoint`` . Multiple values must be complete paths separated by a comma. .. epigraph:: You can only use pure Python libraries with a ``DevEndpoint`` . Libraries that rely on C extensions, such as the `pandas <https://docs.aws.amazon.com/http://pandas.pydata.org/>`_ Python data analysis library, are not currently supported.
        :param glue_version: The AWS Glue version determines the versions of Apache Spark and Python that AWS Glue supports. The Python version indicates the version supported for running your ETL scripts on development endpoints. For more information about the available AWS Glue versions and corresponding Spark and Python versions, see `Glue version <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ in the developer guide. Development endpoints that are created without specifying a Glue version default to Glue 0.9. You can specify a version of Python support for development endpoints by using the ``Arguments`` parameter in the ``CreateDevEndpoint`` or ``UpdateDevEndpoint`` APIs. If no arguments are provided, the version defaults to Python 2.
        :param number_of_nodes: The number of AWS Glue Data Processing Units (DPUs) allocated to this ``DevEndpoint`` .
        :param number_of_workers: The number of workers of a defined ``workerType`` that are allocated to the development endpoint. The maximum number of workers you can define are 299 for ``G.1X`` , and 149 for ``G.2X`` .
        :param public_key: The public key to be used by this ``DevEndpoint`` for authentication. This attribute is provided for backward compatibility because the recommended attribute to use is public keys.
        :param public_keys: A list of public keys to be used by the ``DevEndpoints`` for authentication. Using this attribute is preferred over a single public key because the public keys allow you to have a different private key per client. .. epigraph:: If you previously created an endpoint with a public key, you must remove that key to be able to set a list of public keys. Call the ``UpdateDevEndpoint`` API operation with the public key content in the ``deletePublicKeys`` attribute, and the list of new keys in the ``addPublicKeys`` attribute.
        :param security_configuration: The name of the ``SecurityConfiguration`` structure to be used with this ``DevEndpoint`` .
        :param security_group_ids: A list of security group identifiers used in this ``DevEndpoint`` .
        :param subnet_id: The subnet ID for this ``DevEndpoint`` .
        :param tags: The tags to use with this DevEndpoint.
        :param worker_type: The type of predefined worker that is allocated to the development endpoint. Accepts a value of Standard, G.1X, or G.2X. - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker. - For the ``G.1X`` worker type, each worker maps to 1 DPU (4 vCPU, 16 GB of memory, 64 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs. - For the ``G.2X`` worker type, each worker maps to 2 DPU (8 vCPU, 32 GB of memory, 128 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs. Known issue: when a development endpoint is created with the ``G.2X`` ``WorkerType`` configuration, the Spark drivers for the development endpoint will run on 4 vCPU, 16 GB of memory, and a 64 GB disk.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # arguments_: Any
            # tags: Any
            
            cfn_dev_endpoint_props = glue.CfnDevEndpointProps(
                role_arn="roleArn",
            
                # the properties below are optional
                arguments=arguments_,
                endpoint_name="endpointName",
                extra_jars_s3_path="extraJarsS3Path",
                extra_python_libs_s3_path="extraPythonLibsS3Path",
                glue_version="glueVersion",
                number_of_nodes=123,
                number_of_workers=123,
                public_key="publicKey",
                public_keys=["publicKeys"],
                security_configuration="securityConfiguration",
                security_group_ids=["securityGroupIds"],
                subnet_id="subnetId",
                tags=tags,
                worker_type="workerType"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "role_arn": role_arn,
        }
        if arguments is not None:
            self._values["arguments"] = arguments
        if endpoint_name is not None:
            self._values["endpoint_name"] = endpoint_name
        if extra_jars_s3_path is not None:
            self._values["extra_jars_s3_path"] = extra_jars_s3_path
        if extra_python_libs_s3_path is not None:
            self._values["extra_python_libs_s3_path"] = extra_python_libs_s3_path
        if glue_version is not None:
            self._values["glue_version"] = glue_version
        if number_of_nodes is not None:
            self._values["number_of_nodes"] = number_of_nodes
        if number_of_workers is not None:
            self._values["number_of_workers"] = number_of_workers
        if public_key is not None:
            self._values["public_key"] = public_key
        if public_keys is not None:
            self._values["public_keys"] = public_keys
        if security_configuration is not None:
            self._values["security_configuration"] = security_configuration
        if security_group_ids is not None:
            self._values["security_group_ids"] = security_group_ids
        if subnet_id is not None:
            self._values["subnet_id"] = subnet_id
        if tags is not None:
            self._values["tags"] = tags
        if worker_type is not None:
            self._values["worker_type"] = worker_type

    @builtins.property
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role used in this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-rolearn
        '''
        result = self._values.get("role_arn")
        assert result is not None, "Required property 'role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def arguments(self) -> typing.Any:
        '''A map of arguments used to configure the ``DevEndpoint`` .

        Valid arguments are:

        - ``"--enable-glue-datacatalog": ""``
        - ``"GLUE_PYTHON_VERSION": "3"``
        - ``"GLUE_PYTHON_VERSION": "2"``

        You can specify a version of Python support for development endpoints by using the ``Arguments`` parameter in the ``CreateDevEndpoint`` or ``UpdateDevEndpoint`` APIs. If no arguments are provided, the version defaults to Python 2.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-arguments
        '''
        result = self._values.get("arguments")
        return typing.cast(typing.Any, result)

    @builtins.property
    def endpoint_name(self) -> typing.Optional[builtins.str]:
        '''The name of the ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-endpointname
        '''
        result = self._values.get("endpoint_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def extra_jars_s3_path(self) -> typing.Optional[builtins.str]:
        '''The path to one or more Java ``.jar`` files in an S3 bucket that should be loaded in your ``DevEndpoint`` .

        .. epigraph::

           You can only use pure Java/Scala libraries with a ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-extrajarss3path
        '''
        result = self._values.get("extra_jars_s3_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def extra_python_libs_s3_path(self) -> typing.Optional[builtins.str]:
        '''The paths to one or more Python libraries in an Amazon S3 bucket that should be loaded in your ``DevEndpoint`` .

        Multiple values must be complete paths separated by a comma.
        .. epigraph::

           You can only use pure Python libraries with a ``DevEndpoint`` . Libraries that rely on C extensions, such as the `pandas <https://docs.aws.amazon.com/http://pandas.pydata.org/>`_ Python data analysis library, are not currently supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-extrapythonlibss3path
        '''
        result = self._values.get("extra_python_libs_s3_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def glue_version(self) -> typing.Optional[builtins.str]:
        '''The AWS Glue version determines the versions of Apache Spark and Python that AWS Glue supports.

        The Python version indicates the version supported for running your ETL scripts on development endpoints.

        For more information about the available AWS Glue versions and corresponding Spark and Python versions, see `Glue version <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ in the developer guide.

        Development endpoints that are created without specifying a Glue version default to Glue 0.9.

        You can specify a version of Python support for development endpoints by using the ``Arguments`` parameter in the ``CreateDevEndpoint`` or ``UpdateDevEndpoint`` APIs. If no arguments are provided, the version defaults to Python 2.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-glueversion
        '''
        result = self._values.get("glue_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def number_of_nodes(self) -> typing.Optional[jsii.Number]:
        '''The number of AWS Glue Data Processing Units (DPUs) allocated to this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-numberofnodes
        '''
        result = self._values.get("number_of_nodes")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def number_of_workers(self) -> typing.Optional[jsii.Number]:
        '''The number of workers of a defined ``workerType`` that are allocated to the development endpoint.

        The maximum number of workers you can define are 299 for ``G.1X`` , and 149 for ``G.2X`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-numberofworkers
        '''
        result = self._values.get("number_of_workers")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def public_key(self) -> typing.Optional[builtins.str]:
        '''The public key to be used by this ``DevEndpoint`` for authentication.

        This attribute is provided for backward compatibility because the recommended attribute to use is public keys.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-publickey
        '''
        result = self._values.get("public_key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def public_keys(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of public keys to be used by the ``DevEndpoints`` for authentication.

        Using this attribute is preferred over a single public key because the public keys allow you to have a different private key per client.
        .. epigraph::

           If you previously created an endpoint with a public key, you must remove that key to be able to set a list of public keys. Call the ``UpdateDevEndpoint`` API operation with the public key content in the ``deletePublicKeys`` attribute, and the list of new keys in the ``addPublicKeys`` attribute.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-publickeys
        '''
        result = self._values.get("public_keys")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def security_configuration(self) -> typing.Optional[builtins.str]:
        '''The name of the ``SecurityConfiguration`` structure to be used with this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-securityconfiguration
        '''
        result = self._values.get("security_configuration")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of security group identifiers used in this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-securitygroupids
        '''
        result = self._values.get("security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def subnet_id(self) -> typing.Optional[builtins.str]:
        '''The subnet ID for this ``DevEndpoint`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-subnetid
        '''
        result = self._values.get("subnet_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''The tags to use with this DevEndpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def worker_type(self) -> typing.Optional[builtins.str]:
        '''The type of predefined worker that is allocated to the development endpoint.

        Accepts a value of Standard, G.1X, or G.2X.

        - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker.
        - For the ``G.1X`` worker type, each worker maps to 1 DPU (4 vCPU, 16 GB of memory, 64 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.
        - For the ``G.2X`` worker type, each worker maps to 2 DPU (8 vCPU, 32 GB of memory, 128 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.

        Known issue: when a development endpoint is created with the ``G.2X`` ``WorkerType`` configuration, the Spark drivers for the development endpoint will run on 4 vCPU, 16 GB of memory, and a 64 GB disk.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-devendpoint.html#cfn-glue-devendpoint-workertype
        '''
        result = self._values.get("worker_type")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDevEndpointProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnJob(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnJob",
):
    '''A CloudFormation ``AWS::Glue::Job``.

    The ``AWS::Glue::Job`` resource specifies an AWS Glue job in the data catalog. For more information, see `Adding Jobs in AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ and `Job Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-job.html#aws-glue-api-jobs-job-Job>`_ in the *AWS Glue Developer Guide.*

    :cloudformationResource: AWS::Glue::Job
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # default_arguments: Any
        # tags: Any
        
        cfn_job = glue.CfnJob(self, "MyCfnJob",
            command=glue.CfnJob.JobCommandProperty(
                name="name",
                python_version="pythonVersion",
                script_location="scriptLocation"
            ),
            role="role",
        
            # the properties below are optional
            allocated_capacity=123,
            connections=glue.CfnJob.ConnectionsListProperty(
                connections=["connections"]
            ),
            default_arguments=default_arguments,
            description="description",
            execution_property=glue.CfnJob.ExecutionPropertyProperty(
                max_concurrent_runs=123
            ),
            glue_version="glueVersion",
            log_uri="logUri",
            max_capacity=123,
            max_retries=123,
            name="name",
            notification_property=glue.CfnJob.NotificationPropertyProperty(
                notify_delay_after=123
            ),
            number_of_workers=123,
            security_configuration="securityConfiguration",
            tags=tags,
            timeout=123,
            worker_type="workerType"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        command: typing.Union["CfnJob.JobCommandProperty", _IResolvable_da3f097b],
        role: builtins.str,
        allocated_capacity: typing.Optional[jsii.Number] = None,
        connections: typing.Optional[typing.Union["CfnJob.ConnectionsListProperty", _IResolvable_da3f097b]] = None,
        default_arguments: typing.Any = None,
        description: typing.Optional[builtins.str] = None,
        execution_property: typing.Optional[typing.Union["CfnJob.ExecutionPropertyProperty", _IResolvable_da3f097b]] = None,
        glue_version: typing.Optional[builtins.str] = None,
        log_uri: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_retries: typing.Optional[jsii.Number] = None,
        name: typing.Optional[builtins.str] = None,
        notification_property: typing.Optional[typing.Union["CfnJob.NotificationPropertyProperty", _IResolvable_da3f097b]] = None,
        number_of_workers: typing.Optional[jsii.Number] = None,
        security_configuration: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
        timeout: typing.Optional[jsii.Number] = None,
        worker_type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Glue::Job``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param command: The code that executes a job.
        :param role: The name or Amazon Resource Name (ARN) of the IAM role associated with this job.
        :param allocated_capacity: The number of capacity units that are allocated to this job.
        :param connections: The connections used for this job.
        :param default_arguments: The default arguments for this job, specified as name-value pairs. You can specify arguments here that your own job-execution script consumes, in addition to arguments that AWS Glue itself consumes. For information about how to specify and consume your own job arguments, see `Calling AWS Glue APIs in Python <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-python-calling.html>`_ in the *AWS Glue Developer Guide* . For information about the key-value pairs that AWS Glue consumes to set up your job, see `Special Parameters Used by AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-etl-glue-arguments.html>`_ in the *AWS Glue Developer Guide* .
        :param description: A description of the job.
        :param execution_property: The maximum number of concurrent runs that are allowed for this job.
        :param glue_version: Glue version determines the versions of Apache Spark and Python that AWS Glue supports. The Python version indicates the version supported for jobs of type Spark. For more information about the available AWS Glue versions and corresponding Spark and Python versions, see `Glue version <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ in the developer guide. Jobs that are created without specifying a Glue version default to Glue 0.9.
        :param log_uri: This field is reserved for future use.
        :param max_capacity: The number of AWS Glue data processing units (DPUs) that can be allocated when this job runs. A DPU is a relative measure of processing power that consists of 4 vCPUs of compute capacity and 16 GB of memory. Do not set ``Max Capacity`` if using ``WorkerType`` and ``NumberOfWorkers`` . The value that can be allocated for ``MaxCapacity`` depends on whether you are running a Python shell job or an Apache Spark ETL job: - When you specify a Python shell job ( ``JobCommand.Name`` ="pythonshell"), you can allocate either 0.0625 or 1 DPU. The default is 0.0625 DPU. - When you specify an Apache Spark ETL job ( ``JobCommand.Name`` ="glueetl"), you can allocate from 2 to 100 DPUs. The default is 10 DPUs. This job type cannot have a fractional DPU allocation.
        :param max_retries: The maximum number of times to retry this job after a JobRun fails.
        :param name: The name you assign to this job definition.
        :param notification_property: Specifies configuration properties of a notification.
        :param number_of_workers: The number of workers of a defined ``workerType`` that are allocated when a job runs. The maximum number of workers you can define are 299 for ``G.1X`` , and 149 for ``G.2X`` .
        :param security_configuration: The name of the ``SecurityConfiguration`` structure to be used with this job.
        :param tags: The tags to use with this job.
        :param timeout: The job timeout in minutes. This is the maximum time that a job run can consume resources before it is terminated and enters TIMEOUT status. The default is 2,880 minutes (48 hours).
        :param worker_type: The type of predefined worker that is allocated when a job runs. Accepts a value of Standard, G.1X, or G.2X. - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker. - For the ``G.1X`` worker type, each worker maps to 1 DPU (4 vCPU, 16 GB of memory, 64 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs. - For the ``G.2X`` worker type, each worker maps to 2 DPU (8 vCPU, 32 GB of memory, 128 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.
        '''
        props = CfnJobProps(
            command=command,
            role=role,
            allocated_capacity=allocated_capacity,
            connections=connections,
            default_arguments=default_arguments,
            description=description,
            execution_property=execution_property,
            glue_version=glue_version,
            log_uri=log_uri,
            max_capacity=max_capacity,
            max_retries=max_retries,
            name=name,
            notification_property=notification_property,
            number_of_workers=number_of_workers,
            security_configuration=security_configuration,
            tags=tags,
            timeout=timeout,
            worker_type=worker_type,
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
        '''The tags to use with this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="command")
    def command(
        self,
    ) -> typing.Union["CfnJob.JobCommandProperty", _IResolvable_da3f097b]:
        '''The code that executes a job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-command
        '''
        return typing.cast(typing.Union["CfnJob.JobCommandProperty", _IResolvable_da3f097b], jsii.get(self, "command"))

    @command.setter
    def command(
        self,
        value: typing.Union["CfnJob.JobCommandProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "command", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultArguments")
    def default_arguments(self) -> typing.Any:
        '''The default arguments for this job, specified as name-value pairs.

        You can specify arguments here that your own job-execution script consumes, in addition to arguments that AWS Glue itself consumes.

        For information about how to specify and consume your own job arguments, see `Calling AWS Glue APIs in Python <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-python-calling.html>`_ in the *AWS Glue Developer Guide* .

        For information about the key-value pairs that AWS Glue consumes to set up your job, see `Special Parameters Used by AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-etl-glue-arguments.html>`_ in the *AWS Glue Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-defaultarguments
        '''
        return typing.cast(typing.Any, jsii.get(self, "defaultArguments"))

    @default_arguments.setter
    def default_arguments(self, value: typing.Any) -> None:
        jsii.set(self, "defaultArguments", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> builtins.str:
        '''The name or Amazon Resource Name (ARN) of the IAM role associated with this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-role
        '''
        return typing.cast(builtins.str, jsii.get(self, "role"))

    @role.setter
    def role(self, value: builtins.str) -> None:
        jsii.set(self, "role", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allocatedCapacity")
    def allocated_capacity(self) -> typing.Optional[jsii.Number]:
        '''The number of capacity units that are allocated to this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-allocatedcapacity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "allocatedCapacity"))

    @allocated_capacity.setter
    def allocated_capacity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "allocatedCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(
        self,
    ) -> typing.Optional[typing.Union["CfnJob.ConnectionsListProperty", _IResolvable_da3f097b]]:
        '''The connections used for this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-connections
        '''
        return typing.cast(typing.Optional[typing.Union["CfnJob.ConnectionsListProperty", _IResolvable_da3f097b]], jsii.get(self, "connections"))

    @connections.setter
    def connections(
        self,
        value: typing.Optional[typing.Union["CfnJob.ConnectionsListProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "connections", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="executionProperty")
    def execution_property(
        self,
    ) -> typing.Optional[typing.Union["CfnJob.ExecutionPropertyProperty", _IResolvable_da3f097b]]:
        '''The maximum number of concurrent runs that are allowed for this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-executionproperty
        '''
        return typing.cast(typing.Optional[typing.Union["CfnJob.ExecutionPropertyProperty", _IResolvable_da3f097b]], jsii.get(self, "executionProperty"))

    @execution_property.setter
    def execution_property(
        self,
        value: typing.Optional[typing.Union["CfnJob.ExecutionPropertyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "executionProperty", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="glueVersion")
    def glue_version(self) -> typing.Optional[builtins.str]:
        '''Glue version determines the versions of Apache Spark and Python that AWS Glue supports.

        The Python version indicates the version supported for jobs of type Spark.

        For more information about the available AWS Glue versions and corresponding Spark and Python versions, see `Glue version <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ in the developer guide.

        Jobs that are created without specifying a Glue version default to Glue 0.9.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-glueversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "glueVersion"))

    @glue_version.setter
    def glue_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "glueVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logUri")
    def log_uri(self) -> typing.Optional[builtins.str]:
        '''This field is reserved for future use.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-loguri
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "logUri"))

    @log_uri.setter
    def log_uri(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "logUri", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxCapacity")
    def max_capacity(self) -> typing.Optional[jsii.Number]:
        '''The number of AWS Glue data processing units (DPUs) that can be allocated when this job runs.

        A DPU is a relative measure of processing power that consists of 4 vCPUs of compute capacity and 16 GB of memory.

        Do not set ``Max Capacity`` if using ``WorkerType`` and ``NumberOfWorkers`` .

        The value that can be allocated for ``MaxCapacity`` depends on whether you are running a Python shell job or an Apache Spark ETL job:

        - When you specify a Python shell job ( ``JobCommand.Name`` ="pythonshell"), you can allocate either 0.0625 or 1 DPU. The default is 0.0625 DPU.
        - When you specify an Apache Spark ETL job ( ``JobCommand.Name`` ="glueetl"), you can allocate from 2 to 100 DPUs. The default is 10 DPUs. This job type cannot have a fractional DPU allocation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-maxcapacity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxCapacity"))

    @max_capacity.setter
    def max_capacity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxRetries")
    def max_retries(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of times to retry this job after a JobRun fails.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-maxretries
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxRetries"))

    @max_retries.setter
    def max_retries(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxRetries", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name you assign to this job definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationProperty")
    def notification_property(
        self,
    ) -> typing.Optional[typing.Union["CfnJob.NotificationPropertyProperty", _IResolvable_da3f097b]]:
        '''Specifies configuration properties of a notification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-notificationproperty
        '''
        return typing.cast(typing.Optional[typing.Union["CfnJob.NotificationPropertyProperty", _IResolvable_da3f097b]], jsii.get(self, "notificationProperty"))

    @notification_property.setter
    def notification_property(
        self,
        value: typing.Optional[typing.Union["CfnJob.NotificationPropertyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "notificationProperty", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="numberOfWorkers")
    def number_of_workers(self) -> typing.Optional[jsii.Number]:
        '''The number of workers of a defined ``workerType`` that are allocated when a job runs.

        The maximum number of workers you can define are 299 for ``G.1X`` , and 149 for ``G.2X`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-numberofworkers
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "numberOfWorkers"))

    @number_of_workers.setter
    def number_of_workers(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "numberOfWorkers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityConfiguration")
    def security_configuration(self) -> typing.Optional[builtins.str]:
        '''The name of the ``SecurityConfiguration`` structure to be used with this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-securityconfiguration
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "securityConfiguration"))

    @security_configuration.setter
    def security_configuration(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "securityConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="timeout")
    def timeout(self) -> typing.Optional[jsii.Number]:
        '''The job timeout in minutes.

        This is the maximum time that a job run can consume resources before it is terminated and enters TIMEOUT status. The default is 2,880 minutes (48 hours).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-timeout
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "timeout"))

    @timeout.setter
    def timeout(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "timeout", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workerType")
    def worker_type(self) -> typing.Optional[builtins.str]:
        '''The type of predefined worker that is allocated when a job runs.

        Accepts a value of Standard, G.1X, or G.2X.

        - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker.
        - For the ``G.1X`` worker type, each worker maps to 1 DPU (4 vCPU, 16 GB of memory, 64 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.
        - For the ``G.2X`` worker type, each worker maps to 2 DPU (8 vCPU, 32 GB of memory, 128 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-workertype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "workerType"))

    @worker_type.setter
    def worker_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "workerType", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnJob.ConnectionsListProperty",
        jsii_struct_bases=[],
        name_mapping={"connections": "connections"},
    )
    class ConnectionsListProperty:
        def __init__(
            self,
            *,
            connections: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Specifies the connections used by a job.

            :param connections: A list of connections used by the job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-connectionslist.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                connections_list_property = glue.CfnJob.ConnectionsListProperty(
                    connections=["connections"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if connections is not None:
                self._values["connections"] = connections

        @builtins.property
        def connections(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of connections used by the job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-connectionslist.html#cfn-glue-job-connectionslist-connections
            '''
            result = self._values.get("connections")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectionsListProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnJob.ExecutionPropertyProperty",
        jsii_struct_bases=[],
        name_mapping={"max_concurrent_runs": "maxConcurrentRuns"},
    )
    class ExecutionPropertyProperty:
        def __init__(
            self,
            *,
            max_concurrent_runs: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''An execution property of a job.

            :param max_concurrent_runs: The maximum number of concurrent runs allowed for the job. The default is 1. An error is returned when this threshold is reached. The maximum value you can specify is controlled by a service limit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-executionproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                execution_property_property = glue.CfnJob.ExecutionPropertyProperty(
                    max_concurrent_runs=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max_concurrent_runs is not None:
                self._values["max_concurrent_runs"] = max_concurrent_runs

        @builtins.property
        def max_concurrent_runs(self) -> typing.Optional[jsii.Number]:
            '''The maximum number of concurrent runs allowed for the job.

            The default is 1. An error is returned when this threshold is reached. The maximum value you can specify is controlled by a service limit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-executionproperty.html#cfn-glue-job-executionproperty-maxconcurrentruns
            '''
            result = self._values.get("max_concurrent_runs")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExecutionPropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnJob.JobCommandProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "python_version": "pythonVersion",
            "script_location": "scriptLocation",
        },
    )
    class JobCommandProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            python_version: typing.Optional[builtins.str] = None,
            script_location: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies code executed when a job is run.

            :param name: The name of the job command. For an Apache Spark ETL job, this must be ``glueetl`` . For a Python shell job, it must be ``pythonshell`` .
            :param python_version: The Python version being used to execute a Python shell job. Allowed values are 2 or 3.
            :param script_location: Specifies the Amazon Simple Storage Service (Amazon S3) path to a script that executes a job (required).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-jobcommand.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                job_command_property = glue.CfnJob.JobCommandProperty(
                    name="name",
                    python_version="pythonVersion",
                    script_location="scriptLocation"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if python_version is not None:
                self._values["python_version"] = python_version
            if script_location is not None:
                self._values["script_location"] = script_location

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the job command.

            For an Apache Spark ETL job, this must be ``glueetl`` . For a Python shell job, it must be ``pythonshell`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-jobcommand.html#cfn-glue-job-jobcommand-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def python_version(self) -> typing.Optional[builtins.str]:
            '''The Python version being used to execute a Python shell job.

            Allowed values are 2 or 3.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-jobcommand.html#cfn-glue-job-jobcommand-pythonversion
            '''
            result = self._values.get("python_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def script_location(self) -> typing.Optional[builtins.str]:
            '''Specifies the Amazon Simple Storage Service (Amazon S3) path to a script that executes a job (required).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-jobcommand.html#cfn-glue-job-jobcommand-scriptlocation
            '''
            result = self._values.get("script_location")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JobCommandProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnJob.NotificationPropertyProperty",
        jsii_struct_bases=[],
        name_mapping={"notify_delay_after": "notifyDelayAfter"},
    )
    class NotificationPropertyProperty:
        def __init__(
            self,
            *,
            notify_delay_after: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies configuration properties of a notification.

            :param notify_delay_after: After a job run starts, the number of minutes to wait before sending a job run delay notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-notificationproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                notification_property_property = glue.CfnJob.NotificationPropertyProperty(
                    notify_delay_after=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if notify_delay_after is not None:
                self._values["notify_delay_after"] = notify_delay_after

        @builtins.property
        def notify_delay_after(self) -> typing.Optional[jsii.Number]:
            '''After a job run starts, the number of minutes to wait before sending a job run delay notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-job-notificationproperty.html#cfn-glue-job-notificationproperty-notifydelayafter
            '''
            result = self._values.get("notify_delay_after")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotificationPropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnJobProps",
    jsii_struct_bases=[],
    name_mapping={
        "command": "command",
        "role": "role",
        "allocated_capacity": "allocatedCapacity",
        "connections": "connections",
        "default_arguments": "defaultArguments",
        "description": "description",
        "execution_property": "executionProperty",
        "glue_version": "glueVersion",
        "log_uri": "logUri",
        "max_capacity": "maxCapacity",
        "max_retries": "maxRetries",
        "name": "name",
        "notification_property": "notificationProperty",
        "number_of_workers": "numberOfWorkers",
        "security_configuration": "securityConfiguration",
        "tags": "tags",
        "timeout": "timeout",
        "worker_type": "workerType",
    },
)
class CfnJobProps:
    def __init__(
        self,
        *,
        command: typing.Union[CfnJob.JobCommandProperty, _IResolvable_da3f097b],
        role: builtins.str,
        allocated_capacity: typing.Optional[jsii.Number] = None,
        connections: typing.Optional[typing.Union[CfnJob.ConnectionsListProperty, _IResolvable_da3f097b]] = None,
        default_arguments: typing.Any = None,
        description: typing.Optional[builtins.str] = None,
        execution_property: typing.Optional[typing.Union[CfnJob.ExecutionPropertyProperty, _IResolvable_da3f097b]] = None,
        glue_version: typing.Optional[builtins.str] = None,
        log_uri: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_retries: typing.Optional[jsii.Number] = None,
        name: typing.Optional[builtins.str] = None,
        notification_property: typing.Optional[typing.Union[CfnJob.NotificationPropertyProperty, _IResolvable_da3f097b]] = None,
        number_of_workers: typing.Optional[jsii.Number] = None,
        security_configuration: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
        timeout: typing.Optional[jsii.Number] = None,
        worker_type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnJob``.

        :param command: The code that executes a job.
        :param role: The name or Amazon Resource Name (ARN) of the IAM role associated with this job.
        :param allocated_capacity: The number of capacity units that are allocated to this job.
        :param connections: The connections used for this job.
        :param default_arguments: The default arguments for this job, specified as name-value pairs. You can specify arguments here that your own job-execution script consumes, in addition to arguments that AWS Glue itself consumes. For information about how to specify and consume your own job arguments, see `Calling AWS Glue APIs in Python <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-python-calling.html>`_ in the *AWS Glue Developer Guide* . For information about the key-value pairs that AWS Glue consumes to set up your job, see `Special Parameters Used by AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-etl-glue-arguments.html>`_ in the *AWS Glue Developer Guide* .
        :param description: A description of the job.
        :param execution_property: The maximum number of concurrent runs that are allowed for this job.
        :param glue_version: Glue version determines the versions of Apache Spark and Python that AWS Glue supports. The Python version indicates the version supported for jobs of type Spark. For more information about the available AWS Glue versions and corresponding Spark and Python versions, see `Glue version <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ in the developer guide. Jobs that are created without specifying a Glue version default to Glue 0.9.
        :param log_uri: This field is reserved for future use.
        :param max_capacity: The number of AWS Glue data processing units (DPUs) that can be allocated when this job runs. A DPU is a relative measure of processing power that consists of 4 vCPUs of compute capacity and 16 GB of memory. Do not set ``Max Capacity`` if using ``WorkerType`` and ``NumberOfWorkers`` . The value that can be allocated for ``MaxCapacity`` depends on whether you are running a Python shell job or an Apache Spark ETL job: - When you specify a Python shell job ( ``JobCommand.Name`` ="pythonshell"), you can allocate either 0.0625 or 1 DPU. The default is 0.0625 DPU. - When you specify an Apache Spark ETL job ( ``JobCommand.Name`` ="glueetl"), you can allocate from 2 to 100 DPUs. The default is 10 DPUs. This job type cannot have a fractional DPU allocation.
        :param max_retries: The maximum number of times to retry this job after a JobRun fails.
        :param name: The name you assign to this job definition.
        :param notification_property: Specifies configuration properties of a notification.
        :param number_of_workers: The number of workers of a defined ``workerType`` that are allocated when a job runs. The maximum number of workers you can define are 299 for ``G.1X`` , and 149 for ``G.2X`` .
        :param security_configuration: The name of the ``SecurityConfiguration`` structure to be used with this job.
        :param tags: The tags to use with this job.
        :param timeout: The job timeout in minutes. This is the maximum time that a job run can consume resources before it is terminated and enters TIMEOUT status. The default is 2,880 minutes (48 hours).
        :param worker_type: The type of predefined worker that is allocated when a job runs. Accepts a value of Standard, G.1X, or G.2X. - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker. - For the ``G.1X`` worker type, each worker maps to 1 DPU (4 vCPU, 16 GB of memory, 64 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs. - For the ``G.2X`` worker type, each worker maps to 2 DPU (8 vCPU, 32 GB of memory, 128 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # default_arguments: Any
            # tags: Any
            
            cfn_job_props = glue.CfnJobProps(
                command=glue.CfnJob.JobCommandProperty(
                    name="name",
                    python_version="pythonVersion",
                    script_location="scriptLocation"
                ),
                role="role",
            
                # the properties below are optional
                allocated_capacity=123,
                connections=glue.CfnJob.ConnectionsListProperty(
                    connections=["connections"]
                ),
                default_arguments=default_arguments,
                description="description",
                execution_property=glue.CfnJob.ExecutionPropertyProperty(
                    max_concurrent_runs=123
                ),
                glue_version="glueVersion",
                log_uri="logUri",
                max_capacity=123,
                max_retries=123,
                name="name",
                notification_property=glue.CfnJob.NotificationPropertyProperty(
                    notify_delay_after=123
                ),
                number_of_workers=123,
                security_configuration="securityConfiguration",
                tags=tags,
                timeout=123,
                worker_type="workerType"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "command": command,
            "role": role,
        }
        if allocated_capacity is not None:
            self._values["allocated_capacity"] = allocated_capacity
        if connections is not None:
            self._values["connections"] = connections
        if default_arguments is not None:
            self._values["default_arguments"] = default_arguments
        if description is not None:
            self._values["description"] = description
        if execution_property is not None:
            self._values["execution_property"] = execution_property
        if glue_version is not None:
            self._values["glue_version"] = glue_version
        if log_uri is not None:
            self._values["log_uri"] = log_uri
        if max_capacity is not None:
            self._values["max_capacity"] = max_capacity
        if max_retries is not None:
            self._values["max_retries"] = max_retries
        if name is not None:
            self._values["name"] = name
        if notification_property is not None:
            self._values["notification_property"] = notification_property
        if number_of_workers is not None:
            self._values["number_of_workers"] = number_of_workers
        if security_configuration is not None:
            self._values["security_configuration"] = security_configuration
        if tags is not None:
            self._values["tags"] = tags
        if timeout is not None:
            self._values["timeout"] = timeout
        if worker_type is not None:
            self._values["worker_type"] = worker_type

    @builtins.property
    def command(self) -> typing.Union[CfnJob.JobCommandProperty, _IResolvable_da3f097b]:
        '''The code that executes a job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-command
        '''
        result = self._values.get("command")
        assert result is not None, "Required property 'command' is missing"
        return typing.cast(typing.Union[CfnJob.JobCommandProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def role(self) -> builtins.str:
        '''The name or Amazon Resource Name (ARN) of the IAM role associated with this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-role
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def allocated_capacity(self) -> typing.Optional[jsii.Number]:
        '''The number of capacity units that are allocated to this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-allocatedcapacity
        '''
        result = self._values.get("allocated_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def connections(
        self,
    ) -> typing.Optional[typing.Union[CfnJob.ConnectionsListProperty, _IResolvable_da3f097b]]:
        '''The connections used for this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-connections
        '''
        result = self._values.get("connections")
        return typing.cast(typing.Optional[typing.Union[CfnJob.ConnectionsListProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def default_arguments(self) -> typing.Any:
        '''The default arguments for this job, specified as name-value pairs.

        You can specify arguments here that your own job-execution script consumes, in addition to arguments that AWS Glue itself consumes.

        For information about how to specify and consume your own job arguments, see `Calling AWS Glue APIs in Python <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-python-calling.html>`_ in the *AWS Glue Developer Guide* .

        For information about the key-value pairs that AWS Glue consumes to set up your job, see `Special Parameters Used by AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-etl-glue-arguments.html>`_ in the *AWS Glue Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-defaultarguments
        '''
        result = self._values.get("default_arguments")
        return typing.cast(typing.Any, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def execution_property(
        self,
    ) -> typing.Optional[typing.Union[CfnJob.ExecutionPropertyProperty, _IResolvable_da3f097b]]:
        '''The maximum number of concurrent runs that are allowed for this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-executionproperty
        '''
        result = self._values.get("execution_property")
        return typing.cast(typing.Optional[typing.Union[CfnJob.ExecutionPropertyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def glue_version(self) -> typing.Optional[builtins.str]:
        '''Glue version determines the versions of Apache Spark and Python that AWS Glue supports.

        The Python version indicates the version supported for jobs of type Spark.

        For more information about the available AWS Glue versions and corresponding Spark and Python versions, see `Glue version <https://docs.aws.amazon.com/glue/latest/dg/add-job.html>`_ in the developer guide.

        Jobs that are created without specifying a Glue version default to Glue 0.9.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-glueversion
        '''
        result = self._values.get("glue_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def log_uri(self) -> typing.Optional[builtins.str]:
        '''This field is reserved for future use.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-loguri
        '''
        result = self._values.get("log_uri")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_capacity(self) -> typing.Optional[jsii.Number]:
        '''The number of AWS Glue data processing units (DPUs) that can be allocated when this job runs.

        A DPU is a relative measure of processing power that consists of 4 vCPUs of compute capacity and 16 GB of memory.

        Do not set ``Max Capacity`` if using ``WorkerType`` and ``NumberOfWorkers`` .

        The value that can be allocated for ``MaxCapacity`` depends on whether you are running a Python shell job or an Apache Spark ETL job:

        - When you specify a Python shell job ( ``JobCommand.Name`` ="pythonshell"), you can allocate either 0.0625 or 1 DPU. The default is 0.0625 DPU.
        - When you specify an Apache Spark ETL job ( ``JobCommand.Name`` ="glueetl"), you can allocate from 2 to 100 DPUs. The default is 10 DPUs. This job type cannot have a fractional DPU allocation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-maxcapacity
        '''
        result = self._values.get("max_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def max_retries(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of times to retry this job after a JobRun fails.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-maxretries
        '''
        result = self._values.get("max_retries")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name you assign to this job definition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def notification_property(
        self,
    ) -> typing.Optional[typing.Union[CfnJob.NotificationPropertyProperty, _IResolvable_da3f097b]]:
        '''Specifies configuration properties of a notification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-notificationproperty
        '''
        result = self._values.get("notification_property")
        return typing.cast(typing.Optional[typing.Union[CfnJob.NotificationPropertyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def number_of_workers(self) -> typing.Optional[jsii.Number]:
        '''The number of workers of a defined ``workerType`` that are allocated when a job runs.

        The maximum number of workers you can define are 299 for ``G.1X`` , and 149 for ``G.2X`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-numberofworkers
        '''
        result = self._values.get("number_of_workers")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def security_configuration(self) -> typing.Optional[builtins.str]:
        '''The name of the ``SecurityConfiguration`` structure to be used with this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-securityconfiguration
        '''
        result = self._values.get("security_configuration")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''The tags to use with this job.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def timeout(self) -> typing.Optional[jsii.Number]:
        '''The job timeout in minutes.

        This is the maximum time that a job run can consume resources before it is terminated and enters TIMEOUT status. The default is 2,880 minutes (48 hours).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-timeout
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def worker_type(self) -> typing.Optional[builtins.str]:
        '''The type of predefined worker that is allocated when a job runs.

        Accepts a value of Standard, G.1X, or G.2X.

        - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker.
        - For the ``G.1X`` worker type, each worker maps to 1 DPU (4 vCPU, 16 GB of memory, 64 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.
        - For the ``G.2X`` worker type, each worker maps to 2 DPU (8 vCPU, 32 GB of memory, 128 GB disk), and provides 1 executor per worker. We recommend this worker type for memory-intensive jobs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-job.html#cfn-glue-job-workertype
        '''
        result = self._values.get("worker_type")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnJobProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnMLTransform(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnMLTransform",
):
    '''A CloudFormation ``AWS::Glue::MLTransform``.

    The AWS::Glue::MLTransform is an AWS Glue resource type that manages machine learning transforms.

    :cloudformationResource: AWS::Glue::MLTransform
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # tags: Any
        
        cfn_mLTransform = glue.CfnMLTransform(self, "MyCfnMLTransform",
            input_record_tables=glue.CfnMLTransform.InputRecordTablesProperty(
                glue_tables=[glue.CfnMLTransform.GlueTablesProperty(
                    database_name="databaseName",
                    table_name="tableName",
        
                    # the properties below are optional
                    catalog_id="catalogId",
                    connection_name="connectionName"
                )]
            ),
            role="role",
            transform_parameters=glue.CfnMLTransform.TransformParametersProperty(
                transform_type="transformType",
        
                # the properties below are optional
                find_matches_parameters=glue.CfnMLTransform.FindMatchesParametersProperty(
                    primary_key_column_name="primaryKeyColumnName",
        
                    # the properties below are optional
                    accuracy_cost_tradeoff=123,
                    enforce_provided_labels=False,
                    precision_recall_tradeoff=123
                )
            ),
        
            # the properties below are optional
            description="description",
            glue_version="glueVersion",
            max_capacity=123,
            max_retries=123,
            name="name",
            number_of_workers=123,
            tags=tags,
            timeout=123,
            transform_encryption=glue.CfnMLTransform.TransformEncryptionProperty(
                ml_user_data_encryption=glue.CfnMLTransform.MLUserDataEncryptionProperty(
                    ml_user_data_encryption_mode="mlUserDataEncryptionMode",
        
                    # the properties below are optional
                    kms_key_id="kmsKeyId"
                ),
                task_run_security_configuration_name="taskRunSecurityConfigurationName"
            ),
            worker_type="workerType"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        input_record_tables: typing.Union["CfnMLTransform.InputRecordTablesProperty", _IResolvable_da3f097b],
        role: builtins.str,
        transform_parameters: typing.Union["CfnMLTransform.TransformParametersProperty", _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        glue_version: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_retries: typing.Optional[jsii.Number] = None,
        name: typing.Optional[builtins.str] = None,
        number_of_workers: typing.Optional[jsii.Number] = None,
        tags: typing.Any = None,
        timeout: typing.Optional[jsii.Number] = None,
        transform_encryption: typing.Optional[typing.Union["CfnMLTransform.TransformEncryptionProperty", _IResolvable_da3f097b]] = None,
        worker_type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Glue::MLTransform``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param input_record_tables: A list of AWS Glue table definitions used by the transform.
        :param role: The name or Amazon Resource Name (ARN) of the IAM role with the required permissions. The required permissions include both AWS Glue service role permissions to AWS Glue resources, and Amazon S3 permissions required by the transform. - This role needs AWS Glue service role permissions to allow access to resources in AWS Glue . See `Attach a Policy to IAM Users That Access AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/attach-policy-iam-user.html>`_ . - This role needs permission to your Amazon Simple Storage Service (Amazon S3) sources, targets, temporary directory, scripts, and any libraries used by the task run for this transform.
        :param transform_parameters: The algorithm-specific parameters that are associated with the machine learning transform.
        :param description: A user-defined, long-form description text for the machine learning transform.
        :param glue_version: This value determines which version of AWS Glue this machine learning transform is compatible with. Glue 1.0 is recommended for most customers. If the value is not set, the Glue compatibility defaults to Glue 0.9. For more information, see `AWS Glue Versions <https://docs.aws.amazon.com/glue/latest/dg/release-notes.html#release-notes-versions>`_ in the developer guide.
        :param max_capacity: The number of AWS Glue data processing units (DPUs) that are allocated to task runs for this transform. You can allocate from 2 to 100 DPUs; the default is 10. A DPU is a relative measure of processing power that consists of 4 vCPUs of compute capacity and 16 GB of memory. For more information, see the `AWS Glue pricing page <https://docs.aws.amazon.com/glue/pricing/>`_ . ``MaxCapacity`` is a mutually exclusive option with ``NumberOfWorkers`` and ``WorkerType`` . - If either ``NumberOfWorkers`` or ``WorkerType`` is set, then ``MaxCapacity`` cannot be set. - If ``MaxCapacity`` is set then neither ``NumberOfWorkers`` or ``WorkerType`` can be set. - If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa). - ``MaxCapacity`` and ``NumberOfWorkers`` must both be at least 1. When the ``WorkerType`` field is set to a value other than ``Standard`` , the ``MaxCapacity`` field is set automatically and becomes read-only.
        :param max_retries: The maximum number of times to retry after an ``MLTaskRun`` of the machine learning transform fails.
        :param name: A user-defined name for the machine learning transform. Names are required to be unique. ``Name`` is optional:. - If you supply ``Name`` , the stack cannot be repeatedly created. - If ``Name`` is not provided, a randomly generated name will be used instead.
        :param number_of_workers: The number of workers of a defined ``workerType`` that are allocated when a task of the transform runs. If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa).
        :param tags: The tags to use with this machine learning transform. You may use tags to limit access to the machine learning transform. For more information about tags in AWS Glue , see `AWS Tags in AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/monitor-tags.html>`_ in the developer guide.
        :param timeout: The timeout in minutes of the machine learning transform.
        :param transform_encryption: The encryption-at-rest settings of the transform that apply to accessing user data. Machine learning transforms can access user data encrypted in Amazon S3 using KMS. Additionally, imported labels and trained transforms can now be encrypted using a customer provided KMS key.
        :param worker_type: The type of predefined worker that is allocated when a task of this transform runs. Accepts a value of Standard, G.1X, or G.2X. - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker. - For the ``G.1X`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 64GB disk, and 1 executor per worker. - For the ``G.2X`` worker type, each worker provides 8 vCPU, 32 GB of memory and a 128GB disk, and 1 executor per worker. ``MaxCapacity`` is a mutually exclusive option with ``NumberOfWorkers`` and ``WorkerType`` . - If either ``NumberOfWorkers`` or ``WorkerType`` is set, then ``MaxCapacity`` cannot be set. - If ``MaxCapacity`` is set then neither ``NumberOfWorkers`` or ``WorkerType`` can be set. - If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa). - ``MaxCapacity`` and ``NumberOfWorkers`` must both be at least 1.
        '''
        props = CfnMLTransformProps(
            input_record_tables=input_record_tables,
            role=role,
            transform_parameters=transform_parameters,
            description=description,
            glue_version=glue_version,
            max_capacity=max_capacity,
            max_retries=max_retries,
            name=name,
            number_of_workers=number_of_workers,
            tags=tags,
            timeout=timeout,
            transform_encryption=transform_encryption,
            worker_type=worker_type,
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
        '''The tags to use with this machine learning transform.

        You may use tags to limit access to the machine learning transform. For more information about tags in AWS Glue , see `AWS Tags in AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/monitor-tags.html>`_ in the developer guide.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="inputRecordTables")
    def input_record_tables(
        self,
    ) -> typing.Union["CfnMLTransform.InputRecordTablesProperty", _IResolvable_da3f097b]:
        '''A list of AWS Glue table definitions used by the transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-inputrecordtables
        '''
        return typing.cast(typing.Union["CfnMLTransform.InputRecordTablesProperty", _IResolvable_da3f097b], jsii.get(self, "inputRecordTables"))

    @input_record_tables.setter
    def input_record_tables(
        self,
        value: typing.Union["CfnMLTransform.InputRecordTablesProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "inputRecordTables", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> builtins.str:
        '''The name or Amazon Resource Name (ARN) of the IAM role with the required permissions.

        The required permissions include both AWS Glue service role permissions to AWS Glue resources, and Amazon S3 permissions required by the transform.

        - This role needs AWS Glue service role permissions to allow access to resources in AWS Glue . See `Attach a Policy to IAM Users That Access AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/attach-policy-iam-user.html>`_ .
        - This role needs permission to your Amazon Simple Storage Service (Amazon S3) sources, targets, temporary directory, scripts, and any libraries used by the task run for this transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-role
        '''
        return typing.cast(builtins.str, jsii.get(self, "role"))

    @role.setter
    def role(self, value: builtins.str) -> None:
        jsii.set(self, "role", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="transformParameters")
    def transform_parameters(
        self,
    ) -> typing.Union["CfnMLTransform.TransformParametersProperty", _IResolvable_da3f097b]:
        '''The algorithm-specific parameters that are associated with the machine learning transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-transformparameters
        '''
        return typing.cast(typing.Union["CfnMLTransform.TransformParametersProperty", _IResolvable_da3f097b], jsii.get(self, "transformParameters"))

    @transform_parameters.setter
    def transform_parameters(
        self,
        value: typing.Union["CfnMLTransform.TransformParametersProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "transformParameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A user-defined, long-form description text for the machine learning transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="glueVersion")
    def glue_version(self) -> typing.Optional[builtins.str]:
        '''This value determines which version of AWS Glue this machine learning transform is compatible with.

        Glue 1.0 is recommended for most customers. If the value is not set, the Glue compatibility defaults to Glue 0.9. For more information, see `AWS Glue Versions <https://docs.aws.amazon.com/glue/latest/dg/release-notes.html#release-notes-versions>`_ in the developer guide.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-glueversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "glueVersion"))

    @glue_version.setter
    def glue_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "glueVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxCapacity")
    def max_capacity(self) -> typing.Optional[jsii.Number]:
        '''The number of AWS Glue data processing units (DPUs) that are allocated to task runs for this transform.

        You can allocate from 2 to 100 DPUs; the default is 10. A DPU is a relative measure of processing power that consists of 4 vCPUs of compute capacity and 16 GB of memory. For more information, see the `AWS Glue pricing page <https://docs.aws.amazon.com/glue/pricing/>`_ .

        ``MaxCapacity`` is a mutually exclusive option with ``NumberOfWorkers`` and ``WorkerType`` .

        - If either ``NumberOfWorkers`` or ``WorkerType`` is set, then ``MaxCapacity`` cannot be set.
        - If ``MaxCapacity`` is set then neither ``NumberOfWorkers`` or ``WorkerType`` can be set.
        - If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa).
        - ``MaxCapacity`` and ``NumberOfWorkers`` must both be at least 1.

        When the ``WorkerType`` field is set to a value other than ``Standard`` , the ``MaxCapacity`` field is set automatically and becomes read-only.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-maxcapacity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxCapacity"))

    @max_capacity.setter
    def max_capacity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxRetries")
    def max_retries(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of times to retry after an ``MLTaskRun`` of the machine learning transform fails.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-maxretries
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxRetries"))

    @max_retries.setter
    def max_retries(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxRetries", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''A user-defined name for the machine learning transform. Names are required to be unique. ``Name`` is optional:.

        - If you supply ``Name`` , the stack cannot be repeatedly created.
        - If ``Name`` is not provided, a randomly generated name will be used instead.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="numberOfWorkers")
    def number_of_workers(self) -> typing.Optional[jsii.Number]:
        '''The number of workers of a defined ``workerType`` that are allocated when a task of the transform runs.

        If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-numberofworkers
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "numberOfWorkers"))

    @number_of_workers.setter
    def number_of_workers(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "numberOfWorkers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="timeout")
    def timeout(self) -> typing.Optional[jsii.Number]:
        '''The timeout in minutes of the machine learning transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-timeout
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "timeout"))

    @timeout.setter
    def timeout(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "timeout", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="transformEncryption")
    def transform_encryption(
        self,
    ) -> typing.Optional[typing.Union["CfnMLTransform.TransformEncryptionProperty", _IResolvable_da3f097b]]:
        '''The encryption-at-rest settings of the transform that apply to accessing user data.

        Machine learning
        transforms can access user data encrypted in Amazon S3 using KMS.

        Additionally, imported labels and trained transforms can now be encrypted using a customer provided
        KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-transformencryption
        '''
        return typing.cast(typing.Optional[typing.Union["CfnMLTransform.TransformEncryptionProperty", _IResolvable_da3f097b]], jsii.get(self, "transformEncryption"))

    @transform_encryption.setter
    def transform_encryption(
        self,
        value: typing.Optional[typing.Union["CfnMLTransform.TransformEncryptionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "transformEncryption", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workerType")
    def worker_type(self) -> typing.Optional[builtins.str]:
        '''The type of predefined worker that is allocated when a task of this transform runs.

        Accepts a value of Standard, G.1X, or G.2X.

        - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker.
        - For the ``G.1X`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 64GB disk, and 1 executor per worker.
        - For the ``G.2X`` worker type, each worker provides 8 vCPU, 32 GB of memory and a 128GB disk, and 1 executor per worker.

        ``MaxCapacity`` is a mutually exclusive option with ``NumberOfWorkers`` and ``WorkerType`` .

        - If either ``NumberOfWorkers`` or ``WorkerType`` is set, then ``MaxCapacity`` cannot be set.
        - If ``MaxCapacity`` is set then neither ``NumberOfWorkers`` or ``WorkerType`` can be set.
        - If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa).
        - ``MaxCapacity`` and ``NumberOfWorkers`` must both be at least 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-workertype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "workerType"))

    @worker_type.setter
    def worker_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "workerType", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnMLTransform.FindMatchesParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "primary_key_column_name": "primaryKeyColumnName",
            "accuracy_cost_tradeoff": "accuracyCostTradeoff",
            "enforce_provided_labels": "enforceProvidedLabels",
            "precision_recall_tradeoff": "precisionRecallTradeoff",
        },
    )
    class FindMatchesParametersProperty:
        def __init__(
            self,
            *,
            primary_key_column_name: builtins.str,
            accuracy_cost_tradeoff: typing.Optional[jsii.Number] = None,
            enforce_provided_labels: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            precision_recall_tradeoff: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The parameters to configure the find matches transform.

            :param primary_key_column_name: The name of a column that uniquely identifies rows in the source table. Used to help identify matching records.
            :param accuracy_cost_tradeoff: The value that is selected when tuning your transform for a balance between accuracy and cost. A value of 0.5 means that the system balances accuracy and cost concerns. A value of 1.0 means a bias purely for accuracy, which typically results in a higher cost, sometimes substantially higher. A value of 0.0 means a bias purely for cost, which results in a less accurate ``FindMatches`` transform, sometimes with unacceptable accuracy. Accuracy measures how well the transform finds true positives and true negatives. Increasing accuracy requires more machine resources and cost. But it also results in increased recall. Cost measures how many compute resources, and thus money, are consumed to run the transform.
            :param enforce_provided_labels: The value to switch on or off to force the output to match the provided labels from users. If the value is ``True`` , the ``find matches`` transform forces the output to match the provided labels. The results override the normal conflation results. If the value is ``False`` , the ``find matches`` transform does not ensure all the labels provided are respected, and the results rely on the trained model. Note that setting this value to true may increase the conflation execution time.
            :param precision_recall_tradeoff: The value selected when tuning your transform for a balance between precision and recall. A value of 0.5 means no preference; a value of 1.0 means a bias purely for precision, and a value of 0.0 means a bias for recall. Because this is a tradeoff, choosing values close to 1.0 means very low recall, and choosing values close to 0.0 results in very low precision. The precision metric indicates how often your model is correct when it predicts a match. The recall metric indicates that for an actual match, how often your model predicts the match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformparameters-findmatchesparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                find_matches_parameters_property = glue.CfnMLTransform.FindMatchesParametersProperty(
                    primary_key_column_name="primaryKeyColumnName",
                
                    # the properties below are optional
                    accuracy_cost_tradeoff=123,
                    enforce_provided_labels=False,
                    precision_recall_tradeoff=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "primary_key_column_name": primary_key_column_name,
            }
            if accuracy_cost_tradeoff is not None:
                self._values["accuracy_cost_tradeoff"] = accuracy_cost_tradeoff
            if enforce_provided_labels is not None:
                self._values["enforce_provided_labels"] = enforce_provided_labels
            if precision_recall_tradeoff is not None:
                self._values["precision_recall_tradeoff"] = precision_recall_tradeoff

        @builtins.property
        def primary_key_column_name(self) -> builtins.str:
            '''The name of a column that uniquely identifies rows in the source table.

            Used to help identify matching records.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformparameters-findmatchesparameters.html#cfn-glue-mltransform-transformparameters-findmatchesparameters-primarykeycolumnname
            '''
            result = self._values.get("primary_key_column_name")
            assert result is not None, "Required property 'primary_key_column_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def accuracy_cost_tradeoff(self) -> typing.Optional[jsii.Number]:
            '''The value that is selected when tuning your transform for a balance between accuracy and cost.

            A value of 0.5 means that the system balances accuracy and cost concerns. A value of 1.0 means a bias purely for accuracy, which typically results in a higher cost, sometimes substantially higher. A value of 0.0 means a bias purely for cost, which results in a less accurate ``FindMatches`` transform, sometimes with unacceptable accuracy.

            Accuracy measures how well the transform finds true positives and true negatives. Increasing accuracy requires more machine resources and cost. But it also results in increased recall.

            Cost measures how many compute resources, and thus money, are consumed to run the transform.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformparameters-findmatchesparameters.html#cfn-glue-mltransform-transformparameters-findmatchesparameters-accuracycosttradeoff
            '''
            result = self._values.get("accuracy_cost_tradeoff")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def enforce_provided_labels(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The value to switch on or off to force the output to match the provided labels from users.

            If the value is ``True`` , the ``find matches`` transform forces the output to match the provided labels. The results override the normal conflation results. If the value is ``False`` , the ``find matches`` transform does not ensure all the labels provided are respected, and the results rely on the trained model.

            Note that setting this value to true may increase the conflation execution time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformparameters-findmatchesparameters.html#cfn-glue-mltransform-transformparameters-findmatchesparameters-enforceprovidedlabels
            '''
            result = self._values.get("enforce_provided_labels")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def precision_recall_tradeoff(self) -> typing.Optional[jsii.Number]:
            '''The value selected when tuning your transform for a balance between precision and recall.

            A value of 0.5 means no preference; a value of 1.0 means a bias purely for precision, and a value of 0.0 means a bias for recall. Because this is a tradeoff, choosing values close to 1.0 means very low recall, and choosing values close to 0.0 results in very low precision.

            The precision metric indicates how often your model is correct when it predicts a match.

            The recall metric indicates that for an actual match, how often your model predicts the match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformparameters-findmatchesparameters.html#cfn-glue-mltransform-transformparameters-findmatchesparameters-precisionrecalltradeoff
            '''
            result = self._values.get("precision_recall_tradeoff")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FindMatchesParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnMLTransform.GlueTablesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "database_name": "databaseName",
            "table_name": "tableName",
            "catalog_id": "catalogId",
            "connection_name": "connectionName",
        },
    )
    class GlueTablesProperty:
        def __init__(
            self,
            *,
            database_name: builtins.str,
            table_name: builtins.str,
            catalog_id: typing.Optional[builtins.str] = None,
            connection_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The database and table in the AWS Glue Data Catalog that is used for input or output data.

            :param database_name: A database name in the AWS Glue Data Catalog .
            :param table_name: A table name in the AWS Glue Data Catalog .
            :param catalog_id: A unique identifier for the AWS Glue Data Catalog .
            :param connection_name: The name of the connection to the AWS Glue Data Catalog .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-inputrecordtables-gluetables.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                glue_tables_property = glue.CfnMLTransform.GlueTablesProperty(
                    database_name="databaseName",
                    table_name="tableName",
                
                    # the properties below are optional
                    catalog_id="catalogId",
                    connection_name="connectionName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database_name": database_name,
                "table_name": table_name,
            }
            if catalog_id is not None:
                self._values["catalog_id"] = catalog_id
            if connection_name is not None:
                self._values["connection_name"] = connection_name

        @builtins.property
        def database_name(self) -> builtins.str:
            '''A database name in the AWS Glue Data Catalog .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-inputrecordtables-gluetables.html#cfn-glue-mltransform-inputrecordtables-gluetables-databasename
            '''
            result = self._values.get("database_name")
            assert result is not None, "Required property 'database_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def table_name(self) -> builtins.str:
            '''A table name in the AWS Glue Data Catalog .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-inputrecordtables-gluetables.html#cfn-glue-mltransform-inputrecordtables-gluetables-tablename
            '''
            result = self._values.get("table_name")
            assert result is not None, "Required property 'table_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def catalog_id(self) -> typing.Optional[builtins.str]:
            '''A unique identifier for the AWS Glue Data Catalog .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-inputrecordtables-gluetables.html#cfn-glue-mltransform-inputrecordtables-gluetables-catalogid
            '''
            result = self._values.get("catalog_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def connection_name(self) -> typing.Optional[builtins.str]:
            '''The name of the connection to the AWS Glue Data Catalog .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-inputrecordtables-gluetables.html#cfn-glue-mltransform-inputrecordtables-gluetables-connectionname
            '''
            result = self._values.get("connection_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GlueTablesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnMLTransform.InputRecordTablesProperty",
        jsii_struct_bases=[],
        name_mapping={"glue_tables": "glueTables"},
    )
    class InputRecordTablesProperty:
        def __init__(
            self,
            *,
            glue_tables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnMLTransform.GlueTablesProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A list of AWS Glue table definitions used by the transform.

            :param glue_tables: The database and table in the AWS Glue Data Catalog that is used for input or output data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-inputrecordtables.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                input_record_tables_property = glue.CfnMLTransform.InputRecordTablesProperty(
                    glue_tables=[glue.CfnMLTransform.GlueTablesProperty(
                        database_name="databaseName",
                        table_name="tableName",
                
                        # the properties below are optional
                        catalog_id="catalogId",
                        connection_name="connectionName"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if glue_tables is not None:
                self._values["glue_tables"] = glue_tables

        @builtins.property
        def glue_tables(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnMLTransform.GlueTablesProperty", _IResolvable_da3f097b]]]]:
            '''The database and table in the AWS Glue Data Catalog that is used for input or output data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-inputrecordtables.html#cfn-glue-mltransform-inputrecordtables-gluetables
            '''
            result = self._values.get("glue_tables")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnMLTransform.GlueTablesProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InputRecordTablesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnMLTransform.MLUserDataEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ml_user_data_encryption_mode": "mlUserDataEncryptionMode",
            "kms_key_id": "kmsKeyId",
        },
    )
    class MLUserDataEncryptionProperty:
        def __init__(
            self,
            *,
            ml_user_data_encryption_mode: builtins.str,
            kms_key_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The encryption-at-rest settings of the transform that apply to accessing user data.

            :param ml_user_data_encryption_mode: The encryption mode applied to user data. Valid values are:. - DISABLED: encryption is disabled. - SSEKMS: use of server-side encryption with AWS Key Management Service (SSE-KMS) for user data stored in Amazon S3.
            :param kms_key_id: The ID for the customer-provided KMS key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformencryption-mluserdataencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                m_lUser_data_encryption_property = glue.CfnMLTransform.MLUserDataEncryptionProperty(
                    ml_user_data_encryption_mode="mlUserDataEncryptionMode",
                
                    # the properties below are optional
                    kms_key_id="kmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "ml_user_data_encryption_mode": ml_user_data_encryption_mode,
            }
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id

        @builtins.property
        def ml_user_data_encryption_mode(self) -> builtins.str:
            '''The encryption mode applied to user data. Valid values are:.

            - DISABLED: encryption is disabled.
            - SSEKMS: use of server-side encryption with AWS Key Management Service (SSE-KMS) for user data
              stored in Amazon S3.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformencryption-mluserdataencryption.html#cfn-glue-mltransform-transformencryption-mluserdataencryption-mluserdataencryptionmode
            '''
            result = self._values.get("ml_user_data_encryption_mode")
            assert result is not None, "Required property 'ml_user_data_encryption_mode' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''The ID for the customer-provided KMS key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformencryption-mluserdataencryption.html#cfn-glue-mltransform-transformencryption-mluserdataencryption-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MLUserDataEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnMLTransform.TransformEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ml_user_data_encryption": "mlUserDataEncryption",
            "task_run_security_configuration_name": "taskRunSecurityConfigurationName",
        },
    )
    class TransformEncryptionProperty:
        def __init__(
            self,
            *,
            ml_user_data_encryption: typing.Optional[typing.Union["CfnMLTransform.MLUserDataEncryptionProperty", _IResolvable_da3f097b]] = None,
            task_run_security_configuration_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The encryption-at-rest settings of the transform that apply to accessing user data.

            Machine learning
            transforms can access user data encrypted in Amazon S3 using KMS.

            Additionally, imported labels and trained transforms can now be encrypted using a customer provided
            KMS key.

            :param ml_user_data_encryption: The encryption-at-rest settings of the transform that apply to accessing user data.
            :param task_run_security_configuration_name: The name of the security configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                transform_encryption_property = glue.CfnMLTransform.TransformEncryptionProperty(
                    ml_user_data_encryption=glue.CfnMLTransform.MLUserDataEncryptionProperty(
                        ml_user_data_encryption_mode="mlUserDataEncryptionMode",
                
                        # the properties below are optional
                        kms_key_id="kmsKeyId"
                    ),
                    task_run_security_configuration_name="taskRunSecurityConfigurationName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ml_user_data_encryption is not None:
                self._values["ml_user_data_encryption"] = ml_user_data_encryption
            if task_run_security_configuration_name is not None:
                self._values["task_run_security_configuration_name"] = task_run_security_configuration_name

        @builtins.property
        def ml_user_data_encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnMLTransform.MLUserDataEncryptionProperty", _IResolvable_da3f097b]]:
            '''The encryption-at-rest settings of the transform that apply to accessing user data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformencryption.html#cfn-glue-mltransform-transformencryption-mluserdataencryption
            '''
            result = self._values.get("ml_user_data_encryption")
            return typing.cast(typing.Optional[typing.Union["CfnMLTransform.MLUserDataEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def task_run_security_configuration_name(self) -> typing.Optional[builtins.str]:
            '''The name of the security configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformencryption.html#cfn-glue-mltransform-transformencryption-taskrunsecurityconfigurationname
            '''
            result = self._values.get("task_run_security_configuration_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TransformEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnMLTransform.TransformParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "transform_type": "transformType",
            "find_matches_parameters": "findMatchesParameters",
        },
    )
    class TransformParametersProperty:
        def __init__(
            self,
            *,
            transform_type: builtins.str,
            find_matches_parameters: typing.Optional[typing.Union["CfnMLTransform.FindMatchesParametersProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The algorithm-specific parameters that are associated with the machine learning transform.

            :param transform_type: The type of machine learning transform. ``FIND_MATCHES`` is the only option. For information about the types of machine learning transforms, see `Creating Machine Learning Transforms <https://docs.aws.amazon.com/glue/latest/dg/add-job-machine-learning-transform.html>`_ .
            :param find_matches_parameters: The parameters for the find matches algorithm.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                transform_parameters_property = glue.CfnMLTransform.TransformParametersProperty(
                    transform_type="transformType",
                
                    # the properties below are optional
                    find_matches_parameters=glue.CfnMLTransform.FindMatchesParametersProperty(
                        primary_key_column_name="primaryKeyColumnName",
                
                        # the properties below are optional
                        accuracy_cost_tradeoff=123,
                        enforce_provided_labels=False,
                        precision_recall_tradeoff=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "transform_type": transform_type,
            }
            if find_matches_parameters is not None:
                self._values["find_matches_parameters"] = find_matches_parameters

        @builtins.property
        def transform_type(self) -> builtins.str:
            '''The type of machine learning transform. ``FIND_MATCHES`` is the only option.

            For information about the types of machine learning transforms, see `Creating Machine Learning Transforms <https://docs.aws.amazon.com/glue/latest/dg/add-job-machine-learning-transform.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformparameters.html#cfn-glue-mltransform-transformparameters-transformtype
            '''
            result = self._values.get("transform_type")
            assert result is not None, "Required property 'transform_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def find_matches_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnMLTransform.FindMatchesParametersProperty", _IResolvable_da3f097b]]:
            '''The parameters for the find matches algorithm.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-mltransform-transformparameters.html#cfn-glue-mltransform-transformparameters-findmatchesparameters
            '''
            result = self._values.get("find_matches_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnMLTransform.FindMatchesParametersProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TransformParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnMLTransformProps",
    jsii_struct_bases=[],
    name_mapping={
        "input_record_tables": "inputRecordTables",
        "role": "role",
        "transform_parameters": "transformParameters",
        "description": "description",
        "glue_version": "glueVersion",
        "max_capacity": "maxCapacity",
        "max_retries": "maxRetries",
        "name": "name",
        "number_of_workers": "numberOfWorkers",
        "tags": "tags",
        "timeout": "timeout",
        "transform_encryption": "transformEncryption",
        "worker_type": "workerType",
    },
)
class CfnMLTransformProps:
    def __init__(
        self,
        *,
        input_record_tables: typing.Union[CfnMLTransform.InputRecordTablesProperty, _IResolvable_da3f097b],
        role: builtins.str,
        transform_parameters: typing.Union[CfnMLTransform.TransformParametersProperty, _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        glue_version: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_retries: typing.Optional[jsii.Number] = None,
        name: typing.Optional[builtins.str] = None,
        number_of_workers: typing.Optional[jsii.Number] = None,
        tags: typing.Any = None,
        timeout: typing.Optional[jsii.Number] = None,
        transform_encryption: typing.Optional[typing.Union[CfnMLTransform.TransformEncryptionProperty, _IResolvable_da3f097b]] = None,
        worker_type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnMLTransform``.

        :param input_record_tables: A list of AWS Glue table definitions used by the transform.
        :param role: The name or Amazon Resource Name (ARN) of the IAM role with the required permissions. The required permissions include both AWS Glue service role permissions to AWS Glue resources, and Amazon S3 permissions required by the transform. - This role needs AWS Glue service role permissions to allow access to resources in AWS Glue . See `Attach a Policy to IAM Users That Access AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/attach-policy-iam-user.html>`_ . - This role needs permission to your Amazon Simple Storage Service (Amazon S3) sources, targets, temporary directory, scripts, and any libraries used by the task run for this transform.
        :param transform_parameters: The algorithm-specific parameters that are associated with the machine learning transform.
        :param description: A user-defined, long-form description text for the machine learning transform.
        :param glue_version: This value determines which version of AWS Glue this machine learning transform is compatible with. Glue 1.0 is recommended for most customers. If the value is not set, the Glue compatibility defaults to Glue 0.9. For more information, see `AWS Glue Versions <https://docs.aws.amazon.com/glue/latest/dg/release-notes.html#release-notes-versions>`_ in the developer guide.
        :param max_capacity: The number of AWS Glue data processing units (DPUs) that are allocated to task runs for this transform. You can allocate from 2 to 100 DPUs; the default is 10. A DPU is a relative measure of processing power that consists of 4 vCPUs of compute capacity and 16 GB of memory. For more information, see the `AWS Glue pricing page <https://docs.aws.amazon.com/glue/pricing/>`_ . ``MaxCapacity`` is a mutually exclusive option with ``NumberOfWorkers`` and ``WorkerType`` . - If either ``NumberOfWorkers`` or ``WorkerType`` is set, then ``MaxCapacity`` cannot be set. - If ``MaxCapacity`` is set then neither ``NumberOfWorkers`` or ``WorkerType`` can be set. - If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa). - ``MaxCapacity`` and ``NumberOfWorkers`` must both be at least 1. When the ``WorkerType`` field is set to a value other than ``Standard`` , the ``MaxCapacity`` field is set automatically and becomes read-only.
        :param max_retries: The maximum number of times to retry after an ``MLTaskRun`` of the machine learning transform fails.
        :param name: A user-defined name for the machine learning transform. Names are required to be unique. ``Name`` is optional:. - If you supply ``Name`` , the stack cannot be repeatedly created. - If ``Name`` is not provided, a randomly generated name will be used instead.
        :param number_of_workers: The number of workers of a defined ``workerType`` that are allocated when a task of the transform runs. If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa).
        :param tags: The tags to use with this machine learning transform. You may use tags to limit access to the machine learning transform. For more information about tags in AWS Glue , see `AWS Tags in AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/monitor-tags.html>`_ in the developer guide.
        :param timeout: The timeout in minutes of the machine learning transform.
        :param transform_encryption: The encryption-at-rest settings of the transform that apply to accessing user data. Machine learning transforms can access user data encrypted in Amazon S3 using KMS. Additionally, imported labels and trained transforms can now be encrypted using a customer provided KMS key.
        :param worker_type: The type of predefined worker that is allocated when a task of this transform runs. Accepts a value of Standard, G.1X, or G.2X. - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker. - For the ``G.1X`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 64GB disk, and 1 executor per worker. - For the ``G.2X`` worker type, each worker provides 8 vCPU, 32 GB of memory and a 128GB disk, and 1 executor per worker. ``MaxCapacity`` is a mutually exclusive option with ``NumberOfWorkers`` and ``WorkerType`` . - If either ``NumberOfWorkers`` or ``WorkerType`` is set, then ``MaxCapacity`` cannot be set. - If ``MaxCapacity`` is set then neither ``NumberOfWorkers`` or ``WorkerType`` can be set. - If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa). - ``MaxCapacity`` and ``NumberOfWorkers`` must both be at least 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # tags: Any
            
            cfn_mLTransform_props = glue.CfnMLTransformProps(
                input_record_tables=glue.CfnMLTransform.InputRecordTablesProperty(
                    glue_tables=[glue.CfnMLTransform.GlueTablesProperty(
                        database_name="databaseName",
                        table_name="tableName",
            
                        # the properties below are optional
                        catalog_id="catalogId",
                        connection_name="connectionName"
                    )]
                ),
                role="role",
                transform_parameters=glue.CfnMLTransform.TransformParametersProperty(
                    transform_type="transformType",
            
                    # the properties below are optional
                    find_matches_parameters=glue.CfnMLTransform.FindMatchesParametersProperty(
                        primary_key_column_name="primaryKeyColumnName",
            
                        # the properties below are optional
                        accuracy_cost_tradeoff=123,
                        enforce_provided_labels=False,
                        precision_recall_tradeoff=123
                    )
                ),
            
                # the properties below are optional
                description="description",
                glue_version="glueVersion",
                max_capacity=123,
                max_retries=123,
                name="name",
                number_of_workers=123,
                tags=tags,
                timeout=123,
                transform_encryption=glue.CfnMLTransform.TransformEncryptionProperty(
                    ml_user_data_encryption=glue.CfnMLTransform.MLUserDataEncryptionProperty(
                        ml_user_data_encryption_mode="mlUserDataEncryptionMode",
            
                        # the properties below are optional
                        kms_key_id="kmsKeyId"
                    ),
                    task_run_security_configuration_name="taskRunSecurityConfigurationName"
                ),
                worker_type="workerType"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "input_record_tables": input_record_tables,
            "role": role,
            "transform_parameters": transform_parameters,
        }
        if description is not None:
            self._values["description"] = description
        if glue_version is not None:
            self._values["glue_version"] = glue_version
        if max_capacity is not None:
            self._values["max_capacity"] = max_capacity
        if max_retries is not None:
            self._values["max_retries"] = max_retries
        if name is not None:
            self._values["name"] = name
        if number_of_workers is not None:
            self._values["number_of_workers"] = number_of_workers
        if tags is not None:
            self._values["tags"] = tags
        if timeout is not None:
            self._values["timeout"] = timeout
        if transform_encryption is not None:
            self._values["transform_encryption"] = transform_encryption
        if worker_type is not None:
            self._values["worker_type"] = worker_type

    @builtins.property
    def input_record_tables(
        self,
    ) -> typing.Union[CfnMLTransform.InputRecordTablesProperty, _IResolvable_da3f097b]:
        '''A list of AWS Glue table definitions used by the transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-inputrecordtables
        '''
        result = self._values.get("input_record_tables")
        assert result is not None, "Required property 'input_record_tables' is missing"
        return typing.cast(typing.Union[CfnMLTransform.InputRecordTablesProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def role(self) -> builtins.str:
        '''The name or Amazon Resource Name (ARN) of the IAM role with the required permissions.

        The required permissions include both AWS Glue service role permissions to AWS Glue resources, and Amazon S3 permissions required by the transform.

        - This role needs AWS Glue service role permissions to allow access to resources in AWS Glue . See `Attach a Policy to IAM Users That Access AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/attach-policy-iam-user.html>`_ .
        - This role needs permission to your Amazon Simple Storage Service (Amazon S3) sources, targets, temporary directory, scripts, and any libraries used by the task run for this transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-role
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def transform_parameters(
        self,
    ) -> typing.Union[CfnMLTransform.TransformParametersProperty, _IResolvable_da3f097b]:
        '''The algorithm-specific parameters that are associated with the machine learning transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-transformparameters
        '''
        result = self._values.get("transform_parameters")
        assert result is not None, "Required property 'transform_parameters' is missing"
        return typing.cast(typing.Union[CfnMLTransform.TransformParametersProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A user-defined, long-form description text for the machine learning transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def glue_version(self) -> typing.Optional[builtins.str]:
        '''This value determines which version of AWS Glue this machine learning transform is compatible with.

        Glue 1.0 is recommended for most customers. If the value is not set, the Glue compatibility defaults to Glue 0.9. For more information, see `AWS Glue Versions <https://docs.aws.amazon.com/glue/latest/dg/release-notes.html#release-notes-versions>`_ in the developer guide.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-glueversion
        '''
        result = self._values.get("glue_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_capacity(self) -> typing.Optional[jsii.Number]:
        '''The number of AWS Glue data processing units (DPUs) that are allocated to task runs for this transform.

        You can allocate from 2 to 100 DPUs; the default is 10. A DPU is a relative measure of processing power that consists of 4 vCPUs of compute capacity and 16 GB of memory. For more information, see the `AWS Glue pricing page <https://docs.aws.amazon.com/glue/pricing/>`_ .

        ``MaxCapacity`` is a mutually exclusive option with ``NumberOfWorkers`` and ``WorkerType`` .

        - If either ``NumberOfWorkers`` or ``WorkerType`` is set, then ``MaxCapacity`` cannot be set.
        - If ``MaxCapacity`` is set then neither ``NumberOfWorkers`` or ``WorkerType`` can be set.
        - If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa).
        - ``MaxCapacity`` and ``NumberOfWorkers`` must both be at least 1.

        When the ``WorkerType`` field is set to a value other than ``Standard`` , the ``MaxCapacity`` field is set automatically and becomes read-only.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-maxcapacity
        '''
        result = self._values.get("max_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def max_retries(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of times to retry after an ``MLTaskRun`` of the machine learning transform fails.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-maxretries
        '''
        result = self._values.get("max_retries")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A user-defined name for the machine learning transform. Names are required to be unique. ``Name`` is optional:.

        - If you supply ``Name`` , the stack cannot be repeatedly created.
        - If ``Name`` is not provided, a randomly generated name will be used instead.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def number_of_workers(self) -> typing.Optional[jsii.Number]:
        '''The number of workers of a defined ``workerType`` that are allocated when a task of the transform runs.

        If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-numberofworkers
        '''
        result = self._values.get("number_of_workers")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''The tags to use with this machine learning transform.

        You may use tags to limit access to the machine learning transform. For more information about tags in AWS Glue , see `AWS Tags in AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/monitor-tags.html>`_ in the developer guide.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def timeout(self) -> typing.Optional[jsii.Number]:
        '''The timeout in minutes of the machine learning transform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-timeout
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def transform_encryption(
        self,
    ) -> typing.Optional[typing.Union[CfnMLTransform.TransformEncryptionProperty, _IResolvable_da3f097b]]:
        '''The encryption-at-rest settings of the transform that apply to accessing user data.

        Machine learning
        transforms can access user data encrypted in Amazon S3 using KMS.

        Additionally, imported labels and trained transforms can now be encrypted using a customer provided
        KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-transformencryption
        '''
        result = self._values.get("transform_encryption")
        return typing.cast(typing.Optional[typing.Union[CfnMLTransform.TransformEncryptionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def worker_type(self) -> typing.Optional[builtins.str]:
        '''The type of predefined worker that is allocated when a task of this transform runs.

        Accepts a value of Standard, G.1X, or G.2X.

        - For the ``Standard`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 50GB disk, and 2 executors per worker.
        - For the ``G.1X`` worker type, each worker provides 4 vCPU, 16 GB of memory and a 64GB disk, and 1 executor per worker.
        - For the ``G.2X`` worker type, each worker provides 8 vCPU, 32 GB of memory and a 128GB disk, and 1 executor per worker.

        ``MaxCapacity`` is a mutually exclusive option with ``NumberOfWorkers`` and ``WorkerType`` .

        - If either ``NumberOfWorkers`` or ``WorkerType`` is set, then ``MaxCapacity`` cannot be set.
        - If ``MaxCapacity`` is set then neither ``NumberOfWorkers`` or ``WorkerType`` can be set.
        - If ``WorkerType`` is set, then ``NumberOfWorkers`` is required (and vice versa).
        - ``MaxCapacity`` and ``NumberOfWorkers`` must both be at least 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-mltransform.html#cfn-glue-mltransform-workertype
        '''
        result = self._values.get("worker_type")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnMLTransformProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPartition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnPartition",
):
    '''A CloudFormation ``AWS::Glue::Partition``.

    The ``AWS::Glue::Partition`` resource creates an AWS Glue partition, which represents a slice of table data. For more information, see `CreatePartition Action <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-catalog-partitions.html#aws-glue-api-catalog-partitions-CreatePartition>`_ and `Partition Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-catalog-partitions.html#aws-glue-api-catalog-partitions-Partition>`_ in the *AWS Glue Developer Guide* .

    :cloudformationResource: AWS::Glue::Partition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # parameters: Any
        # skewed_column_value_location_maps: Any
        
        cfn_partition = glue.CfnPartition(self, "MyCfnPartition",
            catalog_id="catalogId",
            database_name="databaseName",
            partition_input=glue.CfnPartition.PartitionInputProperty(
                values=["values"],
        
                # the properties below are optional
                parameters=parameters,
                storage_descriptor=glue.CfnPartition.StorageDescriptorProperty(
                    bucket_columns=["bucketColumns"],
                    columns=[glue.CfnPartition.ColumnProperty(
                        name="name",
        
                        # the properties below are optional
                        comment="comment",
                        type="type"
                    )],
                    compressed=False,
                    input_format="inputFormat",
                    location="location",
                    number_of_buckets=123,
                    output_format="outputFormat",
                    parameters=parameters,
                    schema_reference=glue.CfnPartition.SchemaReferenceProperty(
                        schema_id=glue.CfnPartition.SchemaIdProperty(
                            registry_name="registryName",
                            schema_arn="schemaArn",
                            schema_name="schemaName"
                        ),
                        schema_version_id="schemaVersionId",
                        schema_version_number=123
                    ),
                    serde_info=glue.CfnPartition.SerdeInfoProperty(
                        name="name",
                        parameters=parameters,
                        serialization_library="serializationLibrary"
                    ),
                    skewed_info=glue.CfnPartition.SkewedInfoProperty(
                        skewed_column_names=["skewedColumnNames"],
                        skewed_column_value_location_maps=skewed_column_value_location_maps,
                        skewed_column_values=["skewedColumnValues"]
                    ),
                    sort_columns=[glue.CfnPartition.OrderProperty(
                        column="column",
        
                        # the properties below are optional
                        sort_order=123
                    )],
                    stored_as_sub_directories=False
                )
            ),
            table_name="tableName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        catalog_id: builtins.str,
        database_name: builtins.str,
        partition_input: typing.Union["CfnPartition.PartitionInputProperty", _IResolvable_da3f097b],
        table_name: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Glue::Partition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param catalog_id: The AWS account ID of the catalog in which the partion is to be created. .. epigraph:: To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId``
        :param database_name: The name of the catalog database in which to create the partition.
        :param partition_input: The structure used to create and update a partition.
        :param table_name: The name of the metadata table in which the partition is to be created.
        '''
        props = CfnPartitionProps(
            catalog_id=catalog_id,
            database_name=database_name,
            partition_input=partition_input,
            table_name=table_name,
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
    @jsii.member(jsii_name="catalogId")
    def catalog_id(self) -> builtins.str:
        '''The AWS account ID of the catalog in which the partion is to be created.

        .. epigraph::

           To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html#cfn-glue-partition-catalogid
        '''
        return typing.cast(builtins.str, jsii.get(self, "catalogId"))

    @catalog_id.setter
    def catalog_id(self, value: builtins.str) -> None:
        jsii.set(self, "catalogId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="databaseName")
    def database_name(self) -> builtins.str:
        '''The name of the catalog database in which to create the partition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html#cfn-glue-partition-databasename
        '''
        return typing.cast(builtins.str, jsii.get(self, "databaseName"))

    @database_name.setter
    def database_name(self, value: builtins.str) -> None:
        jsii.set(self, "databaseName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="partitionInput")
    def partition_input(
        self,
    ) -> typing.Union["CfnPartition.PartitionInputProperty", _IResolvable_da3f097b]:
        '''The structure used to create and update a partition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html#cfn-glue-partition-partitioninput
        '''
        return typing.cast(typing.Union["CfnPartition.PartitionInputProperty", _IResolvable_da3f097b], jsii.get(self, "partitionInput"))

    @partition_input.setter
    def partition_input(
        self,
        value: typing.Union["CfnPartition.PartitionInputProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "partitionInput", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tableName")
    def table_name(self) -> builtins.str:
        '''The name of the metadata table in which the partition is to be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html#cfn-glue-partition-tablename
        '''
        return typing.cast(builtins.str, jsii.get(self, "tableName"))

    @table_name.setter
    def table_name(self, value: builtins.str) -> None:
        jsii.set(self, "tableName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnPartition.ColumnProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "comment": "comment", "type": "type"},
    )
    class ColumnProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            comment: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A column in a ``Table`` .

            :param name: The name of the ``Column`` .
            :param comment: A free-form text comment.
            :param type: The data type of the ``Column`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-column.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                column_property = glue.CfnPartition.ColumnProperty(
                    name="name",
                
                    # the properties below are optional
                    comment="comment",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }
            if comment is not None:
                self._values["comment"] = comment
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the ``Column`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-column.html#cfn-glue-partition-column-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def comment(self) -> typing.Optional[builtins.str]:
            '''A free-form text comment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-column.html#cfn-glue-partition-column-comment
            '''
            result = self._values.get("comment")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The data type of the ``Column`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-column.html#cfn-glue-partition-column-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnPartition.OrderProperty",
        jsii_struct_bases=[],
        name_mapping={"column": "column", "sort_order": "sortOrder"},
    )
    class OrderProperty:
        def __init__(
            self,
            *,
            column: builtins.str,
            sort_order: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies the sort order of a sorted column.

            :param column: The name of the column.
            :param sort_order: Indicates that the column is sorted in ascending order ( ``== 1`` ), or in descending order ( ``==0`` ).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-order.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                order_property = glue.CfnPartition.OrderProperty(
                    column="column",
                
                    # the properties below are optional
                    sort_order=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "column": column,
            }
            if sort_order is not None:
                self._values["sort_order"] = sort_order

        @builtins.property
        def column(self) -> builtins.str:
            '''The name of the column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-order.html#cfn-glue-partition-order-column
            '''
            result = self._values.get("column")
            assert result is not None, "Required property 'column' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sort_order(self) -> typing.Optional[jsii.Number]:
            '''Indicates that the column is sorted in ascending order ( ``== 1`` ), or in descending order ( ``==0`` ).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-order.html#cfn-glue-partition-order-sortorder
            '''
            result = self._values.get("sort_order")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OrderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnPartition.PartitionInputProperty",
        jsii_struct_bases=[],
        name_mapping={
            "values": "values",
            "parameters": "parameters",
            "storage_descriptor": "storageDescriptor",
        },
    )
    class PartitionInputProperty:
        def __init__(
            self,
            *,
            values: typing.Sequence[builtins.str],
            parameters: typing.Any = None,
            storage_descriptor: typing.Optional[typing.Union["CfnPartition.StorageDescriptorProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The structure used to create and update a partition.

            :param values: The values of the partition. Although this parameter is not required by the SDK, you must specify this parameter for a valid input. The values for the keys for the new partition must be passed as an array of String objects that must be ordered in the same order as the partition keys appearing in the Amazon S3 prefix. Otherwise AWS Glue will add the values to the wrong keys.
            :param parameters: These key-value pairs define partition parameters.
            :param storage_descriptor: Provides information about the physical location where the partition is stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-partitioninput.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # parameters: Any
                # skewed_column_value_location_maps: Any
                
                partition_input_property = glue.CfnPartition.PartitionInputProperty(
                    values=["values"],
                
                    # the properties below are optional
                    parameters=parameters,
                    storage_descriptor=glue.CfnPartition.StorageDescriptorProperty(
                        bucket_columns=["bucketColumns"],
                        columns=[glue.CfnPartition.ColumnProperty(
                            name="name",
                
                            # the properties below are optional
                            comment="comment",
                            type="type"
                        )],
                        compressed=False,
                        input_format="inputFormat",
                        location="location",
                        number_of_buckets=123,
                        output_format="outputFormat",
                        parameters=parameters,
                        schema_reference=glue.CfnPartition.SchemaReferenceProperty(
                            schema_id=glue.CfnPartition.SchemaIdProperty(
                                registry_name="registryName",
                                schema_arn="schemaArn",
                                schema_name="schemaName"
                            ),
                            schema_version_id="schemaVersionId",
                            schema_version_number=123
                        ),
                        serde_info=glue.CfnPartition.SerdeInfoProperty(
                            name="name",
                            parameters=parameters,
                            serialization_library="serializationLibrary"
                        ),
                        skewed_info=glue.CfnPartition.SkewedInfoProperty(
                            skewed_column_names=["skewedColumnNames"],
                            skewed_column_value_location_maps=skewed_column_value_location_maps,
                            skewed_column_values=["skewedColumnValues"]
                        ),
                        sort_columns=[glue.CfnPartition.OrderProperty(
                            column="column",
                
                            # the properties below are optional
                            sort_order=123
                        )],
                        stored_as_sub_directories=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "values": values,
            }
            if parameters is not None:
                self._values["parameters"] = parameters
            if storage_descriptor is not None:
                self._values["storage_descriptor"] = storage_descriptor

        @builtins.property
        def values(self) -> typing.List[builtins.str]:
            '''The values of the partition.

            Although this parameter is not required by the SDK, you must specify this parameter for a valid input.

            The values for the keys for the new partition must be passed as an array of String objects that must be ordered in the same order as the partition keys appearing in the Amazon S3 prefix. Otherwise AWS Glue will add the values to the wrong keys.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-partitioninput.html#cfn-glue-partition-partitioninput-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''These key-value pairs define partition parameters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-partitioninput.html#cfn-glue-partition-partitioninput-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        @builtins.property
        def storage_descriptor(
            self,
        ) -> typing.Optional[typing.Union["CfnPartition.StorageDescriptorProperty", _IResolvable_da3f097b]]:
            '''Provides information about the physical location where the partition is stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-partitioninput.html#cfn-glue-partition-partitioninput-storagedescriptor
            '''
            result = self._values.get("storage_descriptor")
            return typing.cast(typing.Optional[typing.Union["CfnPartition.StorageDescriptorProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PartitionInputProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnPartition.SchemaIdProperty",
        jsii_struct_bases=[],
        name_mapping={
            "registry_name": "registryName",
            "schema_arn": "schemaArn",
            "schema_name": "schemaName",
        },
    )
    class SchemaIdProperty:
        def __init__(
            self,
            *,
            registry_name: typing.Optional[builtins.str] = None,
            schema_arn: typing.Optional[builtins.str] = None,
            schema_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that contains schema identity fields.

            Either this or the ``SchemaVersionId`` has to be
            provided.

            :param registry_name: The name of the schema registry that contains the schema.
            :param schema_arn: The Amazon Resource Name (ARN) of the schema. One of ``SchemaArn`` or ``SchemaName`` has to be provided.
            :param schema_name: The name of the schema. One of ``SchemaArn`` or ``SchemaName`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-schemaid.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                schema_id_property = glue.CfnPartition.SchemaIdProperty(
                    registry_name="registryName",
                    schema_arn="schemaArn",
                    schema_name="schemaName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if registry_name is not None:
                self._values["registry_name"] = registry_name
            if schema_arn is not None:
                self._values["schema_arn"] = schema_arn
            if schema_name is not None:
                self._values["schema_name"] = schema_name

        @builtins.property
        def registry_name(self) -> typing.Optional[builtins.str]:
            '''The name of the schema registry that contains the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-schemaid.html#cfn-glue-partition-schemaid-registryname
            '''
            result = self._values.get("registry_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the schema.

            One of ``SchemaArn`` or ``SchemaName`` has to be
            provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-schemaid.html#cfn-glue-partition-schemaid-schemaarn
            '''
            result = self._values.get("schema_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema_name(self) -> typing.Optional[builtins.str]:
            '''The name of the schema.

            One of ``SchemaArn`` or ``SchemaName`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-schemaid.html#cfn-glue-partition-schemaid-schemaname
            '''
            result = self._values.get("schema_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaIdProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnPartition.SchemaReferenceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "schema_id": "schemaId",
            "schema_version_id": "schemaVersionId",
            "schema_version_number": "schemaVersionNumber",
        },
    )
    class SchemaReferenceProperty:
        def __init__(
            self,
            *,
            schema_id: typing.Optional[typing.Union["CfnPartition.SchemaIdProperty", _IResolvable_da3f097b]] = None,
            schema_version_id: typing.Optional[builtins.str] = None,
            schema_version_number: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''An object that references a schema stored in the AWS Glue Schema Registry.

            :param schema_id: A structure that contains schema identity fields. Either this or the ``SchemaVersionId`` has to be provided.
            :param schema_version_id: The unique ID assigned to a version of the schema. Either this or the ``SchemaId`` has to be provided.
            :param schema_version_number: The version number of the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-schemareference.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                schema_reference_property = glue.CfnPartition.SchemaReferenceProperty(
                    schema_id=glue.CfnPartition.SchemaIdProperty(
                        registry_name="registryName",
                        schema_arn="schemaArn",
                        schema_name="schemaName"
                    ),
                    schema_version_id="schemaVersionId",
                    schema_version_number=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if schema_id is not None:
                self._values["schema_id"] = schema_id
            if schema_version_id is not None:
                self._values["schema_version_id"] = schema_version_id
            if schema_version_number is not None:
                self._values["schema_version_number"] = schema_version_number

        @builtins.property
        def schema_id(
            self,
        ) -> typing.Optional[typing.Union["CfnPartition.SchemaIdProperty", _IResolvable_da3f097b]]:
            '''A structure that contains schema identity fields.

            Either this or the ``SchemaVersionId`` has to be
            provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-schemareference.html#cfn-glue-partition-schemareference-schemaid
            '''
            result = self._values.get("schema_id")
            return typing.cast(typing.Optional[typing.Union["CfnPartition.SchemaIdProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def schema_version_id(self) -> typing.Optional[builtins.str]:
            '''The unique ID assigned to a version of the schema.

            Either this or the ``SchemaId`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-schemareference.html#cfn-glue-partition-schemareference-schemaversionid
            '''
            result = self._values.get("schema_version_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema_version_number(self) -> typing.Optional[jsii.Number]:
            '''The version number of the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-schemareference.html#cfn-glue-partition-schemareference-schemaversionnumber
            '''
            result = self._values.get("schema_version_number")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaReferenceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnPartition.SerdeInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "parameters": "parameters",
            "serialization_library": "serializationLibrary",
        },
    )
    class SerdeInfoProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            parameters: typing.Any = None,
            serialization_library: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a serialization/deserialization program (SerDe) that serves as an extractor and loader.

            :param name: Name of the SerDe.
            :param parameters: These key-value pairs define initialization parameters for the SerDe.
            :param serialization_library: Usually the class that implements the SerDe. An example is ``org.apache.hadoop.hive.serde2.columnar.ColumnarSerDe`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-serdeinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # parameters: Any
                
                serde_info_property = glue.CfnPartition.SerdeInfoProperty(
                    name="name",
                    parameters=parameters,
                    serialization_library="serializationLibrary"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if parameters is not None:
                self._values["parameters"] = parameters
            if serialization_library is not None:
                self._values["serialization_library"] = serialization_library

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''Name of the SerDe.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-serdeinfo.html#cfn-glue-partition-serdeinfo-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''These key-value pairs define initialization parameters for the SerDe.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-serdeinfo.html#cfn-glue-partition-serdeinfo-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        @builtins.property
        def serialization_library(self) -> typing.Optional[builtins.str]:
            '''Usually the class that implements the SerDe.

            An example is ``org.apache.hadoop.hive.serde2.columnar.ColumnarSerDe`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-serdeinfo.html#cfn-glue-partition-serdeinfo-serializationlibrary
            '''
            result = self._values.get("serialization_library")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SerdeInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnPartition.SkewedInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "skewed_column_names": "skewedColumnNames",
            "skewed_column_value_location_maps": "skewedColumnValueLocationMaps",
            "skewed_column_values": "skewedColumnValues",
        },
    )
    class SkewedInfoProperty:
        def __init__(
            self,
            *,
            skewed_column_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            skewed_column_value_location_maps: typing.Any = None,
            skewed_column_values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Specifies skewed values in a table.

            Skewed values are those that occur with very high frequency.

            :param skewed_column_names: A list of names of columns that contain skewed values.
            :param skewed_column_value_location_maps: A mapping of skewed values to the columns that contain them.
            :param skewed_column_values: A list of values that appear so frequently as to be considered skewed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-skewedinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # skewed_column_value_location_maps: Any
                
                skewed_info_property = glue.CfnPartition.SkewedInfoProperty(
                    skewed_column_names=["skewedColumnNames"],
                    skewed_column_value_location_maps=skewed_column_value_location_maps,
                    skewed_column_values=["skewedColumnValues"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if skewed_column_names is not None:
                self._values["skewed_column_names"] = skewed_column_names
            if skewed_column_value_location_maps is not None:
                self._values["skewed_column_value_location_maps"] = skewed_column_value_location_maps
            if skewed_column_values is not None:
                self._values["skewed_column_values"] = skewed_column_values

        @builtins.property
        def skewed_column_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of names of columns that contain skewed values.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-skewedinfo.html#cfn-glue-partition-skewedinfo-skewedcolumnnames
            '''
            result = self._values.get("skewed_column_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def skewed_column_value_location_maps(self) -> typing.Any:
            '''A mapping of skewed values to the columns that contain them.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-skewedinfo.html#cfn-glue-partition-skewedinfo-skewedcolumnvaluelocationmaps
            '''
            result = self._values.get("skewed_column_value_location_maps")
            return typing.cast(typing.Any, result)

        @builtins.property
        def skewed_column_values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of values that appear so frequently as to be considered skewed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-skewedinfo.html#cfn-glue-partition-skewedinfo-skewedcolumnvalues
            '''
            result = self._values.get("skewed_column_values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SkewedInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnPartition.StorageDescriptorProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_columns": "bucketColumns",
            "columns": "columns",
            "compressed": "compressed",
            "input_format": "inputFormat",
            "location": "location",
            "number_of_buckets": "numberOfBuckets",
            "output_format": "outputFormat",
            "parameters": "parameters",
            "schema_reference": "schemaReference",
            "serde_info": "serdeInfo",
            "skewed_info": "skewedInfo",
            "sort_columns": "sortColumns",
            "stored_as_sub_directories": "storedAsSubDirectories",
        },
    )
    class StorageDescriptorProperty:
        def __init__(
            self,
            *,
            bucket_columns: typing.Optional[typing.Sequence[builtins.str]] = None,
            columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnPartition.ColumnProperty", _IResolvable_da3f097b]]]] = None,
            compressed: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            input_format: typing.Optional[builtins.str] = None,
            location: typing.Optional[builtins.str] = None,
            number_of_buckets: typing.Optional[jsii.Number] = None,
            output_format: typing.Optional[builtins.str] = None,
            parameters: typing.Any = None,
            schema_reference: typing.Optional[typing.Union["CfnPartition.SchemaReferenceProperty", _IResolvable_da3f097b]] = None,
            serde_info: typing.Optional[typing.Union["CfnPartition.SerdeInfoProperty", _IResolvable_da3f097b]] = None,
            skewed_info: typing.Optional[typing.Union["CfnPartition.SkewedInfoProperty", _IResolvable_da3f097b]] = None,
            sort_columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnPartition.OrderProperty", _IResolvable_da3f097b]]]] = None,
            stored_as_sub_directories: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Describes the physical storage of table data.

            :param bucket_columns: A list of reducer grouping columns, clustering columns, and bucketing columns in the table.
            :param columns: A list of the ``Columns`` in the table.
            :param compressed: ``True`` if the data in the table is compressed, or ``False`` if not.
            :param input_format: The input format: ``SequenceFileInputFormat`` (binary), or ``TextInputFormat`` , or a custom format.
            :param location: The physical location of the table. By default, this takes the form of the warehouse location, followed by the database location in the warehouse, followed by the table name.
            :param number_of_buckets: The number of buckets. You must specify this property if the partition contains any dimension columns.
            :param output_format: The output format: ``SequenceFileOutputFormat`` (binary), or ``IgnoreKeyTextOutputFormat`` , or a custom format.
            :param parameters: The user-supplied properties in key-value form.
            :param schema_reference: An object that references a schema stored in the AWS Glue Schema Registry.
            :param serde_info: The serialization/deserialization (SerDe) information.
            :param skewed_info: The information about values that appear frequently in a column (skewed values).
            :param sort_columns: A list specifying the sort order of each bucket in the table.
            :param stored_as_sub_directories: ``True`` if the table data is stored in subdirectories, or ``False`` if not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # parameters: Any
                # skewed_column_value_location_maps: Any
                
                storage_descriptor_property = glue.CfnPartition.StorageDescriptorProperty(
                    bucket_columns=["bucketColumns"],
                    columns=[glue.CfnPartition.ColumnProperty(
                        name="name",
                
                        # the properties below are optional
                        comment="comment",
                        type="type"
                    )],
                    compressed=False,
                    input_format="inputFormat",
                    location="location",
                    number_of_buckets=123,
                    output_format="outputFormat",
                    parameters=parameters,
                    schema_reference=glue.CfnPartition.SchemaReferenceProperty(
                        schema_id=glue.CfnPartition.SchemaIdProperty(
                            registry_name="registryName",
                            schema_arn="schemaArn",
                            schema_name="schemaName"
                        ),
                        schema_version_id="schemaVersionId",
                        schema_version_number=123
                    ),
                    serde_info=glue.CfnPartition.SerdeInfoProperty(
                        name="name",
                        parameters=parameters,
                        serialization_library="serializationLibrary"
                    ),
                    skewed_info=glue.CfnPartition.SkewedInfoProperty(
                        skewed_column_names=["skewedColumnNames"],
                        skewed_column_value_location_maps=skewed_column_value_location_maps,
                        skewed_column_values=["skewedColumnValues"]
                    ),
                    sort_columns=[glue.CfnPartition.OrderProperty(
                        column="column",
                
                        # the properties below are optional
                        sort_order=123
                    )],
                    stored_as_sub_directories=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if bucket_columns is not None:
                self._values["bucket_columns"] = bucket_columns
            if columns is not None:
                self._values["columns"] = columns
            if compressed is not None:
                self._values["compressed"] = compressed
            if input_format is not None:
                self._values["input_format"] = input_format
            if location is not None:
                self._values["location"] = location
            if number_of_buckets is not None:
                self._values["number_of_buckets"] = number_of_buckets
            if output_format is not None:
                self._values["output_format"] = output_format
            if parameters is not None:
                self._values["parameters"] = parameters
            if schema_reference is not None:
                self._values["schema_reference"] = schema_reference
            if serde_info is not None:
                self._values["serde_info"] = serde_info
            if skewed_info is not None:
                self._values["skewed_info"] = skewed_info
            if sort_columns is not None:
                self._values["sort_columns"] = sort_columns
            if stored_as_sub_directories is not None:
                self._values["stored_as_sub_directories"] = stored_as_sub_directories

        @builtins.property
        def bucket_columns(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of reducer grouping columns, clustering columns, and bucketing columns in the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-bucketcolumns
            '''
            result = self._values.get("bucket_columns")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def columns(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPartition.ColumnProperty", _IResolvable_da3f097b]]]]:
            '''A list of the ``Columns`` in the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-columns
            '''
            result = self._values.get("columns")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPartition.ColumnProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def compressed(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``True`` if the data in the table is compressed, or ``False`` if not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-compressed
            '''
            result = self._values.get("compressed")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def input_format(self) -> typing.Optional[builtins.str]:
            '''The input format: ``SequenceFileInputFormat`` (binary), or ``TextInputFormat`` , or a custom format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-inputformat
            '''
            result = self._values.get("input_format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def location(self) -> typing.Optional[builtins.str]:
            '''The physical location of the table.

            By default, this takes the form of the warehouse location, followed by the database location in the warehouse, followed by the table name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-location
            '''
            result = self._values.get("location")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def number_of_buckets(self) -> typing.Optional[jsii.Number]:
            '''The number of buckets.

            You must specify this property if the partition contains any dimension columns.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-numberofbuckets
            '''
            result = self._values.get("number_of_buckets")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def output_format(self) -> typing.Optional[builtins.str]:
            '''The output format: ``SequenceFileOutputFormat`` (binary), or ``IgnoreKeyTextOutputFormat`` , or a custom format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-outputformat
            '''
            result = self._values.get("output_format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''The user-supplied properties in key-value form.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        @builtins.property
        def schema_reference(
            self,
        ) -> typing.Optional[typing.Union["CfnPartition.SchemaReferenceProperty", _IResolvable_da3f097b]]:
            '''An object that references a schema stored in the AWS Glue Schema Registry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-schemareference
            '''
            result = self._values.get("schema_reference")
            return typing.cast(typing.Optional[typing.Union["CfnPartition.SchemaReferenceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def serde_info(
            self,
        ) -> typing.Optional[typing.Union["CfnPartition.SerdeInfoProperty", _IResolvable_da3f097b]]:
            '''The serialization/deserialization (SerDe) information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-serdeinfo
            '''
            result = self._values.get("serde_info")
            return typing.cast(typing.Optional[typing.Union["CfnPartition.SerdeInfoProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def skewed_info(
            self,
        ) -> typing.Optional[typing.Union["CfnPartition.SkewedInfoProperty", _IResolvable_da3f097b]]:
            '''The information about values that appear frequently in a column (skewed values).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-skewedinfo
            '''
            result = self._values.get("skewed_info")
            return typing.cast(typing.Optional[typing.Union["CfnPartition.SkewedInfoProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sort_columns(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPartition.OrderProperty", _IResolvable_da3f097b]]]]:
            '''A list specifying the sort order of each bucket in the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-sortcolumns
            '''
            result = self._values.get("sort_columns")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnPartition.OrderProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def stored_as_sub_directories(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``True`` if the table data is stored in subdirectories, or ``False`` if not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-partition-storagedescriptor.html#cfn-glue-partition-storagedescriptor-storedassubdirectories
            '''
            result = self._values.get("stored_as_sub_directories")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StorageDescriptorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnPartitionProps",
    jsii_struct_bases=[],
    name_mapping={
        "catalog_id": "catalogId",
        "database_name": "databaseName",
        "partition_input": "partitionInput",
        "table_name": "tableName",
    },
)
class CfnPartitionProps:
    def __init__(
        self,
        *,
        catalog_id: builtins.str,
        database_name: builtins.str,
        partition_input: typing.Union[CfnPartition.PartitionInputProperty, _IResolvable_da3f097b],
        table_name: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnPartition``.

        :param catalog_id: The AWS account ID of the catalog in which the partion is to be created. .. epigraph:: To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId``
        :param database_name: The name of the catalog database in which to create the partition.
        :param partition_input: The structure used to create and update a partition.
        :param table_name: The name of the metadata table in which the partition is to be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # parameters: Any
            # skewed_column_value_location_maps: Any
            
            cfn_partition_props = glue.CfnPartitionProps(
                catalog_id="catalogId",
                database_name="databaseName",
                partition_input=glue.CfnPartition.PartitionInputProperty(
                    values=["values"],
            
                    # the properties below are optional
                    parameters=parameters,
                    storage_descriptor=glue.CfnPartition.StorageDescriptorProperty(
                        bucket_columns=["bucketColumns"],
                        columns=[glue.CfnPartition.ColumnProperty(
                            name="name",
            
                            # the properties below are optional
                            comment="comment",
                            type="type"
                        )],
                        compressed=False,
                        input_format="inputFormat",
                        location="location",
                        number_of_buckets=123,
                        output_format="outputFormat",
                        parameters=parameters,
                        schema_reference=glue.CfnPartition.SchemaReferenceProperty(
                            schema_id=glue.CfnPartition.SchemaIdProperty(
                                registry_name="registryName",
                                schema_arn="schemaArn",
                                schema_name="schemaName"
                            ),
                            schema_version_id="schemaVersionId",
                            schema_version_number=123
                        ),
                        serde_info=glue.CfnPartition.SerdeInfoProperty(
                            name="name",
                            parameters=parameters,
                            serialization_library="serializationLibrary"
                        ),
                        skewed_info=glue.CfnPartition.SkewedInfoProperty(
                            skewed_column_names=["skewedColumnNames"],
                            skewed_column_value_location_maps=skewed_column_value_location_maps,
                            skewed_column_values=["skewedColumnValues"]
                        ),
                        sort_columns=[glue.CfnPartition.OrderProperty(
                            column="column",
            
                            # the properties below are optional
                            sort_order=123
                        )],
                        stored_as_sub_directories=False
                    )
                ),
                table_name="tableName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "catalog_id": catalog_id,
            "database_name": database_name,
            "partition_input": partition_input,
            "table_name": table_name,
        }

    @builtins.property
    def catalog_id(self) -> builtins.str:
        '''The AWS account ID of the catalog in which the partion is to be created.

        .. epigraph::

           To specify the account ID, you can use the ``Ref`` intrinsic function with the ``AWS::AccountId`` pseudo parameter. For example: ``!Ref AWS::AccountId``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html#cfn-glue-partition-catalogid
        '''
        result = self._values.get("catalog_id")
        assert result is not None, "Required property 'catalog_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def database_name(self) -> builtins.str:
        '''The name of the catalog database in which to create the partition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html#cfn-glue-partition-databasename
        '''
        result = self._values.get("database_name")
        assert result is not None, "Required property 'database_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def partition_input(
        self,
    ) -> typing.Union[CfnPartition.PartitionInputProperty, _IResolvable_da3f097b]:
        '''The structure used to create and update a partition.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html#cfn-glue-partition-partitioninput
        '''
        result = self._values.get("partition_input")
        assert result is not None, "Required property 'partition_input' is missing"
        return typing.cast(typing.Union[CfnPartition.PartitionInputProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def table_name(self) -> builtins.str:
        '''The name of the metadata table in which the partition is to be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-partition.html#cfn-glue-partition-tablename
        '''
        result = self._values.get("table_name")
        assert result is not None, "Required property 'table_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPartitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRegistry(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnRegistry",
):
    '''A CloudFormation ``AWS::Glue::Registry``.

    The AWS::Glue::Registry is an AWS Glue resource type that manages registries of schemas in the AWS Glue Schema Registry.

    :cloudformationResource: AWS::Glue::Registry
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-registry.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        cfn_registry = glue.CfnRegistry(self, "MyCfnRegistry",
            name="name",
        
            # the properties below are optional
            description="description",
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
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Glue::Registry``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the registry.
        :param description: A description of the registry.
        :param tags: AWS tags that contain a key value pair and may be searched by console, command line, or API.
        '''
        props = CfnRegistryProps(name=name, description=description, tags=tags)

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
        '''
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
        '''AWS tags that contain a key value pair and may be searched by console, command line, or API.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-registry.html#cfn-glue-registry-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-registry.html#cfn-glue-registry-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-registry.html#cfn-glue-registry-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnRegistryProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "description": "description", "tags": "tags"},
)
class CfnRegistryProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRegistry``.

        :param name: The name of the registry.
        :param description: A description of the registry.
        :param tags: AWS tags that contain a key value pair and may be searched by console, command line, or API.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-registry.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            cfn_registry_props = glue.CfnRegistryProps(
                name="name",
            
                # the properties below are optional
                description="description",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-registry.html#cfn-glue-registry-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-registry.html#cfn-glue-registry-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''AWS tags that contain a key value pair and may be searched by console, command line, or API.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-registry.html#cfn-glue-registry-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRegistryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSchema(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnSchema",
):
    '''A CloudFormation ``AWS::Glue::Schema``.

    The ``AWS::Glue::Schema`` is an AWS Glue resource type that manages schemas in the AWS Glue Schema Registry.

    :cloudformationResource: AWS::Glue::Schema
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        cfn_schema = glue.CfnSchema(self, "MyCfnSchema",
            compatibility="compatibility",
            data_format="dataFormat",
            name="name",
            schema_definition="schemaDefinition",
        
            # the properties below are optional
            checkpoint_version=glue.CfnSchema.SchemaVersionProperty(
                is_latest=False,
                version_number=123
            ),
            description="description",
            registry=glue.CfnSchema.RegistryProperty(
                arn="arn",
                name="name"
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
        compatibility: builtins.str,
        data_format: builtins.str,
        name: builtins.str,
        schema_definition: builtins.str,
        checkpoint_version: typing.Optional[typing.Union["CfnSchema.SchemaVersionProperty", _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        registry: typing.Optional[typing.Union["CfnSchema.RegistryProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Glue::Schema``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param compatibility: The compatibility mode of the schema.
        :param data_format: The data format of the schema definition. Currently only ``AVRO`` is supported.
        :param name: Name of the schema to be created of max length of 255, and may only contain letters, numbers, hyphen, underscore, dollar sign, or hash mark. No whitespace.
        :param schema_definition: The schema definition using the ``DataFormat`` setting for ``SchemaName`` .
        :param checkpoint_version: Specify the ``VersionNumber`` or the ``IsLatest`` for setting the checkpoint for the schema. This is only required for updating a checkpoint.
        :param description: A description of the schema if specified when created.
        :param registry: The registry where a schema is stored.
        :param tags: AWS tags that contain a key value pair and may be searched by console, command line, or API.
        '''
        props = CfnSchemaProps(
            compatibility=compatibility,
            data_format=data_format,
            name=name,
            schema_definition=schema_definition,
            checkpoint_version=checkpoint_version,
            description=description,
            registry=registry,
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
        '''The Amazon Resource Name (ARN) of the schema.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrInitialSchemaVersionId")
    def attr_initial_schema_version_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: InitialSchemaVersionId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrInitialSchemaVersionId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''AWS tags that contain a key value pair and may be searched by console, command line, or API.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="compatibility")
    def compatibility(self) -> builtins.str:
        '''The compatibility mode of the schema.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-compatibility
        '''
        return typing.cast(builtins.str, jsii.get(self, "compatibility"))

    @compatibility.setter
    def compatibility(self, value: builtins.str) -> None:
        jsii.set(self, "compatibility", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataFormat")
    def data_format(self) -> builtins.str:
        '''The data format of the schema definition.

        Currently only ``AVRO`` is supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-dataformat
        '''
        return typing.cast(builtins.str, jsii.get(self, "dataFormat"))

    @data_format.setter
    def data_format(self, value: builtins.str) -> None:
        jsii.set(self, "dataFormat", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''Name of the schema to be created of max length of 255, and may only contain letters, numbers, hyphen, underscore, dollar sign, or hash mark.

        No whitespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schemaDefinition")
    def schema_definition(self) -> builtins.str:
        '''The schema definition using the ``DataFormat`` setting for ``SchemaName`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-schemadefinition
        '''
        return typing.cast(builtins.str, jsii.get(self, "schemaDefinition"))

    @schema_definition.setter
    def schema_definition(self, value: builtins.str) -> None:
        jsii.set(self, "schemaDefinition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="checkpointVersion")
    def checkpoint_version(
        self,
    ) -> typing.Optional[typing.Union["CfnSchema.SchemaVersionProperty", _IResolvable_da3f097b]]:
        '''Specify the ``VersionNumber`` or the ``IsLatest`` for setting the checkpoint for the schema.

        This is only required for updating a checkpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-checkpointversion
        '''
        return typing.cast(typing.Optional[typing.Union["CfnSchema.SchemaVersionProperty", _IResolvable_da3f097b]], jsii.get(self, "checkpointVersion"))

    @checkpoint_version.setter
    def checkpoint_version(
        self,
        value: typing.Optional[typing.Union["CfnSchema.SchemaVersionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "checkpointVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the schema if specified when created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="registry")
    def registry(
        self,
    ) -> typing.Optional[typing.Union["CfnSchema.RegistryProperty", _IResolvable_da3f097b]]:
        '''The registry where a schema is stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-registry
        '''
        return typing.cast(typing.Optional[typing.Union["CfnSchema.RegistryProperty", _IResolvable_da3f097b]], jsii.get(self, "registry"))

    @registry.setter
    def registry(
        self,
        value: typing.Optional[typing.Union["CfnSchema.RegistryProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "registry", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnSchema.RegistryProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn", "name": "name"},
    )
    class RegistryProperty:
        def __init__(
            self,
            *,
            arn: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies a registry in the AWS Glue Schema Registry.

            :param arn: The Amazon Resource Name (ARN) of the registry.
            :param name: The name of the registry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schema-registry.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                registry_property = glue.CfnSchema.RegistryProperty(
                    arn="arn",
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if arn is not None:
                self._values["arn"] = arn
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the registry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schema-registry.html#cfn-glue-schema-registry-arn
            '''
            result = self._values.get("arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the registry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schema-registry.html#cfn-glue-schema-registry-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RegistryProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnSchema.SchemaVersionProperty",
        jsii_struct_bases=[],
        name_mapping={"is_latest": "isLatest", "version_number": "versionNumber"},
    )
    class SchemaVersionProperty:
        def __init__(
            self,
            *,
            is_latest: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            version_number: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies the version of a schema.

            :param is_latest: Indicates if this version is the latest version of the schema.
            :param version_number: The version number of the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schema-schemaversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                schema_version_property = glue.CfnSchema.SchemaVersionProperty(
                    is_latest=False,
                    version_number=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if is_latest is not None:
                self._values["is_latest"] = is_latest
            if version_number is not None:
                self._values["version_number"] = version_number

        @builtins.property
        def is_latest(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates if this version is the latest version of the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schema-schemaversion.html#cfn-glue-schema-schemaversion-islatest
            '''
            result = self._values.get("is_latest")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def version_number(self) -> typing.Optional[jsii.Number]:
            '''The version number of the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schema-schemaversion.html#cfn-glue-schema-schemaversion-versionnumber
            '''
            result = self._values.get("version_number")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnSchemaProps",
    jsii_struct_bases=[],
    name_mapping={
        "compatibility": "compatibility",
        "data_format": "dataFormat",
        "name": "name",
        "schema_definition": "schemaDefinition",
        "checkpoint_version": "checkpointVersion",
        "description": "description",
        "registry": "registry",
        "tags": "tags",
    },
)
class CfnSchemaProps:
    def __init__(
        self,
        *,
        compatibility: builtins.str,
        data_format: builtins.str,
        name: builtins.str,
        schema_definition: builtins.str,
        checkpoint_version: typing.Optional[typing.Union[CfnSchema.SchemaVersionProperty, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        registry: typing.Optional[typing.Union[CfnSchema.RegistryProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSchema``.

        :param compatibility: The compatibility mode of the schema.
        :param data_format: The data format of the schema definition. Currently only ``AVRO`` is supported.
        :param name: Name of the schema to be created of max length of 255, and may only contain letters, numbers, hyphen, underscore, dollar sign, or hash mark. No whitespace.
        :param schema_definition: The schema definition using the ``DataFormat`` setting for ``SchemaName`` .
        :param checkpoint_version: Specify the ``VersionNumber`` or the ``IsLatest`` for setting the checkpoint for the schema. This is only required for updating a checkpoint.
        :param description: A description of the schema if specified when created.
        :param registry: The registry where a schema is stored.
        :param tags: AWS tags that contain a key value pair and may be searched by console, command line, or API.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            cfn_schema_props = glue.CfnSchemaProps(
                compatibility="compatibility",
                data_format="dataFormat",
                name="name",
                schema_definition="schemaDefinition",
            
                # the properties below are optional
                checkpoint_version=glue.CfnSchema.SchemaVersionProperty(
                    is_latest=False,
                    version_number=123
                ),
                description="description",
                registry=glue.CfnSchema.RegistryProperty(
                    arn="arn",
                    name="name"
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "compatibility": compatibility,
            "data_format": data_format,
            "name": name,
            "schema_definition": schema_definition,
        }
        if checkpoint_version is not None:
            self._values["checkpoint_version"] = checkpoint_version
        if description is not None:
            self._values["description"] = description
        if registry is not None:
            self._values["registry"] = registry
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def compatibility(self) -> builtins.str:
        '''The compatibility mode of the schema.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-compatibility
        '''
        result = self._values.get("compatibility")
        assert result is not None, "Required property 'compatibility' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def data_format(self) -> builtins.str:
        '''The data format of the schema definition.

        Currently only ``AVRO`` is supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-dataformat
        '''
        result = self._values.get("data_format")
        assert result is not None, "Required property 'data_format' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''Name of the schema to be created of max length of 255, and may only contain letters, numbers, hyphen, underscore, dollar sign, or hash mark.

        No whitespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def schema_definition(self) -> builtins.str:
        '''The schema definition using the ``DataFormat`` setting for ``SchemaName`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-schemadefinition
        '''
        result = self._values.get("schema_definition")
        assert result is not None, "Required property 'schema_definition' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def checkpoint_version(
        self,
    ) -> typing.Optional[typing.Union[CfnSchema.SchemaVersionProperty, _IResolvable_da3f097b]]:
        '''Specify the ``VersionNumber`` or the ``IsLatest`` for setting the checkpoint for the schema.

        This is only required for updating a checkpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-checkpointversion
        '''
        result = self._values.get("checkpoint_version")
        return typing.cast(typing.Optional[typing.Union[CfnSchema.SchemaVersionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the schema if specified when created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def registry(
        self,
    ) -> typing.Optional[typing.Union[CfnSchema.RegistryProperty, _IResolvable_da3f097b]]:
        '''The registry where a schema is stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-registry
        '''
        result = self._values.get("registry")
        return typing.cast(typing.Optional[typing.Union[CfnSchema.RegistryProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''AWS tags that contain a key value pair and may be searched by console, command line, or API.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schema.html#cfn-glue-schema-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSchemaProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSchemaVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnSchemaVersion",
):
    '''A CloudFormation ``AWS::Glue::SchemaVersion``.

    The ``AWS::Glue::SchemaVersion`` is an AWS Glue resource type that manages schema versions of schemas in the AWS Glue Schema Registry.

    :cloudformationResource: AWS::Glue::SchemaVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        cfn_schema_version = glue.CfnSchemaVersion(self, "MyCfnSchemaVersion",
            schema=glue.CfnSchemaVersion.SchemaProperty(
                registry_name="registryName",
                schema_arn="schemaArn",
                schema_name="schemaName"
            ),
            schema_definition="schemaDefinition"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        schema: typing.Union["CfnSchemaVersion.SchemaProperty", _IResolvable_da3f097b],
        schema_definition: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Glue::SchemaVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param schema: The schema that includes the schema version.
        :param schema_definition: The schema definition for the schema version.
        '''
        props = CfnSchemaVersionProps(
            schema=schema, schema_definition=schema_definition
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
    @jsii.member(jsii_name="attrVersionId")
    def attr_version_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: VersionId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrVersionId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schema")
    def schema(
        self,
    ) -> typing.Union["CfnSchemaVersion.SchemaProperty", _IResolvable_da3f097b]:
        '''The schema that includes the schema version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversion.html#cfn-glue-schemaversion-schema
        '''
        return typing.cast(typing.Union["CfnSchemaVersion.SchemaProperty", _IResolvable_da3f097b], jsii.get(self, "schema"))

    @schema.setter
    def schema(
        self,
        value: typing.Union["CfnSchemaVersion.SchemaProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "schema", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schemaDefinition")
    def schema_definition(self) -> builtins.str:
        '''The schema definition for the schema version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversion.html#cfn-glue-schemaversion-schemadefinition
        '''
        return typing.cast(builtins.str, jsii.get(self, "schemaDefinition"))

    @schema_definition.setter
    def schema_definition(self, value: builtins.str) -> None:
        jsii.set(self, "schemaDefinition", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnSchemaVersion.SchemaProperty",
        jsii_struct_bases=[],
        name_mapping={
            "registry_name": "registryName",
            "schema_arn": "schemaArn",
            "schema_name": "schemaName",
        },
    )
    class SchemaProperty:
        def __init__(
            self,
            *,
            registry_name: typing.Optional[builtins.str] = None,
            schema_arn: typing.Optional[builtins.str] = None,
            schema_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A wrapper structure to contain schema identity fields.

            Either ``SchemaArn`` , or ``SchemaName`` and ``RegistryName`` has to be provided.

            :param registry_name: The name of the registry where the schema is stored. Either ``SchemaArn`` , or ``SchemaName`` and ``RegistryName`` has to be provided.
            :param schema_arn: The Amazon Resource Name (ARN) of the schema. Either ``SchemaArn`` , or ``SchemaName`` and ``RegistryName`` has to be provided.
            :param schema_name: The name of the schema. Either ``SchemaArn`` , or ``SchemaName`` and ``RegistryName`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schemaversion-schema.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                schema_property = glue.CfnSchemaVersion.SchemaProperty(
                    registry_name="registryName",
                    schema_arn="schemaArn",
                    schema_name="schemaName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if registry_name is not None:
                self._values["registry_name"] = registry_name
            if schema_arn is not None:
                self._values["schema_arn"] = schema_arn
            if schema_name is not None:
                self._values["schema_name"] = schema_name

        @builtins.property
        def registry_name(self) -> typing.Optional[builtins.str]:
            '''The name of the registry where the schema is stored.

            Either ``SchemaArn`` , or ``SchemaName`` and ``RegistryName`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schemaversion-schema.html#cfn-glue-schemaversion-schema-registryname
            '''
            result = self._values.get("registry_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the schema.

            Either ``SchemaArn`` , or ``SchemaName`` and ``RegistryName`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schemaversion-schema.html#cfn-glue-schemaversion-schema-schemaarn
            '''
            result = self._values.get("schema_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema_name(self) -> typing.Optional[builtins.str]:
            '''The name of the schema.

            Either ``SchemaArn`` , or ``SchemaName`` and ``RegistryName`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-schemaversion-schema.html#cfn-glue-schemaversion-schema-schemaname
            '''
            result = self._values.get("schema_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnSchemaVersionMetadata(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnSchemaVersionMetadata",
):
    '''A CloudFormation ``AWS::Glue::SchemaVersionMetadata``.

    The ``AWS::Glue::SchemaVersionMetadata`` is an AWS Glue resource type that defines the metadata key-value pairs for a schema version in AWS Glue Schema Registry.

    :cloudformationResource: AWS::Glue::SchemaVersionMetadata
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversionmetadata.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        cfn_schema_version_metadata = glue.CfnSchemaVersionMetadata(self, "MyCfnSchemaVersionMetadata",
            key="key",
            schema_version_id="schemaVersionId",
            value="value"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        key: builtins.str,
        schema_version_id: builtins.str,
        value: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Glue::SchemaVersionMetadata``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param key: A metadata key in a key-value pair for metadata.
        :param schema_version_id: The version number of the schema.
        :param value: A metadata key's corresponding value.
        '''
        props = CfnSchemaVersionMetadataProps(
            key=key, schema_version_id=schema_version_id, value=value
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
    @jsii.member(jsii_name="key")
    def key(self) -> builtins.str:
        '''A metadata key in a key-value pair for metadata.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversionmetadata.html#cfn-glue-schemaversionmetadata-key
        '''
        return typing.cast(builtins.str, jsii.get(self, "key"))

    @key.setter
    def key(self, value: builtins.str) -> None:
        jsii.set(self, "key", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schemaVersionId")
    def schema_version_id(self) -> builtins.str:
        '''The version number of the schema.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversionmetadata.html#cfn-glue-schemaversionmetadata-schemaversionid
        '''
        return typing.cast(builtins.str, jsii.get(self, "schemaVersionId"))

    @schema_version_id.setter
    def schema_version_id(self, value: builtins.str) -> None:
        jsii.set(self, "schemaVersionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="value")
    def value(self) -> builtins.str:
        '''A metadata key's corresponding value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversionmetadata.html#cfn-glue-schemaversionmetadata-value
        '''
        return typing.cast(builtins.str, jsii.get(self, "value"))

    @value.setter
    def value(self, value: builtins.str) -> None:
        jsii.set(self, "value", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnSchemaVersionMetadataProps",
    jsii_struct_bases=[],
    name_mapping={
        "key": "key",
        "schema_version_id": "schemaVersionId",
        "value": "value",
    },
)
class CfnSchemaVersionMetadataProps:
    def __init__(
        self,
        *,
        key: builtins.str,
        schema_version_id: builtins.str,
        value: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnSchemaVersionMetadata``.

        :param key: A metadata key in a key-value pair for metadata.
        :param schema_version_id: The version number of the schema.
        :param value: A metadata key's corresponding value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversionmetadata.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            cfn_schema_version_metadata_props = glue.CfnSchemaVersionMetadataProps(
                key="key",
                schema_version_id="schemaVersionId",
                value="value"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "key": key,
            "schema_version_id": schema_version_id,
            "value": value,
        }

    @builtins.property
    def key(self) -> builtins.str:
        '''A metadata key in a key-value pair for metadata.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversionmetadata.html#cfn-glue-schemaversionmetadata-key
        '''
        result = self._values.get("key")
        assert result is not None, "Required property 'key' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def schema_version_id(self) -> builtins.str:
        '''The version number of the schema.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversionmetadata.html#cfn-glue-schemaversionmetadata-schemaversionid
        '''
        result = self._values.get("schema_version_id")
        assert result is not None, "Required property 'schema_version_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def value(self) -> builtins.str:
        '''A metadata key's corresponding value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversionmetadata.html#cfn-glue-schemaversionmetadata-value
        '''
        result = self._values.get("value")
        assert result is not None, "Required property 'value' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSchemaVersionMetadataProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnSchemaVersionProps",
    jsii_struct_bases=[],
    name_mapping={"schema": "schema", "schema_definition": "schemaDefinition"},
)
class CfnSchemaVersionProps:
    def __init__(
        self,
        *,
        schema: typing.Union[CfnSchemaVersion.SchemaProperty, _IResolvable_da3f097b],
        schema_definition: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnSchemaVersion``.

        :param schema: The schema that includes the schema version.
        :param schema_definition: The schema definition for the schema version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            cfn_schema_version_props = glue.CfnSchemaVersionProps(
                schema=glue.CfnSchemaVersion.SchemaProperty(
                    registry_name="registryName",
                    schema_arn="schemaArn",
                    schema_name="schemaName"
                ),
                schema_definition="schemaDefinition"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "schema": schema,
            "schema_definition": schema_definition,
        }

    @builtins.property
    def schema(
        self,
    ) -> typing.Union[CfnSchemaVersion.SchemaProperty, _IResolvable_da3f097b]:
        '''The schema that includes the schema version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversion.html#cfn-glue-schemaversion-schema
        '''
        result = self._values.get("schema")
        assert result is not None, "Required property 'schema' is missing"
        return typing.cast(typing.Union[CfnSchemaVersion.SchemaProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def schema_definition(self) -> builtins.str:
        '''The schema definition for the schema version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-schemaversion.html#cfn-glue-schemaversion-schemadefinition
        '''
        result = self._values.get("schema_definition")
        assert result is not None, "Required property 'schema_definition' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSchemaVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSecurityConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnSecurityConfiguration",
):
    '''A CloudFormation ``AWS::Glue::SecurityConfiguration``.

    Creates a new security configuration. A security configuration is a set of security properties that can be used by AWS Glue . You can use a security configuration to encrypt data at rest. For information about using security configurations in AWS Glue , see `Encrypting Data Written by Crawlers, Jobs, and Development Endpoints <https://docs.aws.amazon.com/glue/latest/dg/encryption-security-configuration.html>`_ .

    :cloudformationResource: AWS::Glue::SecurityConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-securityconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        cfn_security_configuration = glue.CfnSecurityConfiguration(self, "MyCfnSecurityConfiguration",
            encryption_configuration=glue.CfnSecurityConfiguration.EncryptionConfigurationProperty(
                cloud_watch_encryption=glue.CfnSecurityConfiguration.CloudWatchEncryptionProperty(
                    cloud_watch_encryption_mode="cloudWatchEncryptionMode",
                    kms_key_arn="kmsKeyArn"
                ),
                job_bookmarks_encryption=glue.CfnSecurityConfiguration.JobBookmarksEncryptionProperty(
                    job_bookmarks_encryption_mode="jobBookmarksEncryptionMode",
                    kms_key_arn="kmsKeyArn"
                ),
                s3_encryptions=[glue.CfnSecurityConfiguration.S3EncryptionProperty(
                    kms_key_arn="kmsKeyArn",
                    s3_encryption_mode="s3EncryptionMode"
                )]
            ),
            name="name"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        encryption_configuration: typing.Union["CfnSecurityConfiguration.EncryptionConfigurationProperty", _IResolvable_da3f097b],
        name: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Glue::SecurityConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param encryption_configuration: The encryption configuration associated with this security configuration.
        :param name: The name of the security configuration.
        '''
        props = CfnSecurityConfigurationProps(
            encryption_configuration=encryption_configuration, name=name
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
    @jsii.member(jsii_name="encryptionConfiguration")
    def encryption_configuration(
        self,
    ) -> typing.Union["CfnSecurityConfiguration.EncryptionConfigurationProperty", _IResolvable_da3f097b]:
        '''The encryption configuration associated with this security configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-securityconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration
        '''
        return typing.cast(typing.Union["CfnSecurityConfiguration.EncryptionConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "encryptionConfiguration"))

    @encryption_configuration.setter
    def encryption_configuration(
        self,
        value: typing.Union["CfnSecurityConfiguration.EncryptionConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "encryptionConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the security configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-securityconfiguration.html#cfn-glue-securityconfiguration-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnSecurityConfiguration.CloudWatchEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_encryption_mode": "cloudWatchEncryptionMode",
            "kms_key_arn": "kmsKeyArn",
        },
    )
    class CloudWatchEncryptionProperty:
        def __init__(
            self,
            *,
            cloud_watch_encryption_mode: typing.Optional[builtins.str] = None,
            kms_key_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies how Amazon CloudWatch data should be encrypted.

            :param cloud_watch_encryption_mode: The encryption mode to use for CloudWatch data.
            :param kms_key_arn: The Amazon Resource Name (ARN) of the KMS key to be used to encrypt the data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-cloudwatchencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                cloud_watch_encryption_property = glue.CfnSecurityConfiguration.CloudWatchEncryptionProperty(
                    cloud_watch_encryption_mode="cloudWatchEncryptionMode",
                    kms_key_arn="kmsKeyArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cloud_watch_encryption_mode is not None:
                self._values["cloud_watch_encryption_mode"] = cloud_watch_encryption_mode
            if kms_key_arn is not None:
                self._values["kms_key_arn"] = kms_key_arn

        @builtins.property
        def cloud_watch_encryption_mode(self) -> typing.Optional[builtins.str]:
            '''The encryption mode to use for CloudWatch data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-cloudwatchencryption.html#cfn-glue-securityconfiguration-cloudwatchencryption-cloudwatchencryptionmode
            '''
            result = self._values.get("cloud_watch_encryption_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the KMS key to be used to encrypt the data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-cloudwatchencryption.html#cfn-glue-securityconfiguration-cloudwatchencryption-kmskeyarn
            '''
            result = self._values.get("kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CloudWatchEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnSecurityConfiguration.EncryptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_encryption": "cloudWatchEncryption",
            "job_bookmarks_encryption": "jobBookmarksEncryption",
            "s3_encryptions": "s3Encryptions",
        },
    )
    class EncryptionConfigurationProperty:
        def __init__(
            self,
            *,
            cloud_watch_encryption: typing.Optional[typing.Union["CfnSecurityConfiguration.CloudWatchEncryptionProperty", _IResolvable_da3f097b]] = None,
            job_bookmarks_encryption: typing.Optional[typing.Union["CfnSecurityConfiguration.JobBookmarksEncryptionProperty", _IResolvable_da3f097b]] = None,
            s3_encryptions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnSecurityConfiguration.S3EncryptionProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies an encryption configuration.

            :param cloud_watch_encryption: The encryption configuration for Amazon CloudWatch.
            :param job_bookmarks_encryption: The encryption configuration for job bookmarks.
            :param s3_encryptions: The encyption configuration for Amazon Simple Storage Service (Amazon S3) data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                encryption_configuration_property = glue.CfnSecurityConfiguration.EncryptionConfigurationProperty(
                    cloud_watch_encryption=glue.CfnSecurityConfiguration.CloudWatchEncryptionProperty(
                        cloud_watch_encryption_mode="cloudWatchEncryptionMode",
                        kms_key_arn="kmsKeyArn"
                    ),
                    job_bookmarks_encryption=glue.CfnSecurityConfiguration.JobBookmarksEncryptionProperty(
                        job_bookmarks_encryption_mode="jobBookmarksEncryptionMode",
                        kms_key_arn="kmsKeyArn"
                    ),
                    s3_encryptions=[glue.CfnSecurityConfiguration.S3EncryptionProperty(
                        kms_key_arn="kmsKeyArn",
                        s3_encryption_mode="s3EncryptionMode"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cloud_watch_encryption is not None:
                self._values["cloud_watch_encryption"] = cloud_watch_encryption
            if job_bookmarks_encryption is not None:
                self._values["job_bookmarks_encryption"] = job_bookmarks_encryption
            if s3_encryptions is not None:
                self._values["s3_encryptions"] = s3_encryptions

        @builtins.property
        def cloud_watch_encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnSecurityConfiguration.CloudWatchEncryptionProperty", _IResolvable_da3f097b]]:
            '''The encryption configuration for Amazon CloudWatch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration-cloudwatchencryption
            '''
            result = self._values.get("cloud_watch_encryption")
            return typing.cast(typing.Optional[typing.Union["CfnSecurityConfiguration.CloudWatchEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def job_bookmarks_encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnSecurityConfiguration.JobBookmarksEncryptionProperty", _IResolvable_da3f097b]]:
            '''The encryption configuration for job bookmarks.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration-jobbookmarksencryption
            '''
            result = self._values.get("job_bookmarks_encryption")
            return typing.cast(typing.Optional[typing.Union["CfnSecurityConfiguration.JobBookmarksEncryptionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3_encryptions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSecurityConfiguration.S3EncryptionProperty", _IResolvable_da3f097b]]]]:
            '''The encyption configuration for Amazon Simple Storage Service (Amazon S3) data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration-s3encryptions
            '''
            result = self._values.get("s3_encryptions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSecurityConfiguration.S3EncryptionProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnSecurityConfiguration.JobBookmarksEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "job_bookmarks_encryption_mode": "jobBookmarksEncryptionMode",
            "kms_key_arn": "kmsKeyArn",
        },
    )
    class JobBookmarksEncryptionProperty:
        def __init__(
            self,
            *,
            job_bookmarks_encryption_mode: typing.Optional[builtins.str] = None,
            kms_key_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies how job bookmark data should be encrypted.

            :param job_bookmarks_encryption_mode: The encryption mode to use for job bookmarks data.
            :param kms_key_arn: The Amazon Resource Name (ARN) of the KMS key to be used to encrypt the data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-jobbookmarksencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                job_bookmarks_encryption_property = glue.CfnSecurityConfiguration.JobBookmarksEncryptionProperty(
                    job_bookmarks_encryption_mode="jobBookmarksEncryptionMode",
                    kms_key_arn="kmsKeyArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if job_bookmarks_encryption_mode is not None:
                self._values["job_bookmarks_encryption_mode"] = job_bookmarks_encryption_mode
            if kms_key_arn is not None:
                self._values["kms_key_arn"] = kms_key_arn

        @builtins.property
        def job_bookmarks_encryption_mode(self) -> typing.Optional[builtins.str]:
            '''The encryption mode to use for job bookmarks data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-jobbookmarksencryption.html#cfn-glue-securityconfiguration-jobbookmarksencryption-jobbookmarksencryptionmode
            '''
            result = self._values.get("job_bookmarks_encryption_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the KMS key to be used to encrypt the data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-jobbookmarksencryption.html#cfn-glue-securityconfiguration-jobbookmarksencryption-kmskeyarn
            '''
            result = self._values.get("kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JobBookmarksEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnSecurityConfiguration.S3EncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "kms_key_arn": "kmsKeyArn",
            "s3_encryption_mode": "s3EncryptionMode",
        },
    )
    class S3EncryptionProperty:
        def __init__(
            self,
            *,
            kms_key_arn: typing.Optional[builtins.str] = None,
            s3_encryption_mode: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies how Amazon Simple Storage Service (Amazon S3) data should be encrypted.

            :param kms_key_arn: The Amazon Resource Name (ARN) of the KMS key to be used to encrypt the data.
            :param s3_encryption_mode: The encryption mode to use for Amazon S3 data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-s3encryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                s3_encryption_property = glue.CfnSecurityConfiguration.S3EncryptionProperty(
                    kms_key_arn="kmsKeyArn",
                    s3_encryption_mode="s3EncryptionMode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if kms_key_arn is not None:
                self._values["kms_key_arn"] = kms_key_arn
            if s3_encryption_mode is not None:
                self._values["s3_encryption_mode"] = s3_encryption_mode

        @builtins.property
        def kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the KMS key to be used to encrypt the data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-s3encryption.html#cfn-glue-securityconfiguration-s3encryption-kmskeyarn
            '''
            result = self._values.get("kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3_encryption_mode(self) -> typing.Optional[builtins.str]:
            '''The encryption mode to use for Amazon S3 data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-s3encryption.html#cfn-glue-securityconfiguration-s3encryption-s3encryptionmode
            '''
            result = self._values.get("s3_encryption_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3EncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnSecurityConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "encryption_configuration": "encryptionConfiguration",
        "name": "name",
    },
)
class CfnSecurityConfigurationProps:
    def __init__(
        self,
        *,
        encryption_configuration: typing.Union[CfnSecurityConfiguration.EncryptionConfigurationProperty, _IResolvable_da3f097b],
        name: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnSecurityConfiguration``.

        :param encryption_configuration: The encryption configuration associated with this security configuration.
        :param name: The name of the security configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-securityconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            cfn_security_configuration_props = glue.CfnSecurityConfigurationProps(
                encryption_configuration=glue.CfnSecurityConfiguration.EncryptionConfigurationProperty(
                    cloud_watch_encryption=glue.CfnSecurityConfiguration.CloudWatchEncryptionProperty(
                        cloud_watch_encryption_mode="cloudWatchEncryptionMode",
                        kms_key_arn="kmsKeyArn"
                    ),
                    job_bookmarks_encryption=glue.CfnSecurityConfiguration.JobBookmarksEncryptionProperty(
                        job_bookmarks_encryption_mode="jobBookmarksEncryptionMode",
                        kms_key_arn="kmsKeyArn"
                    ),
                    s3_encryptions=[glue.CfnSecurityConfiguration.S3EncryptionProperty(
                        kms_key_arn="kmsKeyArn",
                        s3_encryption_mode="s3EncryptionMode"
                    )]
                ),
                name="name"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "encryption_configuration": encryption_configuration,
            "name": name,
        }

    @builtins.property
    def encryption_configuration(
        self,
    ) -> typing.Union[CfnSecurityConfiguration.EncryptionConfigurationProperty, _IResolvable_da3f097b]:
        '''The encryption configuration associated with this security configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-securityconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration
        '''
        result = self._values.get("encryption_configuration")
        assert result is not None, "Required property 'encryption_configuration' is missing"
        return typing.cast(typing.Union[CfnSecurityConfiguration.EncryptionConfigurationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the security configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-securityconfiguration.html#cfn-glue-securityconfiguration-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSecurityConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTable(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnTable",
):
    '''A CloudFormation ``AWS::Glue::Table``.

    The ``AWS::Glue::Table`` resource specifies tabular data in the AWS Glue data catalog. For more information, see `Defining Tables in the AWS Glue Data Catalog <https://docs.aws.amazon.com/glue/latest/dg/tables-described.html>`_ and `Table Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-catalog-tables.html#aws-glue-api-catalog-tables-Table>`_ in the *AWS Glue Developer Guide* .

    :cloudformationResource: AWS::Glue::Table
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # parameters: Any
        # skewed_column_value_location_maps: Any
        
        cfn_table = glue.CfnTable(self, "MyCfnTable",
            catalog_id="catalogId",
            database_name="databaseName",
            table_input=glue.CfnTable.TableInputProperty(
                description="description",
                name="name",
                owner="owner",
                parameters=parameters,
                partition_keys=[glue.CfnTable.ColumnProperty(
                    name="name",
        
                    # the properties below are optional
                    comment="comment",
                    type="type"
                )],
                retention=123,
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    bucket_columns=["bucketColumns"],
                    columns=[glue.CfnTable.ColumnProperty(
                        name="name",
        
                        # the properties below are optional
                        comment="comment",
                        type="type"
                    )],
                    compressed=False,
                    input_format="inputFormat",
                    location="location",
                    number_of_buckets=123,
                    output_format="outputFormat",
                    parameters=parameters,
                    schema_reference=glue.CfnTable.SchemaReferenceProperty(
                        schema_id=glue.CfnTable.SchemaIdProperty(
                            registry_name="registryName",
                            schema_arn="schemaArn",
                            schema_name="schemaName"
                        ),
                        schema_version_id="schemaVersionId",
                        schema_version_number=123
                    ),
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        name="name",
                        parameters=parameters,
                        serialization_library="serializationLibrary"
                    ),
                    skewed_info=glue.CfnTable.SkewedInfoProperty(
                        skewed_column_names=["skewedColumnNames"],
                        skewed_column_value_location_maps=skewed_column_value_location_maps,
                        skewed_column_values=["skewedColumnValues"]
                    ),
                    sort_columns=[glue.CfnTable.OrderProperty(
                        column="column",
                        sort_order=123
                    )],
                    stored_as_sub_directories=False
                ),
                table_type="tableType",
                target_table=glue.CfnTable.TableIdentifierProperty(
                    catalog_id="catalogId",
                    database_name="databaseName",
                    name="name"
                ),
                view_expanded_text="viewExpandedText",
                view_original_text="viewOriginalText"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        catalog_id: builtins.str,
        database_name: builtins.str,
        table_input: typing.Union["CfnTable.TableInputProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::Glue::Table``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param catalog_id: The ID of the Data Catalog in which to create the ``Table`` . If none is supplied, the AWS account ID is used by default.
        :param database_name: The name of the database where the table metadata resides. For Hive compatibility, this must be all lowercase.
        :param table_input: A structure used to define a table.
        '''
        props = CfnTableProps(
            catalog_id=catalog_id, database_name=database_name, table_input=table_input
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
    @jsii.member(jsii_name="catalogId")
    def catalog_id(self) -> builtins.str:
        '''The ID of the Data Catalog in which to create the ``Table`` .

        If none is supplied, the AWS account ID is used by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html#cfn-glue-table-catalogid
        '''
        return typing.cast(builtins.str, jsii.get(self, "catalogId"))

    @catalog_id.setter
    def catalog_id(self, value: builtins.str) -> None:
        jsii.set(self, "catalogId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="databaseName")
    def database_name(self) -> builtins.str:
        '''The name of the database where the table metadata resides.

        For Hive compatibility, this must be all lowercase.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html#cfn-glue-table-databasename
        '''
        return typing.cast(builtins.str, jsii.get(self, "databaseName"))

    @database_name.setter
    def database_name(self, value: builtins.str) -> None:
        jsii.set(self, "databaseName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tableInput")
    def table_input(
        self,
    ) -> typing.Union["CfnTable.TableInputProperty", _IResolvable_da3f097b]:
        '''A structure used to define a table.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html#cfn-glue-table-tableinput
        '''
        return typing.cast(typing.Union["CfnTable.TableInputProperty", _IResolvable_da3f097b], jsii.get(self, "tableInput"))

    @table_input.setter
    def table_input(
        self,
        value: typing.Union["CfnTable.TableInputProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "tableInput", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.ColumnProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "comment": "comment", "type": "type"},
    )
    class ColumnProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            comment: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A column in a ``Table`` .

            :param name: The name of the ``Column`` .
            :param comment: A free-form text comment.
            :param type: The data type of the ``Column`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-column.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                column_property = glue.CfnTable.ColumnProperty(
                    name="name",
                
                    # the properties below are optional
                    comment="comment",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }
            if comment is not None:
                self._values["comment"] = comment
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the ``Column`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-column.html#cfn-glue-table-column-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def comment(self) -> typing.Optional[builtins.str]:
            '''A free-form text comment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-column.html#cfn-glue-table-column-comment
            '''
            result = self._values.get("comment")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The data type of the ``Column`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-column.html#cfn-glue-table-column-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.OrderProperty",
        jsii_struct_bases=[],
        name_mapping={"column": "column", "sort_order": "sortOrder"},
    )
    class OrderProperty:
        def __init__(self, *, column: builtins.str, sort_order: jsii.Number) -> None:
            '''Specifies the sort order of a sorted column.

            :param column: The name of the column.
            :param sort_order: Indicates that the column is sorted in ascending order ( ``== 1`` ), or in descending order ( ``==0`` ).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-order.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                order_property = glue.CfnTable.OrderProperty(
                    column="column",
                    sort_order=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "column": column,
                "sort_order": sort_order,
            }

        @builtins.property
        def column(self) -> builtins.str:
            '''The name of the column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-order.html#cfn-glue-table-order-column
            '''
            result = self._values.get("column")
            assert result is not None, "Required property 'column' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sort_order(self) -> jsii.Number:
            '''Indicates that the column is sorted in ascending order ( ``== 1`` ), or in descending order ( ``==0`` ).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-order.html#cfn-glue-table-order-sortorder
            '''
            result = self._values.get("sort_order")
            assert result is not None, "Required property 'sort_order' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OrderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.SchemaIdProperty",
        jsii_struct_bases=[],
        name_mapping={
            "registry_name": "registryName",
            "schema_arn": "schemaArn",
            "schema_name": "schemaName",
        },
    )
    class SchemaIdProperty:
        def __init__(
            self,
            *,
            registry_name: typing.Optional[builtins.str] = None,
            schema_arn: typing.Optional[builtins.str] = None,
            schema_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that contains schema identity fields.

            Either this or the ``SchemaVersionId`` has to be
            provided.

            :param registry_name: The name of the schema registry that contains the schema.
            :param schema_arn: The Amazon Resource Name (ARN) of the schema. One of ``SchemaArn`` or ``SchemaName`` has to be provided.
            :param schema_name: The name of the schema. One of ``SchemaArn`` or ``SchemaName`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-schemaid.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                schema_id_property = glue.CfnTable.SchemaIdProperty(
                    registry_name="registryName",
                    schema_arn="schemaArn",
                    schema_name="schemaName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if registry_name is not None:
                self._values["registry_name"] = registry_name
            if schema_arn is not None:
                self._values["schema_arn"] = schema_arn
            if schema_name is not None:
                self._values["schema_name"] = schema_name

        @builtins.property
        def registry_name(self) -> typing.Optional[builtins.str]:
            '''The name of the schema registry that contains the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-schemaid.html#cfn-glue-table-schemaid-registryname
            '''
            result = self._values.get("registry_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the schema.

            One of ``SchemaArn`` or ``SchemaName`` has to be
            provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-schemaid.html#cfn-glue-table-schemaid-schemaarn
            '''
            result = self._values.get("schema_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema_name(self) -> typing.Optional[builtins.str]:
            '''The name of the schema.

            One of ``SchemaArn`` or ``SchemaName`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-schemaid.html#cfn-glue-table-schemaid-schemaname
            '''
            result = self._values.get("schema_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaIdProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.SchemaReferenceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "schema_id": "schemaId",
            "schema_version_id": "schemaVersionId",
            "schema_version_number": "schemaVersionNumber",
        },
    )
    class SchemaReferenceProperty:
        def __init__(
            self,
            *,
            schema_id: typing.Optional[typing.Union["CfnTable.SchemaIdProperty", _IResolvable_da3f097b]] = None,
            schema_version_id: typing.Optional[builtins.str] = None,
            schema_version_number: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''An object that references a schema stored in the AWS Glue Schema Registry.

            :param schema_id: A structure that contains schema identity fields. Either this or the ``SchemaVersionId`` has to be provided.
            :param schema_version_id: The unique ID assigned to a version of the schema. Either this or the ``SchemaId`` has to be provided.
            :param schema_version_number: The version number of the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-schemareference.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                schema_reference_property = glue.CfnTable.SchemaReferenceProperty(
                    schema_id=glue.CfnTable.SchemaIdProperty(
                        registry_name="registryName",
                        schema_arn="schemaArn",
                        schema_name="schemaName"
                    ),
                    schema_version_id="schemaVersionId",
                    schema_version_number=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if schema_id is not None:
                self._values["schema_id"] = schema_id
            if schema_version_id is not None:
                self._values["schema_version_id"] = schema_version_id
            if schema_version_number is not None:
                self._values["schema_version_number"] = schema_version_number

        @builtins.property
        def schema_id(
            self,
        ) -> typing.Optional[typing.Union["CfnTable.SchemaIdProperty", _IResolvable_da3f097b]]:
            '''A structure that contains schema identity fields.

            Either this or the ``SchemaVersionId`` has to be
            provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-schemareference.html#cfn-glue-table-schemareference-schemaid
            '''
            result = self._values.get("schema_id")
            return typing.cast(typing.Optional[typing.Union["CfnTable.SchemaIdProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def schema_version_id(self) -> typing.Optional[builtins.str]:
            '''The unique ID assigned to a version of the schema.

            Either this or the ``SchemaId`` has to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-schemareference.html#cfn-glue-table-schemareference-schemaversionid
            '''
            result = self._values.get("schema_version_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schema_version_number(self) -> typing.Optional[jsii.Number]:
            '''The version number of the schema.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-schemareference.html#cfn-glue-table-schemareference-schemaversionnumber
            '''
            result = self._values.get("schema_version_number")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaReferenceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.SerdeInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "parameters": "parameters",
            "serialization_library": "serializationLibrary",
        },
    )
    class SerdeInfoProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            parameters: typing.Any = None,
            serialization_library: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a serialization/deserialization program (SerDe) that serves as an extractor and loader.

            :param name: Name of the SerDe.
            :param parameters: These key-value pairs define initialization parameters for the SerDe.
            :param serialization_library: Usually the class that implements the SerDe. An example is ``org.apache.hadoop.hive.serde2.columnar.ColumnarSerDe`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-serdeinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # parameters: Any
                
                serde_info_property = glue.CfnTable.SerdeInfoProperty(
                    name="name",
                    parameters=parameters,
                    serialization_library="serializationLibrary"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if parameters is not None:
                self._values["parameters"] = parameters
            if serialization_library is not None:
                self._values["serialization_library"] = serialization_library

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''Name of the SerDe.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-serdeinfo.html#cfn-glue-table-serdeinfo-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''These key-value pairs define initialization parameters for the SerDe.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-serdeinfo.html#cfn-glue-table-serdeinfo-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        @builtins.property
        def serialization_library(self) -> typing.Optional[builtins.str]:
            '''Usually the class that implements the SerDe.

            An example is ``org.apache.hadoop.hive.serde2.columnar.ColumnarSerDe`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-serdeinfo.html#cfn-glue-table-serdeinfo-serializationlibrary
            '''
            result = self._values.get("serialization_library")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SerdeInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.SkewedInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "skewed_column_names": "skewedColumnNames",
            "skewed_column_value_location_maps": "skewedColumnValueLocationMaps",
            "skewed_column_values": "skewedColumnValues",
        },
    )
    class SkewedInfoProperty:
        def __init__(
            self,
            *,
            skewed_column_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            skewed_column_value_location_maps: typing.Any = None,
            skewed_column_values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Specifies skewed values in a table.

            Skewed values are those that occur with very high frequency.

            :param skewed_column_names: A list of names of columns that contain skewed values.
            :param skewed_column_value_location_maps: A mapping of skewed values to the columns that contain them.
            :param skewed_column_values: A list of values that appear so frequently as to be considered skewed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-skewedinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # skewed_column_value_location_maps: Any
                
                skewed_info_property = glue.CfnTable.SkewedInfoProperty(
                    skewed_column_names=["skewedColumnNames"],
                    skewed_column_value_location_maps=skewed_column_value_location_maps,
                    skewed_column_values=["skewedColumnValues"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if skewed_column_names is not None:
                self._values["skewed_column_names"] = skewed_column_names
            if skewed_column_value_location_maps is not None:
                self._values["skewed_column_value_location_maps"] = skewed_column_value_location_maps
            if skewed_column_values is not None:
                self._values["skewed_column_values"] = skewed_column_values

        @builtins.property
        def skewed_column_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of names of columns that contain skewed values.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-skewedinfo.html#cfn-glue-table-skewedinfo-skewedcolumnnames
            '''
            result = self._values.get("skewed_column_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def skewed_column_value_location_maps(self) -> typing.Any:
            '''A mapping of skewed values to the columns that contain them.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-skewedinfo.html#cfn-glue-table-skewedinfo-skewedcolumnvaluelocationmaps
            '''
            result = self._values.get("skewed_column_value_location_maps")
            return typing.cast(typing.Any, result)

        @builtins.property
        def skewed_column_values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of values that appear so frequently as to be considered skewed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-skewedinfo.html#cfn-glue-table-skewedinfo-skewedcolumnvalues
            '''
            result = self._values.get("skewed_column_values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SkewedInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.StorageDescriptorProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_columns": "bucketColumns",
            "columns": "columns",
            "compressed": "compressed",
            "input_format": "inputFormat",
            "location": "location",
            "number_of_buckets": "numberOfBuckets",
            "output_format": "outputFormat",
            "parameters": "parameters",
            "schema_reference": "schemaReference",
            "serde_info": "serdeInfo",
            "skewed_info": "skewedInfo",
            "sort_columns": "sortColumns",
            "stored_as_sub_directories": "storedAsSubDirectories",
        },
    )
    class StorageDescriptorProperty:
        def __init__(
            self,
            *,
            bucket_columns: typing.Optional[typing.Sequence[builtins.str]] = None,
            columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]] = None,
            compressed: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            input_format: typing.Optional[builtins.str] = None,
            location: typing.Optional[builtins.str] = None,
            number_of_buckets: typing.Optional[jsii.Number] = None,
            output_format: typing.Optional[builtins.str] = None,
            parameters: typing.Any = None,
            schema_reference: typing.Optional[typing.Union["CfnTable.SchemaReferenceProperty", _IResolvable_da3f097b]] = None,
            serde_info: typing.Optional[typing.Union["CfnTable.SerdeInfoProperty", _IResolvable_da3f097b]] = None,
            skewed_info: typing.Optional[typing.Union["CfnTable.SkewedInfoProperty", _IResolvable_da3f097b]] = None,
            sort_columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTable.OrderProperty", _IResolvable_da3f097b]]]] = None,
            stored_as_sub_directories: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Describes the physical storage of table data.

            :param bucket_columns: A list of reducer grouping columns, clustering columns, and bucketing columns in the table.
            :param columns: A list of the ``Columns`` in the table.
            :param compressed: ``True`` if the data in the table is compressed, or ``False`` if not.
            :param input_format: The input format: ``SequenceFileInputFormat`` (binary), or ``TextInputFormat`` , or a custom format.
            :param location: The physical location of the table. By default, this takes the form of the warehouse location, followed by the database location in the warehouse, followed by the table name.
            :param number_of_buckets: Must be specified if the table contains any dimension columns.
            :param output_format: The output format: ``SequenceFileOutputFormat`` (binary), or ``IgnoreKeyTextOutputFormat`` , or a custom format.
            :param parameters: The user-supplied properties in key-value form.
            :param schema_reference: An object that references a schema stored in the AWS Glue Schema Registry.
            :param serde_info: The serialization/deserialization (SerDe) information.
            :param skewed_info: The information about values that appear frequently in a column (skewed values).
            :param sort_columns: A list specifying the sort order of each bucket in the table.
            :param stored_as_sub_directories: ``True`` if the table data is stored in subdirectories, or ``False`` if not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # parameters: Any
                # skewed_column_value_location_maps: Any
                
                storage_descriptor_property = glue.CfnTable.StorageDescriptorProperty(
                    bucket_columns=["bucketColumns"],
                    columns=[glue.CfnTable.ColumnProperty(
                        name="name",
                
                        # the properties below are optional
                        comment="comment",
                        type="type"
                    )],
                    compressed=False,
                    input_format="inputFormat",
                    location="location",
                    number_of_buckets=123,
                    output_format="outputFormat",
                    parameters=parameters,
                    schema_reference=glue.CfnTable.SchemaReferenceProperty(
                        schema_id=glue.CfnTable.SchemaIdProperty(
                            registry_name="registryName",
                            schema_arn="schemaArn",
                            schema_name="schemaName"
                        ),
                        schema_version_id="schemaVersionId",
                        schema_version_number=123
                    ),
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        name="name",
                        parameters=parameters,
                        serialization_library="serializationLibrary"
                    ),
                    skewed_info=glue.CfnTable.SkewedInfoProperty(
                        skewed_column_names=["skewedColumnNames"],
                        skewed_column_value_location_maps=skewed_column_value_location_maps,
                        skewed_column_values=["skewedColumnValues"]
                    ),
                    sort_columns=[glue.CfnTable.OrderProperty(
                        column="column",
                        sort_order=123
                    )],
                    stored_as_sub_directories=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if bucket_columns is not None:
                self._values["bucket_columns"] = bucket_columns
            if columns is not None:
                self._values["columns"] = columns
            if compressed is not None:
                self._values["compressed"] = compressed
            if input_format is not None:
                self._values["input_format"] = input_format
            if location is not None:
                self._values["location"] = location
            if number_of_buckets is not None:
                self._values["number_of_buckets"] = number_of_buckets
            if output_format is not None:
                self._values["output_format"] = output_format
            if parameters is not None:
                self._values["parameters"] = parameters
            if schema_reference is not None:
                self._values["schema_reference"] = schema_reference
            if serde_info is not None:
                self._values["serde_info"] = serde_info
            if skewed_info is not None:
                self._values["skewed_info"] = skewed_info
            if sort_columns is not None:
                self._values["sort_columns"] = sort_columns
            if stored_as_sub_directories is not None:
                self._values["stored_as_sub_directories"] = stored_as_sub_directories

        @builtins.property
        def bucket_columns(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of reducer grouping columns, clustering columns, and bucketing columns in the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-bucketcolumns
            '''
            result = self._values.get("bucket_columns")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def columns(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]]:
            '''A list of the ``Columns`` in the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-columns
            '''
            result = self._values.get("columns")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def compressed(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``True`` if the data in the table is compressed, or ``False`` if not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-compressed
            '''
            result = self._values.get("compressed")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def input_format(self) -> typing.Optional[builtins.str]:
            '''The input format: ``SequenceFileInputFormat`` (binary), or ``TextInputFormat`` , or a custom format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-inputformat
            '''
            result = self._values.get("input_format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def location(self) -> typing.Optional[builtins.str]:
            '''The physical location of the table.

            By default, this takes the form of the warehouse location, followed by the database location in the warehouse, followed by the table name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-location
            '''
            result = self._values.get("location")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def number_of_buckets(self) -> typing.Optional[jsii.Number]:
            '''Must be specified if the table contains any dimension columns.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-numberofbuckets
            '''
            result = self._values.get("number_of_buckets")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def output_format(self) -> typing.Optional[builtins.str]:
            '''The output format: ``SequenceFileOutputFormat`` (binary), or ``IgnoreKeyTextOutputFormat`` , or a custom format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-outputformat
            '''
            result = self._values.get("output_format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''The user-supplied properties in key-value form.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        @builtins.property
        def schema_reference(
            self,
        ) -> typing.Optional[typing.Union["CfnTable.SchemaReferenceProperty", _IResolvable_da3f097b]]:
            '''An object that references a schema stored in the AWS Glue Schema Registry.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-schemareference
            '''
            result = self._values.get("schema_reference")
            return typing.cast(typing.Optional[typing.Union["CfnTable.SchemaReferenceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def serde_info(
            self,
        ) -> typing.Optional[typing.Union["CfnTable.SerdeInfoProperty", _IResolvable_da3f097b]]:
            '''The serialization/deserialization (SerDe) information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-serdeinfo
            '''
            result = self._values.get("serde_info")
            return typing.cast(typing.Optional[typing.Union["CfnTable.SerdeInfoProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def skewed_info(
            self,
        ) -> typing.Optional[typing.Union["CfnTable.SkewedInfoProperty", _IResolvable_da3f097b]]:
            '''The information about values that appear frequently in a column (skewed values).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-skewedinfo
            '''
            result = self._values.get("skewed_info")
            return typing.cast(typing.Optional[typing.Union["CfnTable.SkewedInfoProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sort_columns(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.OrderProperty", _IResolvable_da3f097b]]]]:
            '''A list specifying the sort order of each bucket in the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-sortcolumns
            '''
            result = self._values.get("sort_columns")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.OrderProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def stored_as_sub_directories(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``True`` if the table data is stored in subdirectories, or ``False`` if not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-storagedescriptor.html#cfn-glue-table-storagedescriptor-storedassubdirectories
            '''
            result = self._values.get("stored_as_sub_directories")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StorageDescriptorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.TableIdentifierProperty",
        jsii_struct_bases=[],
        name_mapping={
            "catalog_id": "catalogId",
            "database_name": "databaseName",
            "name": "name",
        },
    )
    class TableIdentifierProperty:
        def __init__(
            self,
            *,
            catalog_id: typing.Optional[builtins.str] = None,
            database_name: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that describes a target table for resource linking.

            :param catalog_id: The ID of the Data Catalog in which the table resides.
            :param database_name: The name of the catalog database that contains the target table.
            :param name: The name of the target table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableidentifier.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                table_identifier_property = glue.CfnTable.TableIdentifierProperty(
                    catalog_id="catalogId",
                    database_name="databaseName",
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if catalog_id is not None:
                self._values["catalog_id"] = catalog_id
            if database_name is not None:
                self._values["database_name"] = database_name
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def catalog_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the Data Catalog in which the table resides.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableidentifier.html#cfn-glue-table-tableidentifier-catalogid
            '''
            result = self._values.get("catalog_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def database_name(self) -> typing.Optional[builtins.str]:
            '''The name of the catalog database that contains the target table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableidentifier.html#cfn-glue-table-tableidentifier-databasename
            '''
            result = self._values.get("database_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the target table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableidentifier.html#cfn-glue-table-tableidentifier-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TableIdentifierProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTable.TableInputProperty",
        jsii_struct_bases=[],
        name_mapping={
            "description": "description",
            "name": "name",
            "owner": "owner",
            "parameters": "parameters",
            "partition_keys": "partitionKeys",
            "retention": "retention",
            "storage_descriptor": "storageDescriptor",
            "table_type": "tableType",
            "target_table": "targetTable",
            "view_expanded_text": "viewExpandedText",
            "view_original_text": "viewOriginalText",
        },
    )
    class TableInputProperty:
        def __init__(
            self,
            *,
            description: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
            owner: typing.Optional[builtins.str] = None,
            parameters: typing.Any = None,
            partition_keys: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]] = None,
            retention: typing.Optional[jsii.Number] = None,
            storage_descriptor: typing.Optional[typing.Union["CfnTable.StorageDescriptorProperty", _IResolvable_da3f097b]] = None,
            table_type: typing.Optional[builtins.str] = None,
            target_table: typing.Optional[typing.Union["CfnTable.TableIdentifierProperty", _IResolvable_da3f097b]] = None,
            view_expanded_text: typing.Optional[builtins.str] = None,
            view_original_text: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure used to define a table.

            :param description: A description of the table.
            :param name: The table name. For Hive compatibility, this is folded to lowercase when it is stored.
            :param owner: The table owner.
            :param parameters: These key-value pairs define properties associated with the table.
            :param partition_keys: A list of columns by which the table is partitioned. Only primitive types are supported as partition keys. When you create a table used by Amazon Athena, and you do not specify any ``partitionKeys`` , you must at least set the value of ``partitionKeys`` to an empty list. For example: ``"PartitionKeys": []``
            :param retention: The retention time for this table.
            :param storage_descriptor: A storage descriptor containing information about the physical storage of this table.
            :param table_type: The type of this table ( ``EXTERNAL_TABLE`` , ``VIRTUAL_VIEW`` , etc.).
            :param target_table: A ``TableIdentifier`` structure that describes a target table for resource linking.
            :param view_expanded_text: If the table is a view, the expanded text of the view; otherwise ``null`` .
            :param view_original_text: If the table is a view, the original text of the view; otherwise ``null`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # parameters: Any
                # skewed_column_value_location_maps: Any
                
                table_input_property = glue.CfnTable.TableInputProperty(
                    description="description",
                    name="name",
                    owner="owner",
                    parameters=parameters,
                    partition_keys=[glue.CfnTable.ColumnProperty(
                        name="name",
                
                        # the properties below are optional
                        comment="comment",
                        type="type"
                    )],
                    retention=123,
                    storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                        bucket_columns=["bucketColumns"],
                        columns=[glue.CfnTable.ColumnProperty(
                            name="name",
                
                            # the properties below are optional
                            comment="comment",
                            type="type"
                        )],
                        compressed=False,
                        input_format="inputFormat",
                        location="location",
                        number_of_buckets=123,
                        output_format="outputFormat",
                        parameters=parameters,
                        schema_reference=glue.CfnTable.SchemaReferenceProperty(
                            schema_id=glue.CfnTable.SchemaIdProperty(
                                registry_name="registryName",
                                schema_arn="schemaArn",
                                schema_name="schemaName"
                            ),
                            schema_version_id="schemaVersionId",
                            schema_version_number=123
                        ),
                        serde_info=glue.CfnTable.SerdeInfoProperty(
                            name="name",
                            parameters=parameters,
                            serialization_library="serializationLibrary"
                        ),
                        skewed_info=glue.CfnTable.SkewedInfoProperty(
                            skewed_column_names=["skewedColumnNames"],
                            skewed_column_value_location_maps=skewed_column_value_location_maps,
                            skewed_column_values=["skewedColumnValues"]
                        ),
                        sort_columns=[glue.CfnTable.OrderProperty(
                            column="column",
                            sort_order=123
                        )],
                        stored_as_sub_directories=False
                    ),
                    table_type="tableType",
                    target_table=glue.CfnTable.TableIdentifierProperty(
                        catalog_id="catalogId",
                        database_name="databaseName",
                        name="name"
                    ),
                    view_expanded_text="viewExpandedText",
                    view_original_text="viewOriginalText"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if description is not None:
                self._values["description"] = description
            if name is not None:
                self._values["name"] = name
            if owner is not None:
                self._values["owner"] = owner
            if parameters is not None:
                self._values["parameters"] = parameters
            if partition_keys is not None:
                self._values["partition_keys"] = partition_keys
            if retention is not None:
                self._values["retention"] = retention
            if storage_descriptor is not None:
                self._values["storage_descriptor"] = storage_descriptor
            if table_type is not None:
                self._values["table_type"] = table_type
            if target_table is not None:
                self._values["target_table"] = target_table
            if view_expanded_text is not None:
                self._values["view_expanded_text"] = view_expanded_text
            if view_original_text is not None:
                self._values["view_original_text"] = view_original_text

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A description of the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The table name.

            For Hive compatibility, this is folded to lowercase when it is stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def owner(self) -> typing.Optional[builtins.str]:
            '''The table owner.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-owner
            '''
            result = self._values.get("owner")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def parameters(self) -> typing.Any:
            '''These key-value pairs define properties associated with the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-parameters
            '''
            result = self._values.get("parameters")
            return typing.cast(typing.Any, result)

        @builtins.property
        def partition_keys(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]]:
            '''A list of columns by which the table is partitioned. Only primitive types are supported as partition keys.

            When you create a table used by Amazon Athena, and you do not specify any ``partitionKeys`` , you must at least set the value of ``partitionKeys`` to an empty list. For example:

            ``"PartitionKeys": []``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-partitionkeys
            '''
            result = self._values.get("partition_keys")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def retention(self) -> typing.Optional[jsii.Number]:
            '''The retention time for this table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-retention
            '''
            result = self._values.get("retention")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def storage_descriptor(
            self,
        ) -> typing.Optional[typing.Union["CfnTable.StorageDescriptorProperty", _IResolvable_da3f097b]]:
            '''A storage descriptor containing information about the physical storage of this table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-storagedescriptor
            '''
            result = self._values.get("storage_descriptor")
            return typing.cast(typing.Optional[typing.Union["CfnTable.StorageDescriptorProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def table_type(self) -> typing.Optional[builtins.str]:
            '''The type of this table ( ``EXTERNAL_TABLE`` , ``VIRTUAL_VIEW`` , etc.).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-tabletype
            '''
            result = self._values.get("table_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def target_table(
            self,
        ) -> typing.Optional[typing.Union["CfnTable.TableIdentifierProperty", _IResolvable_da3f097b]]:
            '''A ``TableIdentifier`` structure that describes a target table for resource linking.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-targettable
            '''
            result = self._values.get("target_table")
            return typing.cast(typing.Optional[typing.Union["CfnTable.TableIdentifierProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def view_expanded_text(self) -> typing.Optional[builtins.str]:
            '''If the table is a view, the expanded text of the view;

            otherwise ``null`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-viewexpandedtext
            '''
            result = self._values.get("view_expanded_text")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def view_original_text(self) -> typing.Optional[builtins.str]:
            '''If the table is a view, the original text of the view;

            otherwise ``null`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-table-tableinput.html#cfn-glue-table-tableinput-vieworiginaltext
            '''
            result = self._values.get("view_original_text")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TableInputProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnTableProps",
    jsii_struct_bases=[],
    name_mapping={
        "catalog_id": "catalogId",
        "database_name": "databaseName",
        "table_input": "tableInput",
    },
)
class CfnTableProps:
    def __init__(
        self,
        *,
        catalog_id: builtins.str,
        database_name: builtins.str,
        table_input: typing.Union[CfnTable.TableInputProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnTable``.

        :param catalog_id: The ID of the Data Catalog in which to create the ``Table`` . If none is supplied, the AWS account ID is used by default.
        :param database_name: The name of the database where the table metadata resides. For Hive compatibility, this must be all lowercase.
        :param table_input: A structure used to define a table.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # parameters: Any
            # skewed_column_value_location_maps: Any
            
            cfn_table_props = glue.CfnTableProps(
                catalog_id="catalogId",
                database_name="databaseName",
                table_input=glue.CfnTable.TableInputProperty(
                    description="description",
                    name="name",
                    owner="owner",
                    parameters=parameters,
                    partition_keys=[glue.CfnTable.ColumnProperty(
                        name="name",
            
                        # the properties below are optional
                        comment="comment",
                        type="type"
                    )],
                    retention=123,
                    storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                        bucket_columns=["bucketColumns"],
                        columns=[glue.CfnTable.ColumnProperty(
                            name="name",
            
                            # the properties below are optional
                            comment="comment",
                            type="type"
                        )],
                        compressed=False,
                        input_format="inputFormat",
                        location="location",
                        number_of_buckets=123,
                        output_format="outputFormat",
                        parameters=parameters,
                        schema_reference=glue.CfnTable.SchemaReferenceProperty(
                            schema_id=glue.CfnTable.SchemaIdProperty(
                                registry_name="registryName",
                                schema_arn="schemaArn",
                                schema_name="schemaName"
                            ),
                            schema_version_id="schemaVersionId",
                            schema_version_number=123
                        ),
                        serde_info=glue.CfnTable.SerdeInfoProperty(
                            name="name",
                            parameters=parameters,
                            serialization_library="serializationLibrary"
                        ),
                        skewed_info=glue.CfnTable.SkewedInfoProperty(
                            skewed_column_names=["skewedColumnNames"],
                            skewed_column_value_location_maps=skewed_column_value_location_maps,
                            skewed_column_values=["skewedColumnValues"]
                        ),
                        sort_columns=[glue.CfnTable.OrderProperty(
                            column="column",
                            sort_order=123
                        )],
                        stored_as_sub_directories=False
                    ),
                    table_type="tableType",
                    target_table=glue.CfnTable.TableIdentifierProperty(
                        catalog_id="catalogId",
                        database_name="databaseName",
                        name="name"
                    ),
                    view_expanded_text="viewExpandedText",
                    view_original_text="viewOriginalText"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "catalog_id": catalog_id,
            "database_name": database_name,
            "table_input": table_input,
        }

    @builtins.property
    def catalog_id(self) -> builtins.str:
        '''The ID of the Data Catalog in which to create the ``Table`` .

        If none is supplied, the AWS account ID is used by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html#cfn-glue-table-catalogid
        '''
        result = self._values.get("catalog_id")
        assert result is not None, "Required property 'catalog_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def database_name(self) -> builtins.str:
        '''The name of the database where the table metadata resides.

        For Hive compatibility, this must be all lowercase.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html#cfn-glue-table-databasename
        '''
        result = self._values.get("database_name")
        assert result is not None, "Required property 'database_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def table_input(
        self,
    ) -> typing.Union[CfnTable.TableInputProperty, _IResolvable_da3f097b]:
        '''A structure used to define a table.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-table.html#cfn-glue-table-tableinput
        '''
        result = self._values.get("table_input")
        assert result is not None, "Required property 'table_input' is missing"
        return typing.cast(typing.Union[CfnTable.TableInputProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnTableProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTrigger(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnTrigger",
):
    '''A CloudFormation ``AWS::Glue::Trigger``.

    The ``AWS::Glue::Trigger`` resource specifies triggers that run AWS Glue jobs. For more information, see `Triggering Jobs in AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/trigger-job.html>`_ and `Trigger Structure <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-trigger.html#aws-glue-api-jobs-trigger-Trigger>`_ in the *AWS Glue Developer Guide* .

    :cloudformationResource: AWS::Glue::Trigger
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # arguments_: Any
        # tags: Any
        
        cfn_trigger = glue.CfnTrigger(self, "MyCfnTrigger",
            actions=[glue.CfnTrigger.ActionProperty(
                arguments=arguments_,
                crawler_name="crawlerName",
                job_name="jobName",
                notification_property=glue.CfnTrigger.NotificationPropertyProperty(
                    notify_delay_after=123
                ),
                security_configuration="securityConfiguration",
                timeout=123
            )],
            type="type",
        
            # the properties below are optional
            description="description",
            name="name",
            predicate=glue.CfnTrigger.PredicateProperty(
                conditions=[glue.CfnTrigger.ConditionProperty(
                    crawler_name="crawlerName",
                    crawl_state="crawlState",
                    job_name="jobName",
                    logical_operator="logicalOperator",
                    state="state"
                )],
                logical="logical"
            ),
            schedule="schedule",
            start_on_creation=False,
            tags=tags,
            workflow_name="workflowName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        actions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTrigger.ActionProperty", _IResolvable_da3f097b]]],
        type: builtins.str,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        predicate: typing.Optional[typing.Union["CfnTrigger.PredicateProperty", _IResolvable_da3f097b]] = None,
        schedule: typing.Optional[builtins.str] = None,
        start_on_creation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
        workflow_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Glue::Trigger``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param actions: The actions initiated by this trigger.
        :param type: The type of trigger that this is.
        :param description: A description of this trigger.
        :param name: The name of the trigger.
        :param predicate: The predicate of this trigger, which defines when it will fire.
        :param schedule: A ``cron`` expression used to specify the schedule. For more information, see `Time-Based Schedules for Jobs and Crawlers <https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html>`_ in the *AWS Glue Developer Guide* . For example, to run something every day at 12:15 UTC, specify ``cron(15 12 * * ? *)`` .
        :param start_on_creation: Set to true to start ``SCHEDULED`` and ``CONDITIONAL`` triggers when created. True is not supported for ``ON_DEMAND`` triggers.
        :param tags: The tags to use with this trigger.
        :param workflow_name: The name of the workflow associated with the trigger.
        '''
        props = CfnTriggerProps(
            actions=actions,
            type=type,
            description=description,
            name=name,
            predicate=predicate,
            schedule=schedule,
            start_on_creation=start_on_creation,
            tags=tags,
            workflow_name=workflow_name,
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
        '''The tags to use with this trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="actions")
    def actions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrigger.ActionProperty", _IResolvable_da3f097b]]]:
        '''The actions initiated by this trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-actions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrigger.ActionProperty", _IResolvable_da3f097b]]], jsii.get(self, "actions"))

    @actions.setter
    def actions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrigger.ActionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "actions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''The type of trigger that this is.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of this trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="predicate")
    def predicate(
        self,
    ) -> typing.Optional[typing.Union["CfnTrigger.PredicateProperty", _IResolvable_da3f097b]]:
        '''The predicate of this trigger, which defines when it will fire.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-predicate
        '''
        return typing.cast(typing.Optional[typing.Union["CfnTrigger.PredicateProperty", _IResolvable_da3f097b]], jsii.get(self, "predicate"))

    @predicate.setter
    def predicate(
        self,
        value: typing.Optional[typing.Union["CfnTrigger.PredicateProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "predicate", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schedule")
    def schedule(self) -> typing.Optional[builtins.str]:
        '''A ``cron`` expression used to specify the schedule.

        For more information, see `Time-Based Schedules for Jobs and Crawlers <https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html>`_ in the *AWS Glue Developer Guide* . For example, to run something every day at 12:15 UTC, specify ``cron(15 12 * * ? *)`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-schedule
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "schedule"))

    @schedule.setter
    def schedule(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "schedule", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="startOnCreation")
    def start_on_creation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Set to true to start ``SCHEDULED`` and ``CONDITIONAL`` triggers when created.

        True is not supported for ``ON_DEMAND`` triggers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-startoncreation
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "startOnCreation"))

    @start_on_creation.setter
    def start_on_creation(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "startOnCreation", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workflowName")
    def workflow_name(self) -> typing.Optional[builtins.str]:
        '''The name of the workflow associated with the trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-workflowname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "workflowName"))

    @workflow_name.setter
    def workflow_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "workflowName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTrigger.ActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arguments": "arguments",
            "crawler_name": "crawlerName",
            "job_name": "jobName",
            "notification_property": "notificationProperty",
            "security_configuration": "securityConfiguration",
            "timeout": "timeout",
        },
    )
    class ActionProperty:
        def __init__(
            self,
            *,
            arguments: typing.Any = None,
            crawler_name: typing.Optional[builtins.str] = None,
            job_name: typing.Optional[builtins.str] = None,
            notification_property: typing.Optional[typing.Union["CfnTrigger.NotificationPropertyProperty", _IResolvable_da3f097b]] = None,
            security_configuration: typing.Optional[builtins.str] = None,
            timeout: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Defines an action to be initiated by a trigger.

            :param arguments: The job arguments used when this trigger fires. For this job run, they replace the default arguments set in the job definition itself. You can specify arguments here that your own job-execution script consumes, in addition to arguments that AWS Glue itself consumes. For information about how to specify and consume your own job arguments, see `Calling AWS Glue APIs in Python <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-python-calling.html>`_ in the *AWS Glue Developer Guide* . For information about the key-value pairs that AWS Glue consumes to set up your job, see the `Special Parameters Used by AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-etl-glue-arguments.html>`_ topic in the developer guide.
            :param crawler_name: The name of the crawler to be used with this action.
            :param job_name: The name of a job to be executed.
            :param notification_property: Specifies configuration properties of a job run notification.
            :param security_configuration: The name of the ``SecurityConfiguration`` structure to be used with this action.
            :param timeout: The ``JobRun`` timeout in minutes. This is the maximum time that a job run can consume resources before it is terminated and enters TIMEOUT status. The default is 2,880 minutes (48 hours). This overrides the timeout value set in the parent job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-action.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                # arguments_: Any
                
                action_property = glue.CfnTrigger.ActionProperty(
                    arguments=arguments_,
                    crawler_name="crawlerName",
                    job_name="jobName",
                    notification_property=glue.CfnTrigger.NotificationPropertyProperty(
                        notify_delay_after=123
                    ),
                    security_configuration="securityConfiguration",
                    timeout=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if arguments is not None:
                self._values["arguments"] = arguments
            if crawler_name is not None:
                self._values["crawler_name"] = crawler_name
            if job_name is not None:
                self._values["job_name"] = job_name
            if notification_property is not None:
                self._values["notification_property"] = notification_property
            if security_configuration is not None:
                self._values["security_configuration"] = security_configuration
            if timeout is not None:
                self._values["timeout"] = timeout

        @builtins.property
        def arguments(self) -> typing.Any:
            '''The job arguments used when this trigger fires.

            For this job run, they replace the default arguments set in the job definition itself.

            You can specify arguments here that your own job-execution script consumes, in addition to arguments that AWS Glue itself consumes.

            For information about how to specify and consume your own job arguments, see `Calling AWS Glue APIs in Python <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-python-calling.html>`_ in the *AWS Glue Developer Guide* .

            For information about the key-value pairs that AWS Glue consumes to set up your job, see the `Special Parameters Used by AWS Glue <https://docs.aws.amazon.com/glue/latest/dg/aws-glue-programming-etl-glue-arguments.html>`_ topic in the developer guide.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-action.html#cfn-glue-trigger-action-arguments
            '''
            result = self._values.get("arguments")
            return typing.cast(typing.Any, result)

        @builtins.property
        def crawler_name(self) -> typing.Optional[builtins.str]:
            '''The name of the crawler to be used with this action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-action.html#cfn-glue-trigger-action-crawlername
            '''
            result = self._values.get("crawler_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def job_name(self) -> typing.Optional[builtins.str]:
            '''The name of a job to be executed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-action.html#cfn-glue-trigger-action-jobname
            '''
            result = self._values.get("job_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def notification_property(
            self,
        ) -> typing.Optional[typing.Union["CfnTrigger.NotificationPropertyProperty", _IResolvable_da3f097b]]:
            '''Specifies configuration properties of a job run notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-action.html#cfn-glue-trigger-action-notificationproperty
            '''
            result = self._values.get("notification_property")
            return typing.cast(typing.Optional[typing.Union["CfnTrigger.NotificationPropertyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def security_configuration(self) -> typing.Optional[builtins.str]:
            '''The name of the ``SecurityConfiguration`` structure to be used with this action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-action.html#cfn-glue-trigger-action-securityconfiguration
            '''
            result = self._values.get("security_configuration")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def timeout(self) -> typing.Optional[jsii.Number]:
            '''The ``JobRun`` timeout in minutes.

            This is the maximum time that a job run can consume resources before it is terminated and enters TIMEOUT status. The default is 2,880 minutes (48 hours). This overrides the timeout value set in the parent job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-action.html#cfn-glue-trigger-action-timeout
            '''
            result = self._values.get("timeout")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTrigger.ConditionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "crawler_name": "crawlerName",
            "crawl_state": "crawlState",
            "job_name": "jobName",
            "logical_operator": "logicalOperator",
            "state": "state",
        },
    )
    class ConditionProperty:
        def __init__(
            self,
            *,
            crawler_name: typing.Optional[builtins.str] = None,
            crawl_state: typing.Optional[builtins.str] = None,
            job_name: typing.Optional[builtins.str] = None,
            logical_operator: typing.Optional[builtins.str] = None,
            state: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines a condition under which a trigger fires.

            :param crawler_name: The name of the crawler to which this condition applies.
            :param crawl_state: The state of the crawler to which this condition applies.
            :param job_name: The name of the job whose ``JobRuns`` this condition applies to, and on which this trigger waits.
            :param logical_operator: A logical operator.
            :param state: The condition state. Currently, the values supported are ``SUCCEEDED`` , ``STOPPED`` , ``TIMEOUT`` , and ``FAILED`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-condition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                condition_property = glue.CfnTrigger.ConditionProperty(
                    crawler_name="crawlerName",
                    crawl_state="crawlState",
                    job_name="jobName",
                    logical_operator="logicalOperator",
                    state="state"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if crawler_name is not None:
                self._values["crawler_name"] = crawler_name
            if crawl_state is not None:
                self._values["crawl_state"] = crawl_state
            if job_name is not None:
                self._values["job_name"] = job_name
            if logical_operator is not None:
                self._values["logical_operator"] = logical_operator
            if state is not None:
                self._values["state"] = state

        @builtins.property
        def crawler_name(self) -> typing.Optional[builtins.str]:
            '''The name of the crawler to which this condition applies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-condition.html#cfn-glue-trigger-condition-crawlername
            '''
            result = self._values.get("crawler_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def crawl_state(self) -> typing.Optional[builtins.str]:
            '''The state of the crawler to which this condition applies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-condition.html#cfn-glue-trigger-condition-crawlstate
            '''
            result = self._values.get("crawl_state")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def job_name(self) -> typing.Optional[builtins.str]:
            '''The name of the job whose ``JobRuns`` this condition applies to, and on which this trigger waits.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-condition.html#cfn-glue-trigger-condition-jobname
            '''
            result = self._values.get("job_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def logical_operator(self) -> typing.Optional[builtins.str]:
            '''A logical operator.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-condition.html#cfn-glue-trigger-condition-logicaloperator
            '''
            result = self._values.get("logical_operator")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def state(self) -> typing.Optional[builtins.str]:
            '''The condition state.

            Currently, the values supported are ``SUCCEEDED`` , ``STOPPED`` , ``TIMEOUT`` , and ``FAILED`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-condition.html#cfn-glue-trigger-condition-state
            '''
            result = self._values.get("state")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConditionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTrigger.NotificationPropertyProperty",
        jsii_struct_bases=[],
        name_mapping={"notify_delay_after": "notifyDelayAfter"},
    )
    class NotificationPropertyProperty:
        def __init__(
            self,
            *,
            notify_delay_after: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies configuration properties of a job run notification.

            :param notify_delay_after: After a job run starts, the number of minutes to wait before sending a job run delay notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-notificationproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                notification_property_property = glue.CfnTrigger.NotificationPropertyProperty(
                    notify_delay_after=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if notify_delay_after is not None:
                self._values["notify_delay_after"] = notify_delay_after

        @builtins.property
        def notify_delay_after(self) -> typing.Optional[jsii.Number]:
            '''After a job run starts, the number of minutes to wait before sending a job run delay notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-notificationproperty.html#cfn-glue-trigger-notificationproperty-notifydelayafter
            '''
            result = self._values.get("notify_delay_after")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotificationPropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_glue.CfnTrigger.PredicateProperty",
        jsii_struct_bases=[],
        name_mapping={"conditions": "conditions", "logical": "logical"},
    )
    class PredicateProperty:
        def __init__(
            self,
            *,
            conditions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTrigger.ConditionProperty", _IResolvable_da3f097b]]]] = None,
            logical: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines the predicate of the trigger, which determines when it fires.

            :param conditions: A list of the conditions that determine when the trigger will fire.
            :param logical: An optional field if only one condition is listed. If multiple conditions are listed, then this field is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-predicate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_glue as glue
                
                predicate_property = glue.CfnTrigger.PredicateProperty(
                    conditions=[glue.CfnTrigger.ConditionProperty(
                        crawler_name="crawlerName",
                        crawl_state="crawlState",
                        job_name="jobName",
                        logical_operator="logicalOperator",
                        state="state"
                    )],
                    logical="logical"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if conditions is not None:
                self._values["conditions"] = conditions
            if logical is not None:
                self._values["logical"] = logical

        @builtins.property
        def conditions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrigger.ConditionProperty", _IResolvable_da3f097b]]]]:
            '''A list of the conditions that determine when the trigger will fire.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-predicate.html#cfn-glue-trigger-predicate-conditions
            '''
            result = self._values.get("conditions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTrigger.ConditionProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def logical(self) -> typing.Optional[builtins.str]:
            '''An optional field if only one condition is listed.

            If multiple conditions are listed, then this field is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-trigger-predicate.html#cfn-glue-trigger-predicate-logical
            '''
            result = self._values.get("logical")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PredicateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnTriggerProps",
    jsii_struct_bases=[],
    name_mapping={
        "actions": "actions",
        "type": "type",
        "description": "description",
        "name": "name",
        "predicate": "predicate",
        "schedule": "schedule",
        "start_on_creation": "startOnCreation",
        "tags": "tags",
        "workflow_name": "workflowName",
    },
)
class CfnTriggerProps:
    def __init__(
        self,
        *,
        actions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTrigger.ActionProperty, _IResolvable_da3f097b]]],
        type: builtins.str,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        predicate: typing.Optional[typing.Union[CfnTrigger.PredicateProperty, _IResolvable_da3f097b]] = None,
        schedule: typing.Optional[builtins.str] = None,
        start_on_creation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
        workflow_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnTrigger``.

        :param actions: The actions initiated by this trigger.
        :param type: The type of trigger that this is.
        :param description: A description of this trigger.
        :param name: The name of the trigger.
        :param predicate: The predicate of this trigger, which defines when it will fire.
        :param schedule: A ``cron`` expression used to specify the schedule. For more information, see `Time-Based Schedules for Jobs and Crawlers <https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html>`_ in the *AWS Glue Developer Guide* . For example, to run something every day at 12:15 UTC, specify ``cron(15 12 * * ? *)`` .
        :param start_on_creation: Set to true to start ``SCHEDULED`` and ``CONDITIONAL`` triggers when created. True is not supported for ``ON_DEMAND`` triggers.
        :param tags: The tags to use with this trigger.
        :param workflow_name: The name of the workflow associated with the trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # arguments_: Any
            # tags: Any
            
            cfn_trigger_props = glue.CfnTriggerProps(
                actions=[glue.CfnTrigger.ActionProperty(
                    arguments=arguments_,
                    crawler_name="crawlerName",
                    job_name="jobName",
                    notification_property=glue.CfnTrigger.NotificationPropertyProperty(
                        notify_delay_after=123
                    ),
                    security_configuration="securityConfiguration",
                    timeout=123
                )],
                type="type",
            
                # the properties below are optional
                description="description",
                name="name",
                predicate=glue.CfnTrigger.PredicateProperty(
                    conditions=[glue.CfnTrigger.ConditionProperty(
                        crawler_name="crawlerName",
                        crawl_state="crawlState",
                        job_name="jobName",
                        logical_operator="logicalOperator",
                        state="state"
                    )],
                    logical="logical"
                ),
                schedule="schedule",
                start_on_creation=False,
                tags=tags,
                workflow_name="workflowName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "actions": actions,
            "type": type,
        }
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if predicate is not None:
            self._values["predicate"] = predicate
        if schedule is not None:
            self._values["schedule"] = schedule
        if start_on_creation is not None:
            self._values["start_on_creation"] = start_on_creation
        if tags is not None:
            self._values["tags"] = tags
        if workflow_name is not None:
            self._values["workflow_name"] = workflow_name

    @builtins.property
    def actions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTrigger.ActionProperty, _IResolvable_da3f097b]]]:
        '''The actions initiated by this trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-actions
        '''
        result = self._values.get("actions")
        assert result is not None, "Required property 'actions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTrigger.ActionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def type(self) -> builtins.str:
        '''The type of trigger that this is.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of this trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def predicate(
        self,
    ) -> typing.Optional[typing.Union[CfnTrigger.PredicateProperty, _IResolvable_da3f097b]]:
        '''The predicate of this trigger, which defines when it will fire.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-predicate
        '''
        result = self._values.get("predicate")
        return typing.cast(typing.Optional[typing.Union[CfnTrigger.PredicateProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def schedule(self) -> typing.Optional[builtins.str]:
        '''A ``cron`` expression used to specify the schedule.

        For more information, see `Time-Based Schedules for Jobs and Crawlers <https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html>`_ in the *AWS Glue Developer Guide* . For example, to run something every day at 12:15 UTC, specify ``cron(15 12 * * ? *)`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-schedule
        '''
        result = self._values.get("schedule")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def start_on_creation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Set to true to start ``SCHEDULED`` and ``CONDITIONAL`` triggers when created.

        True is not supported for ``ON_DEMAND`` triggers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-startoncreation
        '''
        result = self._values.get("start_on_creation")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''The tags to use with this trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def workflow_name(self) -> typing.Optional[builtins.str]:
        '''The name of the workflow associated with the trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-trigger.html#cfn-glue-trigger-workflowname
        '''
        result = self._values.get("workflow_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnTriggerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnWorkflow(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_glue.CfnWorkflow",
):
    '''A CloudFormation ``AWS::Glue::Workflow``.

    The ``AWS::Glue::Workflow`` is an AWS Glue resource type that manages AWS Glue workflows. A workflow is a container for a set of related jobs, crawlers, and triggers in AWS Glue . Using a workflow, you can design a complex multi-job extract, transform, and load (ETL) activity that AWS Glue can execute and track as single entity.

    :cloudformationResource: AWS::Glue::Workflow
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_glue as glue
        
        # default_run_properties: Any
        # tags: Any
        
        cfn_workflow = glue.CfnWorkflow(self, "MyCfnWorkflow",
            default_run_properties=default_run_properties,
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
        default_run_properties: typing.Any = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Glue::Workflow``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param default_run_properties: A collection of properties to be used as part of each execution of the workflow.
        :param description: A description of the workflow.
        :param name: The name of the workflow representing the flow.
        :param tags: The tags to use with this workflow.
        '''
        props = CfnWorkflowProps(
            default_run_properties=default_run_properties,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to use with this workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html#cfn-glue-workflow-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultRunProperties")
    def default_run_properties(self) -> typing.Any:
        '''A collection of properties to be used as part of each execution of the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html#cfn-glue-workflow-defaultrunproperties
        '''
        return typing.cast(typing.Any, jsii.get(self, "defaultRunProperties"))

    @default_run_properties.setter
    def default_run_properties(self, value: typing.Any) -> None:
        jsii.set(self, "defaultRunProperties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html#cfn-glue-workflow-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the workflow representing the flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html#cfn-glue-workflow-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_glue.CfnWorkflowProps",
    jsii_struct_bases=[],
    name_mapping={
        "default_run_properties": "defaultRunProperties",
        "description": "description",
        "name": "name",
        "tags": "tags",
    },
)
class CfnWorkflowProps:
    def __init__(
        self,
        *,
        default_run_properties: typing.Any = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnWorkflow``.

        :param default_run_properties: A collection of properties to be used as part of each execution of the workflow.
        :param description: A description of the workflow.
        :param name: The name of the workflow representing the flow.
        :param tags: The tags to use with this workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_glue as glue
            
            # default_run_properties: Any
            # tags: Any
            
            cfn_workflow_props = glue.CfnWorkflowProps(
                default_run_properties=default_run_properties,
                description="description",
                name="name",
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if default_run_properties is not None:
            self._values["default_run_properties"] = default_run_properties
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def default_run_properties(self) -> typing.Any:
        '''A collection of properties to be used as part of each execution of the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html#cfn-glue-workflow-defaultrunproperties
        '''
        result = self._values.get("default_run_properties")
        return typing.cast(typing.Any, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html#cfn-glue-workflow-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the workflow representing the flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html#cfn-glue-workflow-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''The tags to use with this workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-glue-workflow.html#cfn-glue-workflow-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnWorkflowProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnClassifier",
    "CfnClassifierProps",
    "CfnConnection",
    "CfnConnectionProps",
    "CfnCrawler",
    "CfnCrawlerProps",
    "CfnDataCatalogEncryptionSettings",
    "CfnDataCatalogEncryptionSettingsProps",
    "CfnDatabase",
    "CfnDatabaseProps",
    "CfnDevEndpoint",
    "CfnDevEndpointProps",
    "CfnJob",
    "CfnJobProps",
    "CfnMLTransform",
    "CfnMLTransformProps",
    "CfnPartition",
    "CfnPartitionProps",
    "CfnRegistry",
    "CfnRegistryProps",
    "CfnSchema",
    "CfnSchemaProps",
    "CfnSchemaVersion",
    "CfnSchemaVersionMetadata",
    "CfnSchemaVersionMetadataProps",
    "CfnSchemaVersionProps",
    "CfnSecurityConfiguration",
    "CfnSecurityConfigurationProps",
    "CfnTable",
    "CfnTableProps",
    "CfnTrigger",
    "CfnTriggerProps",
    "CfnWorkflow",
    "CfnWorkflowProps",
]

publication.publish()
