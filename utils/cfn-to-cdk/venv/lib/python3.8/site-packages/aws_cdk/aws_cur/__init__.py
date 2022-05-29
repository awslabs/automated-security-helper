'''
# AWS::CUR Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_cur as cur
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-cur-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::CUR](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_CUR.html).

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
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnReportDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cur.CfnReportDefinition",
):
    '''A CloudFormation ``AWS::CUR::ReportDefinition``.

    The definition of AWS Cost and Usage Report. You can specify the report name, time unit, report format, compression format, S3 bucket, additional artifacts, and schema elements in the definition.

    :cloudformationResource: AWS::CUR::ReportDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cur as cur
        
        cfn_report_definition = cur.CfnReportDefinition(self, "MyCfnReportDefinition",
            compression="compression",
            format="format",
            refresh_closed_reports=False,
            report_name="reportName",
            report_versioning="reportVersioning",
            s3_bucket="s3Bucket",
            s3_prefix="s3Prefix",
            s3_region="s3Region",
            time_unit="timeUnit",
        
            # the properties below are optional
            additional_artifacts=["additionalArtifacts"],
            additional_schema_elements=["additionalSchemaElements"],
            billing_view_arn="billingViewArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        compression: builtins.str,
        format: builtins.str,
        refresh_closed_reports: typing.Union[builtins.bool, _IResolvable_da3f097b],
        report_name: builtins.str,
        report_versioning: builtins.str,
        s3_bucket: builtins.str,
        s3_prefix: builtins.str,
        s3_region: builtins.str,
        time_unit: builtins.str,
        additional_artifacts: typing.Optional[typing.Sequence[builtins.str]] = None,
        additional_schema_elements: typing.Optional[typing.Sequence[builtins.str]] = None,
        billing_view_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CUR::ReportDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param compression: The compression format that Amazon Web Services uses for the report.
        :param format: The format that Amazon Web Services saves the report in.
        :param refresh_closed_reports: Whether you want Amazon Web Services to update your reports after they have been finalized if Amazon Web Services detects charges related to previous months. These charges can include refunds, credits, or support fees.
        :param report_name: The name of the report that you want to create. The name must be unique, is case sensitive, and can't include spaces.
        :param report_versioning: Whether you want Amazon Web Services to overwrite the previous version of each report or to deliver the report in addition to the previous versions.
        :param s3_bucket: The S3 bucket where Amazon Web Services delivers the report.
        :param s3_prefix: The prefix that Amazon Web Services adds to the report name when Amazon Web Services delivers the report. Your prefix can't include spaces.
        :param s3_region: The Region of the S3 bucket that Amazon Web Services delivers the report into.
        :param time_unit: The granularity of the line items in the report.
        :param additional_artifacts: A list of manifests that you want Amazon Web Services to create for this report.
        :param additional_schema_elements: A list of strings that indicate additional content that Amazon Web Services includes in the report, such as individual resource IDs.
        :param billing_view_arn: The Amazon Resource Name (ARN) of the billing view. You can get this value by using the billing view service public APIs.
        '''
        props = CfnReportDefinitionProps(
            compression=compression,
            format=format,
            refresh_closed_reports=refresh_closed_reports,
            report_name=report_name,
            report_versioning=report_versioning,
            s3_bucket=s3_bucket,
            s3_prefix=s3_prefix,
            s3_region=s3_region,
            time_unit=time_unit,
            additional_artifacts=additional_artifacts,
            additional_schema_elements=additional_schema_elements,
            billing_view_arn=billing_view_arn,
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
    @jsii.member(jsii_name="compression")
    def compression(self) -> builtins.str:
        '''The compression format that Amazon Web Services uses for the report.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-compression
        '''
        return typing.cast(builtins.str, jsii.get(self, "compression"))

    @compression.setter
    def compression(self, value: builtins.str) -> None:
        jsii.set(self, "compression", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="format")
    def format(self) -> builtins.str:
        '''The format that Amazon Web Services saves the report in.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-format
        '''
        return typing.cast(builtins.str, jsii.get(self, "format"))

    @format.setter
    def format(self, value: builtins.str) -> None:
        jsii.set(self, "format", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="refreshClosedReports")
    def refresh_closed_reports(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Whether you want Amazon Web Services to update your reports after they have been finalized if Amazon Web Services detects charges related to previous months.

        These charges can include refunds, credits, or support fees.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-refreshclosedreports
        '''
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], jsii.get(self, "refreshClosedReports"))

    @refresh_closed_reports.setter
    def refresh_closed_reports(
        self,
        value: typing.Union[builtins.bool, _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "refreshClosedReports", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="reportName")
    def report_name(self) -> builtins.str:
        '''The name of the report that you want to create.

        The name must be unique, is case sensitive, and can't include spaces.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-reportname
        '''
        return typing.cast(builtins.str, jsii.get(self, "reportName"))

    @report_name.setter
    def report_name(self, value: builtins.str) -> None:
        jsii.set(self, "reportName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="reportVersioning")
    def report_versioning(self) -> builtins.str:
        '''Whether you want Amazon Web Services to overwrite the previous version of each report or to deliver the report in addition to the previous versions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-reportversioning
        '''
        return typing.cast(builtins.str, jsii.get(self, "reportVersioning"))

    @report_versioning.setter
    def report_versioning(self, value: builtins.str) -> None:
        jsii.set(self, "reportVersioning", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="s3Bucket")
    def s3_bucket(self) -> builtins.str:
        '''The S3 bucket where Amazon Web Services delivers the report.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-s3bucket
        '''
        return typing.cast(builtins.str, jsii.get(self, "s3Bucket"))

    @s3_bucket.setter
    def s3_bucket(self, value: builtins.str) -> None:
        jsii.set(self, "s3Bucket", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="s3Prefix")
    def s3_prefix(self) -> builtins.str:
        '''The prefix that Amazon Web Services adds to the report name when Amazon Web Services delivers the report.

        Your prefix can't include spaces.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-s3prefix
        '''
        return typing.cast(builtins.str, jsii.get(self, "s3Prefix"))

    @s3_prefix.setter
    def s3_prefix(self, value: builtins.str) -> None:
        jsii.set(self, "s3Prefix", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="s3Region")
    def s3_region(self) -> builtins.str:
        '''The Region of the S3 bucket that Amazon Web Services delivers the report into.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-s3region
        '''
        return typing.cast(builtins.str, jsii.get(self, "s3Region"))

    @s3_region.setter
    def s3_region(self, value: builtins.str) -> None:
        jsii.set(self, "s3Region", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="timeUnit")
    def time_unit(self) -> builtins.str:
        '''The granularity of the line items in the report.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-timeunit
        '''
        return typing.cast(builtins.str, jsii.get(self, "timeUnit"))

    @time_unit.setter
    def time_unit(self, value: builtins.str) -> None:
        jsii.set(self, "timeUnit", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="additionalArtifacts")
    def additional_artifacts(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of manifests that you want Amazon Web Services to create for this report.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-additionalartifacts
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "additionalArtifacts"))

    @additional_artifacts.setter
    def additional_artifacts(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "additionalArtifacts", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="additionalSchemaElements")
    def additional_schema_elements(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of strings that indicate additional content that Amazon Web Services includes in the report, such as individual resource IDs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-additionalschemaelements
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "additionalSchemaElements"))

    @additional_schema_elements.setter
    def additional_schema_elements(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "additionalSchemaElements", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="billingViewArn")
    def billing_view_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the billing view.

        You can get this value by using the billing view service public APIs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-billingviewarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "billingViewArn"))

    @billing_view_arn.setter
    def billing_view_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "billingViewArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cur.CfnReportDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={
        "compression": "compression",
        "format": "format",
        "refresh_closed_reports": "refreshClosedReports",
        "report_name": "reportName",
        "report_versioning": "reportVersioning",
        "s3_bucket": "s3Bucket",
        "s3_prefix": "s3Prefix",
        "s3_region": "s3Region",
        "time_unit": "timeUnit",
        "additional_artifacts": "additionalArtifacts",
        "additional_schema_elements": "additionalSchemaElements",
        "billing_view_arn": "billingViewArn",
    },
)
class CfnReportDefinitionProps:
    def __init__(
        self,
        *,
        compression: builtins.str,
        format: builtins.str,
        refresh_closed_reports: typing.Union[builtins.bool, _IResolvable_da3f097b],
        report_name: builtins.str,
        report_versioning: builtins.str,
        s3_bucket: builtins.str,
        s3_prefix: builtins.str,
        s3_region: builtins.str,
        time_unit: builtins.str,
        additional_artifacts: typing.Optional[typing.Sequence[builtins.str]] = None,
        additional_schema_elements: typing.Optional[typing.Sequence[builtins.str]] = None,
        billing_view_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnReportDefinition``.

        :param compression: The compression format that Amazon Web Services uses for the report.
        :param format: The format that Amazon Web Services saves the report in.
        :param refresh_closed_reports: Whether you want Amazon Web Services to update your reports after they have been finalized if Amazon Web Services detects charges related to previous months. These charges can include refunds, credits, or support fees.
        :param report_name: The name of the report that you want to create. The name must be unique, is case sensitive, and can't include spaces.
        :param report_versioning: Whether you want Amazon Web Services to overwrite the previous version of each report or to deliver the report in addition to the previous versions.
        :param s3_bucket: The S3 bucket where Amazon Web Services delivers the report.
        :param s3_prefix: The prefix that Amazon Web Services adds to the report name when Amazon Web Services delivers the report. Your prefix can't include spaces.
        :param s3_region: The Region of the S3 bucket that Amazon Web Services delivers the report into.
        :param time_unit: The granularity of the line items in the report.
        :param additional_artifacts: A list of manifests that you want Amazon Web Services to create for this report.
        :param additional_schema_elements: A list of strings that indicate additional content that Amazon Web Services includes in the report, such as individual resource IDs.
        :param billing_view_arn: The Amazon Resource Name (ARN) of the billing view. You can get this value by using the billing view service public APIs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cur as cur
            
            cfn_report_definition_props = cur.CfnReportDefinitionProps(
                compression="compression",
                format="format",
                refresh_closed_reports=False,
                report_name="reportName",
                report_versioning="reportVersioning",
                s3_bucket="s3Bucket",
                s3_prefix="s3Prefix",
                s3_region="s3Region",
                time_unit="timeUnit",
            
                # the properties below are optional
                additional_artifacts=["additionalArtifacts"],
                additional_schema_elements=["additionalSchemaElements"],
                billing_view_arn="billingViewArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "compression": compression,
            "format": format,
            "refresh_closed_reports": refresh_closed_reports,
            "report_name": report_name,
            "report_versioning": report_versioning,
            "s3_bucket": s3_bucket,
            "s3_prefix": s3_prefix,
            "s3_region": s3_region,
            "time_unit": time_unit,
        }
        if additional_artifacts is not None:
            self._values["additional_artifacts"] = additional_artifacts
        if additional_schema_elements is not None:
            self._values["additional_schema_elements"] = additional_schema_elements
        if billing_view_arn is not None:
            self._values["billing_view_arn"] = billing_view_arn

    @builtins.property
    def compression(self) -> builtins.str:
        '''The compression format that Amazon Web Services uses for the report.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-compression
        '''
        result = self._values.get("compression")
        assert result is not None, "Required property 'compression' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def format(self) -> builtins.str:
        '''The format that Amazon Web Services saves the report in.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-format
        '''
        result = self._values.get("format")
        assert result is not None, "Required property 'format' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def refresh_closed_reports(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Whether you want Amazon Web Services to update your reports after they have been finalized if Amazon Web Services detects charges related to previous months.

        These charges can include refunds, credits, or support fees.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-refreshclosedreports
        '''
        result = self._values.get("refresh_closed_reports")
        assert result is not None, "Required property 'refresh_closed_reports' is missing"
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

    @builtins.property
    def report_name(self) -> builtins.str:
        '''The name of the report that you want to create.

        The name must be unique, is case sensitive, and can't include spaces.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-reportname
        '''
        result = self._values.get("report_name")
        assert result is not None, "Required property 'report_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def report_versioning(self) -> builtins.str:
        '''Whether you want Amazon Web Services to overwrite the previous version of each report or to deliver the report in addition to the previous versions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-reportversioning
        '''
        result = self._values.get("report_versioning")
        assert result is not None, "Required property 'report_versioning' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def s3_bucket(self) -> builtins.str:
        '''The S3 bucket where Amazon Web Services delivers the report.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-s3bucket
        '''
        result = self._values.get("s3_bucket")
        assert result is not None, "Required property 's3_bucket' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def s3_prefix(self) -> builtins.str:
        '''The prefix that Amazon Web Services adds to the report name when Amazon Web Services delivers the report.

        Your prefix can't include spaces.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-s3prefix
        '''
        result = self._values.get("s3_prefix")
        assert result is not None, "Required property 's3_prefix' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def s3_region(self) -> builtins.str:
        '''The Region of the S3 bucket that Amazon Web Services delivers the report into.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-s3region
        '''
        result = self._values.get("s3_region")
        assert result is not None, "Required property 's3_region' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def time_unit(self) -> builtins.str:
        '''The granularity of the line items in the report.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-timeunit
        '''
        result = self._values.get("time_unit")
        assert result is not None, "Required property 'time_unit' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def additional_artifacts(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of manifests that you want Amazon Web Services to create for this report.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-additionalartifacts
        '''
        result = self._values.get("additional_artifacts")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def additional_schema_elements(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of strings that indicate additional content that Amazon Web Services includes in the report, such as individual resource IDs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-additionalschemaelements
        '''
        result = self._values.get("additional_schema_elements")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def billing_view_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the billing view.

        You can get this value by using the billing view service public APIs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cur-reportdefinition.html#cfn-cur-reportdefinition-billingviewarn
        '''
        result = self._values.get("billing_view_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnReportDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnReportDefinition",
    "CfnReportDefinitionProps",
]

publication.publish()
