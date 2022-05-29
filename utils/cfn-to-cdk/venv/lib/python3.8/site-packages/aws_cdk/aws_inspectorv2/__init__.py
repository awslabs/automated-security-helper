'''
# AWS::InspectorV2 Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_inspectorv2 as inspector
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-inspectorv2-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::InspectorV2](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_InspectorV2.html).

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
class CfnFilter(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilter",
):
    '''A CloudFormation ``AWS::InspectorV2::Filter``.

    :cloudformationResource: AWS::InspectorV2::Filter
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_inspectorv2 as inspectorv2
        
        cfn_filter = inspectorv2.CfnFilter(self, "MyCfnFilter",
            filter_action="filterAction",
            filter_criteria=inspectorv2.CfnFilter.FilterCriteriaProperty(
                aws_account_id=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                component_id=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                component_type=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                ec2_instance_image_id=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                ec2_instance_subnet_id=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                ec2_instance_vpc_id=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                ecr_image_architecture=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                ecr_image_hash=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                ecr_image_pushed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                    end_inclusive=123,
                    start_inclusive=123
                )],
                ecr_image_registry=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                ecr_image_repository_name=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                ecr_image_tags=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                finding_arn=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                finding_status=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                finding_type=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                first_observed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                    end_inclusive=123,
                    start_inclusive=123
                )],
                inspector_score=[inspectorv2.CfnFilter.NumberFilterProperty(
                    lower_inclusive=123,
                    upper_inclusive=123
                )],
                last_observed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                    end_inclusive=123,
                    start_inclusive=123
                )],
                network_protocol=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                port_range=[inspectorv2.CfnFilter.PortRangeFilterProperty(
                    begin_inclusive=123,
                    end_inclusive=123
                )],
                related_vulnerabilities=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                resource_id=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                resource_tags=[inspectorv2.CfnFilter.MapFilterProperty(
                    comparison="comparison",
        
                    # the properties below are optional
                    key="key",
                    value="value"
                )],
                resource_type=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                severity=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                title=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                updated_at=[inspectorv2.CfnFilter.DateFilterProperty(
                    end_inclusive=123,
                    start_inclusive=123
                )],
                vendor_severity=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                vulnerability_id=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                vulnerability_source=[inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )],
                vulnerable_packages=[inspectorv2.CfnFilter.PackageFilterProperty(
                    architecture=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    ),
                    epoch=inspectorv2.CfnFilter.NumberFilterProperty(
                        lower_inclusive=123,
                        upper_inclusive=123
                    ),
                    name=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    ),
                    release=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    ),
                    source_layer_hash=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    ),
                    version=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )
                )]
            ),
            name="name",
        
            # the properties below are optional
            description="description"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        filter_action: builtins.str,
        filter_criteria: typing.Union["CfnFilter.FilterCriteriaProperty", _IResolvable_da3f097b],
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::InspectorV2::Filter``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param filter_action: ``AWS::InspectorV2::Filter.FilterAction``.
        :param filter_criteria: ``AWS::InspectorV2::Filter.FilterCriteria``.
        :param name: ``AWS::InspectorV2::Filter.Name``.
        :param description: ``AWS::InspectorV2::Filter.Description``.
        '''
        props = CfnFilterProps(
            filter_action=filter_action,
            filter_criteria=filter_criteria,
            name=name,
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
    @jsii.member(jsii_name="filterAction")
    def filter_action(self) -> builtins.str:
        '''``AWS::InspectorV2::Filter.FilterAction``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html#cfn-inspectorv2-filter-filteraction
        '''
        return typing.cast(builtins.str, jsii.get(self, "filterAction"))

    @filter_action.setter
    def filter_action(self, value: builtins.str) -> None:
        jsii.set(self, "filterAction", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="filterCriteria")
    def filter_criteria(
        self,
    ) -> typing.Union["CfnFilter.FilterCriteriaProperty", _IResolvable_da3f097b]:
        '''``AWS::InspectorV2::Filter.FilterCriteria``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html#cfn-inspectorv2-filter-filtercriteria
        '''
        return typing.cast(typing.Union["CfnFilter.FilterCriteriaProperty", _IResolvable_da3f097b], jsii.get(self, "filterCriteria"))

    @filter_criteria.setter
    def filter_criteria(
        self,
        value: typing.Union["CfnFilter.FilterCriteriaProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "filterCriteria", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''``AWS::InspectorV2::Filter.Name``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html#cfn-inspectorv2-filter-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''``AWS::InspectorV2::Filter.Description``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html#cfn-inspectorv2-filter-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilter.DateFilterProperty",
        jsii_struct_bases=[],
        name_mapping={
            "end_inclusive": "endInclusive",
            "start_inclusive": "startInclusive",
        },
    )
    class DateFilterProperty:
        def __init__(
            self,
            *,
            end_inclusive: typing.Optional[jsii.Number] = None,
            start_inclusive: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''
            :param end_inclusive: ``CfnFilter.DateFilterProperty.EndInclusive``.
            :param start_inclusive: ``CfnFilter.DateFilterProperty.StartInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-datefilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_inspectorv2 as inspectorv2
                
                date_filter_property = inspectorv2.CfnFilter.DateFilterProperty(
                    end_inclusive=123,
                    start_inclusive=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if end_inclusive is not None:
                self._values["end_inclusive"] = end_inclusive
            if start_inclusive is not None:
                self._values["start_inclusive"] = start_inclusive

        @builtins.property
        def end_inclusive(self) -> typing.Optional[jsii.Number]:
            '''``CfnFilter.DateFilterProperty.EndInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-datefilter.html#cfn-inspectorv2-filter-datefilter-endinclusive
            '''
            result = self._values.get("end_inclusive")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def start_inclusive(self) -> typing.Optional[jsii.Number]:
            '''``CfnFilter.DateFilterProperty.StartInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-datefilter.html#cfn-inspectorv2-filter-datefilter-startinclusive
            '''
            result = self._values.get("start_inclusive")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DateFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilter.FilterCriteriaProperty",
        jsii_struct_bases=[],
        name_mapping={
            "aws_account_id": "awsAccountId",
            "component_id": "componentId",
            "component_type": "componentType",
            "ec2_instance_image_id": "ec2InstanceImageId",
            "ec2_instance_subnet_id": "ec2InstanceSubnetId",
            "ec2_instance_vpc_id": "ec2InstanceVpcId",
            "ecr_image_architecture": "ecrImageArchitecture",
            "ecr_image_hash": "ecrImageHash",
            "ecr_image_pushed_at": "ecrImagePushedAt",
            "ecr_image_registry": "ecrImageRegistry",
            "ecr_image_repository_name": "ecrImageRepositoryName",
            "ecr_image_tags": "ecrImageTags",
            "finding_arn": "findingArn",
            "finding_status": "findingStatus",
            "finding_type": "findingType",
            "first_observed_at": "firstObservedAt",
            "inspector_score": "inspectorScore",
            "last_observed_at": "lastObservedAt",
            "network_protocol": "networkProtocol",
            "port_range": "portRange",
            "related_vulnerabilities": "relatedVulnerabilities",
            "resource_id": "resourceId",
            "resource_tags": "resourceTags",
            "resource_type": "resourceType",
            "severity": "severity",
            "title": "title",
            "updated_at": "updatedAt",
            "vendor_severity": "vendorSeverity",
            "vulnerability_id": "vulnerabilityId",
            "vulnerability_source": "vulnerabilitySource",
            "vulnerable_packages": "vulnerablePackages",
        },
    )
    class FilterCriteriaProperty:
        def __init__(
            self,
            *,
            aws_account_id: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            component_id: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            component_type: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            ec2_instance_image_id: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            ec2_instance_subnet_id: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            ec2_instance_vpc_id: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            ecr_image_architecture: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            ecr_image_hash: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            ecr_image_pushed_at: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]] = None,
            ecr_image_registry: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            ecr_image_repository_name: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            ecr_image_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            finding_arn: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            finding_status: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            finding_type: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            first_observed_at: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]] = None,
            inspector_score: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.NumberFilterProperty", _IResolvable_da3f097b]]]] = None,
            last_observed_at: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]] = None,
            network_protocol: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            port_range: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.PortRangeFilterProperty", _IResolvable_da3f097b]]]] = None,
            related_vulnerabilities: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            resource_id: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            resource_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.MapFilterProperty", _IResolvable_da3f097b]]]] = None,
            resource_type: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            severity: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            title: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            updated_at: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]] = None,
            vendor_severity: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            vulnerability_id: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            vulnerability_source: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]] = None,
            vulnerable_packages: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFilter.PackageFilterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''
            :param aws_account_id: ``CfnFilter.FilterCriteriaProperty.AwsAccountId``.
            :param component_id: ``CfnFilter.FilterCriteriaProperty.ComponentId``.
            :param component_type: ``CfnFilter.FilterCriteriaProperty.ComponentType``.
            :param ec2_instance_image_id: ``CfnFilter.FilterCriteriaProperty.Ec2InstanceImageId``.
            :param ec2_instance_subnet_id: ``CfnFilter.FilterCriteriaProperty.Ec2InstanceSubnetId``.
            :param ec2_instance_vpc_id: ``CfnFilter.FilterCriteriaProperty.Ec2InstanceVpcId``.
            :param ecr_image_architecture: ``CfnFilter.FilterCriteriaProperty.EcrImageArchitecture``.
            :param ecr_image_hash: ``CfnFilter.FilterCriteriaProperty.EcrImageHash``.
            :param ecr_image_pushed_at: ``CfnFilter.FilterCriteriaProperty.EcrImagePushedAt``.
            :param ecr_image_registry: ``CfnFilter.FilterCriteriaProperty.EcrImageRegistry``.
            :param ecr_image_repository_name: ``CfnFilter.FilterCriteriaProperty.EcrImageRepositoryName``.
            :param ecr_image_tags: ``CfnFilter.FilterCriteriaProperty.EcrImageTags``.
            :param finding_arn: ``CfnFilter.FilterCriteriaProperty.FindingArn``.
            :param finding_status: ``CfnFilter.FilterCriteriaProperty.FindingStatus``.
            :param finding_type: ``CfnFilter.FilterCriteriaProperty.FindingType``.
            :param first_observed_at: ``CfnFilter.FilterCriteriaProperty.FirstObservedAt``.
            :param inspector_score: ``CfnFilter.FilterCriteriaProperty.InspectorScore``.
            :param last_observed_at: ``CfnFilter.FilterCriteriaProperty.LastObservedAt``.
            :param network_protocol: ``CfnFilter.FilterCriteriaProperty.NetworkProtocol``.
            :param port_range: ``CfnFilter.FilterCriteriaProperty.PortRange``.
            :param related_vulnerabilities: ``CfnFilter.FilterCriteriaProperty.RelatedVulnerabilities``.
            :param resource_id: ``CfnFilter.FilterCriteriaProperty.ResourceId``.
            :param resource_tags: ``CfnFilter.FilterCriteriaProperty.ResourceTags``.
            :param resource_type: ``CfnFilter.FilterCriteriaProperty.ResourceType``.
            :param severity: ``CfnFilter.FilterCriteriaProperty.Severity``.
            :param title: ``CfnFilter.FilterCriteriaProperty.Title``.
            :param updated_at: ``CfnFilter.FilterCriteriaProperty.UpdatedAt``.
            :param vendor_severity: ``CfnFilter.FilterCriteriaProperty.VendorSeverity``.
            :param vulnerability_id: ``CfnFilter.FilterCriteriaProperty.VulnerabilityId``.
            :param vulnerability_source: ``CfnFilter.FilterCriteriaProperty.VulnerabilitySource``.
            :param vulnerable_packages: ``CfnFilter.FilterCriteriaProperty.VulnerablePackages``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_inspectorv2 as inspectorv2
                
                filter_criteria_property = inspectorv2.CfnFilter.FilterCriteriaProperty(
                    aws_account_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    component_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    component_type=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ec2_instance_image_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ec2_instance_subnet_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ec2_instance_vpc_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_architecture=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_hash=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_pushed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                        end_inclusive=123,
                        start_inclusive=123
                    )],
                    ecr_image_registry=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_repository_name=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_tags=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    finding_arn=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    finding_status=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    finding_type=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    first_observed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                        end_inclusive=123,
                        start_inclusive=123
                    )],
                    inspector_score=[inspectorv2.CfnFilter.NumberFilterProperty(
                        lower_inclusive=123,
                        upper_inclusive=123
                    )],
                    last_observed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                        end_inclusive=123,
                        start_inclusive=123
                    )],
                    network_protocol=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    port_range=[inspectorv2.CfnFilter.PortRangeFilterProperty(
                        begin_inclusive=123,
                        end_inclusive=123
                    )],
                    related_vulnerabilities=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    resource_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    resource_tags=[inspectorv2.CfnFilter.MapFilterProperty(
                        comparison="comparison",
                
                        # the properties below are optional
                        key="key",
                        value="value"
                    )],
                    resource_type=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    severity=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    title=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    updated_at=[inspectorv2.CfnFilter.DateFilterProperty(
                        end_inclusive=123,
                        start_inclusive=123
                    )],
                    vendor_severity=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    vulnerability_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    vulnerability_source=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    vulnerable_packages=[inspectorv2.CfnFilter.PackageFilterProperty(
                        architecture=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        ),
                        epoch=inspectorv2.CfnFilter.NumberFilterProperty(
                            lower_inclusive=123,
                            upper_inclusive=123
                        ),
                        name=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        ),
                        release=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        ),
                        source_layer_hash=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        ),
                        version=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if aws_account_id is not None:
                self._values["aws_account_id"] = aws_account_id
            if component_id is not None:
                self._values["component_id"] = component_id
            if component_type is not None:
                self._values["component_type"] = component_type
            if ec2_instance_image_id is not None:
                self._values["ec2_instance_image_id"] = ec2_instance_image_id
            if ec2_instance_subnet_id is not None:
                self._values["ec2_instance_subnet_id"] = ec2_instance_subnet_id
            if ec2_instance_vpc_id is not None:
                self._values["ec2_instance_vpc_id"] = ec2_instance_vpc_id
            if ecr_image_architecture is not None:
                self._values["ecr_image_architecture"] = ecr_image_architecture
            if ecr_image_hash is not None:
                self._values["ecr_image_hash"] = ecr_image_hash
            if ecr_image_pushed_at is not None:
                self._values["ecr_image_pushed_at"] = ecr_image_pushed_at
            if ecr_image_registry is not None:
                self._values["ecr_image_registry"] = ecr_image_registry
            if ecr_image_repository_name is not None:
                self._values["ecr_image_repository_name"] = ecr_image_repository_name
            if ecr_image_tags is not None:
                self._values["ecr_image_tags"] = ecr_image_tags
            if finding_arn is not None:
                self._values["finding_arn"] = finding_arn
            if finding_status is not None:
                self._values["finding_status"] = finding_status
            if finding_type is not None:
                self._values["finding_type"] = finding_type
            if first_observed_at is not None:
                self._values["first_observed_at"] = first_observed_at
            if inspector_score is not None:
                self._values["inspector_score"] = inspector_score
            if last_observed_at is not None:
                self._values["last_observed_at"] = last_observed_at
            if network_protocol is not None:
                self._values["network_protocol"] = network_protocol
            if port_range is not None:
                self._values["port_range"] = port_range
            if related_vulnerabilities is not None:
                self._values["related_vulnerabilities"] = related_vulnerabilities
            if resource_id is not None:
                self._values["resource_id"] = resource_id
            if resource_tags is not None:
                self._values["resource_tags"] = resource_tags
            if resource_type is not None:
                self._values["resource_type"] = resource_type
            if severity is not None:
                self._values["severity"] = severity
            if title is not None:
                self._values["title"] = title
            if updated_at is not None:
                self._values["updated_at"] = updated_at
            if vendor_severity is not None:
                self._values["vendor_severity"] = vendor_severity
            if vulnerability_id is not None:
                self._values["vulnerability_id"] = vulnerability_id
            if vulnerability_source is not None:
                self._values["vulnerability_source"] = vulnerability_source
            if vulnerable_packages is not None:
                self._values["vulnerable_packages"] = vulnerable_packages

        @builtins.property
        def aws_account_id(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.AwsAccountId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-awsaccountid
            '''
            result = self._values.get("aws_account_id")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def component_id(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.ComponentId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-componentid
            '''
            result = self._values.get("component_id")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def component_type(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.ComponentType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-componenttype
            '''
            result = self._values.get("component_type")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ec2_instance_image_id(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.Ec2InstanceImageId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ec2instanceimageid
            '''
            result = self._values.get("ec2_instance_image_id")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ec2_instance_subnet_id(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.Ec2InstanceSubnetId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ec2instancesubnetid
            '''
            result = self._values.get("ec2_instance_subnet_id")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ec2_instance_vpc_id(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.Ec2InstanceVpcId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ec2instancevpcid
            '''
            result = self._values.get("ec2_instance_vpc_id")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ecr_image_architecture(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.EcrImageArchitecture``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ecrimagearchitecture
            '''
            result = self._values.get("ecr_image_architecture")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ecr_image_hash(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.EcrImageHash``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ecrimagehash
            '''
            result = self._values.get("ecr_image_hash")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ecr_image_pushed_at(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.EcrImagePushedAt``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ecrimagepushedat
            '''
            result = self._values.get("ecr_image_pushed_at")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ecr_image_registry(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.EcrImageRegistry``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ecrimageregistry
            '''
            result = self._values.get("ecr_image_registry")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ecr_image_repository_name(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.EcrImageRepositoryName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ecrimagerepositoryname
            '''
            result = self._values.get("ecr_image_repository_name")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ecr_image_tags(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.EcrImageTags``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-ecrimagetags
            '''
            result = self._values.get("ecr_image_tags")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def finding_arn(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.FindingArn``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-findingarn
            '''
            result = self._values.get("finding_arn")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def finding_status(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.FindingStatus``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-findingstatus
            '''
            result = self._values.get("finding_status")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def finding_type(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.FindingType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-findingtype
            '''
            result = self._values.get("finding_type")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def first_observed_at(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.FirstObservedAt``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-firstobservedat
            '''
            result = self._values.get("first_observed_at")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def inspector_score(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.NumberFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.InspectorScore``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-inspectorscore
            '''
            result = self._values.get("inspector_score")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.NumberFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def last_observed_at(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.LastObservedAt``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-lastobservedat
            '''
            result = self._values.get("last_observed_at")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def network_protocol(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.NetworkProtocol``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-networkprotocol
            '''
            result = self._values.get("network_protocol")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def port_range(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.PortRangeFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.PortRange``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-portrange
            '''
            result = self._values.get("port_range")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.PortRangeFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def related_vulnerabilities(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.RelatedVulnerabilities``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-relatedvulnerabilities
            '''
            result = self._values.get("related_vulnerabilities")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def resource_id(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.ResourceId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-resourceid
            '''
            result = self._values.get("resource_id")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def resource_tags(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.MapFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.ResourceTags``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-resourcetags
            '''
            result = self._values.get("resource_tags")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.MapFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def resource_type(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.ResourceType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-resourcetype
            '''
            result = self._values.get("resource_type")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def severity(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.Severity``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-severity
            '''
            result = self._values.get("severity")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def title(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.Title``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-title
            '''
            result = self._values.get("title")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def updated_at(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.UpdatedAt``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-updatedat
            '''
            result = self._values.get("updated_at")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.DateFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def vendor_severity(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.VendorSeverity``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-vendorseverity
            '''
            result = self._values.get("vendor_severity")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def vulnerability_id(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.VulnerabilityId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-vulnerabilityid
            '''
            result = self._values.get("vulnerability_id")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def vulnerability_source(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.VulnerabilitySource``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-vulnerabilitysource
            '''
            result = self._values.get("vulnerability_source")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def vulnerable_packages(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.PackageFilterProperty", _IResolvable_da3f097b]]]]:
            '''``CfnFilter.FilterCriteriaProperty.VulnerablePackages``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-filtercriteria.html#cfn-inspectorv2-filter-filtercriteria-vulnerablepackages
            '''
            result = self._values.get("vulnerable_packages")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFilter.PackageFilterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FilterCriteriaProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilter.MapFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"comparison": "comparison", "key": "key", "value": "value"},
    )
    class MapFilterProperty:
        def __init__(
            self,
            *,
            comparison: builtins.str,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param comparison: ``CfnFilter.MapFilterProperty.Comparison``.
            :param key: ``CfnFilter.MapFilterProperty.Key``.
            :param value: ``CfnFilter.MapFilterProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-mapfilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_inspectorv2 as inspectorv2
                
                map_filter_property = inspectorv2.CfnFilter.MapFilterProperty(
                    comparison="comparison",
                
                    # the properties below are optional
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "comparison": comparison,
            }
            if key is not None:
                self._values["key"] = key
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def comparison(self) -> builtins.str:
            '''``CfnFilter.MapFilterProperty.Comparison``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-mapfilter.html#cfn-inspectorv2-filter-mapfilter-comparison
            '''
            result = self._values.get("comparison")
            assert result is not None, "Required property 'comparison' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''``CfnFilter.MapFilterProperty.Key``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-mapfilter.html#cfn-inspectorv2-filter-mapfilter-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''``CfnFilter.MapFilterProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-mapfilter.html#cfn-inspectorv2-filter-mapfilter-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MapFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilter.NumberFilterProperty",
        jsii_struct_bases=[],
        name_mapping={
            "lower_inclusive": "lowerInclusive",
            "upper_inclusive": "upperInclusive",
        },
    )
    class NumberFilterProperty:
        def __init__(
            self,
            *,
            lower_inclusive: typing.Optional[jsii.Number] = None,
            upper_inclusive: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''
            :param lower_inclusive: ``CfnFilter.NumberFilterProperty.LowerInclusive``.
            :param upper_inclusive: ``CfnFilter.NumberFilterProperty.UpperInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-numberfilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_inspectorv2 as inspectorv2
                
                number_filter_property = inspectorv2.CfnFilter.NumberFilterProperty(
                    lower_inclusive=123,
                    upper_inclusive=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if lower_inclusive is not None:
                self._values["lower_inclusive"] = lower_inclusive
            if upper_inclusive is not None:
                self._values["upper_inclusive"] = upper_inclusive

        @builtins.property
        def lower_inclusive(self) -> typing.Optional[jsii.Number]:
            '''``CfnFilter.NumberFilterProperty.LowerInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-numberfilter.html#cfn-inspectorv2-filter-numberfilter-lowerinclusive
            '''
            result = self._values.get("lower_inclusive")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def upper_inclusive(self) -> typing.Optional[jsii.Number]:
            '''``CfnFilter.NumberFilterProperty.UpperInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-numberfilter.html#cfn-inspectorv2-filter-numberfilter-upperinclusive
            '''
            result = self._values.get("upper_inclusive")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NumberFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilter.PackageFilterProperty",
        jsii_struct_bases=[],
        name_mapping={
            "architecture": "architecture",
            "epoch": "epoch",
            "name": "name",
            "release": "release",
            "source_layer_hash": "sourceLayerHash",
            "version": "version",
        },
    )
    class PackageFilterProperty:
        def __init__(
            self,
            *,
            architecture: typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]] = None,
            epoch: typing.Optional[typing.Union["CfnFilter.NumberFilterProperty", _IResolvable_da3f097b]] = None,
            name: typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]] = None,
            release: typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]] = None,
            source_layer_hash: typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]] = None,
            version: typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param architecture: ``CfnFilter.PackageFilterProperty.Architecture``.
            :param epoch: ``CfnFilter.PackageFilterProperty.Epoch``.
            :param name: ``CfnFilter.PackageFilterProperty.Name``.
            :param release: ``CfnFilter.PackageFilterProperty.Release``.
            :param source_layer_hash: ``CfnFilter.PackageFilterProperty.SourceLayerHash``.
            :param version: ``CfnFilter.PackageFilterProperty.Version``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-packagefilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_inspectorv2 as inspectorv2
                
                package_filter_property = inspectorv2.CfnFilter.PackageFilterProperty(
                    architecture=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    ),
                    epoch=inspectorv2.CfnFilter.NumberFilterProperty(
                        lower_inclusive=123,
                        upper_inclusive=123
                    ),
                    name=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    ),
                    release=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    ),
                    source_layer_hash=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    ),
                    version=inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if architecture is not None:
                self._values["architecture"] = architecture
            if epoch is not None:
                self._values["epoch"] = epoch
            if name is not None:
                self._values["name"] = name
            if release is not None:
                self._values["release"] = release
            if source_layer_hash is not None:
                self._values["source_layer_hash"] = source_layer_hash
            if version is not None:
                self._values["version"] = version

        @builtins.property
        def architecture(
            self,
        ) -> typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]:
            '''``CfnFilter.PackageFilterProperty.Architecture``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-packagefilter.html#cfn-inspectorv2-filter-packagefilter-architecture
            '''
            result = self._values.get("architecture")
            return typing.cast(typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def epoch(
            self,
        ) -> typing.Optional[typing.Union["CfnFilter.NumberFilterProperty", _IResolvable_da3f097b]]:
            '''``CfnFilter.PackageFilterProperty.Epoch``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-packagefilter.html#cfn-inspectorv2-filter-packagefilter-epoch
            '''
            result = self._values.get("epoch")
            return typing.cast(typing.Optional[typing.Union["CfnFilter.NumberFilterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def name(
            self,
        ) -> typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]:
            '''``CfnFilter.PackageFilterProperty.Name``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-packagefilter.html#cfn-inspectorv2-filter-packagefilter-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def release(
            self,
        ) -> typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]:
            '''``CfnFilter.PackageFilterProperty.Release``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-packagefilter.html#cfn-inspectorv2-filter-packagefilter-release
            '''
            result = self._values.get("release")
            return typing.cast(typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def source_layer_hash(
            self,
        ) -> typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]:
            '''``CfnFilter.PackageFilterProperty.SourceLayerHash``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-packagefilter.html#cfn-inspectorv2-filter-packagefilter-sourcelayerhash
            '''
            result = self._values.get("source_layer_hash")
            return typing.cast(typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def version(
            self,
        ) -> typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]]:
            '''``CfnFilter.PackageFilterProperty.Version``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-packagefilter.html#cfn-inspectorv2-filter-packagefilter-version
            '''
            result = self._values.get("version")
            return typing.cast(typing.Optional[typing.Union["CfnFilter.StringFilterProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PackageFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilter.PortRangeFilterProperty",
        jsii_struct_bases=[],
        name_mapping={
            "begin_inclusive": "beginInclusive",
            "end_inclusive": "endInclusive",
        },
    )
    class PortRangeFilterProperty:
        def __init__(
            self,
            *,
            begin_inclusive: typing.Optional[jsii.Number] = None,
            end_inclusive: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''
            :param begin_inclusive: ``CfnFilter.PortRangeFilterProperty.BeginInclusive``.
            :param end_inclusive: ``CfnFilter.PortRangeFilterProperty.EndInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-portrangefilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_inspectorv2 as inspectorv2
                
                port_range_filter_property = inspectorv2.CfnFilter.PortRangeFilterProperty(
                    begin_inclusive=123,
                    end_inclusive=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if begin_inclusive is not None:
                self._values["begin_inclusive"] = begin_inclusive
            if end_inclusive is not None:
                self._values["end_inclusive"] = end_inclusive

        @builtins.property
        def begin_inclusive(self) -> typing.Optional[jsii.Number]:
            '''``CfnFilter.PortRangeFilterProperty.BeginInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-portrangefilter.html#cfn-inspectorv2-filter-portrangefilter-begininclusive
            '''
            result = self._values.get("begin_inclusive")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def end_inclusive(self) -> typing.Optional[jsii.Number]:
            '''``CfnFilter.PortRangeFilterProperty.EndInclusive``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-portrangefilter.html#cfn-inspectorv2-filter-portrangefilter-endinclusive
            '''
            result = self._values.get("end_inclusive")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PortRangeFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilter.StringFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"comparison": "comparison", "value": "value"},
    )
    class StringFilterProperty:
        def __init__(self, *, comparison: builtins.str, value: builtins.str) -> None:
            '''
            :param comparison: ``CfnFilter.StringFilterProperty.Comparison``.
            :param value: ``CfnFilter.StringFilterProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-stringfilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_inspectorv2 as inspectorv2
                
                string_filter_property = inspectorv2.CfnFilter.StringFilterProperty(
                    comparison="comparison",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "comparison": comparison,
                "value": value,
            }

        @builtins.property
        def comparison(self) -> builtins.str:
            '''``CfnFilter.StringFilterProperty.Comparison``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-stringfilter.html#cfn-inspectorv2-filter-stringfilter-comparison
            '''
            result = self._values.get("comparison")
            assert result is not None, "Required property 'comparison' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''``CfnFilter.StringFilterProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-inspectorv2-filter-stringfilter.html#cfn-inspectorv2-filter-stringfilter-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StringFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_inspectorv2.CfnFilterProps",
    jsii_struct_bases=[],
    name_mapping={
        "filter_action": "filterAction",
        "filter_criteria": "filterCriteria",
        "name": "name",
        "description": "description",
    },
)
class CfnFilterProps:
    def __init__(
        self,
        *,
        filter_action: builtins.str,
        filter_criteria: typing.Union[CfnFilter.FilterCriteriaProperty, _IResolvable_da3f097b],
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnFilter``.

        :param filter_action: ``AWS::InspectorV2::Filter.FilterAction``.
        :param filter_criteria: ``AWS::InspectorV2::Filter.FilterCriteria``.
        :param name: ``AWS::InspectorV2::Filter.Name``.
        :param description: ``AWS::InspectorV2::Filter.Description``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_inspectorv2 as inspectorv2
            
            cfn_filter_props = inspectorv2.CfnFilterProps(
                filter_action="filterAction",
                filter_criteria=inspectorv2.CfnFilter.FilterCriteriaProperty(
                    aws_account_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    component_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    component_type=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ec2_instance_image_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ec2_instance_subnet_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ec2_instance_vpc_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_architecture=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_hash=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_pushed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                        end_inclusive=123,
                        start_inclusive=123
                    )],
                    ecr_image_registry=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_repository_name=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    ecr_image_tags=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    finding_arn=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    finding_status=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    finding_type=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    first_observed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                        end_inclusive=123,
                        start_inclusive=123
                    )],
                    inspector_score=[inspectorv2.CfnFilter.NumberFilterProperty(
                        lower_inclusive=123,
                        upper_inclusive=123
                    )],
                    last_observed_at=[inspectorv2.CfnFilter.DateFilterProperty(
                        end_inclusive=123,
                        start_inclusive=123
                    )],
                    network_protocol=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    port_range=[inspectorv2.CfnFilter.PortRangeFilterProperty(
                        begin_inclusive=123,
                        end_inclusive=123
                    )],
                    related_vulnerabilities=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    resource_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    resource_tags=[inspectorv2.CfnFilter.MapFilterProperty(
                        comparison="comparison",
            
                        # the properties below are optional
                        key="key",
                        value="value"
                    )],
                    resource_type=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    severity=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    title=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    updated_at=[inspectorv2.CfnFilter.DateFilterProperty(
                        end_inclusive=123,
                        start_inclusive=123
                    )],
                    vendor_severity=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    vulnerability_id=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    vulnerability_source=[inspectorv2.CfnFilter.StringFilterProperty(
                        comparison="comparison",
                        value="value"
                    )],
                    vulnerable_packages=[inspectorv2.CfnFilter.PackageFilterProperty(
                        architecture=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        ),
                        epoch=inspectorv2.CfnFilter.NumberFilterProperty(
                            lower_inclusive=123,
                            upper_inclusive=123
                        ),
                        name=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        ),
                        release=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        ),
                        source_layer_hash=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        ),
                        version=inspectorv2.CfnFilter.StringFilterProperty(
                            comparison="comparison",
                            value="value"
                        )
                    )]
                ),
                name="name",
            
                # the properties below are optional
                description="description"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "filter_action": filter_action,
            "filter_criteria": filter_criteria,
            "name": name,
        }
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def filter_action(self) -> builtins.str:
        '''``AWS::InspectorV2::Filter.FilterAction``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html#cfn-inspectorv2-filter-filteraction
        '''
        result = self._values.get("filter_action")
        assert result is not None, "Required property 'filter_action' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def filter_criteria(
        self,
    ) -> typing.Union[CfnFilter.FilterCriteriaProperty, _IResolvable_da3f097b]:
        '''``AWS::InspectorV2::Filter.FilterCriteria``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html#cfn-inspectorv2-filter-filtercriteria
        '''
        result = self._values.get("filter_criteria")
        assert result is not None, "Required property 'filter_criteria' is missing"
        return typing.cast(typing.Union[CfnFilter.FilterCriteriaProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def name(self) -> builtins.str:
        '''``AWS::InspectorV2::Filter.Name``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html#cfn-inspectorv2-filter-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''``AWS::InspectorV2::Filter.Description``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspectorv2-filter.html#cfn-inspectorv2-filter-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFilterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnFilter",
    "CfnFilterProps",
]

publication.publish()
