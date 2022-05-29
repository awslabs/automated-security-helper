'''
# AWS Batch Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_batch as batch
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-batch-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Batch](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Batch.html).

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
class CfnComputeEnvironment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_batch.CfnComputeEnvironment",
):
    '''A CloudFormation ``AWS::Batch::ComputeEnvironment``.

    :cloudformationResource: AWS::Batch::ComputeEnvironment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_batch as batch
        
        cfn_compute_environment = batch.CfnComputeEnvironment(self, "MyCfnComputeEnvironment",
            type="type",
        
            # the properties below are optional
            compute_environment_name="computeEnvironmentName",
            compute_resources=batch.CfnComputeEnvironment.ComputeResourcesProperty(
                maxv_cpus=123,
                subnets=["subnets"],
                type="type",
        
                # the properties below are optional
                allocation_strategy="allocationStrategy",
                bid_percentage=123,
                desiredv_cpus=123,
                ec2_configuration=[batch.CfnComputeEnvironment.Ec2ConfigurationObjectProperty(
                    image_type="imageType",
        
                    # the properties below are optional
                    image_id_override="imageIdOverride"
                )],
                ec2_key_pair="ec2KeyPair",
                image_id="imageId",
                instance_role="instanceRole",
                instance_types=["instanceTypes"],
                launch_template=batch.CfnComputeEnvironment.LaunchTemplateSpecificationProperty(
                    launch_template_id="launchTemplateId",
                    launch_template_name="launchTemplateName",
                    version="version"
                ),
                minv_cpus=123,
                placement_group="placementGroup",
                security_group_ids=["securityGroupIds"],
                spot_iam_fleet_role="spotIamFleetRole",
                tags={
                    "tags_key": "tags"
                }
            ),
            service_role="serviceRole",
            state="state",
            tags={
                "tags_key": "tags"
            },
            unmanagedv_cpus=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        type: builtins.str,
        compute_environment_name: typing.Optional[builtins.str] = None,
        compute_resources: typing.Optional[typing.Union["CfnComputeEnvironment.ComputeResourcesProperty", _IResolvable_da3f097b]] = None,
        service_role: typing.Optional[builtins.str] = None,
        state: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        unmanagedv_cpus: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Create a new ``AWS::Batch::ComputeEnvironment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param type: ``AWS::Batch::ComputeEnvironment.Type``.
        :param compute_environment_name: ``AWS::Batch::ComputeEnvironment.ComputeEnvironmentName``.
        :param compute_resources: ``AWS::Batch::ComputeEnvironment.ComputeResources``.
        :param service_role: ``AWS::Batch::ComputeEnvironment.ServiceRole``.
        :param state: ``AWS::Batch::ComputeEnvironment.State``.
        :param tags: ``AWS::Batch::ComputeEnvironment.Tags``.
        :param unmanagedv_cpus: ``AWS::Batch::ComputeEnvironment.UnmanagedvCpus``.
        '''
        props = CfnComputeEnvironmentProps(
            type=type,
            compute_environment_name=compute_environment_name,
            compute_resources=compute_resources,
            service_role=service_role,
            state=state,
            tags=tags,
            unmanagedv_cpus=unmanagedv_cpus,
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
    @jsii.member(jsii_name="attrComputeEnvironmentArn")
    def attr_compute_environment_arn(self) -> builtins.str:
        '''
        :cloudformationAttribute: ComputeEnvironmentArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrComputeEnvironmentArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''``AWS::Batch::ComputeEnvironment.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''``AWS::Batch::ComputeEnvironment.Type``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="computeEnvironmentName")
    def compute_environment_name(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::ComputeEnvironment.ComputeEnvironmentName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-computeenvironmentname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "computeEnvironmentName"))

    @compute_environment_name.setter
    def compute_environment_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "computeEnvironmentName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="computeResources")
    def compute_resources(
        self,
    ) -> typing.Optional[typing.Union["CfnComputeEnvironment.ComputeResourcesProperty", _IResolvable_da3f097b]]:
        '''``AWS::Batch::ComputeEnvironment.ComputeResources``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-computeresources
        '''
        return typing.cast(typing.Optional[typing.Union["CfnComputeEnvironment.ComputeResourcesProperty", _IResolvable_da3f097b]], jsii.get(self, "computeResources"))

    @compute_resources.setter
    def compute_resources(
        self,
        value: typing.Optional[typing.Union["CfnComputeEnvironment.ComputeResourcesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "computeResources", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceRole")
    def service_role(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::ComputeEnvironment.ServiceRole``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-servicerole
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "serviceRole"))

    @service_role.setter
    def service_role(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "serviceRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="state")
    def state(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::ComputeEnvironment.State``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-state
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "state"))

    @state.setter
    def state(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "state", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="unmanagedvCpus")
    def unmanagedv_cpus(self) -> typing.Optional[jsii.Number]:
        '''``AWS::Batch::ComputeEnvironment.UnmanagedvCpus``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-unmanagedvcpus
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "unmanagedvCpus"))

    @unmanagedv_cpus.setter
    def unmanagedv_cpus(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "unmanagedvCpus", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnComputeEnvironment.ComputeResourcesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "maxv_cpus": "maxvCpus",
            "subnets": "subnets",
            "type": "type",
            "allocation_strategy": "allocationStrategy",
            "bid_percentage": "bidPercentage",
            "desiredv_cpus": "desiredvCpus",
            "ec2_configuration": "ec2Configuration",
            "ec2_key_pair": "ec2KeyPair",
            "image_id": "imageId",
            "instance_role": "instanceRole",
            "instance_types": "instanceTypes",
            "launch_template": "launchTemplate",
            "minv_cpus": "minvCpus",
            "placement_group": "placementGroup",
            "security_group_ids": "securityGroupIds",
            "spot_iam_fleet_role": "spotIamFleetRole",
            "tags": "tags",
        },
    )
    class ComputeResourcesProperty:
        def __init__(
            self,
            *,
            maxv_cpus: jsii.Number,
            subnets: typing.Sequence[builtins.str],
            type: builtins.str,
            allocation_strategy: typing.Optional[builtins.str] = None,
            bid_percentage: typing.Optional[jsii.Number] = None,
            desiredv_cpus: typing.Optional[jsii.Number] = None,
            ec2_configuration: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnComputeEnvironment.Ec2ConfigurationObjectProperty", _IResolvable_da3f097b]]]] = None,
            ec2_key_pair: typing.Optional[builtins.str] = None,
            image_id: typing.Optional[builtins.str] = None,
            instance_role: typing.Optional[builtins.str] = None,
            instance_types: typing.Optional[typing.Sequence[builtins.str]] = None,
            launch_template: typing.Optional[typing.Union["CfnComputeEnvironment.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]] = None,
            minv_cpus: typing.Optional[jsii.Number] = None,
            placement_group: typing.Optional[builtins.str] = None,
            security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            spot_iam_fleet_role: typing.Optional[builtins.str] = None,
            tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        ) -> None:
            '''
            :param maxv_cpus: ``CfnComputeEnvironment.ComputeResourcesProperty.MaxvCpus``.
            :param subnets: ``CfnComputeEnvironment.ComputeResourcesProperty.Subnets``.
            :param type: ``CfnComputeEnvironment.ComputeResourcesProperty.Type``.
            :param allocation_strategy: ``CfnComputeEnvironment.ComputeResourcesProperty.AllocationStrategy``.
            :param bid_percentage: ``CfnComputeEnvironment.ComputeResourcesProperty.BidPercentage``.
            :param desiredv_cpus: ``CfnComputeEnvironment.ComputeResourcesProperty.DesiredvCpus``.
            :param ec2_configuration: ``CfnComputeEnvironment.ComputeResourcesProperty.Ec2Configuration``.
            :param ec2_key_pair: ``CfnComputeEnvironment.ComputeResourcesProperty.Ec2KeyPair``.
            :param image_id: ``CfnComputeEnvironment.ComputeResourcesProperty.ImageId``.
            :param instance_role: ``CfnComputeEnvironment.ComputeResourcesProperty.InstanceRole``.
            :param instance_types: ``CfnComputeEnvironment.ComputeResourcesProperty.InstanceTypes``.
            :param launch_template: ``CfnComputeEnvironment.ComputeResourcesProperty.LaunchTemplate``.
            :param minv_cpus: ``CfnComputeEnvironment.ComputeResourcesProperty.MinvCpus``.
            :param placement_group: ``CfnComputeEnvironment.ComputeResourcesProperty.PlacementGroup``.
            :param security_group_ids: ``CfnComputeEnvironment.ComputeResourcesProperty.SecurityGroupIds``.
            :param spot_iam_fleet_role: ``CfnComputeEnvironment.ComputeResourcesProperty.SpotIamFleetRole``.
            :param tags: ``CfnComputeEnvironment.ComputeResourcesProperty.Tags``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                compute_resources_property = batch.CfnComputeEnvironment.ComputeResourcesProperty(
                    maxv_cpus=123,
                    subnets=["subnets"],
                    type="type",
                
                    # the properties below are optional
                    allocation_strategy="allocationStrategy",
                    bid_percentage=123,
                    desiredv_cpus=123,
                    ec2_configuration=[batch.CfnComputeEnvironment.Ec2ConfigurationObjectProperty(
                        image_type="imageType",
                
                        # the properties below are optional
                        image_id_override="imageIdOverride"
                    )],
                    ec2_key_pair="ec2KeyPair",
                    image_id="imageId",
                    instance_role="instanceRole",
                    instance_types=["instanceTypes"],
                    launch_template=batch.CfnComputeEnvironment.LaunchTemplateSpecificationProperty(
                        launch_template_id="launchTemplateId",
                        launch_template_name="launchTemplateName",
                        version="version"
                    ),
                    minv_cpus=123,
                    placement_group="placementGroup",
                    security_group_ids=["securityGroupIds"],
                    spot_iam_fleet_role="spotIamFleetRole",
                    tags={
                        "tags_key": "tags"
                    }
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "maxv_cpus": maxv_cpus,
                "subnets": subnets,
                "type": type,
            }
            if allocation_strategy is not None:
                self._values["allocation_strategy"] = allocation_strategy
            if bid_percentage is not None:
                self._values["bid_percentage"] = bid_percentage
            if desiredv_cpus is not None:
                self._values["desiredv_cpus"] = desiredv_cpus
            if ec2_configuration is not None:
                self._values["ec2_configuration"] = ec2_configuration
            if ec2_key_pair is not None:
                self._values["ec2_key_pair"] = ec2_key_pair
            if image_id is not None:
                self._values["image_id"] = image_id
            if instance_role is not None:
                self._values["instance_role"] = instance_role
            if instance_types is not None:
                self._values["instance_types"] = instance_types
            if launch_template is not None:
                self._values["launch_template"] = launch_template
            if minv_cpus is not None:
                self._values["minv_cpus"] = minv_cpus
            if placement_group is not None:
                self._values["placement_group"] = placement_group
            if security_group_ids is not None:
                self._values["security_group_ids"] = security_group_ids
            if spot_iam_fleet_role is not None:
                self._values["spot_iam_fleet_role"] = spot_iam_fleet_role
            if tags is not None:
                self._values["tags"] = tags

        @builtins.property
        def maxv_cpus(self) -> jsii.Number:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.MaxvCpus``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-maxvcpus
            '''
            result = self._values.get("maxv_cpus")
            assert result is not None, "Required property 'maxv_cpus' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def subnets(self) -> typing.List[builtins.str]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.Subnets``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-subnets
            '''
            result = self._values.get("subnets")
            assert result is not None, "Required property 'subnets' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def type(self) -> builtins.str:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.Type``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def allocation_strategy(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.AllocationStrategy``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-allocationstrategy
            '''
            result = self._values.get("allocation_strategy")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def bid_percentage(self) -> typing.Optional[jsii.Number]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.BidPercentage``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-bidpercentage
            '''
            result = self._values.get("bid_percentage")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def desiredv_cpus(self) -> typing.Optional[jsii.Number]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.DesiredvCpus``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-desiredvcpus
            '''
            result = self._values.get("desiredv_cpus")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def ec2_configuration(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComputeEnvironment.Ec2ConfigurationObjectProperty", _IResolvable_da3f097b]]]]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.Ec2Configuration``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-ec2configuration
            '''
            result = self._values.get("ec2_configuration")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnComputeEnvironment.Ec2ConfigurationObjectProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ec2_key_pair(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.Ec2KeyPair``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-ec2keypair
            '''
            result = self._values.get("ec2_key_pair")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def image_id(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.ImageId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-imageid
            '''
            result = self._values.get("image_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def instance_role(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.InstanceRole``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-instancerole
            '''
            result = self._values.get("instance_role")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def instance_types(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.InstanceTypes``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-instancetypes
            '''
            result = self._values.get("instance_types")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def launch_template(
            self,
        ) -> typing.Optional[typing.Union["CfnComputeEnvironment.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.LaunchTemplate``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-launchtemplate
            '''
            result = self._values.get("launch_template")
            return typing.cast(typing.Optional[typing.Union["CfnComputeEnvironment.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def minv_cpus(self) -> typing.Optional[jsii.Number]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.MinvCpus``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-minvcpus
            '''
            result = self._values.get("minv_cpus")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def placement_group(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.PlacementGroup``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-placementgroup
            '''
            result = self._values.get("placement_group")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.SecurityGroupIds``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-securitygroupids
            '''
            result = self._values.get("security_group_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def spot_iam_fleet_role(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.SpotIamFleetRole``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-spotiamfleetrole
            '''
            result = self._values.get("spot_iam_fleet_role")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
            '''``CfnComputeEnvironment.ComputeResourcesProperty.Tags``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-computeresources.html#cfn-batch-computeenvironment-computeresources-tags
            '''
            result = self._values.get("tags")
            return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComputeResourcesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnComputeEnvironment.Ec2ConfigurationObjectProperty",
        jsii_struct_bases=[],
        name_mapping={
            "image_type": "imageType",
            "image_id_override": "imageIdOverride",
        },
    )
    class Ec2ConfigurationObjectProperty:
        def __init__(
            self,
            *,
            image_type: builtins.str,
            image_id_override: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param image_type: ``CfnComputeEnvironment.Ec2ConfigurationObjectProperty.ImageType``.
            :param image_id_override: ``CfnComputeEnvironment.Ec2ConfigurationObjectProperty.ImageIdOverride``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-ec2configurationobject.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                ec2_configuration_object_property = batch.CfnComputeEnvironment.Ec2ConfigurationObjectProperty(
                    image_type="imageType",
                
                    # the properties below are optional
                    image_id_override="imageIdOverride"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "image_type": image_type,
            }
            if image_id_override is not None:
                self._values["image_id_override"] = image_id_override

        @builtins.property
        def image_type(self) -> builtins.str:
            '''``CfnComputeEnvironment.Ec2ConfigurationObjectProperty.ImageType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-ec2configurationobject.html#cfn-batch-computeenvironment-ec2configurationobject-imagetype
            '''
            result = self._values.get("image_type")
            assert result is not None, "Required property 'image_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def image_id_override(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.Ec2ConfigurationObjectProperty.ImageIdOverride``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-ec2configurationobject.html#cfn-batch-computeenvironment-ec2configurationobject-imageidoverride
            '''
            result = self._values.get("image_id_override")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "Ec2ConfigurationObjectProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnComputeEnvironment.LaunchTemplateSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "launch_template_id": "launchTemplateId",
            "launch_template_name": "launchTemplateName",
            "version": "version",
        },
    )
    class LaunchTemplateSpecificationProperty:
        def __init__(
            self,
            *,
            launch_template_id: typing.Optional[builtins.str] = None,
            launch_template_name: typing.Optional[builtins.str] = None,
            version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param launch_template_id: ``CfnComputeEnvironment.LaunchTemplateSpecificationProperty.LaunchTemplateId``.
            :param launch_template_name: ``CfnComputeEnvironment.LaunchTemplateSpecificationProperty.LaunchTemplateName``.
            :param version: ``CfnComputeEnvironment.LaunchTemplateSpecificationProperty.Version``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-launchtemplatespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                launch_template_specification_property = batch.CfnComputeEnvironment.LaunchTemplateSpecificationProperty(
                    launch_template_id="launchTemplateId",
                    launch_template_name="launchTemplateName",
                    version="version"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if launch_template_id is not None:
                self._values["launch_template_id"] = launch_template_id
            if launch_template_name is not None:
                self._values["launch_template_name"] = launch_template_name
            if version is not None:
                self._values["version"] = version

        @builtins.property
        def launch_template_id(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.LaunchTemplateSpecificationProperty.LaunchTemplateId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-launchtemplatespecification.html#cfn-batch-computeenvironment-launchtemplatespecification-launchtemplateid
            '''
            result = self._values.get("launch_template_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def launch_template_name(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.LaunchTemplateSpecificationProperty.LaunchTemplateName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-launchtemplatespecification.html#cfn-batch-computeenvironment-launchtemplatespecification-launchtemplatename
            '''
            result = self._values.get("launch_template_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def version(self) -> typing.Optional[builtins.str]:
            '''``CfnComputeEnvironment.LaunchTemplateSpecificationProperty.Version``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-computeenvironment-launchtemplatespecification.html#cfn-batch-computeenvironment-launchtemplatespecification-version
            '''
            result = self._values.get("version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LaunchTemplateSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_batch.CfnComputeEnvironmentProps",
    jsii_struct_bases=[],
    name_mapping={
        "type": "type",
        "compute_environment_name": "computeEnvironmentName",
        "compute_resources": "computeResources",
        "service_role": "serviceRole",
        "state": "state",
        "tags": "tags",
        "unmanagedv_cpus": "unmanagedvCpus",
    },
)
class CfnComputeEnvironmentProps:
    def __init__(
        self,
        *,
        type: builtins.str,
        compute_environment_name: typing.Optional[builtins.str] = None,
        compute_resources: typing.Optional[typing.Union[CfnComputeEnvironment.ComputeResourcesProperty, _IResolvable_da3f097b]] = None,
        service_role: typing.Optional[builtins.str] = None,
        state: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        unmanagedv_cpus: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for defining a ``CfnComputeEnvironment``.

        :param type: ``AWS::Batch::ComputeEnvironment.Type``.
        :param compute_environment_name: ``AWS::Batch::ComputeEnvironment.ComputeEnvironmentName``.
        :param compute_resources: ``AWS::Batch::ComputeEnvironment.ComputeResources``.
        :param service_role: ``AWS::Batch::ComputeEnvironment.ServiceRole``.
        :param state: ``AWS::Batch::ComputeEnvironment.State``.
        :param tags: ``AWS::Batch::ComputeEnvironment.Tags``.
        :param unmanagedv_cpus: ``AWS::Batch::ComputeEnvironment.UnmanagedvCpus``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_batch as batch
            
            cfn_compute_environment_props = batch.CfnComputeEnvironmentProps(
                type="type",
            
                # the properties below are optional
                compute_environment_name="computeEnvironmentName",
                compute_resources=batch.CfnComputeEnvironment.ComputeResourcesProperty(
                    maxv_cpus=123,
                    subnets=["subnets"],
                    type="type",
            
                    # the properties below are optional
                    allocation_strategy="allocationStrategy",
                    bid_percentage=123,
                    desiredv_cpus=123,
                    ec2_configuration=[batch.CfnComputeEnvironment.Ec2ConfigurationObjectProperty(
                        image_type="imageType",
            
                        # the properties below are optional
                        image_id_override="imageIdOverride"
                    )],
                    ec2_key_pair="ec2KeyPair",
                    image_id="imageId",
                    instance_role="instanceRole",
                    instance_types=["instanceTypes"],
                    launch_template=batch.CfnComputeEnvironment.LaunchTemplateSpecificationProperty(
                        launch_template_id="launchTemplateId",
                        launch_template_name="launchTemplateName",
                        version="version"
                    ),
                    minv_cpus=123,
                    placement_group="placementGroup",
                    security_group_ids=["securityGroupIds"],
                    spot_iam_fleet_role="spotIamFleetRole",
                    tags={
                        "tags_key": "tags"
                    }
                ),
                service_role="serviceRole",
                state="state",
                tags={
                    "tags_key": "tags"
                },
                unmanagedv_cpus=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "type": type,
        }
        if compute_environment_name is not None:
            self._values["compute_environment_name"] = compute_environment_name
        if compute_resources is not None:
            self._values["compute_resources"] = compute_resources
        if service_role is not None:
            self._values["service_role"] = service_role
        if state is not None:
            self._values["state"] = state
        if tags is not None:
            self._values["tags"] = tags
        if unmanagedv_cpus is not None:
            self._values["unmanagedv_cpus"] = unmanagedv_cpus

    @builtins.property
    def type(self) -> builtins.str:
        '''``AWS::Batch::ComputeEnvironment.Type``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def compute_environment_name(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::ComputeEnvironment.ComputeEnvironmentName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-computeenvironmentname
        '''
        result = self._values.get("compute_environment_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def compute_resources(
        self,
    ) -> typing.Optional[typing.Union[CfnComputeEnvironment.ComputeResourcesProperty, _IResolvable_da3f097b]]:
        '''``AWS::Batch::ComputeEnvironment.ComputeResources``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-computeresources
        '''
        result = self._values.get("compute_resources")
        return typing.cast(typing.Optional[typing.Union[CfnComputeEnvironment.ComputeResourcesProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def service_role(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::ComputeEnvironment.ServiceRole``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-servicerole
        '''
        result = self._values.get("service_role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def state(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::ComputeEnvironment.State``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-state
        '''
        result = self._values.get("state")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''``AWS::Batch::ComputeEnvironment.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def unmanagedv_cpus(self) -> typing.Optional[jsii.Number]:
        '''``AWS::Batch::ComputeEnvironment.UnmanagedvCpus``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-computeenvironment.html#cfn-batch-computeenvironment-unmanagedvcpus
        '''
        result = self._values.get("unmanagedv_cpus")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnComputeEnvironmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnJobDefinition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition",
):
    '''A CloudFormation ``AWS::Batch::JobDefinition``.

    :cloudformationResource: AWS::Batch::JobDefinition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_batch as batch
        
        # options: Any
        # parameters: Any
        # tags: Any
        
        cfn_job_definition = batch.CfnJobDefinition(self, "MyCfnJobDefinition",
            type="type",
        
            # the properties below are optional
            container_properties=batch.CfnJobDefinition.ContainerPropertiesProperty(
                image="image",
        
                # the properties below are optional
                command=["command"],
                environment=[batch.CfnJobDefinition.EnvironmentProperty(
                    name="name",
                    value="value"
                )],
                execution_role_arn="executionRoleArn",
                fargate_platform_configuration=batch.CfnJobDefinition.FargatePlatformConfigurationProperty(
                    platform_version="platformVersion"
                ),
                instance_type="instanceType",
                job_role_arn="jobRoleArn",
                linux_parameters=batch.CfnJobDefinition.LinuxParametersProperty(
                    devices=[batch.CfnJobDefinition.DeviceProperty(
                        container_path="containerPath",
                        host_path="hostPath",
                        permissions=["permissions"]
                    )],
                    init_process_enabled=False,
                    max_swap=123,
                    shared_memory_size=123,
                    swappiness=123,
                    tmpfs=[batch.CfnJobDefinition.TmpfsProperty(
                        container_path="containerPath",
                        size=123,
        
                        # the properties below are optional
                        mount_options=["mountOptions"]
                    )]
                ),
                log_configuration=batch.CfnJobDefinition.LogConfigurationProperty(
                    log_driver="logDriver",
        
                    # the properties below are optional
                    options=options,
                    secret_options=[batch.CfnJobDefinition.SecretProperty(
                        name="name",
                        value_from="valueFrom"
                    )]
                ),
                memory=123,
                mount_points=[batch.CfnJobDefinition.MountPointsProperty(
                    container_path="containerPath",
                    read_only=False,
                    source_volume="sourceVolume"
                )],
                network_configuration=batch.CfnJobDefinition.NetworkConfigurationProperty(
                    assign_public_ip="assignPublicIp"
                ),
                privileged=False,
                readonly_root_filesystem=False,
                resource_requirements=[batch.CfnJobDefinition.ResourceRequirementProperty(
                    type="type",
                    value="value"
                )],
                secrets=[batch.CfnJobDefinition.SecretProperty(
                    name="name",
                    value_from="valueFrom"
                )],
                ulimits=[batch.CfnJobDefinition.UlimitProperty(
                    hard_limit=123,
                    name="name",
                    soft_limit=123
                )],
                user="user",
                vcpus=123,
                volumes=[batch.CfnJobDefinition.VolumesProperty(
                    efs_volume_configuration=batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                        file_system_id="fileSystemId",
        
                        # the properties below are optional
                        authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                            access_point_id="accessPointId",
                            iam="iam"
                        ),
                        root_directory="rootDirectory",
                        transit_encryption="transitEncryption",
                        transit_encryption_port=123
                    ),
                    host=batch.CfnJobDefinition.VolumesHostProperty(
                        source_path="sourcePath"
                    ),
                    name="name"
                )]
            ),
            job_definition_name="jobDefinitionName",
            node_properties=batch.CfnJobDefinition.NodePropertiesProperty(
                main_node=123,
                node_range_properties=[batch.CfnJobDefinition.NodeRangePropertyProperty(
                    target_nodes="targetNodes",
        
                    # the properties below are optional
                    container=batch.CfnJobDefinition.ContainerPropertiesProperty(
                        image="image",
        
                        # the properties below are optional
                        command=["command"],
                        environment=[batch.CfnJobDefinition.EnvironmentProperty(
                            name="name",
                            value="value"
                        )],
                        execution_role_arn="executionRoleArn",
                        fargate_platform_configuration=batch.CfnJobDefinition.FargatePlatformConfigurationProperty(
                            platform_version="platformVersion"
                        ),
                        instance_type="instanceType",
                        job_role_arn="jobRoleArn",
                        linux_parameters=batch.CfnJobDefinition.LinuxParametersProperty(
                            devices=[batch.CfnJobDefinition.DeviceProperty(
                                container_path="containerPath",
                                host_path="hostPath",
                                permissions=["permissions"]
                            )],
                            init_process_enabled=False,
                            max_swap=123,
                            shared_memory_size=123,
                            swappiness=123,
                            tmpfs=[batch.CfnJobDefinition.TmpfsProperty(
                                container_path="containerPath",
                                size=123,
        
                                # the properties below are optional
                                mount_options=["mountOptions"]
                            )]
                        ),
                        log_configuration=batch.CfnJobDefinition.LogConfigurationProperty(
                            log_driver="logDriver",
        
                            # the properties below are optional
                            options=options,
                            secret_options=[batch.CfnJobDefinition.SecretProperty(
                                name="name",
                                value_from="valueFrom"
                            )]
                        ),
                        memory=123,
                        mount_points=[batch.CfnJobDefinition.MountPointsProperty(
                            container_path="containerPath",
                            read_only=False,
                            source_volume="sourceVolume"
                        )],
                        network_configuration=batch.CfnJobDefinition.NetworkConfigurationProperty(
                            assign_public_ip="assignPublicIp"
                        ),
                        privileged=False,
                        readonly_root_filesystem=False,
                        resource_requirements=[batch.CfnJobDefinition.ResourceRequirementProperty(
                            type="type",
                            value="value"
                        )],
                        secrets=[batch.CfnJobDefinition.SecretProperty(
                            name="name",
                            value_from="valueFrom"
                        )],
                        ulimits=[batch.CfnJobDefinition.UlimitProperty(
                            hard_limit=123,
                            name="name",
                            soft_limit=123
                        )],
                        user="user",
                        vcpus=123,
                        volumes=[batch.CfnJobDefinition.VolumesProperty(
                            efs_volume_configuration=batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                                file_system_id="fileSystemId",
        
                                # the properties below are optional
                                authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                                    access_point_id="accessPointId",
                                    iam="iam"
                                ),
                                root_directory="rootDirectory",
                                transit_encryption="transitEncryption",
                                transit_encryption_port=123
                            ),
                            host=batch.CfnJobDefinition.VolumesHostProperty(
                                source_path="sourcePath"
                            ),
                            name="name"
                        )]
                    )
                )],
                num_nodes=123
            ),
            parameters=parameters,
            platform_capabilities=["platformCapabilities"],
            propagate_tags=False,
            retry_strategy=batch.CfnJobDefinition.RetryStrategyProperty(
                attempts=123,
                evaluate_on_exit=[batch.CfnJobDefinition.EvaluateOnExitProperty(
                    action="action",
        
                    # the properties below are optional
                    on_exit_code="onExitCode",
                    on_reason="onReason",
                    on_status_reason="onStatusReason"
                )]
            ),
            scheduling_priority=123,
            tags=tags,
            timeout=batch.CfnJobDefinition.TimeoutProperty(
                attempt_duration_seconds=123
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        type: builtins.str,
        container_properties: typing.Optional[typing.Union["CfnJobDefinition.ContainerPropertiesProperty", _IResolvable_da3f097b]] = None,
        job_definition_name: typing.Optional[builtins.str] = None,
        node_properties: typing.Optional[typing.Union["CfnJobDefinition.NodePropertiesProperty", _IResolvable_da3f097b]] = None,
        parameters: typing.Any = None,
        platform_capabilities: typing.Optional[typing.Sequence[builtins.str]] = None,
        propagate_tags: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        retry_strategy: typing.Optional[typing.Union["CfnJobDefinition.RetryStrategyProperty", _IResolvable_da3f097b]] = None,
        scheduling_priority: typing.Optional[jsii.Number] = None,
        tags: typing.Any = None,
        timeout: typing.Optional[typing.Union["CfnJobDefinition.TimeoutProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Batch::JobDefinition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param type: ``AWS::Batch::JobDefinition.Type``.
        :param container_properties: ``AWS::Batch::JobDefinition.ContainerProperties``.
        :param job_definition_name: ``AWS::Batch::JobDefinition.JobDefinitionName``.
        :param node_properties: ``AWS::Batch::JobDefinition.NodeProperties``.
        :param parameters: ``AWS::Batch::JobDefinition.Parameters``.
        :param platform_capabilities: ``AWS::Batch::JobDefinition.PlatformCapabilities``.
        :param propagate_tags: ``AWS::Batch::JobDefinition.PropagateTags``.
        :param retry_strategy: ``AWS::Batch::JobDefinition.RetryStrategy``.
        :param scheduling_priority: ``AWS::Batch::JobDefinition.SchedulingPriority``.
        :param tags: ``AWS::Batch::JobDefinition.Tags``.
        :param timeout: ``AWS::Batch::JobDefinition.Timeout``.
        '''
        props = CfnJobDefinitionProps(
            type=type,
            container_properties=container_properties,
            job_definition_name=job_definition_name,
            node_properties=node_properties,
            parameters=parameters,
            platform_capabilities=platform_capabilities,
            propagate_tags=propagate_tags,
            retry_strategy=retry_strategy,
            scheduling_priority=scheduling_priority,
            tags=tags,
            timeout=timeout,
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
        '''``AWS::Batch::JobDefinition.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parameters")
    def parameters(self) -> typing.Any:
        '''``AWS::Batch::JobDefinition.Parameters``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-parameters
        '''
        return typing.cast(typing.Any, jsii.get(self, "parameters"))

    @parameters.setter
    def parameters(self, value: typing.Any) -> None:
        jsii.set(self, "parameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''``AWS::Batch::JobDefinition.Type``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="containerProperties")
    def container_properties(
        self,
    ) -> typing.Optional[typing.Union["CfnJobDefinition.ContainerPropertiesProperty", _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.ContainerProperties``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-containerproperties
        '''
        return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.ContainerPropertiesProperty", _IResolvable_da3f097b]], jsii.get(self, "containerProperties"))

    @container_properties.setter
    def container_properties(
        self,
        value: typing.Optional[typing.Union["CfnJobDefinition.ContainerPropertiesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "containerProperties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="jobDefinitionName")
    def job_definition_name(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::JobDefinition.JobDefinitionName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-jobdefinitionname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "jobDefinitionName"))

    @job_definition_name.setter
    def job_definition_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "jobDefinitionName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodeProperties")
    def node_properties(
        self,
    ) -> typing.Optional[typing.Union["CfnJobDefinition.NodePropertiesProperty", _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.NodeProperties``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-nodeproperties
        '''
        return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.NodePropertiesProperty", _IResolvable_da3f097b]], jsii.get(self, "nodeProperties"))

    @node_properties.setter
    def node_properties(
        self,
        value: typing.Optional[typing.Union["CfnJobDefinition.NodePropertiesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "nodeProperties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="platformCapabilities")
    def platform_capabilities(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::Batch::JobDefinition.PlatformCapabilities``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-platformcapabilities
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "platformCapabilities"))

    @platform_capabilities.setter
    def platform_capabilities(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "platformCapabilities", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="propagateTags")
    def propagate_tags(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.PropagateTags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-propagatetags
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "propagateTags"))

    @propagate_tags.setter
    def propagate_tags(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "propagateTags", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="retryStrategy")
    def retry_strategy(
        self,
    ) -> typing.Optional[typing.Union["CfnJobDefinition.RetryStrategyProperty", _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.RetryStrategy``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-retrystrategy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.RetryStrategyProperty", _IResolvable_da3f097b]], jsii.get(self, "retryStrategy"))

    @retry_strategy.setter
    def retry_strategy(
        self,
        value: typing.Optional[typing.Union["CfnJobDefinition.RetryStrategyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "retryStrategy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schedulingPriority")
    def scheduling_priority(self) -> typing.Optional[jsii.Number]:
        '''``AWS::Batch::JobDefinition.SchedulingPriority``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-schedulingpriority
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "schedulingPriority"))

    @scheduling_priority.setter
    def scheduling_priority(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "schedulingPriority", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="timeout")
    def timeout(
        self,
    ) -> typing.Optional[typing.Union["CfnJobDefinition.TimeoutProperty", _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.Timeout``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-timeout
        '''
        return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.TimeoutProperty", _IResolvable_da3f097b]], jsii.get(self, "timeout"))

    @timeout.setter
    def timeout(
        self,
        value: typing.Optional[typing.Union["CfnJobDefinition.TimeoutProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "timeout", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.AuthorizationConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"access_point_id": "accessPointId", "iam": "iam"},
    )
    class AuthorizationConfigProperty:
        def __init__(
            self,
            *,
            access_point_id: typing.Optional[builtins.str] = None,
            iam: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param access_point_id: ``CfnJobDefinition.AuthorizationConfigProperty.AccessPointId``.
            :param iam: ``CfnJobDefinition.AuthorizationConfigProperty.Iam``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-authorizationconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                authorization_config_property = batch.CfnJobDefinition.AuthorizationConfigProperty(
                    access_point_id="accessPointId",
                    iam="iam"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if access_point_id is not None:
                self._values["access_point_id"] = access_point_id
            if iam is not None:
                self._values["iam"] = iam

        @builtins.property
        def access_point_id(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.AuthorizationConfigProperty.AccessPointId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-authorizationconfig.html#cfn-batch-jobdefinition-authorizationconfig-accesspointid
            '''
            result = self._values.get("access_point_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def iam(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.AuthorizationConfigProperty.Iam``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-authorizationconfig.html#cfn-batch-jobdefinition-authorizationconfig-iam
            '''
            result = self._values.get("iam")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuthorizationConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.ContainerPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "image": "image",
            "command": "command",
            "environment": "environment",
            "execution_role_arn": "executionRoleArn",
            "fargate_platform_configuration": "fargatePlatformConfiguration",
            "instance_type": "instanceType",
            "job_role_arn": "jobRoleArn",
            "linux_parameters": "linuxParameters",
            "log_configuration": "logConfiguration",
            "memory": "memory",
            "mount_points": "mountPoints",
            "network_configuration": "networkConfiguration",
            "privileged": "privileged",
            "readonly_root_filesystem": "readonlyRootFilesystem",
            "resource_requirements": "resourceRequirements",
            "secrets": "secrets",
            "ulimits": "ulimits",
            "user": "user",
            "vcpus": "vcpus",
            "volumes": "volumes",
        },
    )
    class ContainerPropertiesProperty:
        def __init__(
            self,
            *,
            image: builtins.str,
            command: typing.Optional[typing.Sequence[builtins.str]] = None,
            environment: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.EnvironmentProperty", _IResolvable_da3f097b]]]] = None,
            execution_role_arn: typing.Optional[builtins.str] = None,
            fargate_platform_configuration: typing.Optional[typing.Union["CfnJobDefinition.FargatePlatformConfigurationProperty", _IResolvable_da3f097b]] = None,
            instance_type: typing.Optional[builtins.str] = None,
            job_role_arn: typing.Optional[builtins.str] = None,
            linux_parameters: typing.Optional[typing.Union["CfnJobDefinition.LinuxParametersProperty", _IResolvable_da3f097b]] = None,
            log_configuration: typing.Optional[typing.Union["CfnJobDefinition.LogConfigurationProperty", _IResolvable_da3f097b]] = None,
            memory: typing.Optional[jsii.Number] = None,
            mount_points: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.MountPointsProperty", _IResolvable_da3f097b]]]] = None,
            network_configuration: typing.Optional[typing.Union["CfnJobDefinition.NetworkConfigurationProperty", _IResolvable_da3f097b]] = None,
            privileged: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            readonly_root_filesystem: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            resource_requirements: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.ResourceRequirementProperty", _IResolvable_da3f097b]]]] = None,
            secrets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.SecretProperty", _IResolvable_da3f097b]]]] = None,
            ulimits: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.UlimitProperty", _IResolvable_da3f097b]]]] = None,
            user: typing.Optional[builtins.str] = None,
            vcpus: typing.Optional[jsii.Number] = None,
            volumes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.VolumesProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''
            :param image: ``CfnJobDefinition.ContainerPropertiesProperty.Image``.
            :param command: ``CfnJobDefinition.ContainerPropertiesProperty.Command``.
            :param environment: ``CfnJobDefinition.ContainerPropertiesProperty.Environment``.
            :param execution_role_arn: ``CfnJobDefinition.ContainerPropertiesProperty.ExecutionRoleArn``.
            :param fargate_platform_configuration: ``CfnJobDefinition.ContainerPropertiesProperty.FargatePlatformConfiguration``.
            :param instance_type: ``CfnJobDefinition.ContainerPropertiesProperty.InstanceType``.
            :param job_role_arn: ``CfnJobDefinition.ContainerPropertiesProperty.JobRoleArn``.
            :param linux_parameters: ``CfnJobDefinition.ContainerPropertiesProperty.LinuxParameters``.
            :param log_configuration: ``CfnJobDefinition.ContainerPropertiesProperty.LogConfiguration``.
            :param memory: ``CfnJobDefinition.ContainerPropertiesProperty.Memory``.
            :param mount_points: ``CfnJobDefinition.ContainerPropertiesProperty.MountPoints``.
            :param network_configuration: ``CfnJobDefinition.ContainerPropertiesProperty.NetworkConfiguration``.
            :param privileged: ``CfnJobDefinition.ContainerPropertiesProperty.Privileged``.
            :param readonly_root_filesystem: ``CfnJobDefinition.ContainerPropertiesProperty.ReadonlyRootFilesystem``.
            :param resource_requirements: ``CfnJobDefinition.ContainerPropertiesProperty.ResourceRequirements``.
            :param secrets: ``CfnJobDefinition.ContainerPropertiesProperty.Secrets``.
            :param ulimits: ``CfnJobDefinition.ContainerPropertiesProperty.Ulimits``.
            :param user: ``CfnJobDefinition.ContainerPropertiesProperty.User``.
            :param vcpus: ``CfnJobDefinition.ContainerPropertiesProperty.Vcpus``.
            :param volumes: ``CfnJobDefinition.ContainerPropertiesProperty.Volumes``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                # options: Any
                
                container_properties_property = batch.CfnJobDefinition.ContainerPropertiesProperty(
                    image="image",
                
                    # the properties below are optional
                    command=["command"],
                    environment=[batch.CfnJobDefinition.EnvironmentProperty(
                        name="name",
                        value="value"
                    )],
                    execution_role_arn="executionRoleArn",
                    fargate_platform_configuration=batch.CfnJobDefinition.FargatePlatformConfigurationProperty(
                        platform_version="platformVersion"
                    ),
                    instance_type="instanceType",
                    job_role_arn="jobRoleArn",
                    linux_parameters=batch.CfnJobDefinition.LinuxParametersProperty(
                        devices=[batch.CfnJobDefinition.DeviceProperty(
                            container_path="containerPath",
                            host_path="hostPath",
                            permissions=["permissions"]
                        )],
                        init_process_enabled=False,
                        max_swap=123,
                        shared_memory_size=123,
                        swappiness=123,
                        tmpfs=[batch.CfnJobDefinition.TmpfsProperty(
                            container_path="containerPath",
                            size=123,
                
                            # the properties below are optional
                            mount_options=["mountOptions"]
                        )]
                    ),
                    log_configuration=batch.CfnJobDefinition.LogConfigurationProperty(
                        log_driver="logDriver",
                
                        # the properties below are optional
                        options=options,
                        secret_options=[batch.CfnJobDefinition.SecretProperty(
                            name="name",
                            value_from="valueFrom"
                        )]
                    ),
                    memory=123,
                    mount_points=[batch.CfnJobDefinition.MountPointsProperty(
                        container_path="containerPath",
                        read_only=False,
                        source_volume="sourceVolume"
                    )],
                    network_configuration=batch.CfnJobDefinition.NetworkConfigurationProperty(
                        assign_public_ip="assignPublicIp"
                    ),
                    privileged=False,
                    readonly_root_filesystem=False,
                    resource_requirements=[batch.CfnJobDefinition.ResourceRequirementProperty(
                        type="type",
                        value="value"
                    )],
                    secrets=[batch.CfnJobDefinition.SecretProperty(
                        name="name",
                        value_from="valueFrom"
                    )],
                    ulimits=[batch.CfnJobDefinition.UlimitProperty(
                        hard_limit=123,
                        name="name",
                        soft_limit=123
                    )],
                    user="user",
                    vcpus=123,
                    volumes=[batch.CfnJobDefinition.VolumesProperty(
                        efs_volume_configuration=batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                            file_system_id="fileSystemId",
                
                            # the properties below are optional
                            authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                                access_point_id="accessPointId",
                                iam="iam"
                            ),
                            root_directory="rootDirectory",
                            transit_encryption="transitEncryption",
                            transit_encryption_port=123
                        ),
                        host=batch.CfnJobDefinition.VolumesHostProperty(
                            source_path="sourcePath"
                        ),
                        name="name"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "image": image,
            }
            if command is not None:
                self._values["command"] = command
            if environment is not None:
                self._values["environment"] = environment
            if execution_role_arn is not None:
                self._values["execution_role_arn"] = execution_role_arn
            if fargate_platform_configuration is not None:
                self._values["fargate_platform_configuration"] = fargate_platform_configuration
            if instance_type is not None:
                self._values["instance_type"] = instance_type
            if job_role_arn is not None:
                self._values["job_role_arn"] = job_role_arn
            if linux_parameters is not None:
                self._values["linux_parameters"] = linux_parameters
            if log_configuration is not None:
                self._values["log_configuration"] = log_configuration
            if memory is not None:
                self._values["memory"] = memory
            if mount_points is not None:
                self._values["mount_points"] = mount_points
            if network_configuration is not None:
                self._values["network_configuration"] = network_configuration
            if privileged is not None:
                self._values["privileged"] = privileged
            if readonly_root_filesystem is not None:
                self._values["readonly_root_filesystem"] = readonly_root_filesystem
            if resource_requirements is not None:
                self._values["resource_requirements"] = resource_requirements
            if secrets is not None:
                self._values["secrets"] = secrets
            if ulimits is not None:
                self._values["ulimits"] = ulimits
            if user is not None:
                self._values["user"] = user
            if vcpus is not None:
                self._values["vcpus"] = vcpus
            if volumes is not None:
                self._values["volumes"] = volumes

        @builtins.property
        def image(self) -> builtins.str:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Image``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-image
            '''
            result = self._values.get("image")
            assert result is not None, "Required property 'image' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def command(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Command``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-command
            '''
            result = self._values.get("command")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def environment(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.EnvironmentProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Environment``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-environment
            '''
            result = self._values.get("environment")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.EnvironmentProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def execution_role_arn(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.ExecutionRoleArn``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-executionrolearn
            '''
            result = self._values.get("execution_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def fargate_platform_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnJobDefinition.FargatePlatformConfigurationProperty", _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.FargatePlatformConfiguration``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-fargateplatformconfiguration
            '''
            result = self._values.get("fargate_platform_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.FargatePlatformConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def instance_type(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.InstanceType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-instancetype
            '''
            result = self._values.get("instance_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def job_role_arn(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.JobRoleArn``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-jobrolearn
            '''
            result = self._values.get("job_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def linux_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnJobDefinition.LinuxParametersProperty", _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.LinuxParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-linuxparameters
            '''
            result = self._values.get("linux_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.LinuxParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def log_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnJobDefinition.LogConfigurationProperty", _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.LogConfiguration``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-logconfiguration
            '''
            result = self._values.get("log_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.LogConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def memory(self) -> typing.Optional[jsii.Number]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Memory``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-memory
            '''
            result = self._values.get("memory")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def mount_points(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.MountPointsProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.MountPoints``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-mountpoints
            '''
            result = self._values.get("mount_points")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.MountPointsProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def network_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnJobDefinition.NetworkConfigurationProperty", _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.NetworkConfiguration``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-networkconfiguration
            '''
            result = self._values.get("network_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.NetworkConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def privileged(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Privileged``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-privileged
            '''
            result = self._values.get("privileged")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def readonly_root_filesystem(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.ReadonlyRootFilesystem``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-readonlyrootfilesystem
            '''
            result = self._values.get("readonly_root_filesystem")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def resource_requirements(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.ResourceRequirementProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.ResourceRequirements``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-resourcerequirements
            '''
            result = self._values.get("resource_requirements")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.ResourceRequirementProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def secrets(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.SecretProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Secrets``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-secrets
            '''
            result = self._values.get("secrets")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.SecretProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ulimits(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.UlimitProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Ulimits``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-ulimits
            '''
            result = self._values.get("ulimits")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.UlimitProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def user(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.User``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-user
            '''
            result = self._values.get("user")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def vcpus(self) -> typing.Optional[jsii.Number]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Vcpus``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-vcpus
            '''
            result = self._values.get("vcpus")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volumes(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.VolumesProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.ContainerPropertiesProperty.Volumes``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties.html#cfn-batch-jobdefinition-containerproperties-volumes
            '''
            result = self._values.get("volumes")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.VolumesProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ContainerPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.DeviceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "container_path": "containerPath",
            "host_path": "hostPath",
            "permissions": "permissions",
        },
    )
    class DeviceProperty:
        def __init__(
            self,
            *,
            container_path: typing.Optional[builtins.str] = None,
            host_path: typing.Optional[builtins.str] = None,
            permissions: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''
            :param container_path: ``CfnJobDefinition.DeviceProperty.ContainerPath``.
            :param host_path: ``CfnJobDefinition.DeviceProperty.HostPath``.
            :param permissions: ``CfnJobDefinition.DeviceProperty.Permissions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-device.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                device_property = batch.CfnJobDefinition.DeviceProperty(
                    container_path="containerPath",
                    host_path="hostPath",
                    permissions=["permissions"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if container_path is not None:
                self._values["container_path"] = container_path
            if host_path is not None:
                self._values["host_path"] = host_path
            if permissions is not None:
                self._values["permissions"] = permissions

        @builtins.property
        def container_path(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.DeviceProperty.ContainerPath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-device.html#cfn-batch-jobdefinition-device-containerpath
            '''
            result = self._values.get("container_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def host_path(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.DeviceProperty.HostPath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-device.html#cfn-batch-jobdefinition-device-hostpath
            '''
            result = self._values.get("host_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def permissions(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnJobDefinition.DeviceProperty.Permissions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-device.html#cfn-batch-jobdefinition-device-permissions
            '''
            result = self._values.get("permissions")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeviceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.EfsVolumeConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "file_system_id": "fileSystemId",
            "authorization_config": "authorizationConfig",
            "root_directory": "rootDirectory",
            "transit_encryption": "transitEncryption",
            "transit_encryption_port": "transitEncryptionPort",
        },
    )
    class EfsVolumeConfigurationProperty:
        def __init__(
            self,
            *,
            file_system_id: builtins.str,
            authorization_config: typing.Optional[typing.Union["CfnJobDefinition.AuthorizationConfigProperty", _IResolvable_da3f097b]] = None,
            root_directory: typing.Optional[builtins.str] = None,
            transit_encryption: typing.Optional[builtins.str] = None,
            transit_encryption_port: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''
            :param file_system_id: ``CfnJobDefinition.EfsVolumeConfigurationProperty.FileSystemId``.
            :param authorization_config: ``CfnJobDefinition.EfsVolumeConfigurationProperty.AuthorizationConfig``.
            :param root_directory: ``CfnJobDefinition.EfsVolumeConfigurationProperty.RootDirectory``.
            :param transit_encryption: ``CfnJobDefinition.EfsVolumeConfigurationProperty.TransitEncryption``.
            :param transit_encryption_port: ``CfnJobDefinition.EfsVolumeConfigurationProperty.TransitEncryptionPort``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-efsvolumeconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                efs_volume_configuration_property = batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                    file_system_id="fileSystemId",
                
                    # the properties below are optional
                    authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                        access_point_id="accessPointId",
                        iam="iam"
                    ),
                    root_directory="rootDirectory",
                    transit_encryption="transitEncryption",
                    transit_encryption_port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "file_system_id": file_system_id,
            }
            if authorization_config is not None:
                self._values["authorization_config"] = authorization_config
            if root_directory is not None:
                self._values["root_directory"] = root_directory
            if transit_encryption is not None:
                self._values["transit_encryption"] = transit_encryption
            if transit_encryption_port is not None:
                self._values["transit_encryption_port"] = transit_encryption_port

        @builtins.property
        def file_system_id(self) -> builtins.str:
            '''``CfnJobDefinition.EfsVolumeConfigurationProperty.FileSystemId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-efsvolumeconfiguration.html#cfn-batch-jobdefinition-efsvolumeconfiguration-filesystemid
            '''
            result = self._values.get("file_system_id")
            assert result is not None, "Required property 'file_system_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def authorization_config(
            self,
        ) -> typing.Optional[typing.Union["CfnJobDefinition.AuthorizationConfigProperty", _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.EfsVolumeConfigurationProperty.AuthorizationConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-efsvolumeconfiguration.html#cfn-batch-jobdefinition-efsvolumeconfiguration-authorizationconfig
            '''
            result = self._values.get("authorization_config")
            return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.AuthorizationConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def root_directory(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.EfsVolumeConfigurationProperty.RootDirectory``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-efsvolumeconfiguration.html#cfn-batch-jobdefinition-efsvolumeconfiguration-rootdirectory
            '''
            result = self._values.get("root_directory")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def transit_encryption(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.EfsVolumeConfigurationProperty.TransitEncryption``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-efsvolumeconfiguration.html#cfn-batch-jobdefinition-efsvolumeconfiguration-transitencryption
            '''
            result = self._values.get("transit_encryption")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def transit_encryption_port(self) -> typing.Optional[jsii.Number]:
            '''``CfnJobDefinition.EfsVolumeConfigurationProperty.TransitEncryptionPort``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-efsvolumeconfiguration.html#cfn-batch-jobdefinition-efsvolumeconfiguration-transitencryptionport
            '''
            result = self._values.get("transit_encryption_port")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EfsVolumeConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.EnvironmentProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class EnvironmentProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param name: ``CfnJobDefinition.EnvironmentProperty.Name``.
            :param value: ``CfnJobDefinition.EnvironmentProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-environment.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                environment_property = batch.CfnJobDefinition.EnvironmentProperty(
                    name="name",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.EnvironmentProperty.Name``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-environment.html#cfn-batch-jobdefinition-environment-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.EnvironmentProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-environment.html#cfn-batch-jobdefinition-environment-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EnvironmentProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.EvaluateOnExitProperty",
        jsii_struct_bases=[],
        name_mapping={
            "action": "action",
            "on_exit_code": "onExitCode",
            "on_reason": "onReason",
            "on_status_reason": "onStatusReason",
        },
    )
    class EvaluateOnExitProperty:
        def __init__(
            self,
            *,
            action: builtins.str,
            on_exit_code: typing.Optional[builtins.str] = None,
            on_reason: typing.Optional[builtins.str] = None,
            on_status_reason: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param action: ``CfnJobDefinition.EvaluateOnExitProperty.Action``.
            :param on_exit_code: ``CfnJobDefinition.EvaluateOnExitProperty.OnExitCode``.
            :param on_reason: ``CfnJobDefinition.EvaluateOnExitProperty.OnReason``.
            :param on_status_reason: ``CfnJobDefinition.EvaluateOnExitProperty.OnStatusReason``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-evaluateonexit.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                evaluate_on_exit_property = batch.CfnJobDefinition.EvaluateOnExitProperty(
                    action="action",
                
                    # the properties below are optional
                    on_exit_code="onExitCode",
                    on_reason="onReason",
                    on_status_reason="onStatusReason"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "action": action,
            }
            if on_exit_code is not None:
                self._values["on_exit_code"] = on_exit_code
            if on_reason is not None:
                self._values["on_reason"] = on_reason
            if on_status_reason is not None:
                self._values["on_status_reason"] = on_status_reason

        @builtins.property
        def action(self) -> builtins.str:
            '''``CfnJobDefinition.EvaluateOnExitProperty.Action``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-evaluateonexit.html#cfn-batch-jobdefinition-evaluateonexit-action
            '''
            result = self._values.get("action")
            assert result is not None, "Required property 'action' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def on_exit_code(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.EvaluateOnExitProperty.OnExitCode``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-evaluateonexit.html#cfn-batch-jobdefinition-evaluateonexit-onexitcode
            '''
            result = self._values.get("on_exit_code")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def on_reason(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.EvaluateOnExitProperty.OnReason``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-evaluateonexit.html#cfn-batch-jobdefinition-evaluateonexit-onreason
            '''
            result = self._values.get("on_reason")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def on_status_reason(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.EvaluateOnExitProperty.OnStatusReason``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-evaluateonexit.html#cfn-batch-jobdefinition-evaluateonexit-onstatusreason
            '''
            result = self._values.get("on_status_reason")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EvaluateOnExitProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.FargatePlatformConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"platform_version": "platformVersion"},
    )
    class FargatePlatformConfigurationProperty:
        def __init__(
            self,
            *,
            platform_version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param platform_version: ``CfnJobDefinition.FargatePlatformConfigurationProperty.PlatformVersion``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-fargateplatformconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                fargate_platform_configuration_property = batch.CfnJobDefinition.FargatePlatformConfigurationProperty(
                    platform_version="platformVersion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if platform_version is not None:
                self._values["platform_version"] = platform_version

        @builtins.property
        def platform_version(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.FargatePlatformConfigurationProperty.PlatformVersion``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-fargateplatformconfiguration.html#cfn-batch-jobdefinition-containerproperties-fargateplatformconfiguration-platformversion
            '''
            result = self._values.get("platform_version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FargatePlatformConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.LinuxParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "devices": "devices",
            "init_process_enabled": "initProcessEnabled",
            "max_swap": "maxSwap",
            "shared_memory_size": "sharedMemorySize",
            "swappiness": "swappiness",
            "tmpfs": "tmpfs",
        },
    )
    class LinuxParametersProperty:
        def __init__(
            self,
            *,
            devices: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.DeviceProperty", _IResolvable_da3f097b]]]] = None,
            init_process_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            max_swap: typing.Optional[jsii.Number] = None,
            shared_memory_size: typing.Optional[jsii.Number] = None,
            swappiness: typing.Optional[jsii.Number] = None,
            tmpfs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.TmpfsProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''
            :param devices: ``CfnJobDefinition.LinuxParametersProperty.Devices``.
            :param init_process_enabled: ``CfnJobDefinition.LinuxParametersProperty.InitProcessEnabled``.
            :param max_swap: ``CfnJobDefinition.LinuxParametersProperty.MaxSwap``.
            :param shared_memory_size: ``CfnJobDefinition.LinuxParametersProperty.SharedMemorySize``.
            :param swappiness: ``CfnJobDefinition.LinuxParametersProperty.Swappiness``.
            :param tmpfs: ``CfnJobDefinition.LinuxParametersProperty.Tmpfs``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-linuxparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                linux_parameters_property = batch.CfnJobDefinition.LinuxParametersProperty(
                    devices=[batch.CfnJobDefinition.DeviceProperty(
                        container_path="containerPath",
                        host_path="hostPath",
                        permissions=["permissions"]
                    )],
                    init_process_enabled=False,
                    max_swap=123,
                    shared_memory_size=123,
                    swappiness=123,
                    tmpfs=[batch.CfnJobDefinition.TmpfsProperty(
                        container_path="containerPath",
                        size=123,
                
                        # the properties below are optional
                        mount_options=["mountOptions"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if devices is not None:
                self._values["devices"] = devices
            if init_process_enabled is not None:
                self._values["init_process_enabled"] = init_process_enabled
            if max_swap is not None:
                self._values["max_swap"] = max_swap
            if shared_memory_size is not None:
                self._values["shared_memory_size"] = shared_memory_size
            if swappiness is not None:
                self._values["swappiness"] = swappiness
            if tmpfs is not None:
                self._values["tmpfs"] = tmpfs

        @builtins.property
        def devices(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.DeviceProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.LinuxParametersProperty.Devices``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-linuxparameters.html#cfn-batch-jobdefinition-containerproperties-linuxparameters-devices
            '''
            result = self._values.get("devices")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.DeviceProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def init_process_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.LinuxParametersProperty.InitProcessEnabled``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-linuxparameters.html#cfn-batch-jobdefinition-containerproperties-linuxparameters-initprocessenabled
            '''
            result = self._values.get("init_process_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def max_swap(self) -> typing.Optional[jsii.Number]:
            '''``CfnJobDefinition.LinuxParametersProperty.MaxSwap``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-linuxparameters.html#cfn-batch-jobdefinition-containerproperties-linuxparameters-maxswap
            '''
            result = self._values.get("max_swap")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def shared_memory_size(self) -> typing.Optional[jsii.Number]:
            '''``CfnJobDefinition.LinuxParametersProperty.SharedMemorySize``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-linuxparameters.html#cfn-batch-jobdefinition-containerproperties-linuxparameters-sharedmemorysize
            '''
            result = self._values.get("shared_memory_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def swappiness(self) -> typing.Optional[jsii.Number]:
            '''``CfnJobDefinition.LinuxParametersProperty.Swappiness``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-linuxparameters.html#cfn-batch-jobdefinition-containerproperties-linuxparameters-swappiness
            '''
            result = self._values.get("swappiness")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def tmpfs(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.TmpfsProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.LinuxParametersProperty.Tmpfs``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-linuxparameters.html#cfn-batch-jobdefinition-containerproperties-linuxparameters-tmpfs
            '''
            result = self._values.get("tmpfs")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.TmpfsProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LinuxParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.LogConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "log_driver": "logDriver",
            "options": "options",
            "secret_options": "secretOptions",
        },
    )
    class LogConfigurationProperty:
        def __init__(
            self,
            *,
            log_driver: builtins.str,
            options: typing.Any = None,
            secret_options: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.SecretProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''
            :param log_driver: ``CfnJobDefinition.LogConfigurationProperty.LogDriver``.
            :param options: ``CfnJobDefinition.LogConfigurationProperty.Options``.
            :param secret_options: ``CfnJobDefinition.LogConfigurationProperty.SecretOptions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-logconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                # options: Any
                
                log_configuration_property = batch.CfnJobDefinition.LogConfigurationProperty(
                    log_driver="logDriver",
                
                    # the properties below are optional
                    options=options,
                    secret_options=[batch.CfnJobDefinition.SecretProperty(
                        name="name",
                        value_from="valueFrom"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "log_driver": log_driver,
            }
            if options is not None:
                self._values["options"] = options
            if secret_options is not None:
                self._values["secret_options"] = secret_options

        @builtins.property
        def log_driver(self) -> builtins.str:
            '''``CfnJobDefinition.LogConfigurationProperty.LogDriver``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-logconfiguration.html#cfn-batch-jobdefinition-containerproperties-logconfiguration-logdriver
            '''
            result = self._values.get("log_driver")
            assert result is not None, "Required property 'log_driver' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def options(self) -> typing.Any:
            '''``CfnJobDefinition.LogConfigurationProperty.Options``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-logconfiguration.html#cfn-batch-jobdefinition-containerproperties-logconfiguration-options
            '''
            result = self._values.get("options")
            return typing.cast(typing.Any, result)

        @builtins.property
        def secret_options(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.SecretProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.LogConfigurationProperty.SecretOptions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-logconfiguration.html#cfn-batch-jobdefinition-containerproperties-logconfiguration-secretoptions
            '''
            result = self._values.get("secret_options")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.SecretProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.MountPointsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "container_path": "containerPath",
            "read_only": "readOnly",
            "source_volume": "sourceVolume",
        },
    )
    class MountPointsProperty:
        def __init__(
            self,
            *,
            container_path: typing.Optional[builtins.str] = None,
            read_only: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            source_volume: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param container_path: ``CfnJobDefinition.MountPointsProperty.ContainerPath``.
            :param read_only: ``CfnJobDefinition.MountPointsProperty.ReadOnly``.
            :param source_volume: ``CfnJobDefinition.MountPointsProperty.SourceVolume``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-mountpoints.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                mount_points_property = batch.CfnJobDefinition.MountPointsProperty(
                    container_path="containerPath",
                    read_only=False,
                    source_volume="sourceVolume"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if container_path is not None:
                self._values["container_path"] = container_path
            if read_only is not None:
                self._values["read_only"] = read_only
            if source_volume is not None:
                self._values["source_volume"] = source_volume

        @builtins.property
        def container_path(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.MountPointsProperty.ContainerPath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-mountpoints.html#cfn-batch-jobdefinition-mountpoints-containerpath
            '''
            result = self._values.get("container_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def read_only(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.MountPointsProperty.ReadOnly``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-mountpoints.html#cfn-batch-jobdefinition-mountpoints-readonly
            '''
            result = self._values.get("read_only")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def source_volume(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.MountPointsProperty.SourceVolume``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-mountpoints.html#cfn-batch-jobdefinition-mountpoints-sourcevolume
            '''
            result = self._values.get("source_volume")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MountPointsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.NetworkConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"assign_public_ip": "assignPublicIp"},
    )
    class NetworkConfigurationProperty:
        def __init__(
            self,
            *,
            assign_public_ip: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param assign_public_ip: ``CfnJobDefinition.NetworkConfigurationProperty.AssignPublicIp``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-networkconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                network_configuration_property = batch.CfnJobDefinition.NetworkConfigurationProperty(
                    assign_public_ip="assignPublicIp"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if assign_public_ip is not None:
                self._values["assign_public_ip"] = assign_public_ip

        @builtins.property
        def assign_public_ip(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.NetworkConfigurationProperty.AssignPublicIp``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-containerproperties-networkconfiguration.html#cfn-batch-jobdefinition-containerproperties-networkconfiguration-assignpublicip
            '''
            result = self._values.get("assign_public_ip")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NetworkConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.NodePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "main_node": "mainNode",
            "node_range_properties": "nodeRangeProperties",
            "num_nodes": "numNodes",
        },
    )
    class NodePropertiesProperty:
        def __init__(
            self,
            *,
            main_node: jsii.Number,
            node_range_properties: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.NodeRangePropertyProperty", _IResolvable_da3f097b]]],
            num_nodes: jsii.Number,
        ) -> None:
            '''
            :param main_node: ``CfnJobDefinition.NodePropertiesProperty.MainNode``.
            :param node_range_properties: ``CfnJobDefinition.NodePropertiesProperty.NodeRangeProperties``.
            :param num_nodes: ``CfnJobDefinition.NodePropertiesProperty.NumNodes``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-nodeproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                # options: Any
                
                node_properties_property = batch.CfnJobDefinition.NodePropertiesProperty(
                    main_node=123,
                    node_range_properties=[batch.CfnJobDefinition.NodeRangePropertyProperty(
                        target_nodes="targetNodes",
                
                        # the properties below are optional
                        container=batch.CfnJobDefinition.ContainerPropertiesProperty(
                            image="image",
                
                            # the properties below are optional
                            command=["command"],
                            environment=[batch.CfnJobDefinition.EnvironmentProperty(
                                name="name",
                                value="value"
                            )],
                            execution_role_arn="executionRoleArn",
                            fargate_platform_configuration=batch.CfnJobDefinition.FargatePlatformConfigurationProperty(
                                platform_version="platformVersion"
                            ),
                            instance_type="instanceType",
                            job_role_arn="jobRoleArn",
                            linux_parameters=batch.CfnJobDefinition.LinuxParametersProperty(
                                devices=[batch.CfnJobDefinition.DeviceProperty(
                                    container_path="containerPath",
                                    host_path="hostPath",
                                    permissions=["permissions"]
                                )],
                                init_process_enabled=False,
                                max_swap=123,
                                shared_memory_size=123,
                                swappiness=123,
                                tmpfs=[batch.CfnJobDefinition.TmpfsProperty(
                                    container_path="containerPath",
                                    size=123,
                
                                    # the properties below are optional
                                    mount_options=["mountOptions"]
                                )]
                            ),
                            log_configuration=batch.CfnJobDefinition.LogConfigurationProperty(
                                log_driver="logDriver",
                
                                # the properties below are optional
                                options=options,
                                secret_options=[batch.CfnJobDefinition.SecretProperty(
                                    name="name",
                                    value_from="valueFrom"
                                )]
                            ),
                            memory=123,
                            mount_points=[batch.CfnJobDefinition.MountPointsProperty(
                                container_path="containerPath",
                                read_only=False,
                                source_volume="sourceVolume"
                            )],
                            network_configuration=batch.CfnJobDefinition.NetworkConfigurationProperty(
                                assign_public_ip="assignPublicIp"
                            ),
                            privileged=False,
                            readonly_root_filesystem=False,
                            resource_requirements=[batch.CfnJobDefinition.ResourceRequirementProperty(
                                type="type",
                                value="value"
                            )],
                            secrets=[batch.CfnJobDefinition.SecretProperty(
                                name="name",
                                value_from="valueFrom"
                            )],
                            ulimits=[batch.CfnJobDefinition.UlimitProperty(
                                hard_limit=123,
                                name="name",
                                soft_limit=123
                            )],
                            user="user",
                            vcpus=123,
                            volumes=[batch.CfnJobDefinition.VolumesProperty(
                                efs_volume_configuration=batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                                    file_system_id="fileSystemId",
                
                                    # the properties below are optional
                                    authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                                        access_point_id="accessPointId",
                                        iam="iam"
                                    ),
                                    root_directory="rootDirectory",
                                    transit_encryption="transitEncryption",
                                    transit_encryption_port=123
                                ),
                                host=batch.CfnJobDefinition.VolumesHostProperty(
                                    source_path="sourcePath"
                                ),
                                name="name"
                            )]
                        )
                    )],
                    num_nodes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "main_node": main_node,
                "node_range_properties": node_range_properties,
                "num_nodes": num_nodes,
            }

        @builtins.property
        def main_node(self) -> jsii.Number:
            '''``CfnJobDefinition.NodePropertiesProperty.MainNode``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-nodeproperties.html#cfn-batch-jobdefinition-nodeproperties-mainnode
            '''
            result = self._values.get("main_node")
            assert result is not None, "Required property 'main_node' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def node_range_properties(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.NodeRangePropertyProperty", _IResolvable_da3f097b]]]:
            '''``CfnJobDefinition.NodePropertiesProperty.NodeRangeProperties``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-nodeproperties.html#cfn-batch-jobdefinition-nodeproperties-noderangeproperties
            '''
            result = self._values.get("node_range_properties")
            assert result is not None, "Required property 'node_range_properties' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.NodeRangePropertyProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def num_nodes(self) -> jsii.Number:
            '''``CfnJobDefinition.NodePropertiesProperty.NumNodes``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-nodeproperties.html#cfn-batch-jobdefinition-nodeproperties-numnodes
            '''
            result = self._values.get("num_nodes")
            assert result is not None, "Required property 'num_nodes' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NodePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.NodeRangePropertyProperty",
        jsii_struct_bases=[],
        name_mapping={"target_nodes": "targetNodes", "container": "container"},
    )
    class NodeRangePropertyProperty:
        def __init__(
            self,
            *,
            target_nodes: builtins.str,
            container: typing.Optional[typing.Union["CfnJobDefinition.ContainerPropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param target_nodes: ``CfnJobDefinition.NodeRangePropertyProperty.TargetNodes``.
            :param container: ``CfnJobDefinition.NodeRangePropertyProperty.Container``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-noderangeproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                # options: Any
                
                node_range_property_property = batch.CfnJobDefinition.NodeRangePropertyProperty(
                    target_nodes="targetNodes",
                
                    # the properties below are optional
                    container=batch.CfnJobDefinition.ContainerPropertiesProperty(
                        image="image",
                
                        # the properties below are optional
                        command=["command"],
                        environment=[batch.CfnJobDefinition.EnvironmentProperty(
                            name="name",
                            value="value"
                        )],
                        execution_role_arn="executionRoleArn",
                        fargate_platform_configuration=batch.CfnJobDefinition.FargatePlatformConfigurationProperty(
                            platform_version="platformVersion"
                        ),
                        instance_type="instanceType",
                        job_role_arn="jobRoleArn",
                        linux_parameters=batch.CfnJobDefinition.LinuxParametersProperty(
                            devices=[batch.CfnJobDefinition.DeviceProperty(
                                container_path="containerPath",
                                host_path="hostPath",
                                permissions=["permissions"]
                            )],
                            init_process_enabled=False,
                            max_swap=123,
                            shared_memory_size=123,
                            swappiness=123,
                            tmpfs=[batch.CfnJobDefinition.TmpfsProperty(
                                container_path="containerPath",
                                size=123,
                
                                # the properties below are optional
                                mount_options=["mountOptions"]
                            )]
                        ),
                        log_configuration=batch.CfnJobDefinition.LogConfigurationProperty(
                            log_driver="logDriver",
                
                            # the properties below are optional
                            options=options,
                            secret_options=[batch.CfnJobDefinition.SecretProperty(
                                name="name",
                                value_from="valueFrom"
                            )]
                        ),
                        memory=123,
                        mount_points=[batch.CfnJobDefinition.MountPointsProperty(
                            container_path="containerPath",
                            read_only=False,
                            source_volume="sourceVolume"
                        )],
                        network_configuration=batch.CfnJobDefinition.NetworkConfigurationProperty(
                            assign_public_ip="assignPublicIp"
                        ),
                        privileged=False,
                        readonly_root_filesystem=False,
                        resource_requirements=[batch.CfnJobDefinition.ResourceRequirementProperty(
                            type="type",
                            value="value"
                        )],
                        secrets=[batch.CfnJobDefinition.SecretProperty(
                            name="name",
                            value_from="valueFrom"
                        )],
                        ulimits=[batch.CfnJobDefinition.UlimitProperty(
                            hard_limit=123,
                            name="name",
                            soft_limit=123
                        )],
                        user="user",
                        vcpus=123,
                        volumes=[batch.CfnJobDefinition.VolumesProperty(
                            efs_volume_configuration=batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                                file_system_id="fileSystemId",
                
                                # the properties below are optional
                                authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                                    access_point_id="accessPointId",
                                    iam="iam"
                                ),
                                root_directory="rootDirectory",
                                transit_encryption="transitEncryption",
                                transit_encryption_port=123
                            ),
                            host=batch.CfnJobDefinition.VolumesHostProperty(
                                source_path="sourcePath"
                            ),
                            name="name"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "target_nodes": target_nodes,
            }
            if container is not None:
                self._values["container"] = container

        @builtins.property
        def target_nodes(self) -> builtins.str:
            '''``CfnJobDefinition.NodeRangePropertyProperty.TargetNodes``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-noderangeproperty.html#cfn-batch-jobdefinition-noderangeproperty-targetnodes
            '''
            result = self._values.get("target_nodes")
            assert result is not None, "Required property 'target_nodes' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def container(
            self,
        ) -> typing.Optional[typing.Union["CfnJobDefinition.ContainerPropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.NodeRangePropertyProperty.Container``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-noderangeproperty.html#cfn-batch-jobdefinition-noderangeproperty-container
            '''
            result = self._values.get("container")
            return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.ContainerPropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NodeRangePropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.ResourceRequirementProperty",
        jsii_struct_bases=[],
        name_mapping={"type": "type", "value": "value"},
    )
    class ResourceRequirementProperty:
        def __init__(
            self,
            *,
            type: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param type: ``CfnJobDefinition.ResourceRequirementProperty.Type``.
            :param value: ``CfnJobDefinition.ResourceRequirementProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-resourcerequirement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                resource_requirement_property = batch.CfnJobDefinition.ResourceRequirementProperty(
                    type="type",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if type is not None:
                self._values["type"] = type
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.ResourceRequirementProperty.Type``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-resourcerequirement.html#cfn-batch-jobdefinition-resourcerequirement-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.ResourceRequirementProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-resourcerequirement.html#cfn-batch-jobdefinition-resourcerequirement-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceRequirementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.RetryStrategyProperty",
        jsii_struct_bases=[],
        name_mapping={"attempts": "attempts", "evaluate_on_exit": "evaluateOnExit"},
    )
    class RetryStrategyProperty:
        def __init__(
            self,
            *,
            attempts: typing.Optional[jsii.Number] = None,
            evaluate_on_exit: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobDefinition.EvaluateOnExitProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''
            :param attempts: ``CfnJobDefinition.RetryStrategyProperty.Attempts``.
            :param evaluate_on_exit: ``CfnJobDefinition.RetryStrategyProperty.EvaluateOnExit``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-retrystrategy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                retry_strategy_property = batch.CfnJobDefinition.RetryStrategyProperty(
                    attempts=123,
                    evaluate_on_exit=[batch.CfnJobDefinition.EvaluateOnExitProperty(
                        action="action",
                
                        # the properties below are optional
                        on_exit_code="onExitCode",
                        on_reason="onReason",
                        on_status_reason="onStatusReason"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if attempts is not None:
                self._values["attempts"] = attempts
            if evaluate_on_exit is not None:
                self._values["evaluate_on_exit"] = evaluate_on_exit

        @builtins.property
        def attempts(self) -> typing.Optional[jsii.Number]:
            '''``CfnJobDefinition.RetryStrategyProperty.Attempts``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-retrystrategy.html#cfn-batch-jobdefinition-retrystrategy-attempts
            '''
            result = self._values.get("attempts")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def evaluate_on_exit(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.EvaluateOnExitProperty", _IResolvable_da3f097b]]]]:
            '''``CfnJobDefinition.RetryStrategyProperty.EvaluateOnExit``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-retrystrategy.html#cfn-batch-jobdefinition-retrystrategy-evaluateonexit
            '''
            result = self._values.get("evaluate_on_exit")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobDefinition.EvaluateOnExitProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RetryStrategyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.SecretProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value_from": "valueFrom"},
    )
    class SecretProperty:
        def __init__(self, *, name: builtins.str, value_from: builtins.str) -> None:
            '''
            :param name: ``CfnJobDefinition.SecretProperty.Name``.
            :param value_from: ``CfnJobDefinition.SecretProperty.ValueFrom``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-secret.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                secret_property = batch.CfnJobDefinition.SecretProperty(
                    name="name",
                    value_from="valueFrom"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "value_from": value_from,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''``CfnJobDefinition.SecretProperty.Name``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-secret.html#cfn-batch-jobdefinition-secret-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value_from(self) -> builtins.str:
            '''``CfnJobDefinition.SecretProperty.ValueFrom``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-secret.html#cfn-batch-jobdefinition-secret-valuefrom
            '''
            result = self._values.get("value_from")
            assert result is not None, "Required property 'value_from' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SecretProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.TimeoutProperty",
        jsii_struct_bases=[],
        name_mapping={"attempt_duration_seconds": "attemptDurationSeconds"},
    )
    class TimeoutProperty:
        def __init__(
            self,
            *,
            attempt_duration_seconds: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''
            :param attempt_duration_seconds: ``CfnJobDefinition.TimeoutProperty.AttemptDurationSeconds``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-timeout.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                timeout_property = batch.CfnJobDefinition.TimeoutProperty(
                    attempt_duration_seconds=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if attempt_duration_seconds is not None:
                self._values["attempt_duration_seconds"] = attempt_duration_seconds

        @builtins.property
        def attempt_duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''``CfnJobDefinition.TimeoutProperty.AttemptDurationSeconds``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-timeout.html#cfn-batch-jobdefinition-timeout-attemptdurationseconds
            '''
            result = self._values.get("attempt_duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TimeoutProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.TmpfsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "container_path": "containerPath",
            "size": "size",
            "mount_options": "mountOptions",
        },
    )
    class TmpfsProperty:
        def __init__(
            self,
            *,
            container_path: builtins.str,
            size: jsii.Number,
            mount_options: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''
            :param container_path: ``CfnJobDefinition.TmpfsProperty.ContainerPath``.
            :param size: ``CfnJobDefinition.TmpfsProperty.Size``.
            :param mount_options: ``CfnJobDefinition.TmpfsProperty.MountOptions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-tmpfs.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                tmpfs_property = batch.CfnJobDefinition.TmpfsProperty(
                    container_path="containerPath",
                    size=123,
                
                    # the properties below are optional
                    mount_options=["mountOptions"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "container_path": container_path,
                "size": size,
            }
            if mount_options is not None:
                self._values["mount_options"] = mount_options

        @builtins.property
        def container_path(self) -> builtins.str:
            '''``CfnJobDefinition.TmpfsProperty.ContainerPath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-tmpfs.html#cfn-batch-jobdefinition-tmpfs-containerpath
            '''
            result = self._values.get("container_path")
            assert result is not None, "Required property 'container_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def size(self) -> jsii.Number:
            '''``CfnJobDefinition.TmpfsProperty.Size``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-tmpfs.html#cfn-batch-jobdefinition-tmpfs-size
            '''
            result = self._values.get("size")
            assert result is not None, "Required property 'size' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def mount_options(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnJobDefinition.TmpfsProperty.MountOptions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-tmpfs.html#cfn-batch-jobdefinition-tmpfs-mountoptions
            '''
            result = self._values.get("mount_options")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TmpfsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.UlimitProperty",
        jsii_struct_bases=[],
        name_mapping={
            "hard_limit": "hardLimit",
            "name": "name",
            "soft_limit": "softLimit",
        },
    )
    class UlimitProperty:
        def __init__(
            self,
            *,
            hard_limit: jsii.Number,
            name: builtins.str,
            soft_limit: jsii.Number,
        ) -> None:
            '''
            :param hard_limit: ``CfnJobDefinition.UlimitProperty.HardLimit``.
            :param name: ``CfnJobDefinition.UlimitProperty.Name``.
            :param soft_limit: ``CfnJobDefinition.UlimitProperty.SoftLimit``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-ulimit.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                ulimit_property = batch.CfnJobDefinition.UlimitProperty(
                    hard_limit=123,
                    name="name",
                    soft_limit=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "hard_limit": hard_limit,
                "name": name,
                "soft_limit": soft_limit,
            }

        @builtins.property
        def hard_limit(self) -> jsii.Number:
            '''``CfnJobDefinition.UlimitProperty.HardLimit``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-ulimit.html#cfn-batch-jobdefinition-ulimit-hardlimit
            '''
            result = self._values.get("hard_limit")
            assert result is not None, "Required property 'hard_limit' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''``CfnJobDefinition.UlimitProperty.Name``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-ulimit.html#cfn-batch-jobdefinition-ulimit-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def soft_limit(self) -> jsii.Number:
            '''``CfnJobDefinition.UlimitProperty.SoftLimit``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-ulimit.html#cfn-batch-jobdefinition-ulimit-softlimit
            '''
            result = self._values.get("soft_limit")
            assert result is not None, "Required property 'soft_limit' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UlimitProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.VolumesHostProperty",
        jsii_struct_bases=[],
        name_mapping={"source_path": "sourcePath"},
    )
    class VolumesHostProperty:
        def __init__(
            self,
            *,
            source_path: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param source_path: ``CfnJobDefinition.VolumesHostProperty.SourcePath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-volumeshost.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                volumes_host_property = batch.CfnJobDefinition.VolumesHostProperty(
                    source_path="sourcePath"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if source_path is not None:
                self._values["source_path"] = source_path

        @builtins.property
        def source_path(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.VolumesHostProperty.SourcePath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-volumeshost.html#cfn-batch-jobdefinition-volumeshost-sourcepath
            '''
            result = self._values.get("source_path")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VolumesHostProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinition.VolumesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "efs_volume_configuration": "efsVolumeConfiguration",
            "host": "host",
            "name": "name",
        },
    )
    class VolumesProperty:
        def __init__(
            self,
            *,
            efs_volume_configuration: typing.Optional[typing.Union["CfnJobDefinition.EfsVolumeConfigurationProperty", _IResolvable_da3f097b]] = None,
            host: typing.Optional[typing.Union["CfnJobDefinition.VolumesHostProperty", _IResolvable_da3f097b]] = None,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param efs_volume_configuration: ``CfnJobDefinition.VolumesProperty.EfsVolumeConfiguration``.
            :param host: ``CfnJobDefinition.VolumesProperty.Host``.
            :param name: ``CfnJobDefinition.VolumesProperty.Name``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-volumes.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                volumes_property = batch.CfnJobDefinition.VolumesProperty(
                    efs_volume_configuration=batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                        file_system_id="fileSystemId",
                
                        # the properties below are optional
                        authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                            access_point_id="accessPointId",
                            iam="iam"
                        ),
                        root_directory="rootDirectory",
                        transit_encryption="transitEncryption",
                        transit_encryption_port=123
                    ),
                    host=batch.CfnJobDefinition.VolumesHostProperty(
                        source_path="sourcePath"
                    ),
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if efs_volume_configuration is not None:
                self._values["efs_volume_configuration"] = efs_volume_configuration
            if host is not None:
                self._values["host"] = host
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def efs_volume_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnJobDefinition.EfsVolumeConfigurationProperty", _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.VolumesProperty.EfsVolumeConfiguration``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-volumes.html#cfn-batch-jobdefinition-volumes-efsvolumeconfiguration
            '''
            result = self._values.get("efs_volume_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.EfsVolumeConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def host(
            self,
        ) -> typing.Optional[typing.Union["CfnJobDefinition.VolumesHostProperty", _IResolvable_da3f097b]]:
            '''``CfnJobDefinition.VolumesProperty.Host``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-volumes.html#cfn-batch-jobdefinition-volumes-host
            '''
            result = self._values.get("host")
            return typing.cast(typing.Optional[typing.Union["CfnJobDefinition.VolumesHostProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''``CfnJobDefinition.VolumesProperty.Name``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobdefinition-volumes.html#cfn-batch-jobdefinition-volumes-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VolumesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_batch.CfnJobDefinitionProps",
    jsii_struct_bases=[],
    name_mapping={
        "type": "type",
        "container_properties": "containerProperties",
        "job_definition_name": "jobDefinitionName",
        "node_properties": "nodeProperties",
        "parameters": "parameters",
        "platform_capabilities": "platformCapabilities",
        "propagate_tags": "propagateTags",
        "retry_strategy": "retryStrategy",
        "scheduling_priority": "schedulingPriority",
        "tags": "tags",
        "timeout": "timeout",
    },
)
class CfnJobDefinitionProps:
    def __init__(
        self,
        *,
        type: builtins.str,
        container_properties: typing.Optional[typing.Union[CfnJobDefinition.ContainerPropertiesProperty, _IResolvable_da3f097b]] = None,
        job_definition_name: typing.Optional[builtins.str] = None,
        node_properties: typing.Optional[typing.Union[CfnJobDefinition.NodePropertiesProperty, _IResolvable_da3f097b]] = None,
        parameters: typing.Any = None,
        platform_capabilities: typing.Optional[typing.Sequence[builtins.str]] = None,
        propagate_tags: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        retry_strategy: typing.Optional[typing.Union[CfnJobDefinition.RetryStrategyProperty, _IResolvable_da3f097b]] = None,
        scheduling_priority: typing.Optional[jsii.Number] = None,
        tags: typing.Any = None,
        timeout: typing.Optional[typing.Union[CfnJobDefinition.TimeoutProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnJobDefinition``.

        :param type: ``AWS::Batch::JobDefinition.Type``.
        :param container_properties: ``AWS::Batch::JobDefinition.ContainerProperties``.
        :param job_definition_name: ``AWS::Batch::JobDefinition.JobDefinitionName``.
        :param node_properties: ``AWS::Batch::JobDefinition.NodeProperties``.
        :param parameters: ``AWS::Batch::JobDefinition.Parameters``.
        :param platform_capabilities: ``AWS::Batch::JobDefinition.PlatformCapabilities``.
        :param propagate_tags: ``AWS::Batch::JobDefinition.PropagateTags``.
        :param retry_strategy: ``AWS::Batch::JobDefinition.RetryStrategy``.
        :param scheduling_priority: ``AWS::Batch::JobDefinition.SchedulingPriority``.
        :param tags: ``AWS::Batch::JobDefinition.Tags``.
        :param timeout: ``AWS::Batch::JobDefinition.Timeout``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_batch as batch
            
            # options: Any
            # parameters: Any
            # tags: Any
            
            cfn_job_definition_props = batch.CfnJobDefinitionProps(
                type="type",
            
                # the properties below are optional
                container_properties=batch.CfnJobDefinition.ContainerPropertiesProperty(
                    image="image",
            
                    # the properties below are optional
                    command=["command"],
                    environment=[batch.CfnJobDefinition.EnvironmentProperty(
                        name="name",
                        value="value"
                    )],
                    execution_role_arn="executionRoleArn",
                    fargate_platform_configuration=batch.CfnJobDefinition.FargatePlatformConfigurationProperty(
                        platform_version="platformVersion"
                    ),
                    instance_type="instanceType",
                    job_role_arn="jobRoleArn",
                    linux_parameters=batch.CfnJobDefinition.LinuxParametersProperty(
                        devices=[batch.CfnJobDefinition.DeviceProperty(
                            container_path="containerPath",
                            host_path="hostPath",
                            permissions=["permissions"]
                        )],
                        init_process_enabled=False,
                        max_swap=123,
                        shared_memory_size=123,
                        swappiness=123,
                        tmpfs=[batch.CfnJobDefinition.TmpfsProperty(
                            container_path="containerPath",
                            size=123,
            
                            # the properties below are optional
                            mount_options=["mountOptions"]
                        )]
                    ),
                    log_configuration=batch.CfnJobDefinition.LogConfigurationProperty(
                        log_driver="logDriver",
            
                        # the properties below are optional
                        options=options,
                        secret_options=[batch.CfnJobDefinition.SecretProperty(
                            name="name",
                            value_from="valueFrom"
                        )]
                    ),
                    memory=123,
                    mount_points=[batch.CfnJobDefinition.MountPointsProperty(
                        container_path="containerPath",
                        read_only=False,
                        source_volume="sourceVolume"
                    )],
                    network_configuration=batch.CfnJobDefinition.NetworkConfigurationProperty(
                        assign_public_ip="assignPublicIp"
                    ),
                    privileged=False,
                    readonly_root_filesystem=False,
                    resource_requirements=[batch.CfnJobDefinition.ResourceRequirementProperty(
                        type="type",
                        value="value"
                    )],
                    secrets=[batch.CfnJobDefinition.SecretProperty(
                        name="name",
                        value_from="valueFrom"
                    )],
                    ulimits=[batch.CfnJobDefinition.UlimitProperty(
                        hard_limit=123,
                        name="name",
                        soft_limit=123
                    )],
                    user="user",
                    vcpus=123,
                    volumes=[batch.CfnJobDefinition.VolumesProperty(
                        efs_volume_configuration=batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                            file_system_id="fileSystemId",
            
                            # the properties below are optional
                            authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                                access_point_id="accessPointId",
                                iam="iam"
                            ),
                            root_directory="rootDirectory",
                            transit_encryption="transitEncryption",
                            transit_encryption_port=123
                        ),
                        host=batch.CfnJobDefinition.VolumesHostProperty(
                            source_path="sourcePath"
                        ),
                        name="name"
                    )]
                ),
                job_definition_name="jobDefinitionName",
                node_properties=batch.CfnJobDefinition.NodePropertiesProperty(
                    main_node=123,
                    node_range_properties=[batch.CfnJobDefinition.NodeRangePropertyProperty(
                        target_nodes="targetNodes",
            
                        # the properties below are optional
                        container=batch.CfnJobDefinition.ContainerPropertiesProperty(
                            image="image",
            
                            # the properties below are optional
                            command=["command"],
                            environment=[batch.CfnJobDefinition.EnvironmentProperty(
                                name="name",
                                value="value"
                            )],
                            execution_role_arn="executionRoleArn",
                            fargate_platform_configuration=batch.CfnJobDefinition.FargatePlatformConfigurationProperty(
                                platform_version="platformVersion"
                            ),
                            instance_type="instanceType",
                            job_role_arn="jobRoleArn",
                            linux_parameters=batch.CfnJobDefinition.LinuxParametersProperty(
                                devices=[batch.CfnJobDefinition.DeviceProperty(
                                    container_path="containerPath",
                                    host_path="hostPath",
                                    permissions=["permissions"]
                                )],
                                init_process_enabled=False,
                                max_swap=123,
                                shared_memory_size=123,
                                swappiness=123,
                                tmpfs=[batch.CfnJobDefinition.TmpfsProperty(
                                    container_path="containerPath",
                                    size=123,
            
                                    # the properties below are optional
                                    mount_options=["mountOptions"]
                                )]
                            ),
                            log_configuration=batch.CfnJobDefinition.LogConfigurationProperty(
                                log_driver="logDriver",
            
                                # the properties below are optional
                                options=options,
                                secret_options=[batch.CfnJobDefinition.SecretProperty(
                                    name="name",
                                    value_from="valueFrom"
                                )]
                            ),
                            memory=123,
                            mount_points=[batch.CfnJobDefinition.MountPointsProperty(
                                container_path="containerPath",
                                read_only=False,
                                source_volume="sourceVolume"
                            )],
                            network_configuration=batch.CfnJobDefinition.NetworkConfigurationProperty(
                                assign_public_ip="assignPublicIp"
                            ),
                            privileged=False,
                            readonly_root_filesystem=False,
                            resource_requirements=[batch.CfnJobDefinition.ResourceRequirementProperty(
                                type="type",
                                value="value"
                            )],
                            secrets=[batch.CfnJobDefinition.SecretProperty(
                                name="name",
                                value_from="valueFrom"
                            )],
                            ulimits=[batch.CfnJobDefinition.UlimitProperty(
                                hard_limit=123,
                                name="name",
                                soft_limit=123
                            )],
                            user="user",
                            vcpus=123,
                            volumes=[batch.CfnJobDefinition.VolumesProperty(
                                efs_volume_configuration=batch.CfnJobDefinition.EfsVolumeConfigurationProperty(
                                    file_system_id="fileSystemId",
            
                                    # the properties below are optional
                                    authorization_config=batch.CfnJobDefinition.AuthorizationConfigProperty(
                                        access_point_id="accessPointId",
                                        iam="iam"
                                    ),
                                    root_directory="rootDirectory",
                                    transit_encryption="transitEncryption",
                                    transit_encryption_port=123
                                ),
                                host=batch.CfnJobDefinition.VolumesHostProperty(
                                    source_path="sourcePath"
                                ),
                                name="name"
                            )]
                        )
                    )],
                    num_nodes=123
                ),
                parameters=parameters,
                platform_capabilities=["platformCapabilities"],
                propagate_tags=False,
                retry_strategy=batch.CfnJobDefinition.RetryStrategyProperty(
                    attempts=123,
                    evaluate_on_exit=[batch.CfnJobDefinition.EvaluateOnExitProperty(
                        action="action",
            
                        # the properties below are optional
                        on_exit_code="onExitCode",
                        on_reason="onReason",
                        on_status_reason="onStatusReason"
                    )]
                ),
                scheduling_priority=123,
                tags=tags,
                timeout=batch.CfnJobDefinition.TimeoutProperty(
                    attempt_duration_seconds=123
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "type": type,
        }
        if container_properties is not None:
            self._values["container_properties"] = container_properties
        if job_definition_name is not None:
            self._values["job_definition_name"] = job_definition_name
        if node_properties is not None:
            self._values["node_properties"] = node_properties
        if parameters is not None:
            self._values["parameters"] = parameters
        if platform_capabilities is not None:
            self._values["platform_capabilities"] = platform_capabilities
        if propagate_tags is not None:
            self._values["propagate_tags"] = propagate_tags
        if retry_strategy is not None:
            self._values["retry_strategy"] = retry_strategy
        if scheduling_priority is not None:
            self._values["scheduling_priority"] = scheduling_priority
        if tags is not None:
            self._values["tags"] = tags
        if timeout is not None:
            self._values["timeout"] = timeout

    @builtins.property
    def type(self) -> builtins.str:
        '''``AWS::Batch::JobDefinition.Type``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def container_properties(
        self,
    ) -> typing.Optional[typing.Union[CfnJobDefinition.ContainerPropertiesProperty, _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.ContainerProperties``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-containerproperties
        '''
        result = self._values.get("container_properties")
        return typing.cast(typing.Optional[typing.Union[CfnJobDefinition.ContainerPropertiesProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def job_definition_name(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::JobDefinition.JobDefinitionName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-jobdefinitionname
        '''
        result = self._values.get("job_definition_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def node_properties(
        self,
    ) -> typing.Optional[typing.Union[CfnJobDefinition.NodePropertiesProperty, _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.NodeProperties``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-nodeproperties
        '''
        result = self._values.get("node_properties")
        return typing.cast(typing.Optional[typing.Union[CfnJobDefinition.NodePropertiesProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def parameters(self) -> typing.Any:
        '''``AWS::Batch::JobDefinition.Parameters``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-parameters
        '''
        result = self._values.get("parameters")
        return typing.cast(typing.Any, result)

    @builtins.property
    def platform_capabilities(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::Batch::JobDefinition.PlatformCapabilities``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-platformcapabilities
        '''
        result = self._values.get("platform_capabilities")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def propagate_tags(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.PropagateTags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-propagatetags
        '''
        result = self._values.get("propagate_tags")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def retry_strategy(
        self,
    ) -> typing.Optional[typing.Union[CfnJobDefinition.RetryStrategyProperty, _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.RetryStrategy``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-retrystrategy
        '''
        result = self._values.get("retry_strategy")
        return typing.cast(typing.Optional[typing.Union[CfnJobDefinition.RetryStrategyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def scheduling_priority(self) -> typing.Optional[jsii.Number]:
        '''``AWS::Batch::JobDefinition.SchedulingPriority``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-schedulingpriority
        '''
        result = self._values.get("scheduling_priority")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''``AWS::Batch::JobDefinition.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def timeout(
        self,
    ) -> typing.Optional[typing.Union[CfnJobDefinition.TimeoutProperty, _IResolvable_da3f097b]]:
        '''``AWS::Batch::JobDefinition.Timeout``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html#cfn-batch-jobdefinition-timeout
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[typing.Union[CfnJobDefinition.TimeoutProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnJobDefinitionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnJobQueue(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_batch.CfnJobQueue",
):
    '''A CloudFormation ``AWS::Batch::JobQueue``.

    :cloudformationResource: AWS::Batch::JobQueue
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_batch as batch
        
        cfn_job_queue = batch.CfnJobQueue(self, "MyCfnJobQueue",
            compute_environment_order=[batch.CfnJobQueue.ComputeEnvironmentOrderProperty(
                compute_environment="computeEnvironment",
                order=123
            )],
            priority=123,
        
            # the properties below are optional
            job_queue_name="jobQueueName",
            scheduling_policy_arn="schedulingPolicyArn",
            state="state",
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
        compute_environment_order: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnJobQueue.ComputeEnvironmentOrderProperty", _IResolvable_da3f097b]]],
        priority: jsii.Number,
        job_queue_name: typing.Optional[builtins.str] = None,
        scheduling_policy_arn: typing.Optional[builtins.str] = None,
        state: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::Batch::JobQueue``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param compute_environment_order: ``AWS::Batch::JobQueue.ComputeEnvironmentOrder``.
        :param priority: ``AWS::Batch::JobQueue.Priority``.
        :param job_queue_name: ``AWS::Batch::JobQueue.JobQueueName``.
        :param scheduling_policy_arn: ``AWS::Batch::JobQueue.SchedulingPolicyArn``.
        :param state: ``AWS::Batch::JobQueue.State``.
        :param tags: ``AWS::Batch::JobQueue.Tags``.
        '''
        props = CfnJobQueueProps(
            compute_environment_order=compute_environment_order,
            priority=priority,
            job_queue_name=job_queue_name,
            scheduling_policy_arn=scheduling_policy_arn,
            state=state,
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
    @jsii.member(jsii_name="attrJobQueueArn")
    def attr_job_queue_arn(self) -> builtins.str:
        '''
        :cloudformationAttribute: JobQueueArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrJobQueueArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''``AWS::Batch::JobQueue.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="computeEnvironmentOrder")
    def compute_environment_order(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobQueue.ComputeEnvironmentOrderProperty", _IResolvable_da3f097b]]]:
        '''``AWS::Batch::JobQueue.ComputeEnvironmentOrder``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-computeenvironmentorder
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobQueue.ComputeEnvironmentOrderProperty", _IResolvable_da3f097b]]], jsii.get(self, "computeEnvironmentOrder"))

    @compute_environment_order.setter
    def compute_environment_order(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnJobQueue.ComputeEnvironmentOrderProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "computeEnvironmentOrder", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="priority")
    def priority(self) -> jsii.Number:
        '''``AWS::Batch::JobQueue.Priority``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-priority
        '''
        return typing.cast(jsii.Number, jsii.get(self, "priority"))

    @priority.setter
    def priority(self, value: jsii.Number) -> None:
        jsii.set(self, "priority", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="jobQueueName")
    def job_queue_name(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::JobQueue.JobQueueName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-jobqueuename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "jobQueueName"))

    @job_queue_name.setter
    def job_queue_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "jobQueueName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schedulingPolicyArn")
    def scheduling_policy_arn(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::JobQueue.SchedulingPolicyArn``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-schedulingpolicyarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "schedulingPolicyArn"))

    @scheduling_policy_arn.setter
    def scheduling_policy_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "schedulingPolicyArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="state")
    def state(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::JobQueue.State``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-state
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "state"))

    @state.setter
    def state(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "state", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnJobQueue.ComputeEnvironmentOrderProperty",
        jsii_struct_bases=[],
        name_mapping={"compute_environment": "computeEnvironment", "order": "order"},
    )
    class ComputeEnvironmentOrderProperty:
        def __init__(
            self,
            *,
            compute_environment: builtins.str,
            order: jsii.Number,
        ) -> None:
            '''
            :param compute_environment: ``CfnJobQueue.ComputeEnvironmentOrderProperty.ComputeEnvironment``.
            :param order: ``CfnJobQueue.ComputeEnvironmentOrderProperty.Order``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobqueue-computeenvironmentorder.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                compute_environment_order_property = batch.CfnJobQueue.ComputeEnvironmentOrderProperty(
                    compute_environment="computeEnvironment",
                    order=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "compute_environment": compute_environment,
                "order": order,
            }

        @builtins.property
        def compute_environment(self) -> builtins.str:
            '''``CfnJobQueue.ComputeEnvironmentOrderProperty.ComputeEnvironment``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobqueue-computeenvironmentorder.html#cfn-batch-jobqueue-computeenvironmentorder-computeenvironment
            '''
            result = self._values.get("compute_environment")
            assert result is not None, "Required property 'compute_environment' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def order(self) -> jsii.Number:
            '''``CfnJobQueue.ComputeEnvironmentOrderProperty.Order``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-jobqueue-computeenvironmentorder.html#cfn-batch-jobqueue-computeenvironmentorder-order
            '''
            result = self._values.get("order")
            assert result is not None, "Required property 'order' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComputeEnvironmentOrderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_batch.CfnJobQueueProps",
    jsii_struct_bases=[],
    name_mapping={
        "compute_environment_order": "computeEnvironmentOrder",
        "priority": "priority",
        "job_queue_name": "jobQueueName",
        "scheduling_policy_arn": "schedulingPolicyArn",
        "state": "state",
        "tags": "tags",
    },
)
class CfnJobQueueProps:
    def __init__(
        self,
        *,
        compute_environment_order: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnJobQueue.ComputeEnvironmentOrderProperty, _IResolvable_da3f097b]]],
        priority: jsii.Number,
        job_queue_name: typing.Optional[builtins.str] = None,
        scheduling_policy_arn: typing.Optional[builtins.str] = None,
        state: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnJobQueue``.

        :param compute_environment_order: ``AWS::Batch::JobQueue.ComputeEnvironmentOrder``.
        :param priority: ``AWS::Batch::JobQueue.Priority``.
        :param job_queue_name: ``AWS::Batch::JobQueue.JobQueueName``.
        :param scheduling_policy_arn: ``AWS::Batch::JobQueue.SchedulingPolicyArn``.
        :param state: ``AWS::Batch::JobQueue.State``.
        :param tags: ``AWS::Batch::JobQueue.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_batch as batch
            
            cfn_job_queue_props = batch.CfnJobQueueProps(
                compute_environment_order=[batch.CfnJobQueue.ComputeEnvironmentOrderProperty(
                    compute_environment="computeEnvironment",
                    order=123
                )],
                priority=123,
            
                # the properties below are optional
                job_queue_name="jobQueueName",
                scheduling_policy_arn="schedulingPolicyArn",
                state="state",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "compute_environment_order": compute_environment_order,
            "priority": priority,
        }
        if job_queue_name is not None:
            self._values["job_queue_name"] = job_queue_name
        if scheduling_policy_arn is not None:
            self._values["scheduling_policy_arn"] = scheduling_policy_arn
        if state is not None:
            self._values["state"] = state
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def compute_environment_order(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnJobQueue.ComputeEnvironmentOrderProperty, _IResolvable_da3f097b]]]:
        '''``AWS::Batch::JobQueue.ComputeEnvironmentOrder``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-computeenvironmentorder
        '''
        result = self._values.get("compute_environment_order")
        assert result is not None, "Required property 'compute_environment_order' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnJobQueue.ComputeEnvironmentOrderProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def priority(self) -> jsii.Number:
        '''``AWS::Batch::JobQueue.Priority``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-priority
        '''
        result = self._values.get("priority")
        assert result is not None, "Required property 'priority' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def job_queue_name(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::JobQueue.JobQueueName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-jobqueuename
        '''
        result = self._values.get("job_queue_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def scheduling_policy_arn(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::JobQueue.SchedulingPolicyArn``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-schedulingpolicyarn
        '''
        result = self._values.get("scheduling_policy_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def state(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::JobQueue.State``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-state
        '''
        result = self._values.get("state")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''``AWS::Batch::JobQueue.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobqueue.html#cfn-batch-jobqueue-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnJobQueueProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSchedulingPolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_batch.CfnSchedulingPolicy",
):
    '''A CloudFormation ``AWS::Batch::SchedulingPolicy``.

    :cloudformationResource: AWS::Batch::SchedulingPolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-schedulingpolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_batch as batch
        
        cfn_scheduling_policy = batch.CfnSchedulingPolicy(self, "MyCfnSchedulingPolicy",
            fairshare_policy=batch.CfnSchedulingPolicy.FairsharePolicyProperty(
                compute_reservation=123,
                share_decay_seconds=123,
                share_distribution=[batch.CfnSchedulingPolicy.ShareAttributesProperty(
                    share_identifier="shareIdentifier",
                    weight_factor=123
                )]
            ),
            name="name",
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
        fairshare_policy: typing.Optional[typing.Union["CfnSchedulingPolicy.FairsharePolicyProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::Batch::SchedulingPolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param fairshare_policy: ``AWS::Batch::SchedulingPolicy.FairsharePolicy``.
        :param name: ``AWS::Batch::SchedulingPolicy.Name``.
        :param tags: ``AWS::Batch::SchedulingPolicy.Tags``.
        '''
        props = CfnSchedulingPolicyProps(
            fairshare_policy=fairshare_policy, name=name, tags=tags
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
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''``AWS::Batch::SchedulingPolicy.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-schedulingpolicy.html#cfn-batch-schedulingpolicy-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fairsharePolicy")
    def fairshare_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnSchedulingPolicy.FairsharePolicyProperty", _IResolvable_da3f097b]]:
        '''``AWS::Batch::SchedulingPolicy.FairsharePolicy``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-schedulingpolicy.html#cfn-batch-schedulingpolicy-fairsharepolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnSchedulingPolicy.FairsharePolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "fairsharePolicy"))

    @fairshare_policy.setter
    def fairshare_policy(
        self,
        value: typing.Optional[typing.Union["CfnSchedulingPolicy.FairsharePolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "fairsharePolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::SchedulingPolicy.Name``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-schedulingpolicy.html#cfn-batch-schedulingpolicy-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnSchedulingPolicy.FairsharePolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "compute_reservation": "computeReservation",
            "share_decay_seconds": "shareDecaySeconds",
            "share_distribution": "shareDistribution",
        },
    )
    class FairsharePolicyProperty:
        def __init__(
            self,
            *,
            compute_reservation: typing.Optional[jsii.Number] = None,
            share_decay_seconds: typing.Optional[jsii.Number] = None,
            share_distribution: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnSchedulingPolicy.ShareAttributesProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''
            :param compute_reservation: ``CfnSchedulingPolicy.FairsharePolicyProperty.ComputeReservation``.
            :param share_decay_seconds: ``CfnSchedulingPolicy.FairsharePolicyProperty.ShareDecaySeconds``.
            :param share_distribution: ``CfnSchedulingPolicy.FairsharePolicyProperty.ShareDistribution``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-schedulingpolicy-fairsharepolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                fairshare_policy_property = batch.CfnSchedulingPolicy.FairsharePolicyProperty(
                    compute_reservation=123,
                    share_decay_seconds=123,
                    share_distribution=[batch.CfnSchedulingPolicy.ShareAttributesProperty(
                        share_identifier="shareIdentifier",
                        weight_factor=123
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if compute_reservation is not None:
                self._values["compute_reservation"] = compute_reservation
            if share_decay_seconds is not None:
                self._values["share_decay_seconds"] = share_decay_seconds
            if share_distribution is not None:
                self._values["share_distribution"] = share_distribution

        @builtins.property
        def compute_reservation(self) -> typing.Optional[jsii.Number]:
            '''``CfnSchedulingPolicy.FairsharePolicyProperty.ComputeReservation``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-schedulingpolicy-fairsharepolicy.html#cfn-batch-schedulingpolicy-fairsharepolicy-computereservation
            '''
            result = self._values.get("compute_reservation")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def share_decay_seconds(self) -> typing.Optional[jsii.Number]:
            '''``CfnSchedulingPolicy.FairsharePolicyProperty.ShareDecaySeconds``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-schedulingpolicy-fairsharepolicy.html#cfn-batch-schedulingpolicy-fairsharepolicy-sharedecayseconds
            '''
            result = self._values.get("share_decay_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def share_distribution(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSchedulingPolicy.ShareAttributesProperty", _IResolvable_da3f097b]]]]:
            '''``CfnSchedulingPolicy.FairsharePolicyProperty.ShareDistribution``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-schedulingpolicy-fairsharepolicy.html#cfn-batch-schedulingpolicy-fairsharepolicy-sharedistribution
            '''
            result = self._values.get("share_distribution")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSchedulingPolicy.ShareAttributesProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FairsharePolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_batch.CfnSchedulingPolicy.ShareAttributesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "share_identifier": "shareIdentifier",
            "weight_factor": "weightFactor",
        },
    )
    class ShareAttributesProperty:
        def __init__(
            self,
            *,
            share_identifier: typing.Optional[builtins.str] = None,
            weight_factor: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''
            :param share_identifier: ``CfnSchedulingPolicy.ShareAttributesProperty.ShareIdentifier``.
            :param weight_factor: ``CfnSchedulingPolicy.ShareAttributesProperty.WeightFactor``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-schedulingpolicy-shareattributes.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_batch as batch
                
                share_attributes_property = batch.CfnSchedulingPolicy.ShareAttributesProperty(
                    share_identifier="shareIdentifier",
                    weight_factor=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if share_identifier is not None:
                self._values["share_identifier"] = share_identifier
            if weight_factor is not None:
                self._values["weight_factor"] = weight_factor

        @builtins.property
        def share_identifier(self) -> typing.Optional[builtins.str]:
            '''``CfnSchedulingPolicy.ShareAttributesProperty.ShareIdentifier``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-schedulingpolicy-shareattributes.html#cfn-batch-schedulingpolicy-shareattributes-shareidentifier
            '''
            result = self._values.get("share_identifier")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def weight_factor(self) -> typing.Optional[jsii.Number]:
            '''``CfnSchedulingPolicy.ShareAttributesProperty.WeightFactor``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-batch-schedulingpolicy-shareattributes.html#cfn-batch-schedulingpolicy-shareattributes-weightfactor
            '''
            result = self._values.get("weight_factor")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ShareAttributesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_batch.CfnSchedulingPolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "fairshare_policy": "fairsharePolicy",
        "name": "name",
        "tags": "tags",
    },
)
class CfnSchedulingPolicyProps:
    def __init__(
        self,
        *,
        fairshare_policy: typing.Optional[typing.Union[CfnSchedulingPolicy.FairsharePolicyProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSchedulingPolicy``.

        :param fairshare_policy: ``AWS::Batch::SchedulingPolicy.FairsharePolicy``.
        :param name: ``AWS::Batch::SchedulingPolicy.Name``.
        :param tags: ``AWS::Batch::SchedulingPolicy.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-schedulingpolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_batch as batch
            
            cfn_scheduling_policy_props = batch.CfnSchedulingPolicyProps(
                fairshare_policy=batch.CfnSchedulingPolicy.FairsharePolicyProperty(
                    compute_reservation=123,
                    share_decay_seconds=123,
                    share_distribution=[batch.CfnSchedulingPolicy.ShareAttributesProperty(
                        share_identifier="shareIdentifier",
                        weight_factor=123
                    )]
                ),
                name="name",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if fairshare_policy is not None:
            self._values["fairshare_policy"] = fairshare_policy
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def fairshare_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnSchedulingPolicy.FairsharePolicyProperty, _IResolvable_da3f097b]]:
        '''``AWS::Batch::SchedulingPolicy.FairsharePolicy``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-schedulingpolicy.html#cfn-batch-schedulingpolicy-fairsharepolicy
        '''
        result = self._values.get("fairshare_policy")
        return typing.cast(typing.Optional[typing.Union[CfnSchedulingPolicy.FairsharePolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''``AWS::Batch::SchedulingPolicy.Name``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-schedulingpolicy.html#cfn-batch-schedulingpolicy-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''``AWS::Batch::SchedulingPolicy.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-schedulingpolicy.html#cfn-batch-schedulingpolicy-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSchedulingPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnComputeEnvironment",
    "CfnComputeEnvironmentProps",
    "CfnJobDefinition",
    "CfnJobDefinitionProps",
    "CfnJobQueue",
    "CfnJobQueueProps",
    "CfnSchedulingPolicy",
    "CfnSchedulingPolicyProps",
]

publication.publish()
