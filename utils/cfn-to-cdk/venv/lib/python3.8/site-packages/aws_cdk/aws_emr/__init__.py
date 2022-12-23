'''
# Amazon EMR Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_emr as emr
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-emr-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::EMR](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_EMR.html).

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
class CfnCluster(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_emr.CfnCluster",
):
    '''A CloudFormation ``AWS::EMR::Cluster``.

    The ``AWS::EMR::Cluster`` resource specifies an Amazon EMR cluster. This cluster is a collection of Amazon EC2 instances that run open source big data frameworks and applications to process and analyze vast amounts of data. For more information, see the `Amazon EMR Management Guide <https://docs.aws.amazon.com//emr/latest/ManagementGuide/>`_ .

    Amazon EMR now supports launching task instance groups and task instance fleets as part of the ``AWS::EMR::Cluster`` resource. This can be done by using the ``JobFlowInstancesConfig`` property type's ``TaskInstanceGroups`` and ``TaskInstanceFleets`` subproperties. Using these subproperties reduces delays in provisioning task nodes compared to specifying task nodes with the ``AWS::EMR::InstanceGroupConfig`` and ``AWS::EMR::InstanceFleetConfig`` resources. Please refer to the examples at the bottom of this page to learn how to use these subproperties.

    :cloudformationResource: AWS::EMR::Cluster
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_emr as emr
        
        # additional_info: Any
        # configuration_property_: emr.CfnCluster.ConfigurationProperty
        
        cfn_cluster = emr.CfnCluster(self, "MyCfnCluster",
            instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
                additional_master_security_groups=["additionalMasterSecurityGroups"],
                additional_slave_security_groups=["additionalSlaveSecurityGroups"],
                core_instance_fleet=emr.CfnCluster.InstanceFleetConfigProperty(
                    instance_type_configs=[emr.CfnCluster.InstanceTypeConfigProperty(
                        instance_type="instanceType",
        
                        # the properties below are optional
                        bid_price="bidPrice",
                        bid_price_as_percentage_of_on_demand_price=123,
                        configurations=[emr.CfnCluster.ConfigurationProperty(
                            classification="classification",
                            configuration_properties={
                                "configuration_properties_key": "configurationProperties"
                            },
                            configurations=[configuration_property_]
                        )],
                        custom_ami_id="customAmiId",
                        ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                            ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                    size_in_gb=123,
                                    volume_type="volumeType",
        
                                    # the properties below are optional
                                    iops=123
                                ),
        
                                # the properties below are optional
                                volumes_per_instance=123
                            )],
                            ebs_optimized=False
                        ),
                        weighted_capacity=123
                    )],
                    launch_specifications=emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty(
                        on_demand_specification=emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                            allocation_strategy="allocationStrategy"
                        ),
                        spot_specification=emr.CfnCluster.SpotProvisioningSpecificationProperty(
                            timeout_action="timeoutAction",
                            timeout_duration_minutes=123,
        
                            # the properties below are optional
                            allocation_strategy="allocationStrategy",
                            block_duration_minutes=123
                        )
                    ),
                    name="name",
                    target_on_demand_capacity=123,
                    target_spot_capacity=123
                ),
                core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                    instance_count=123,
                    instance_type="instanceType",
        
                    # the properties below are optional
                    auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                        constraints=emr.CfnCluster.ScalingConstraintsProperty(
                            max_capacity=123,
                            min_capacity=123
                        ),
                        rules=[emr.CfnCluster.ScalingRuleProperty(
                            action=emr.CfnCluster.ScalingActionProperty(
                                simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                    scaling_adjustment=123,
        
                                    # the properties below are optional
                                    adjustment_type="adjustmentType",
                                    cool_down=123
                                ),
        
                                # the properties below are optional
                                market="market"
                            ),
                            name="name",
                            trigger=emr.CfnCluster.ScalingTriggerProperty(
                                cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                    comparison_operator="comparisonOperator",
                                    metric_name="metricName",
                                    period=123,
                                    threshold=123,
        
                                    # the properties below are optional
                                    dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                        key="key",
                                        value="value"
                                    )],
                                    evaluation_periods=123,
                                    namespace="namespace",
                                    statistic="statistic",
                                    unit="unit"
                                )
                            ),
        
                            # the properties below are optional
                            description="description"
                        )]
                    ),
                    bid_price="bidPrice",
                    configurations=[emr.CfnCluster.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )],
                    custom_ami_id="customAmiId",
                    ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                        ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                            volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                size_in_gb=123,
                                volume_type="volumeType",
        
                                # the properties below are optional
                                iops=123
                            ),
        
                            # the properties below are optional
                            volumes_per_instance=123
                        )],
                        ebs_optimized=False
                    ),
                    market="market",
                    name="name"
                ),
                ec2_key_name="ec2KeyName",
                ec2_subnet_id="ec2SubnetId",
                ec2_subnet_ids=["ec2SubnetIds"],
                emr_managed_master_security_group="emrManagedMasterSecurityGroup",
                emr_managed_slave_security_group="emrManagedSlaveSecurityGroup",
                hadoop_version="hadoopVersion",
                keep_job_flow_alive_when_no_steps=False,
                master_instance_fleet=emr.CfnCluster.InstanceFleetConfigProperty(
                    instance_type_configs=[emr.CfnCluster.InstanceTypeConfigProperty(
                        instance_type="instanceType",
        
                        # the properties below are optional
                        bid_price="bidPrice",
                        bid_price_as_percentage_of_on_demand_price=123,
                        configurations=[emr.CfnCluster.ConfigurationProperty(
                            classification="classification",
                            configuration_properties={
                                "configuration_properties_key": "configurationProperties"
                            },
                            configurations=[configuration_property_]
                        )],
                        custom_ami_id="customAmiId",
                        ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                            ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                    size_in_gb=123,
                                    volume_type="volumeType",
        
                                    # the properties below are optional
                                    iops=123
                                ),
        
                                # the properties below are optional
                                volumes_per_instance=123
                            )],
                            ebs_optimized=False
                        ),
                        weighted_capacity=123
                    )],
                    launch_specifications=emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty(
                        on_demand_specification=emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                            allocation_strategy="allocationStrategy"
                        ),
                        spot_specification=emr.CfnCluster.SpotProvisioningSpecificationProperty(
                            timeout_action="timeoutAction",
                            timeout_duration_minutes=123,
        
                            # the properties below are optional
                            allocation_strategy="allocationStrategy",
                            block_duration_minutes=123
                        )
                    ),
                    name="name",
                    target_on_demand_capacity=123,
                    target_spot_capacity=123
                ),
                master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                    instance_count=123,
                    instance_type="instanceType",
        
                    # the properties below are optional
                    auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                        constraints=emr.CfnCluster.ScalingConstraintsProperty(
                            max_capacity=123,
                            min_capacity=123
                        ),
                        rules=[emr.CfnCluster.ScalingRuleProperty(
                            action=emr.CfnCluster.ScalingActionProperty(
                                simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                    scaling_adjustment=123,
        
                                    # the properties below are optional
                                    adjustment_type="adjustmentType",
                                    cool_down=123
                                ),
        
                                # the properties below are optional
                                market="market"
                            ),
                            name="name",
                            trigger=emr.CfnCluster.ScalingTriggerProperty(
                                cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                    comparison_operator="comparisonOperator",
                                    metric_name="metricName",
                                    period=123,
                                    threshold=123,
        
                                    # the properties below are optional
                                    dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                        key="key",
                                        value="value"
                                    )],
                                    evaluation_periods=123,
                                    namespace="namespace",
                                    statistic="statistic",
                                    unit="unit"
                                )
                            ),
        
                            # the properties below are optional
                            description="description"
                        )]
                    ),
                    bid_price="bidPrice",
                    configurations=[emr.CfnCluster.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )],
                    custom_ami_id="customAmiId",
                    ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                        ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                            volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                size_in_gb=123,
                                volume_type="volumeType",
        
                                # the properties below are optional
                                iops=123
                            ),
        
                            # the properties below are optional
                            volumes_per_instance=123
                        )],
                        ebs_optimized=False
                    ),
                    market="market",
                    name="name"
                ),
                placement=emr.CfnCluster.PlacementTypeProperty(
                    availability_zone="availabilityZone"
                ),
                service_access_security_group="serviceAccessSecurityGroup",
                termination_protected=False
            ),
            job_flow_role="jobFlowRole",
            name="name",
            service_role="serviceRole",
        
            # the properties below are optional
            additional_info=additional_info,
            applications=[emr.CfnCluster.ApplicationProperty(
                additional_info={
                    "additional_info_key": "additionalInfo"
                },
                args=["args"],
                name="name",
                version="version"
            )],
            auto_scaling_role="autoScalingRole",
            bootstrap_actions=[emr.CfnCluster.BootstrapActionConfigProperty(
                name="name",
                script_bootstrap_action=emr.CfnCluster.ScriptBootstrapActionConfigProperty(
                    path="path",
        
                    # the properties below are optional
                    args=["args"]
                )
            )],
            configurations=[emr.CfnCluster.ConfigurationProperty(
                classification="classification",
                configuration_properties={
                    "configuration_properties_key": "configurationProperties"
                },
                configurations=[configuration_property_]
            )],
            custom_ami_id="customAmiId",
            ebs_root_volume_size=123,
            kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
                kdc_admin_password="kdcAdminPassword",
                realm="realm",
        
                # the properties below are optional
                ad_domain_join_password="adDomainJoinPassword",
                ad_domain_join_user="adDomainJoinUser",
                cross_realm_trust_principal_password="crossRealmTrustPrincipalPassword"
            ),
            log_encryption_kms_key_id="logEncryptionKmsKeyId",
            log_uri="logUri",
            managed_scaling_policy=emr.CfnCluster.ManagedScalingPolicyProperty(
                compute_limits=emr.CfnCluster.ComputeLimitsProperty(
                    maximum_capacity_units=123,
                    minimum_capacity_units=123,
                    unit_type="unitType",
        
                    # the properties below are optional
                    maximum_core_capacity_units=123,
                    maximum_on_demand_capacity_units=123
                )
            ),
            release_label="releaseLabel",
            scale_down_behavior="scaleDownBehavior",
            security_configuration="securityConfiguration",
            step_concurrency_level=123,
            steps=[emr.CfnCluster.StepConfigProperty(
                hadoop_jar_step=emr.CfnCluster.HadoopJarStepConfigProperty(
                    jar="jar",
        
                    # the properties below are optional
                    args=["args"],
                    main_class="mainClass",
                    step_properties=[emr.CfnCluster.KeyValueProperty(
                        key="key",
                        value="value"
                    )]
                ),
                name="name",
        
                # the properties below are optional
                action_on_failure="actionOnFailure"
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            visible_to_all_users=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instances: typing.Union["CfnCluster.JobFlowInstancesConfigProperty", _IResolvable_da3f097b],
        job_flow_role: builtins.str,
        name: builtins.str,
        service_role: builtins.str,
        additional_info: typing.Any = None,
        applications: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.ApplicationProperty", _IResolvable_da3f097b]]]] = None,
        auto_scaling_role: typing.Optional[builtins.str] = None,
        bootstrap_actions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.BootstrapActionConfigProperty", _IResolvable_da3f097b]]]] = None,
        configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        custom_ami_id: typing.Optional[builtins.str] = None,
        ebs_root_volume_size: typing.Optional[jsii.Number] = None,
        kerberos_attributes: typing.Optional[typing.Union["CfnCluster.KerberosAttributesProperty", _IResolvable_da3f097b]] = None,
        log_encryption_kms_key_id: typing.Optional[builtins.str] = None,
        log_uri: typing.Optional[builtins.str] = None,
        managed_scaling_policy: typing.Optional[typing.Union["CfnCluster.ManagedScalingPolicyProperty", _IResolvable_da3f097b]] = None,
        release_label: typing.Optional[builtins.str] = None,
        scale_down_behavior: typing.Optional[builtins.str] = None,
        security_configuration: typing.Optional[builtins.str] = None,
        step_concurrency_level: typing.Optional[jsii.Number] = None,
        steps: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.StepConfigProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        visible_to_all_users: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::EMR::Cluster``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param instances: A specification of the number and type of Amazon EC2 instances.
        :param job_flow_role: Also called instance profile and EC2 role. An IAM role for an EMR cluster. The EC2 instances of the cluster assume this role. The default role is ``EMR_EC2_DefaultRole`` . In order to use the default role, you must have already created it using the CLI or console.
        :param name: The name of the cluster.
        :param service_role: The IAM role that Amazon EMR assumes in order to access AWS resources on your behalf.
        :param additional_info: A JSON string for selecting additional features.
        :param applications: The applications to install on this cluster, for example, Spark, Flink, Oozie, Zeppelin, and so on.
        :param auto_scaling_role: An IAM role for automatic scaling policies. The default role is ``EMR_AutoScaling_DefaultRole`` . The IAM role provides permissions that the automatic scaling feature requires to launch and terminate EC2 instances in an instance group.
        :param bootstrap_actions: A list of bootstrap actions to run before Hadoop starts on the cluster nodes.
        :param configurations: Applies only to Amazon EMR releases 4.x and later. The list of Configurations supplied to the EMR cluster.
        :param custom_ami_id: Available only in Amazon EMR version 5.7.0 and later. The ID of a custom Amazon EBS-backed Linux AMI if the cluster uses a custom AMI.
        :param ebs_root_volume_size: The size, in GiB, of the Amazon EBS root device volume of the Linux AMI that is used for each EC2 instance. Available in Amazon EMR version 4.x and later.
        :param kerberos_attributes: Attributes for Kerberos configuration when Kerberos authentication is enabled using a security configuration. For more information see `Use Kerberos Authentication <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html>`_ in the *Amazon EMR Management Guide* .
        :param log_encryption_kms_key_id: The AWS KMS key used for encrypting log files. This attribute is only available with EMR version 5.30.0 and later, excluding EMR 6.0.0.
        :param log_uri: The path to the Amazon S3 location where logs for this cluster are stored.
        :param managed_scaling_policy: Creates or updates a managed scaling policy for an Amazon EMR cluster. The managed scaling policy defines the limits for resources, such as EC2 instances that can be added or terminated from a cluster. The policy only applies to the core and task nodes. The master node cannot be scaled after initial configuration.
        :param release_label: The Amazon EMR release label, which determines the version of open-source application packages installed on the cluster. Release labels are in the form ``emr-x.x.x`` , where x.x.x is an Amazon EMR release version such as ``emr-5.14.0`` . For more information about Amazon EMR release versions and included application versions and features, see ` <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/>`_ . The release label applies only to Amazon EMR releases version 4.0 and later. Earlier versions use ``AmiVersion`` .
        :param scale_down_behavior: The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized. ``TERMINATE_AT_INSTANCE_HOUR`` indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. ``TERMINATE_AT_TASK_COMPLETION`` indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. ``TERMINATE_AT_TASK_COMPLETION`` is available only in Amazon EMR version 4.1.0 and later, and is the default for versions of Amazon EMR earlier than 5.1.0.
        :param security_configuration: The name of the security configuration applied to the cluster.
        :param step_concurrency_level: Specifies the number of steps that can be executed concurrently. The default value is ``1`` . The maximum value is ``256`` .
        :param steps: A list of steps to run.
        :param tags: A list of tags associated with a cluster.
        :param visible_to_all_users: Indicates whether the cluster is visible to all IAM users of the AWS account associated with the cluster. If this value is set to ``true`` , all IAM users of that AWS account can view and manage the cluster if they have the proper policy permissions set. If this value is ``false`` , only the IAM user that created the cluster can view and manage it. This value can be changed using the SetVisibleToAllUsers action. .. epigraph:: When you create clusters directly through the EMR console or API, this value is set to ``true`` by default. However, for ``AWS::EMR::Cluster`` resources in CloudFormation, the default is ``false`` .
        '''
        props = CfnClusterProps(
            instances=instances,
            job_flow_role=job_flow_role,
            name=name,
            service_role=service_role,
            additional_info=additional_info,
            applications=applications,
            auto_scaling_role=auto_scaling_role,
            bootstrap_actions=bootstrap_actions,
            configurations=configurations,
            custom_ami_id=custom_ami_id,
            ebs_root_volume_size=ebs_root_volume_size,
            kerberos_attributes=kerberos_attributes,
            log_encryption_kms_key_id=log_encryption_kms_key_id,
            log_uri=log_uri,
            managed_scaling_policy=managed_scaling_policy,
            release_label=release_label,
            scale_down_behavior=scale_down_behavior,
            security_configuration=security_configuration,
            step_concurrency_level=step_concurrency_level,
            steps=steps,
            tags=tags,
            visible_to_all_users=visible_to_all_users,
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
    @jsii.member(jsii_name="attrMasterPublicDns")
    def attr_master_public_dns(self) -> builtins.str:
        '''The public DNS name of the master node (instance), such as ``ec2-12-123-123-123.us-west-2.compute.amazonaws.com`` .

        :cloudformationAttribute: MasterPublicDNS
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrMasterPublicDns"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A list of tags associated with a cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="additionalInfo")
    def additional_info(self) -> typing.Any:
        '''A JSON string for selecting additional features.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-additionalinfo
        '''
        return typing.cast(typing.Any, jsii.get(self, "additionalInfo"))

    @additional_info.setter
    def additional_info(self, value: typing.Any) -> None:
        jsii.set(self, "additionalInfo", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instances")
    def instances(
        self,
    ) -> typing.Union["CfnCluster.JobFlowInstancesConfigProperty", _IResolvable_da3f097b]:
        '''A specification of the number and type of Amazon EC2 instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-instances
        '''
        return typing.cast(typing.Union["CfnCluster.JobFlowInstancesConfigProperty", _IResolvable_da3f097b], jsii.get(self, "instances"))

    @instances.setter
    def instances(
        self,
        value: typing.Union["CfnCluster.JobFlowInstancesConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "instances", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="jobFlowRole")
    def job_flow_role(self) -> builtins.str:
        '''Also called instance profile and EC2 role.

        An IAM role for an EMR cluster. The EC2 instances of the cluster assume this role. The default role is ``EMR_EC2_DefaultRole`` . In order to use the default role, you must have already created it using the CLI or console.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-jobflowrole
        '''
        return typing.cast(builtins.str, jsii.get(self, "jobFlowRole"))

    @job_flow_role.setter
    def job_flow_role(self, value: builtins.str) -> None:
        jsii.set(self, "jobFlowRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceRole")
    def service_role(self) -> builtins.str:
        '''The IAM role that Amazon EMR assumes in order to access AWS resources on your behalf.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-servicerole
        '''
        return typing.cast(builtins.str, jsii.get(self, "serviceRole"))

    @service_role.setter
    def service_role(self, value: builtins.str) -> None:
        jsii.set(self, "serviceRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="applications")
    def applications(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ApplicationProperty", _IResolvable_da3f097b]]]]:
        '''The applications to install on this cluster, for example, Spark, Flink, Oozie, Zeppelin, and so on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-applications
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ApplicationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "applications"))

    @applications.setter
    def applications(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ApplicationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "applications", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingRole")
    def auto_scaling_role(self) -> typing.Optional[builtins.str]:
        '''An IAM role for automatic scaling policies.

        The default role is ``EMR_AutoScaling_DefaultRole`` . The IAM role provides permissions that the automatic scaling feature requires to launch and terminate EC2 instances in an instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-autoscalingrole
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "autoScalingRole"))

    @auto_scaling_role.setter
    def auto_scaling_role(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "autoScalingRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bootstrapActions")
    def bootstrap_actions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.BootstrapActionConfigProperty", _IResolvable_da3f097b]]]]:
        '''A list of bootstrap actions to run before Hadoop starts on the cluster nodes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-bootstrapactions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.BootstrapActionConfigProperty", _IResolvable_da3f097b]]]], jsii.get(self, "bootstrapActions"))

    @bootstrap_actions.setter
    def bootstrap_actions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.BootstrapActionConfigProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "bootstrapActions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="configurations")
    def configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''Applies only to Amazon EMR releases 4.x and later. The list of Configurations supplied to the EMR cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-configurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "configurations"))

    @configurations.setter
    def configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "configurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="customAmiId")
    def custom_ami_id(self) -> typing.Optional[builtins.str]:
        '''Available only in Amazon EMR version 5.7.0 and later. The ID of a custom Amazon EBS-backed Linux AMI if the cluster uses a custom AMI.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-customamiid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "customAmiId"))

    @custom_ami_id.setter
    def custom_ami_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "customAmiId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ebsRootVolumeSize")
    def ebs_root_volume_size(self) -> typing.Optional[jsii.Number]:
        '''The size, in GiB, of the Amazon EBS root device volume of the Linux AMI that is used for each EC2 instance.

        Available in Amazon EMR version 4.x and later.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-ebsrootvolumesize
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "ebsRootVolumeSize"))

    @ebs_root_volume_size.setter
    def ebs_root_volume_size(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "ebsRootVolumeSize", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kerberosAttributes")
    def kerberos_attributes(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.KerberosAttributesProperty", _IResolvable_da3f097b]]:
        '''Attributes for Kerberos configuration when Kerberos authentication is enabled using a security configuration.

        For more information see `Use Kerberos Authentication <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html>`_ in the *Amazon EMR Management Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-kerberosattributes
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.KerberosAttributesProperty", _IResolvable_da3f097b]], jsii.get(self, "kerberosAttributes"))

    @kerberos_attributes.setter
    def kerberos_attributes(
        self,
        value: typing.Optional[typing.Union["CfnCluster.KerberosAttributesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "kerberosAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logEncryptionKmsKeyId")
    def log_encryption_kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The AWS KMS key used for encrypting log files.

        This attribute is only available with EMR version 5.30.0 and later, excluding EMR 6.0.0.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-logencryptionkmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "logEncryptionKmsKeyId"))

    @log_encryption_kms_key_id.setter
    def log_encryption_kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "logEncryptionKmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logUri")
    def log_uri(self) -> typing.Optional[builtins.str]:
        '''The path to the Amazon S3 location where logs for this cluster are stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-loguri
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "logUri"))

    @log_uri.setter
    def log_uri(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "logUri", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedScalingPolicy")
    def managed_scaling_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.ManagedScalingPolicyProperty", _IResolvable_da3f097b]]:
        '''Creates or updates a managed scaling policy for an Amazon EMR cluster.

        The managed scaling policy defines the limits for resources, such as EC2 instances that can be added or terminated from a cluster. The policy only applies to the core and task nodes. The master node cannot be scaled after initial configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-managedscalingpolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.ManagedScalingPolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "managedScalingPolicy"))

    @managed_scaling_policy.setter
    def managed_scaling_policy(
        self,
        value: typing.Optional[typing.Union["CfnCluster.ManagedScalingPolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "managedScalingPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="releaseLabel")
    def release_label(self) -> typing.Optional[builtins.str]:
        '''The Amazon EMR release label, which determines the version of open-source application packages installed on the cluster.

        Release labels are in the form ``emr-x.x.x`` , where x.x.x is an Amazon EMR release version such as ``emr-5.14.0`` . For more information about Amazon EMR release versions and included application versions and features, see ` <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/>`_ . The release label applies only to Amazon EMR releases version 4.0 and later. Earlier versions use ``AmiVersion`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-releaselabel
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "releaseLabel"))

    @release_label.setter
    def release_label(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "releaseLabel", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scaleDownBehavior")
    def scale_down_behavior(self) -> typing.Optional[builtins.str]:
        '''The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized.

        ``TERMINATE_AT_INSTANCE_HOUR`` indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. ``TERMINATE_AT_TASK_COMPLETION`` indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. ``TERMINATE_AT_TASK_COMPLETION`` is available only in Amazon EMR version 4.1.0 and later, and is the default for versions of Amazon EMR earlier than 5.1.0.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-scaledownbehavior
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "scaleDownBehavior"))

    @scale_down_behavior.setter
    def scale_down_behavior(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "scaleDownBehavior", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityConfiguration")
    def security_configuration(self) -> typing.Optional[builtins.str]:
        '''The name of the security configuration applied to the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "securityConfiguration"))

    @security_configuration.setter
    def security_configuration(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "securityConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="stepConcurrencyLevel")
    def step_concurrency_level(self) -> typing.Optional[jsii.Number]:
        '''Specifies the number of steps that can be executed concurrently.

        The default value is ``1`` . The maximum value is ``256`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-stepconcurrencylevel
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "stepConcurrencyLevel"))

    @step_concurrency_level.setter
    def step_concurrency_level(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "stepConcurrencyLevel", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="steps")
    def steps(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.StepConfigProperty", _IResolvable_da3f097b]]]]:
        '''A list of steps to run.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-steps
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.StepConfigProperty", _IResolvable_da3f097b]]]], jsii.get(self, "steps"))

    @steps.setter
    def steps(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.StepConfigProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "steps", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="visibleToAllUsers")
    def visible_to_all_users(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether the cluster is visible to all IAM users of the AWS account associated with the cluster.

        If this value is set to ``true`` , all IAM users of that AWS account can view and manage the cluster if they have the proper policy permissions set. If this value is ``false`` , only the IAM user that created the cluster can view and manage it. This value can be changed using the SetVisibleToAllUsers action.
        .. epigraph::

           When you create clusters directly through the EMR console or API, this value is set to ``true`` by default. However, for ``AWS::EMR::Cluster`` resources in CloudFormation, the default is ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-visibletoallusers
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "visibleToAllUsers"))

    @visible_to_all_users.setter
    def visible_to_all_users(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "visibleToAllUsers", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ApplicationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "additional_info": "additionalInfo",
            "args": "args",
            "name": "name",
            "version": "version",
        },
    )
    class ApplicationProperty:
        def __init__(
            self,
            *,
            additional_info: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            args: typing.Optional[typing.Sequence[builtins.str]] = None,
            name: typing.Optional[builtins.str] = None,
            version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``Application`` is a property of ``AWS::EMR::Cluster`` .

            The ``Application`` property type defines the open-source big data applications for EMR to install and configure when a cluster is created.

            With Amazon EMR release version 4.0 and later, the only accepted parameter is the application ``Name`` . To pass arguments to these applications, you use configuration classifications specified using JSON objects in a ``Configuration`` property. For more information, see `Configuring Applications <https://docs.aws.amazon.com//emr/latest/ReleaseGuide/emr-configure-apps.html>`_ .

            With earlier Amazon EMR releases, the application is any AWS or third-party software that you can add to the cluster. You can specify the version of the application and arguments to pass to it. Amazon EMR accepts and forwards the argument list to the corresponding installation script as a bootstrap action argument.

            :param additional_info: This option is for advanced users only. This is meta information about clusters and applications that are used for testing and troubleshooting.
            :param args: Arguments for Amazon EMR to pass to the application.
            :param name: The name of the application.
            :param version: The version of the application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-application.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                application_property = emr.CfnCluster.ApplicationProperty(
                    additional_info={
                        "additional_info_key": "additionalInfo"
                    },
                    args=["args"],
                    name="name",
                    version="version"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if additional_info is not None:
                self._values["additional_info"] = additional_info
            if args is not None:
                self._values["args"] = args
            if name is not None:
                self._values["name"] = name
            if version is not None:
                self._values["version"] = version

        @builtins.property
        def additional_info(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''This option is for advanced users only.

            This is meta information about clusters and applications that are used for testing and troubleshooting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-application.html#cfn-elasticmapreduce-cluster-application-additionalinfo
            '''
            result = self._values.get("additional_info")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def args(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Arguments for Amazon EMR to pass to the application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-application.html#cfn-elasticmapreduce-cluster-application-args
            '''
            result = self._values.get("args")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-application.html#cfn-elasticmapreduce-cluster-application-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def version(self) -> typing.Optional[builtins.str]:
            '''The version of the application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-application.html#cfn-elasticmapreduce-cluster-application-version
            '''
            result = self._values.get("version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ApplicationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.AutoScalingPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={"constraints": "constraints", "rules": "rules"},
    )
    class AutoScalingPolicyProperty:
        def __init__(
            self,
            *,
            constraints: typing.Union["CfnCluster.ScalingConstraintsProperty", _IResolvable_da3f097b],
            rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.ScalingRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''``AutoScalingPolicy`` is a subproperty of ``InstanceGroupConfig`` .

            ``AutoScalingPolicy`` defines how an instance group dynamically adds and terminates EC2 instances in response to the value of a CloudWatch metric. For more information, see `Using Automatic Scaling in Amazon EMR <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-automatic-scaling.html>`_ in the *Amazon EMR Management Guide* .

            :param constraints: The upper and lower EC2 instance limits for an automatic scaling policy. Automatic scaling activity will not cause an instance group to grow above or below these limits.
            :param rules: The scale-in and scale-out rules that comprise the automatic scaling policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-autoscalingpolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                auto_scaling_policy_property = emr.CfnCluster.AutoScalingPolicyProperty(
                    constraints=emr.CfnCluster.ScalingConstraintsProperty(
                        max_capacity=123,
                        min_capacity=123
                    ),
                    rules=[emr.CfnCluster.ScalingRuleProperty(
                        action=emr.CfnCluster.ScalingActionProperty(
                            simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                scaling_adjustment=123,
                
                                # the properties below are optional
                                adjustment_type="adjustmentType",
                                cool_down=123
                            ),
                
                            # the properties below are optional
                            market="market"
                        ),
                        name="name",
                        trigger=emr.CfnCluster.ScalingTriggerProperty(
                            cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                comparison_operator="comparisonOperator",
                                metric_name="metricName",
                                period=123,
                                threshold=123,
                
                                # the properties below are optional
                                dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                    key="key",
                                    value="value"
                                )],
                                evaluation_periods=123,
                                namespace="namespace",
                                statistic="statistic",
                                unit="unit"
                            )
                        ),
                
                        # the properties below are optional
                        description="description"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "constraints": constraints,
                "rules": rules,
            }

        @builtins.property
        def constraints(
            self,
        ) -> typing.Union["CfnCluster.ScalingConstraintsProperty", _IResolvable_da3f097b]:
            '''The upper and lower EC2 instance limits for an automatic scaling policy.

            Automatic scaling activity will not cause an instance group to grow above or below these limits.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-autoscalingpolicy.html#cfn-elasticmapreduce-cluster-autoscalingpolicy-constraints
            '''
            result = self._values.get("constraints")
            assert result is not None, "Required property 'constraints' is missing"
            return typing.cast(typing.Union["CfnCluster.ScalingConstraintsProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def rules(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ScalingRuleProperty", _IResolvable_da3f097b]]]:
            '''The scale-in and scale-out rules that comprise the automatic scaling policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-autoscalingpolicy.html#cfn-elasticmapreduce-cluster-autoscalingpolicy-rules
            '''
            result = self._values.get("rules")
            assert result is not None, "Required property 'rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ScalingRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AutoScalingPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.BootstrapActionConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "script_bootstrap_action": "scriptBootstrapAction",
        },
    )
    class BootstrapActionConfigProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            script_bootstrap_action: typing.Union["CfnCluster.ScriptBootstrapActionConfigProperty", _IResolvable_da3f097b],
        ) -> None:
            '''``BootstrapActionConfig`` is a property of ``AWS::EMR::Cluster`` that can be used to run bootstrap actions on EMR clusters.

            You can use a bootstrap action to install software and configure EC2 instances for all cluster nodes before EMR installs and configures open-source big data applications on cluster instances. For more information, see `Create Bootstrap Actions to Install Additional Software <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-plan-bootstrap.html>`_ in the *Amazon EMR Management Guide* .

            :param name: The name of the bootstrap action.
            :param script_bootstrap_action: The script run by the bootstrap action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-bootstrapactionconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                bootstrap_action_config_property = emr.CfnCluster.BootstrapActionConfigProperty(
                    name="name",
                    script_bootstrap_action=emr.CfnCluster.ScriptBootstrapActionConfigProperty(
                        path="path",
                
                        # the properties below are optional
                        args=["args"]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "script_bootstrap_action": script_bootstrap_action,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the bootstrap action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-bootstrapactionconfig.html#cfn-elasticmapreduce-cluster-bootstrapactionconfig-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def script_bootstrap_action(
            self,
        ) -> typing.Union["CfnCluster.ScriptBootstrapActionConfigProperty", _IResolvable_da3f097b]:
            '''The script run by the bootstrap action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-bootstrapactionconfig.html#cfn-elasticmapreduce-cluster-bootstrapactionconfig-scriptbootstrapaction
            '''
            result = self._values.get("script_bootstrap_action")
            assert result is not None, "Required property 'script_bootstrap_action' is missing"
            return typing.cast(typing.Union["CfnCluster.ScriptBootstrapActionConfigProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BootstrapActionConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.CloudWatchAlarmDefinitionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "comparison_operator": "comparisonOperator",
            "metric_name": "metricName",
            "period": "period",
            "threshold": "threshold",
            "dimensions": "dimensions",
            "evaluation_periods": "evaluationPeriods",
            "namespace": "namespace",
            "statistic": "statistic",
            "unit": "unit",
        },
    )
    class CloudWatchAlarmDefinitionProperty:
        def __init__(
            self,
            *,
            comparison_operator: builtins.str,
            metric_name: builtins.str,
            period: jsii.Number,
            threshold: jsii.Number,
            dimensions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.MetricDimensionProperty", _IResolvable_da3f097b]]]] = None,
            evaluation_periods: typing.Optional[jsii.Number] = None,
            namespace: typing.Optional[builtins.str] = None,
            statistic: typing.Optional[builtins.str] = None,
            unit: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``CloudWatchAlarmDefinition`` is a subproperty of the ``ScalingTrigger`` property, which determines when to trigger an automatic scaling activity.

            Scaling activity begins when you satisfy the defined alarm conditions.

            :param comparison_operator: Determines how the metric specified by ``MetricName`` is compared to the value specified by ``Threshold`` .
            :param metric_name: The name of the CloudWatch metric that is watched to determine an alarm condition.
            :param period: The period, in seconds, over which the statistic is applied. EMR CloudWatch metrics are emitted every five minutes (300 seconds), so if an EMR CloudWatch metric is specified, specify ``300`` .
            :param threshold: The value against which the specified statistic is compared.
            :param dimensions: A CloudWatch metric dimension.
            :param evaluation_periods: The number of periods, in five-minute increments, during which the alarm condition must exist before the alarm triggers automatic scaling activity. The default value is ``1`` .
            :param namespace: The namespace for the CloudWatch metric. The default is ``AWS/ElasticMapReduce`` .
            :param statistic: The statistic to apply to the metric associated with the alarm. The default is ``AVERAGE`` .
            :param unit: The unit of measure associated with the CloudWatch metric being watched. The value specified for ``Unit`` must correspond to the units specified in the CloudWatch metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                cloud_watch_alarm_definition_property = emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                    comparison_operator="comparisonOperator",
                    metric_name="metricName",
                    period=123,
                    threshold=123,
                
                    # the properties below are optional
                    dimensions=[emr.CfnCluster.MetricDimensionProperty(
                        key="key",
                        value="value"
                    )],
                    evaluation_periods=123,
                    namespace="namespace",
                    statistic="statistic",
                    unit="unit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "comparison_operator": comparison_operator,
                "metric_name": metric_name,
                "period": period,
                "threshold": threshold,
            }
            if dimensions is not None:
                self._values["dimensions"] = dimensions
            if evaluation_periods is not None:
                self._values["evaluation_periods"] = evaluation_periods
            if namespace is not None:
                self._values["namespace"] = namespace
            if statistic is not None:
                self._values["statistic"] = statistic
            if unit is not None:
                self._values["unit"] = unit

        @builtins.property
        def comparison_operator(self) -> builtins.str:
            '''Determines how the metric specified by ``MetricName`` is compared to the value specified by ``Threshold`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-comparisonoperator
            '''
            result = self._values.get("comparison_operator")
            assert result is not None, "Required property 'comparison_operator' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def metric_name(self) -> builtins.str:
            '''The name of the CloudWatch metric that is watched to determine an alarm condition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-metricname
            '''
            result = self._values.get("metric_name")
            assert result is not None, "Required property 'metric_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def period(self) -> jsii.Number:
            '''The period, in seconds, over which the statistic is applied.

            EMR CloudWatch metrics are emitted every five minutes (300 seconds), so if an EMR CloudWatch metric is specified, specify ``300`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-period
            '''
            result = self._values.get("period")
            assert result is not None, "Required property 'period' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def threshold(self) -> jsii.Number:
            '''The value against which the specified statistic is compared.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-threshold
            '''
            result = self._values.get("threshold")
            assert result is not None, "Required property 'threshold' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def dimensions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.MetricDimensionProperty", _IResolvable_da3f097b]]]]:
            '''A CloudWatch metric dimension.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-dimensions
            '''
            result = self._values.get("dimensions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.MetricDimensionProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def evaluation_periods(self) -> typing.Optional[jsii.Number]:
            '''The number of periods, in five-minute increments, during which the alarm condition must exist before the alarm triggers automatic scaling activity.

            The default value is ``1`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-evaluationperiods
            '''
            result = self._values.get("evaluation_periods")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def namespace(self) -> typing.Optional[builtins.str]:
            '''The namespace for the CloudWatch metric.

            The default is ``AWS/ElasticMapReduce`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-namespace
            '''
            result = self._values.get("namespace")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def statistic(self) -> typing.Optional[builtins.str]:
            '''The statistic to apply to the metric associated with the alarm.

            The default is ``AVERAGE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-statistic
            '''
            result = self._values.get("statistic")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def unit(self) -> typing.Optional[builtins.str]:
            '''The unit of measure associated with the CloudWatch metric being watched.

            The value specified for ``Unit`` must correspond to the units specified in the CloudWatch metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-cluster-cloudwatchalarmdefinition-unit
            '''
            result = self._values.get("unit")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CloudWatchAlarmDefinitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ComputeLimitsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "maximum_capacity_units": "maximumCapacityUnits",
            "minimum_capacity_units": "minimumCapacityUnits",
            "unit_type": "unitType",
            "maximum_core_capacity_units": "maximumCoreCapacityUnits",
            "maximum_on_demand_capacity_units": "maximumOnDemandCapacityUnits",
        },
    )
    class ComputeLimitsProperty:
        def __init__(
            self,
            *,
            maximum_capacity_units: jsii.Number,
            minimum_capacity_units: jsii.Number,
            unit_type: builtins.str,
            maximum_core_capacity_units: typing.Optional[jsii.Number] = None,
            maximum_on_demand_capacity_units: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The EC2 unit limits for a managed scaling policy.

            The managed scaling activity of a cluster can not be above or below these limits. The limit only applies to the core and task nodes. The master node cannot be scaled after initial configuration.

            :param maximum_capacity_units: The upper boundary of EC2 units. It is measured through vCPU cores or instances for instance groups and measured through units for instance fleets. Managed scaling activities are not allowed beyond this boundary. The limit only applies to the core and task nodes. The master node cannot be scaled after initial configuration.
            :param minimum_capacity_units: The lower boundary of EC2 units. It is measured through vCPU cores or instances for instance groups and measured through units for instance fleets. Managed scaling activities are not allowed beyond this boundary. The limit only applies to the core and task nodes. The master node cannot be scaled after initial configuration.
            :param unit_type: The unit type used for specifying a managed scaling policy.
            :param maximum_core_capacity_units: The upper boundary of EC2 units for core node type in a cluster. It is measured through vCPU cores or instances for instance groups and measured through units for instance fleets. The core units are not allowed to scale beyond this boundary. The parameter is used to split capacity allocation between core and task nodes.
            :param maximum_on_demand_capacity_units: The upper boundary of On-Demand EC2 units. It is measured through vCPU cores or instances for instance groups and measured through units for instance fleets. The On-Demand units are not allowed to scale beyond this boundary. The parameter is used to split capacity allocation between On-Demand and Spot Instances.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-computelimits.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                compute_limits_property = emr.CfnCluster.ComputeLimitsProperty(
                    maximum_capacity_units=123,
                    minimum_capacity_units=123,
                    unit_type="unitType",
                
                    # the properties below are optional
                    maximum_core_capacity_units=123,
                    maximum_on_demand_capacity_units=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "maximum_capacity_units": maximum_capacity_units,
                "minimum_capacity_units": minimum_capacity_units,
                "unit_type": unit_type,
            }
            if maximum_core_capacity_units is not None:
                self._values["maximum_core_capacity_units"] = maximum_core_capacity_units
            if maximum_on_demand_capacity_units is not None:
                self._values["maximum_on_demand_capacity_units"] = maximum_on_demand_capacity_units

        @builtins.property
        def maximum_capacity_units(self) -> jsii.Number:
            '''The upper boundary of EC2 units.

            It is measured through vCPU cores or instances for instance groups and measured through units for instance fleets. Managed scaling activities are not allowed beyond this boundary. The limit only applies to the core and task nodes. The master node cannot be scaled after initial configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-computelimits.html#cfn-elasticmapreduce-cluster-computelimits-maximumcapacityunits
            '''
            result = self._values.get("maximum_capacity_units")
            assert result is not None, "Required property 'maximum_capacity_units' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def minimum_capacity_units(self) -> jsii.Number:
            '''The lower boundary of EC2 units.

            It is measured through vCPU cores or instances for instance groups and measured through units for instance fleets. Managed scaling activities are not allowed beyond this boundary. The limit only applies to the core and task nodes. The master node cannot be scaled after initial configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-computelimits.html#cfn-elasticmapreduce-cluster-computelimits-minimumcapacityunits
            '''
            result = self._values.get("minimum_capacity_units")
            assert result is not None, "Required property 'minimum_capacity_units' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def unit_type(self) -> builtins.str:
            '''The unit type used for specifying a managed scaling policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-computelimits.html#cfn-elasticmapreduce-cluster-computelimits-unittype
            '''
            result = self._values.get("unit_type")
            assert result is not None, "Required property 'unit_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def maximum_core_capacity_units(self) -> typing.Optional[jsii.Number]:
            '''The upper boundary of EC2 units for core node type in a cluster.

            It is measured through vCPU cores or instances for instance groups and measured through units for instance fleets. The core units are not allowed to scale beyond this boundary. The parameter is used to split capacity allocation between core and task nodes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-computelimits.html#cfn-elasticmapreduce-cluster-computelimits-maximumcorecapacityunits
            '''
            result = self._values.get("maximum_core_capacity_units")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def maximum_on_demand_capacity_units(self) -> typing.Optional[jsii.Number]:
            '''The upper boundary of On-Demand EC2 units.

            It is measured through vCPU cores or instances for instance groups and measured through units for instance fleets. The On-Demand units are not allowed to scale beyond this boundary. The parameter is used to split capacity allocation between On-Demand and Spot Instances.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-computelimits.html#cfn-elasticmapreduce-cluster-computelimits-maximumondemandcapacityunits
            '''
            result = self._values.get("maximum_on_demand_capacity_units")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ComputeLimitsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "classification": "classification",
            "configuration_properties": "configurationProperties",
            "configurations": "configurations",
        },
    )
    class ConfigurationProperty:
        def __init__(
            self,
            *,
            classification: typing.Optional[builtins.str] = None,
            configuration_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''.. epigraph::

   Used only with Amazon EMR release 4.0 and later.

            ``Configuration`` is a subproperty of ``InstanceFleetConfig`` or ``InstanceGroupConfig`` . ``Configuration`` specifies optional configurations for customizing open-source big data applications and environment parameters. A configuration consists of a classification, properties, and optional nested configurations. A classification refers to an application-specific configuration file. Properties are the settings you want to change in that file. For more information, see `Configuring Applications <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-configure-apps.html>`_ in the *Amazon EMR Release Guide* .

            :param classification: The classification within a configuration.
            :param configuration_properties: A list of additional configurations to apply within a configuration object.
            :param configurations: A list of additional configurations to apply within a configuration object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-configuration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                # configuration_property_: emr.CfnCluster.ConfigurationProperty
                
                configuration_property = emr.CfnCluster.ConfigurationProperty(
                    classification="classification",
                    configuration_properties={
                        "configuration_properties_key": "configurationProperties"
                    },
                    configurations=[emr.CfnCluster.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if classification is not None:
                self._values["classification"] = classification
            if configuration_properties is not None:
                self._values["configuration_properties"] = configuration_properties
            if configurations is not None:
                self._values["configurations"] = configurations

        @builtins.property
        def classification(self) -> typing.Optional[builtins.str]:
            '''The classification within a configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-configuration.html#cfn-elasticmapreduce-cluster-configuration-classification
            '''
            result = self._values.get("classification")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def configuration_properties(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''A list of additional configurations to apply within a configuration object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-configuration.html#cfn-elasticmapreduce-cluster-configuration-configurationproperties
            '''
            result = self._values.get("configuration_properties")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''A list of additional configurations to apply within a configuration object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-configuration.html#cfn-elasticmapreduce-cluster-configuration-configurations
            '''
            result = self._values.get("configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.EbsBlockDeviceConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "volume_specification": "volumeSpecification",
            "volumes_per_instance": "volumesPerInstance",
        },
    )
    class EbsBlockDeviceConfigProperty:
        def __init__(
            self,
            *,
            volume_specification: typing.Union["CfnCluster.VolumeSpecificationProperty", _IResolvable_da3f097b],
            volumes_per_instance: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``EbsBlockDeviceConfig`` is a subproperty of the ``EbsConfiguration`` property type.

            ``EbsBlockDeviceConfig`` defines the number and type of EBS volumes to associate with all EC2 instances in an EMR cluster.

            :param volume_specification: EBS volume specifications such as volume type, IOPS, and size (GiB) that will be requested for the EBS volume attached to an EC2 instance in the cluster.
            :param volumes_per_instance: Number of EBS volumes with a specific volume configuration that will be associated with every instance in the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-ebsblockdeviceconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                ebs_block_device_config_property = emr.CfnCluster.EbsBlockDeviceConfigProperty(
                    volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                        size_in_gb=123,
                        volume_type="volumeType",
                
                        # the properties below are optional
                        iops=123
                    ),
                
                    # the properties below are optional
                    volumes_per_instance=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "volume_specification": volume_specification,
            }
            if volumes_per_instance is not None:
                self._values["volumes_per_instance"] = volumes_per_instance

        @builtins.property
        def volume_specification(
            self,
        ) -> typing.Union["CfnCluster.VolumeSpecificationProperty", _IResolvable_da3f097b]:
            '''EBS volume specifications such as volume type, IOPS, and size (GiB) that will be requested for the EBS volume attached to an EC2 instance in the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-ebsblockdeviceconfig.html#cfn-elasticmapreduce-cluster-ebsblockdeviceconfig-volumespecification
            '''
            result = self._values.get("volume_specification")
            assert result is not None, "Required property 'volume_specification' is missing"
            return typing.cast(typing.Union["CfnCluster.VolumeSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def volumes_per_instance(self) -> typing.Optional[jsii.Number]:
            '''Number of EBS volumes with a specific volume configuration that will be associated with every instance in the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-ebsblockdeviceconfig.html#cfn-elasticmapreduce-cluster-ebsblockdeviceconfig-volumesperinstance
            '''
            result = self._values.get("volumes_per_instance")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EbsBlockDeviceConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.EbsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ebs_block_device_configs": "ebsBlockDeviceConfigs",
            "ebs_optimized": "ebsOptimized",
        },
    )
    class EbsConfigurationProperty:
        def __init__(
            self,
            *,
            ebs_block_device_configs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]] = None,
            ebs_optimized: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``EbsConfiguration`` is a subproperty of ``InstanceFleetConfig`` or ``InstanceGroupConfig`` .

            ``EbsConfiguration`` determines the EBS volumes to attach to EMR cluster instances.

            :param ebs_block_device_configs: An array of Amazon EBS volume specifications attached to a cluster instance.
            :param ebs_optimized: Indicates whether an Amazon EBS volume is EBS-optimized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-ebsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                ebs_configuration_property = emr.CfnCluster.EbsConfigurationProperty(
                    ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                        volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                            size_in_gb=123,
                            volume_type="volumeType",
                
                            # the properties below are optional
                            iops=123
                        ),
                
                        # the properties below are optional
                        volumes_per_instance=123
                    )],
                    ebs_optimized=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ebs_block_device_configs is not None:
                self._values["ebs_block_device_configs"] = ebs_block_device_configs
            if ebs_optimized is not None:
                self._values["ebs_optimized"] = ebs_optimized

        @builtins.property
        def ebs_block_device_configs(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]]:
            '''An array of Amazon EBS volume specifications attached to a cluster instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-ebsconfiguration.html#cfn-elasticmapreduce-cluster-ebsconfiguration-ebsblockdeviceconfigs
            '''
            result = self._values.get("ebs_block_device_configs")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ebs_optimized(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether an Amazon EBS volume is EBS-optimized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-ebsconfiguration.html#cfn-elasticmapreduce-cluster-ebsconfiguration-ebsoptimized
            '''
            result = self._values.get("ebs_optimized")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EbsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.HadoopJarStepConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "jar": "jar",
            "args": "args",
            "main_class": "mainClass",
            "step_properties": "stepProperties",
        },
    )
    class HadoopJarStepConfigProperty:
        def __init__(
            self,
            *,
            jar: builtins.str,
            args: typing.Optional[typing.Sequence[builtins.str]] = None,
            main_class: typing.Optional[builtins.str] = None,
            step_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.KeyValueProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The ``HadoopJarStepConfig`` property type specifies a job flow step consisting of a JAR file whose main function will be executed.

            The main function submits a job for the cluster to execute as a step on the master node, and then waits for the job to finish or fail before executing subsequent steps.

            :param jar: A path to a JAR file run during the step.
            :param args: A list of command line arguments passed to the JAR file's main function when executed.
            :param main_class: The name of the main class in the specified Java file. If not specified, the JAR file should specify a Main-Class in its manifest file.
            :param step_properties: A list of Java properties that are set when the step runs. You can use these properties to pass key-value pairs to your main function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-hadoopjarstepconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                hadoop_jar_step_config_property = emr.CfnCluster.HadoopJarStepConfigProperty(
                    jar="jar",
                
                    # the properties below are optional
                    args=["args"],
                    main_class="mainClass",
                    step_properties=[emr.CfnCluster.KeyValueProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "jar": jar,
            }
            if args is not None:
                self._values["args"] = args
            if main_class is not None:
                self._values["main_class"] = main_class
            if step_properties is not None:
                self._values["step_properties"] = step_properties

        @builtins.property
        def jar(self) -> builtins.str:
            '''A path to a JAR file run during the step.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-hadoopjarstepconfig.html#cfn-elasticmapreduce-cluster-hadoopjarstepconfig-jar
            '''
            result = self._values.get("jar")
            assert result is not None, "Required property 'jar' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def args(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of command line arguments passed to the JAR file's main function when executed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-hadoopjarstepconfig.html#cfn-elasticmapreduce-cluster-hadoopjarstepconfig-args
            '''
            result = self._values.get("args")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def main_class(self) -> typing.Optional[builtins.str]:
            '''The name of the main class in the specified Java file.

            If not specified, the JAR file should specify a Main-Class in its manifest file.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-hadoopjarstepconfig.html#cfn-elasticmapreduce-cluster-hadoopjarstepconfig-mainclass
            '''
            result = self._values.get("main_class")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def step_properties(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.KeyValueProperty", _IResolvable_da3f097b]]]]:
            '''A list of Java properties that are set when the step runs.

            You can use these properties to pass key-value pairs to your main function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-hadoopjarstepconfig.html#cfn-elasticmapreduce-cluster-hadoopjarstepconfig-stepproperties
            '''
            result = self._values.get("step_properties")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.KeyValueProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HadoopJarStepConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.InstanceFleetConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "instance_type_configs": "instanceTypeConfigs",
            "launch_specifications": "launchSpecifications",
            "name": "name",
            "target_on_demand_capacity": "targetOnDemandCapacity",
            "target_spot_capacity": "targetSpotCapacity",
        },
    )
    class InstanceFleetConfigProperty:
        def __init__(
            self,
            *,
            instance_type_configs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.InstanceTypeConfigProperty", _IResolvable_da3f097b]]]] = None,
            launch_specifications: typing.Optional[typing.Union["CfnCluster.InstanceFleetProvisioningSpecificationsProperty", _IResolvable_da3f097b]] = None,
            name: typing.Optional[builtins.str] = None,
            target_on_demand_capacity: typing.Optional[jsii.Number] = None,
            target_spot_capacity: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Use ``InstanceFleetConfig`` to define instance fleets for an EMR cluster.

            A cluster can not use both instance fleets and instance groups. For more information, see `Configure Instance Fleets <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-instance-group-configuration.html>`_ in the *Amazon EMR Management Guide* .
            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

            :param instance_type_configs: The instance type configurations that define the EC2 instances in the instance fleet.
            :param launch_specifications: The launch specification for the instance fleet.
            :param name: The friendly name of the instance fleet.
            :param target_on_demand_capacity: The target capacity of On-Demand units for the instance fleet, which determines how many On-Demand instances to provision. When the instance fleet launches, Amazon EMR tries to provision On-Demand instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When an On-Demand instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units. .. epigraph:: If not specified or set to 0, only Spot instances are provisioned for the instance fleet using ``TargetSpotCapacity`` . At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.
            :param target_spot_capacity: The target capacity of Spot units for the instance fleet, which determines how many Spot instances to provision. When the instance fleet launches, Amazon EMR tries to provision Spot instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When a Spot instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units. .. epigraph:: If not specified or set to 0, only On-Demand instances are provisioned for the instance fleet. At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                # configuration_property_: emr.CfnCluster.ConfigurationProperty
                
                instance_fleet_config_property = emr.CfnCluster.InstanceFleetConfigProperty(
                    instance_type_configs=[emr.CfnCluster.InstanceTypeConfigProperty(
                        instance_type="instanceType",
                
                        # the properties below are optional
                        bid_price="bidPrice",
                        bid_price_as_percentage_of_on_demand_price=123,
                        configurations=[emr.CfnCluster.ConfigurationProperty(
                            classification="classification",
                            configuration_properties={
                                "configuration_properties_key": "configurationProperties"
                            },
                            configurations=[configuration_property_]
                        )],
                        custom_ami_id="customAmiId",
                        ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                            ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                    size_in_gb=123,
                                    volume_type="volumeType",
                
                                    # the properties below are optional
                                    iops=123
                                ),
                
                                # the properties below are optional
                                volumes_per_instance=123
                            )],
                            ebs_optimized=False
                        ),
                        weighted_capacity=123
                    )],
                    launch_specifications=emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty(
                        on_demand_specification=emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                            allocation_strategy="allocationStrategy"
                        ),
                        spot_specification=emr.CfnCluster.SpotProvisioningSpecificationProperty(
                            timeout_action="timeoutAction",
                            timeout_duration_minutes=123,
                
                            # the properties below are optional
                            allocation_strategy="allocationStrategy",
                            block_duration_minutes=123
                        )
                    ),
                    name="name",
                    target_on_demand_capacity=123,
                    target_spot_capacity=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if instance_type_configs is not None:
                self._values["instance_type_configs"] = instance_type_configs
            if launch_specifications is not None:
                self._values["launch_specifications"] = launch_specifications
            if name is not None:
                self._values["name"] = name
            if target_on_demand_capacity is not None:
                self._values["target_on_demand_capacity"] = target_on_demand_capacity
            if target_spot_capacity is not None:
                self._values["target_spot_capacity"] = target_spot_capacity

        @builtins.property
        def instance_type_configs(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.InstanceTypeConfigProperty", _IResolvable_da3f097b]]]]:
            '''The instance type configurations that define the EC2 instances in the instance fleet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetconfig.html#cfn-elasticmapreduce-cluster-instancefleetconfig-instancetypeconfigs
            '''
            result = self._values.get("instance_type_configs")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.InstanceTypeConfigProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def launch_specifications(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.InstanceFleetProvisioningSpecificationsProperty", _IResolvable_da3f097b]]:
            '''The launch specification for the instance fleet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetconfig.html#cfn-elasticmapreduce-cluster-instancefleetconfig-launchspecifications
            '''
            result = self._values.get("launch_specifications")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.InstanceFleetProvisioningSpecificationsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The friendly name of the instance fleet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetconfig.html#cfn-elasticmapreduce-cluster-instancefleetconfig-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def target_on_demand_capacity(self) -> typing.Optional[jsii.Number]:
            '''The target capacity of On-Demand units for the instance fleet, which determines how many On-Demand instances to provision.

            When the instance fleet launches, Amazon EMR tries to provision On-Demand instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When an On-Demand instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units.
            .. epigraph::

               If not specified or set to 0, only Spot instances are provisioned for the instance fleet using ``TargetSpotCapacity`` . At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetconfig.html#cfn-elasticmapreduce-cluster-instancefleetconfig-targetondemandcapacity
            '''
            result = self._values.get("target_on_demand_capacity")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def target_spot_capacity(self) -> typing.Optional[jsii.Number]:
            '''The target capacity of Spot units for the instance fleet, which determines how many Spot instances to provision.

            When the instance fleet launches, Amazon EMR tries to provision Spot instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When a Spot instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units.
            .. epigraph::

               If not specified or set to 0, only On-Demand instances are provisioned for the instance fleet. At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetconfig.html#cfn-elasticmapreduce-cluster-instancefleetconfig-targetspotcapacity
            '''
            result = self._values.get("target_spot_capacity")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceFleetConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "on_demand_specification": "onDemandSpecification",
            "spot_specification": "spotSpecification",
        },
    )
    class InstanceFleetProvisioningSpecificationsProperty:
        def __init__(
            self,
            *,
            on_demand_specification: typing.Optional[typing.Union["CfnCluster.OnDemandProvisioningSpecificationProperty", _IResolvable_da3f097b]] = None,
            spot_specification: typing.Optional[typing.Union["CfnCluster.SpotProvisioningSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``InstanceFleetProvisioningSpecification`` is a subproperty of ``InstanceFleetConfig`` .

            ``InstanceFleetProvisioningSpecification`` defines the launch specification for Spot instances in an instance fleet, which determines the defined duration and provisioning timeout behavior for Spot instances.
            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

            :param on_demand_specification: The launch specification for On-Demand Instances in the instance fleet, which determines the allocation strategy. .. epigraph:: The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions. On-Demand Instances allocation strategy is available in Amazon EMR version 5.12.1 and later.
            :param spot_specification: The launch specification for Spot Instances in the fleet, which determines the defined duration, provisioning timeout behavior, and allocation strategy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetprovisioningspecifications.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                instance_fleet_provisioning_specifications_property = emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty(
                    on_demand_specification=emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                        allocation_strategy="allocationStrategy"
                    ),
                    spot_specification=emr.CfnCluster.SpotProvisioningSpecificationProperty(
                        timeout_action="timeoutAction",
                        timeout_duration_minutes=123,
                
                        # the properties below are optional
                        allocation_strategy="allocationStrategy",
                        block_duration_minutes=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if on_demand_specification is not None:
                self._values["on_demand_specification"] = on_demand_specification
            if spot_specification is not None:
                self._values["spot_specification"] = spot_specification

        @builtins.property
        def on_demand_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.OnDemandProvisioningSpecificationProperty", _IResolvable_da3f097b]]:
            '''The launch specification for On-Demand Instances in the instance fleet, which determines the allocation strategy.

            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions. On-Demand Instances allocation strategy is available in Amazon EMR version 5.12.1 and later.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetprovisioningspecifications.html#cfn-elasticmapreduce-cluster-instancefleetprovisioningspecifications-ondemandspecification
            '''
            result = self._values.get("on_demand_specification")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.OnDemandProvisioningSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def spot_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.SpotProvisioningSpecificationProperty", _IResolvable_da3f097b]]:
            '''The launch specification for Spot Instances in the fleet, which determines the defined duration, provisioning timeout behavior, and allocation strategy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancefleetprovisioningspecifications.html#cfn-elasticmapreduce-cluster-instancefleetprovisioningspecifications-spotspecification
            '''
            result = self._values.get("spot_specification")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.SpotProvisioningSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceFleetProvisioningSpecificationsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.InstanceGroupConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "instance_count": "instanceCount",
            "instance_type": "instanceType",
            "auto_scaling_policy": "autoScalingPolicy",
            "bid_price": "bidPrice",
            "configurations": "configurations",
            "custom_ami_id": "customAmiId",
            "ebs_configuration": "ebsConfiguration",
            "market": "market",
            "name": "name",
        },
    )
    class InstanceGroupConfigProperty:
        def __init__(
            self,
            *,
            instance_count: jsii.Number,
            instance_type: builtins.str,
            auto_scaling_policy: typing.Optional[typing.Union["CfnCluster.AutoScalingPolicyProperty", _IResolvable_da3f097b]] = None,
            bid_price: typing.Optional[builtins.str] = None,
            configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]] = None,
            custom_ami_id: typing.Optional[builtins.str] = None,
            ebs_configuration: typing.Optional[typing.Union["CfnCluster.EbsConfigurationProperty", _IResolvable_da3f097b]] = None,
            market: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Use ``InstanceGroupConfig`` to define instance groups for an EMR cluster.

            A cluster can not use both instance groups and instance fleets. For more information, see `Create a Cluster with Instance Fleets or Uniform Instance Groups <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-instance-group-configuration.html>`_ in the *Amazon EMR Management Guide* .

            :param instance_count: Target number of instances for the instance group.
            :param instance_type: The EC2 instance type for all instances in the instance group.
            :param auto_scaling_policy: ``AutoScalingPolicy`` is a subproperty of the `InstanceGroupConfig <https://docs.aws.amazon.com//AWSCloudFormation/latest/UserGuide/aws-properties-emr-cluster-jobflowinstancesconfig-instancegroupconfig.html>`_ property type that specifies the constraints and rules of an automatic scaling policy in Amazon EMR . The automatic scaling policy defines how an instance group dynamically adds and terminates EC2 instances in response to the value of a CloudWatch metric. Only core and task instance groups can use automatic scaling policies. For more information, see `Using Automatic Scaling in Amazon EMR <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-automatic-scaling.html>`_ .
            :param bid_price: If specified, indicates that the instance group uses Spot Instances. This is the maximum price you are willing to pay for Spot Instances. Specify ``OnDemandPrice`` to set the amount equal to the On-Demand price, or specify an amount in USD.
            :param configurations: .. epigraph:: Amazon EMR releases 4.x or later. The list of configurations supplied for an EMR cluster instance group. You can specify a separate configuration for each instance group (master, core, and task).
            :param custom_ami_id: The custom AMI ID to use for the provisioned instance group.
            :param ebs_configuration: EBS configurations that will be attached to each EC2 instance in the instance group.
            :param market: Market type of the EC2 instances used to create a cluster node.
            :param name: Friendly name given to the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                # configuration_property_: emr.CfnCluster.ConfigurationProperty
                
                instance_group_config_property = emr.CfnCluster.InstanceGroupConfigProperty(
                    instance_count=123,
                    instance_type="instanceType",
                
                    # the properties below are optional
                    auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                        constraints=emr.CfnCluster.ScalingConstraintsProperty(
                            max_capacity=123,
                            min_capacity=123
                        ),
                        rules=[emr.CfnCluster.ScalingRuleProperty(
                            action=emr.CfnCluster.ScalingActionProperty(
                                simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                    scaling_adjustment=123,
                
                                    # the properties below are optional
                                    adjustment_type="adjustmentType",
                                    cool_down=123
                                ),
                
                                # the properties below are optional
                                market="market"
                            ),
                            name="name",
                            trigger=emr.CfnCluster.ScalingTriggerProperty(
                                cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                    comparison_operator="comparisonOperator",
                                    metric_name="metricName",
                                    period=123,
                                    threshold=123,
                
                                    # the properties below are optional
                                    dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                        key="key",
                                        value="value"
                                    )],
                                    evaluation_periods=123,
                                    namespace="namespace",
                                    statistic="statistic",
                                    unit="unit"
                                )
                            ),
                
                            # the properties below are optional
                            description="description"
                        )]
                    ),
                    bid_price="bidPrice",
                    configurations=[emr.CfnCluster.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )],
                    custom_ami_id="customAmiId",
                    ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                        ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                            volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                size_in_gb=123,
                                volume_type="volumeType",
                
                                # the properties below are optional
                                iops=123
                            ),
                
                            # the properties below are optional
                            volumes_per_instance=123
                        )],
                        ebs_optimized=False
                    ),
                    market="market",
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_count": instance_count,
                "instance_type": instance_type,
            }
            if auto_scaling_policy is not None:
                self._values["auto_scaling_policy"] = auto_scaling_policy
            if bid_price is not None:
                self._values["bid_price"] = bid_price
            if configurations is not None:
                self._values["configurations"] = configurations
            if custom_ami_id is not None:
                self._values["custom_ami_id"] = custom_ami_id
            if ebs_configuration is not None:
                self._values["ebs_configuration"] = ebs_configuration
            if market is not None:
                self._values["market"] = market
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def instance_count(self) -> jsii.Number:
            '''Target number of instances for the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-instancecount
            '''
            result = self._values.get("instance_count")
            assert result is not None, "Required property 'instance_count' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def instance_type(self) -> builtins.str:
            '''The EC2 instance type for all instances in the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-instancetype
            '''
            result = self._values.get("instance_type")
            assert result is not None, "Required property 'instance_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def auto_scaling_policy(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.AutoScalingPolicyProperty", _IResolvable_da3f097b]]:
            '''``AutoScalingPolicy`` is a subproperty of the `InstanceGroupConfig <https://docs.aws.amazon.com//AWSCloudFormation/latest/UserGuide/aws-properties-emr-cluster-jobflowinstancesconfig-instancegroupconfig.html>`_ property type that specifies the constraints and rules of an automatic scaling policy in Amazon EMR . The automatic scaling policy defines how an instance group dynamically adds and terminates EC2 instances in response to the value of a CloudWatch metric. Only core and task instance groups can use automatic scaling policies. For more information, see `Using Automatic Scaling in Amazon EMR <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-automatic-scaling.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-autoscalingpolicy
            '''
            result = self._values.get("auto_scaling_policy")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.AutoScalingPolicyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def bid_price(self) -> typing.Optional[builtins.str]:
            '''If specified, indicates that the instance group uses Spot Instances.

            This is the maximum price you are willing to pay for Spot Instances. Specify ``OnDemandPrice`` to set the amount equal to the On-Demand price, or specify an amount in USD.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-bidprice
            '''
            result = self._values.get("bid_price")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''.. epigraph::

   Amazon EMR releases 4.x or later.

            The list of configurations supplied for an EMR cluster instance group. You can specify a separate configuration for each instance group (master, core, and task).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-configurations
            '''
            result = self._values.get("configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def custom_ami_id(self) -> typing.Optional[builtins.str]:
            '''The custom AMI ID to use for the provisioned instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-customamiid
            '''
            result = self._values.get("custom_ami_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ebs_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.EbsConfigurationProperty", _IResolvable_da3f097b]]:
            '''EBS configurations that will be attached to each EC2 instance in the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-ebsconfiguration
            '''
            result = self._values.get("ebs_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.EbsConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def market(self) -> typing.Optional[builtins.str]:
            '''Market type of the EC2 instances used to create a cluster node.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-market
            '''
            result = self._values.get("market")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''Friendly name given to the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancegroupconfig.html#cfn-elasticmapreduce-cluster-instancegroupconfig-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceGroupConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.InstanceTypeConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "instance_type": "instanceType",
            "bid_price": "bidPrice",
            "bid_price_as_percentage_of_on_demand_price": "bidPriceAsPercentageOfOnDemandPrice",
            "configurations": "configurations",
            "custom_ami_id": "customAmiId",
            "ebs_configuration": "ebsConfiguration",
            "weighted_capacity": "weightedCapacity",
        },
    )
    class InstanceTypeConfigProperty:
        def __init__(
            self,
            *,
            instance_type: builtins.str,
            bid_price: typing.Optional[builtins.str] = None,
            bid_price_as_percentage_of_on_demand_price: typing.Optional[jsii.Number] = None,
            configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]] = None,
            custom_ami_id: typing.Optional[builtins.str] = None,
            ebs_configuration: typing.Optional[typing.Union["CfnCluster.EbsConfigurationProperty", _IResolvable_da3f097b]] = None,
            weighted_capacity: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''.. epigraph::

   The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

            ``InstanceTypeConfig`` is a sub-property of ``InstanceFleetConfig`` . ``InstanceTypeConfig`` determines the EC2 instances that Amazon EMR attempts to provision to fulfill On-Demand and Spot target capacities.

            :param instance_type: An EC2 instance type, such as ``m3.xlarge`` .
            :param bid_price: The bid price for each EC2 Spot Instance type as defined by ``InstanceType`` . Expressed in USD. If neither ``BidPrice`` nor ``BidPriceAsPercentageOfOnDemandPrice`` is provided, ``BidPriceAsPercentageOfOnDemandPrice`` defaults to 100%.
            :param bid_price_as_percentage_of_on_demand_price: The bid price, as a percentage of On-Demand price, for each EC2 Spot Instance as defined by ``InstanceType`` . Expressed as a number (for example, 20 specifies 20%). If neither ``BidPrice`` nor ``BidPriceAsPercentageOfOnDemandPrice`` is provided, ``BidPriceAsPercentageOfOnDemandPrice`` defaults to 100%.
            :param configurations: A configuration classification that applies when provisioning cluster instances, which can include configurations for applications and software that run on the cluster.
            :param custom_ami_id: The custom AMI ID to use for the instance type.
            :param ebs_configuration: The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by ``InstanceType`` .
            :param weighted_capacity: The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in ``InstanceFleetConfig`` . This value is 1 for a master instance fleet, and must be 1 or greater for core and task instance fleets. Defaults to 1 if not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancetypeconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                # configuration_property_: emr.CfnCluster.ConfigurationProperty
                
                instance_type_config_property = emr.CfnCluster.InstanceTypeConfigProperty(
                    instance_type="instanceType",
                
                    # the properties below are optional
                    bid_price="bidPrice",
                    bid_price_as_percentage_of_on_demand_price=123,
                    configurations=[emr.CfnCluster.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )],
                    custom_ami_id="customAmiId",
                    ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                        ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                            volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                size_in_gb=123,
                                volume_type="volumeType",
                
                                # the properties below are optional
                                iops=123
                            ),
                
                            # the properties below are optional
                            volumes_per_instance=123
                        )],
                        ebs_optimized=False
                    ),
                    weighted_capacity=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_type": instance_type,
            }
            if bid_price is not None:
                self._values["bid_price"] = bid_price
            if bid_price_as_percentage_of_on_demand_price is not None:
                self._values["bid_price_as_percentage_of_on_demand_price"] = bid_price_as_percentage_of_on_demand_price
            if configurations is not None:
                self._values["configurations"] = configurations
            if custom_ami_id is not None:
                self._values["custom_ami_id"] = custom_ami_id
            if ebs_configuration is not None:
                self._values["ebs_configuration"] = ebs_configuration
            if weighted_capacity is not None:
                self._values["weighted_capacity"] = weighted_capacity

        @builtins.property
        def instance_type(self) -> builtins.str:
            '''An EC2 instance type, such as ``m3.xlarge`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancetypeconfig.html#cfn-elasticmapreduce-cluster-instancetypeconfig-instancetype
            '''
            result = self._values.get("instance_type")
            assert result is not None, "Required property 'instance_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bid_price(self) -> typing.Optional[builtins.str]:
            '''The bid price for each EC2 Spot Instance type as defined by ``InstanceType`` .

            Expressed in USD. If neither ``BidPrice`` nor ``BidPriceAsPercentageOfOnDemandPrice`` is provided, ``BidPriceAsPercentageOfOnDemandPrice`` defaults to 100%.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancetypeconfig.html#cfn-elasticmapreduce-cluster-instancetypeconfig-bidprice
            '''
            result = self._values.get("bid_price")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def bid_price_as_percentage_of_on_demand_price(
            self,
        ) -> typing.Optional[jsii.Number]:
            '''The bid price, as a percentage of On-Demand price, for each EC2 Spot Instance as defined by ``InstanceType`` .

            Expressed as a number (for example, 20 specifies 20%). If neither ``BidPrice`` nor ``BidPriceAsPercentageOfOnDemandPrice`` is provided, ``BidPriceAsPercentageOfOnDemandPrice`` defaults to 100%.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancetypeconfig.html#cfn-elasticmapreduce-cluster-instancetypeconfig-bidpriceaspercentageofondemandprice
            '''
            result = self._values.get("bid_price_as_percentage_of_on_demand_price")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''A configuration classification that applies when provisioning cluster instances, which can include configurations for applications and software that run on the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancetypeconfig.html#cfn-elasticmapreduce-cluster-instancetypeconfig-configurations
            '''
            result = self._values.get("configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.ConfigurationProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def custom_ami_id(self) -> typing.Optional[builtins.str]:
            '''The custom AMI ID to use for the instance type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancetypeconfig.html#cfn-elasticmapreduce-cluster-instancetypeconfig-customamiid
            '''
            result = self._values.get("custom_ami_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ebs_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.EbsConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by ``InstanceType`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancetypeconfig.html#cfn-elasticmapreduce-cluster-instancetypeconfig-ebsconfiguration
            '''
            result = self._values.get("ebs_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.EbsConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def weighted_capacity(self) -> typing.Optional[jsii.Number]:
            '''The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in ``InstanceFleetConfig`` .

            This value is 1 for a master instance fleet, and must be 1 or greater for core and task instance fleets. Defaults to 1 if not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-instancetypeconfig.html#cfn-elasticmapreduce-cluster-instancetypeconfig-weightedcapacity
            '''
            result = self._values.get("weighted_capacity")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceTypeConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.JobFlowInstancesConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "additional_master_security_groups": "additionalMasterSecurityGroups",
            "additional_slave_security_groups": "additionalSlaveSecurityGroups",
            "core_instance_fleet": "coreInstanceFleet",
            "core_instance_group": "coreInstanceGroup",
            "ec2_key_name": "ec2KeyName",
            "ec2_subnet_id": "ec2SubnetId",
            "ec2_subnet_ids": "ec2SubnetIds",
            "emr_managed_master_security_group": "emrManagedMasterSecurityGroup",
            "emr_managed_slave_security_group": "emrManagedSlaveSecurityGroup",
            "hadoop_version": "hadoopVersion",
            "keep_job_flow_alive_when_no_steps": "keepJobFlowAliveWhenNoSteps",
            "master_instance_fleet": "masterInstanceFleet",
            "master_instance_group": "masterInstanceGroup",
            "placement": "placement",
            "service_access_security_group": "serviceAccessSecurityGroup",
            "termination_protected": "terminationProtected",
        },
    )
    class JobFlowInstancesConfigProperty:
        def __init__(
            self,
            *,
            additional_master_security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
            additional_slave_security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
            core_instance_fleet: typing.Optional[typing.Union["CfnCluster.InstanceFleetConfigProperty", _IResolvable_da3f097b]] = None,
            core_instance_group: typing.Optional[typing.Union["CfnCluster.InstanceGroupConfigProperty", _IResolvable_da3f097b]] = None,
            ec2_key_name: typing.Optional[builtins.str] = None,
            ec2_subnet_id: typing.Optional[builtins.str] = None,
            ec2_subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            emr_managed_master_security_group: typing.Optional[builtins.str] = None,
            emr_managed_slave_security_group: typing.Optional[builtins.str] = None,
            hadoop_version: typing.Optional[builtins.str] = None,
            keep_job_flow_alive_when_no_steps: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            master_instance_fleet: typing.Optional[typing.Union["CfnCluster.InstanceFleetConfigProperty", _IResolvable_da3f097b]] = None,
            master_instance_group: typing.Optional[typing.Union["CfnCluster.InstanceGroupConfigProperty", _IResolvable_da3f097b]] = None,
            placement: typing.Optional[typing.Union["CfnCluster.PlacementTypeProperty", _IResolvable_da3f097b]] = None,
            service_access_security_group: typing.Optional[builtins.str] = None,
            termination_protected: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``JobFlowInstancesConfig`` is a property of the ``AWS::EMR::Cluster`` resource.

            ``JobFlowInstancesConfig`` defines the instance groups or instance fleets that comprise the cluster. ``JobFlowInstancesConfig`` must contain either ``InstanceFleetConfig`` or ``InstanceGroupConfig`` . They cannot be used together.

            You can now define task instance groups or task instance fleets using the ``TaskInstanceGroups`` and ``TaskInstanceFleets`` subproperties. Using these subproperties reduces delays in provisioning task nodes compared to specifying task nodes with the ``InstanceFleetConfig`` and ``InstanceGroupConfig`` resources.

            :param additional_master_security_groups: A list of additional Amazon EC2 security group IDs for the master node.
            :param additional_slave_security_groups: A list of additional Amazon EC2 security group IDs for the core and task nodes.
            :param core_instance_fleet: Describes the EC2 instances and instance configurations for the core instance fleet when using clusters with the instance fleet configuration.
            :param core_instance_group: Describes the EC2 instances and instance configurations for core instance groups when using clusters with the uniform instance group configuration.
            :param ec2_key_name: The name of the EC2 key pair that can be used to connect to the master node using SSH as the user called "hadoop.".
            :param ec2_subnet_id: Applies to clusters that use the uniform instance group configuration. To launch the cluster in Amazon Virtual Private Cloud (Amazon VPC), set this parameter to the identifier of the Amazon VPC subnet where you want the cluster to launch. If you do not specify this value and your account supports EC2-Classic, the cluster launches in EC2-Classic.
            :param ec2_subnet_ids: Applies to clusters that use the instance fleet configuration. When multiple EC2 subnet IDs are specified, Amazon EMR evaluates them and launches instances in the optimal subnet. .. epigraph:: The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.
            :param emr_managed_master_security_group: The identifier of the Amazon EC2 security group for the master node. If you specify ``EmrManagedMasterSecurityGroup`` , you must also specify ``EmrManagedSlaveSecurityGroup`` .
            :param emr_managed_slave_security_group: The identifier of the Amazon EC2 security group for the core and task nodes. If you specify ``EmrManagedSlaveSecurityGroup`` , you must also specify ``EmrManagedMasterSecurityGroup`` .
            :param hadoop_version: Applies only to Amazon EMR release versions earlier than 4.0. The Hadoop version for the cluster. Valid inputs are "0.18" (no longer maintained), "0.20" (no longer maintained), "0.20.205" (no longer maintained), "1.0.3", "2.2.0", or "2.4.0". If you do not set this value, the default of 0.18 is used, unless the ``AmiVersion`` parameter is set in the RunJobFlow call, in which case the default version of Hadoop for that AMI version is used.
            :param keep_job_flow_alive_when_no_steps: Specifies whether the cluster should remain available after completing all steps. Defaults to ``true`` . For more information about configuring cluster termination, see `Control Cluster Termination <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-termination.html>`_ in the *EMR Management Guide* .
            :param master_instance_fleet: Describes the EC2 instances and instance configurations for the master instance fleet when using clusters with the instance fleet configuration.
            :param master_instance_group: Describes the EC2 instances and instance configurations for the master instance group when using clusters with the uniform instance group configuration.
            :param placement: The Availability Zone in which the cluster runs.
            :param service_access_security_group: The identifier of the Amazon EC2 security group for the Amazon EMR service to access clusters in VPC private subnets.
            :param termination_protected: Specifies whether to lock the cluster to prevent the Amazon EC2 instances from being terminated by API call, user intervention, or in the event of a job-flow error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                # configuration_property_: emr.CfnCluster.ConfigurationProperty
                
                job_flow_instances_config_property = emr.CfnCluster.JobFlowInstancesConfigProperty(
                    additional_master_security_groups=["additionalMasterSecurityGroups"],
                    additional_slave_security_groups=["additionalSlaveSecurityGroups"],
                    core_instance_fleet=emr.CfnCluster.InstanceFleetConfigProperty(
                        instance_type_configs=[emr.CfnCluster.InstanceTypeConfigProperty(
                            instance_type="instanceType",
                
                            # the properties below are optional
                            bid_price="bidPrice",
                            bid_price_as_percentage_of_on_demand_price=123,
                            configurations=[emr.CfnCluster.ConfigurationProperty(
                                classification="classification",
                                configuration_properties={
                                    "configuration_properties_key": "configurationProperties"
                                },
                                configurations=[configuration_property_]
                            )],
                            custom_ami_id="customAmiId",
                            ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                                ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                    volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                        size_in_gb=123,
                                        volume_type="volumeType",
                
                                        # the properties below are optional
                                        iops=123
                                    ),
                
                                    # the properties below are optional
                                    volumes_per_instance=123
                                )],
                                ebs_optimized=False
                            ),
                            weighted_capacity=123
                        )],
                        launch_specifications=emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty(
                            on_demand_specification=emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                                allocation_strategy="allocationStrategy"
                            ),
                            spot_specification=emr.CfnCluster.SpotProvisioningSpecificationProperty(
                                timeout_action="timeoutAction",
                                timeout_duration_minutes=123,
                
                                # the properties below are optional
                                allocation_strategy="allocationStrategy",
                                block_duration_minutes=123
                            )
                        ),
                        name="name",
                        target_on_demand_capacity=123,
                        target_spot_capacity=123
                    ),
                    core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                        instance_count=123,
                        instance_type="instanceType",
                
                        # the properties below are optional
                        auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                            constraints=emr.CfnCluster.ScalingConstraintsProperty(
                                max_capacity=123,
                                min_capacity=123
                            ),
                            rules=[emr.CfnCluster.ScalingRuleProperty(
                                action=emr.CfnCluster.ScalingActionProperty(
                                    simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                        scaling_adjustment=123,
                
                                        # the properties below are optional
                                        adjustment_type="adjustmentType",
                                        cool_down=123
                                    ),
                
                                    # the properties below are optional
                                    market="market"
                                ),
                                name="name",
                                trigger=emr.CfnCluster.ScalingTriggerProperty(
                                    cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                        comparison_operator="comparisonOperator",
                                        metric_name="metricName",
                                        period=123,
                                        threshold=123,
                
                                        # the properties below are optional
                                        dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                            key="key",
                                            value="value"
                                        )],
                                        evaluation_periods=123,
                                        namespace="namespace",
                                        statistic="statistic",
                                        unit="unit"
                                    )
                                ),
                
                                # the properties below are optional
                                description="description"
                            )]
                        ),
                        bid_price="bidPrice",
                        configurations=[emr.CfnCluster.ConfigurationProperty(
                            classification="classification",
                            configuration_properties={
                                "configuration_properties_key": "configurationProperties"
                            },
                            configurations=[configuration_property_]
                        )],
                        custom_ami_id="customAmiId",
                        ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                            ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                    size_in_gb=123,
                                    volume_type="volumeType",
                
                                    # the properties below are optional
                                    iops=123
                                ),
                
                                # the properties below are optional
                                volumes_per_instance=123
                            )],
                            ebs_optimized=False
                        ),
                        market="market",
                        name="name"
                    ),
                    ec2_key_name="ec2KeyName",
                    ec2_subnet_id="ec2SubnetId",
                    ec2_subnet_ids=["ec2SubnetIds"],
                    emr_managed_master_security_group="emrManagedMasterSecurityGroup",
                    emr_managed_slave_security_group="emrManagedSlaveSecurityGroup",
                    hadoop_version="hadoopVersion",
                    keep_job_flow_alive_when_no_steps=False,
                    master_instance_fleet=emr.CfnCluster.InstanceFleetConfigProperty(
                        instance_type_configs=[emr.CfnCluster.InstanceTypeConfigProperty(
                            instance_type="instanceType",
                
                            # the properties below are optional
                            bid_price="bidPrice",
                            bid_price_as_percentage_of_on_demand_price=123,
                            configurations=[emr.CfnCluster.ConfigurationProperty(
                                classification="classification",
                                configuration_properties={
                                    "configuration_properties_key": "configurationProperties"
                                },
                                configurations=[configuration_property_]
                            )],
                            custom_ami_id="customAmiId",
                            ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                                ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                    volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                        size_in_gb=123,
                                        volume_type="volumeType",
                
                                        # the properties below are optional
                                        iops=123
                                    ),
                
                                    # the properties below are optional
                                    volumes_per_instance=123
                                )],
                                ebs_optimized=False
                            ),
                            weighted_capacity=123
                        )],
                        launch_specifications=emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty(
                            on_demand_specification=emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                                allocation_strategy="allocationStrategy"
                            ),
                            spot_specification=emr.CfnCluster.SpotProvisioningSpecificationProperty(
                                timeout_action="timeoutAction",
                                timeout_duration_minutes=123,
                
                                # the properties below are optional
                                allocation_strategy="allocationStrategy",
                                block_duration_minutes=123
                            )
                        ),
                        name="name",
                        target_on_demand_capacity=123,
                        target_spot_capacity=123
                    ),
                    master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                        instance_count=123,
                        instance_type="instanceType",
                
                        # the properties below are optional
                        auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                            constraints=emr.CfnCluster.ScalingConstraintsProperty(
                                max_capacity=123,
                                min_capacity=123
                            ),
                            rules=[emr.CfnCluster.ScalingRuleProperty(
                                action=emr.CfnCluster.ScalingActionProperty(
                                    simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                        scaling_adjustment=123,
                
                                        # the properties below are optional
                                        adjustment_type="adjustmentType",
                                        cool_down=123
                                    ),
                
                                    # the properties below are optional
                                    market="market"
                                ),
                                name="name",
                                trigger=emr.CfnCluster.ScalingTriggerProperty(
                                    cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                        comparison_operator="comparisonOperator",
                                        metric_name="metricName",
                                        period=123,
                                        threshold=123,
                
                                        # the properties below are optional
                                        dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                            key="key",
                                            value="value"
                                        )],
                                        evaluation_periods=123,
                                        namespace="namespace",
                                        statistic="statistic",
                                        unit="unit"
                                    )
                                ),
                
                                # the properties below are optional
                                description="description"
                            )]
                        ),
                        bid_price="bidPrice",
                        configurations=[emr.CfnCluster.ConfigurationProperty(
                            classification="classification",
                            configuration_properties={
                                "configuration_properties_key": "configurationProperties"
                            },
                            configurations=[configuration_property_]
                        )],
                        custom_ami_id="customAmiId",
                        ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                            ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                    size_in_gb=123,
                                    volume_type="volumeType",
                
                                    # the properties below are optional
                                    iops=123
                                ),
                
                                # the properties below are optional
                                volumes_per_instance=123
                            )],
                            ebs_optimized=False
                        ),
                        market="market",
                        name="name"
                    ),
                    placement=emr.CfnCluster.PlacementTypeProperty(
                        availability_zone="availabilityZone"
                    ),
                    service_access_security_group="serviceAccessSecurityGroup",
                    termination_protected=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if additional_master_security_groups is not None:
                self._values["additional_master_security_groups"] = additional_master_security_groups
            if additional_slave_security_groups is not None:
                self._values["additional_slave_security_groups"] = additional_slave_security_groups
            if core_instance_fleet is not None:
                self._values["core_instance_fleet"] = core_instance_fleet
            if core_instance_group is not None:
                self._values["core_instance_group"] = core_instance_group
            if ec2_key_name is not None:
                self._values["ec2_key_name"] = ec2_key_name
            if ec2_subnet_id is not None:
                self._values["ec2_subnet_id"] = ec2_subnet_id
            if ec2_subnet_ids is not None:
                self._values["ec2_subnet_ids"] = ec2_subnet_ids
            if emr_managed_master_security_group is not None:
                self._values["emr_managed_master_security_group"] = emr_managed_master_security_group
            if emr_managed_slave_security_group is not None:
                self._values["emr_managed_slave_security_group"] = emr_managed_slave_security_group
            if hadoop_version is not None:
                self._values["hadoop_version"] = hadoop_version
            if keep_job_flow_alive_when_no_steps is not None:
                self._values["keep_job_flow_alive_when_no_steps"] = keep_job_flow_alive_when_no_steps
            if master_instance_fleet is not None:
                self._values["master_instance_fleet"] = master_instance_fleet
            if master_instance_group is not None:
                self._values["master_instance_group"] = master_instance_group
            if placement is not None:
                self._values["placement"] = placement
            if service_access_security_group is not None:
                self._values["service_access_security_group"] = service_access_security_group
            if termination_protected is not None:
                self._values["termination_protected"] = termination_protected

        @builtins.property
        def additional_master_security_groups(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of additional Amazon EC2 security group IDs for the master node.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-additionalmastersecuritygroups
            '''
            result = self._values.get("additional_master_security_groups")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def additional_slave_security_groups(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of additional Amazon EC2 security group IDs for the core and task nodes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-additionalslavesecuritygroups
            '''
            result = self._values.get("additional_slave_security_groups")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def core_instance_fleet(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.InstanceFleetConfigProperty", _IResolvable_da3f097b]]:
            '''Describes the EC2 instances and instance configurations for the core instance fleet when using clusters with the instance fleet configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-coreinstancefleet
            '''
            result = self._values.get("core_instance_fleet")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.InstanceFleetConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def core_instance_group(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.InstanceGroupConfigProperty", _IResolvable_da3f097b]]:
            '''Describes the EC2 instances and instance configurations for core instance groups when using clusters with the uniform instance group configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-coreinstancegroup
            '''
            result = self._values.get("core_instance_group")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.InstanceGroupConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def ec2_key_name(self) -> typing.Optional[builtins.str]:
            '''The name of the EC2 key pair that can be used to connect to the master node using SSH as the user called "hadoop.".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-ec2keyname
            '''
            result = self._values.get("ec2_key_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ec2_subnet_id(self) -> typing.Optional[builtins.str]:
            '''Applies to clusters that use the uniform instance group configuration.

            To launch the cluster in Amazon Virtual Private Cloud (Amazon VPC), set this parameter to the identifier of the Amazon VPC subnet where you want the cluster to launch. If you do not specify this value and your account supports EC2-Classic, the cluster launches in EC2-Classic.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-ec2subnetid
            '''
            result = self._values.get("ec2_subnet_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ec2_subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Applies to clusters that use the instance fleet configuration.

            When multiple EC2 subnet IDs are specified, Amazon EMR evaluates them and launches instances in the optimal subnet.
            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-ec2subnetids
            '''
            result = self._values.get("ec2_subnet_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def emr_managed_master_security_group(self) -> typing.Optional[builtins.str]:
            '''The identifier of the Amazon EC2 security group for the master node.

            If you specify ``EmrManagedMasterSecurityGroup`` , you must also specify ``EmrManagedSlaveSecurityGroup`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-emrmanagedmastersecuritygroup
            '''
            result = self._values.get("emr_managed_master_security_group")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def emr_managed_slave_security_group(self) -> typing.Optional[builtins.str]:
            '''The identifier of the Amazon EC2 security group for the core and task nodes.

            If you specify ``EmrManagedSlaveSecurityGroup`` , you must also specify ``EmrManagedMasterSecurityGroup`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-emrmanagedslavesecuritygroup
            '''
            result = self._values.get("emr_managed_slave_security_group")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def hadoop_version(self) -> typing.Optional[builtins.str]:
            '''Applies only to Amazon EMR release versions earlier than 4.0. The Hadoop version for the cluster. Valid inputs are "0.18" (no longer maintained), "0.20" (no longer maintained), "0.20.205" (no longer maintained), "1.0.3", "2.2.0", or "2.4.0". If you do not set this value, the default of 0.18 is used, unless the ``AmiVersion`` parameter is set in the RunJobFlow call, in which case the default version of Hadoop for that AMI version is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-hadoopversion
            '''
            result = self._values.get("hadoop_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def keep_job_flow_alive_when_no_steps(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether the cluster should remain available after completing all steps.

            Defaults to ``true`` . For more information about configuring cluster termination, see `Control Cluster Termination <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-termination.html>`_ in the *EMR Management Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-keepjobflowalivewhennosteps
            '''
            result = self._values.get("keep_job_flow_alive_when_no_steps")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def master_instance_fleet(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.InstanceFleetConfigProperty", _IResolvable_da3f097b]]:
            '''Describes the EC2 instances and instance configurations for the master instance fleet when using clusters with the instance fleet configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-masterinstancefleet
            '''
            result = self._values.get("master_instance_fleet")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.InstanceFleetConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def master_instance_group(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.InstanceGroupConfigProperty", _IResolvable_da3f097b]]:
            '''Describes the EC2 instances and instance configurations for the master instance group when using clusters with the uniform instance group configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-masterinstancegroup
            '''
            result = self._values.get("master_instance_group")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.InstanceGroupConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def placement(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.PlacementTypeProperty", _IResolvable_da3f097b]]:
            '''The Availability Zone in which the cluster runs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-placement
            '''
            result = self._values.get("placement")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.PlacementTypeProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def service_access_security_group(self) -> typing.Optional[builtins.str]:
            '''The identifier of the Amazon EC2 security group for the Amazon EMR service to access clusters in VPC private subnets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-serviceaccesssecuritygroup
            '''
            result = self._values.get("service_access_security_group")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def termination_protected(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether to lock the cluster to prevent the Amazon EC2 instances from being terminated by API call, user intervention, or in the event of a job-flow error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html#cfn-elasticmapreduce-cluster-jobflowinstancesconfig-terminationprotected
            '''
            result = self._values.get("termination_protected")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JobFlowInstancesConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.KerberosAttributesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "kdc_admin_password": "kdcAdminPassword",
            "realm": "realm",
            "ad_domain_join_password": "adDomainJoinPassword",
            "ad_domain_join_user": "adDomainJoinUser",
            "cross_realm_trust_principal_password": "crossRealmTrustPrincipalPassword",
        },
    )
    class KerberosAttributesProperty:
        def __init__(
            self,
            *,
            kdc_admin_password: builtins.str,
            realm: builtins.str,
            ad_domain_join_password: typing.Optional[builtins.str] = None,
            ad_domain_join_user: typing.Optional[builtins.str] = None,
            cross_realm_trust_principal_password: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``KerberosAttributes`` is a property of the ``AWS::EMR::Cluster`` resource.

            ``KerberosAttributes`` define the cluster-specific Kerberos configuration when Kerberos authentication is enabled using a security configuration. The cluster-specific configuration must be compatible with the security configuration. For more information see `Use Kerberos Authentication <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html>`_ in the *EMR Management Guide* .

            :param kdc_admin_password: The password used within the cluster for the kadmin service on the cluster-dedicated KDC, which maintains Kerberos principals, password policies, and keytabs for the cluster.
            :param realm: The name of the Kerberos realm to which all nodes in a cluster belong. For example, ``EC2.INTERNAL`` .
            :param ad_domain_join_password: The Active Directory password for ``ADDomainJoinUser`` .
            :param ad_domain_join_user: Required only when establishing a cross-realm trust with an Active Directory domain. A user with sufficient privileges to join resources to the domain.
            :param cross_realm_trust_principal_password: Required only when establishing a cross-realm trust with a KDC in a different realm. The cross-realm principal password, which must be identical across realms.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-kerberosattributes.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                kerberos_attributes_property = emr.CfnCluster.KerberosAttributesProperty(
                    kdc_admin_password="kdcAdminPassword",
                    realm="realm",
                
                    # the properties below are optional
                    ad_domain_join_password="adDomainJoinPassword",
                    ad_domain_join_user="adDomainJoinUser",
                    cross_realm_trust_principal_password="crossRealmTrustPrincipalPassword"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "kdc_admin_password": kdc_admin_password,
                "realm": realm,
            }
            if ad_domain_join_password is not None:
                self._values["ad_domain_join_password"] = ad_domain_join_password
            if ad_domain_join_user is not None:
                self._values["ad_domain_join_user"] = ad_domain_join_user
            if cross_realm_trust_principal_password is not None:
                self._values["cross_realm_trust_principal_password"] = cross_realm_trust_principal_password

        @builtins.property
        def kdc_admin_password(self) -> builtins.str:
            '''The password used within the cluster for the kadmin service on the cluster-dedicated KDC, which maintains Kerberos principals, password policies, and keytabs for the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-kerberosattributes.html#cfn-elasticmapreduce-cluster-kerberosattributes-kdcadminpassword
            '''
            result = self._values.get("kdc_admin_password")
            assert result is not None, "Required property 'kdc_admin_password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def realm(self) -> builtins.str:
            '''The name of the Kerberos realm to which all nodes in a cluster belong.

            For example, ``EC2.INTERNAL`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-kerberosattributes.html#cfn-elasticmapreduce-cluster-kerberosattributes-realm
            '''
            result = self._values.get("realm")
            assert result is not None, "Required property 'realm' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ad_domain_join_password(self) -> typing.Optional[builtins.str]:
            '''The Active Directory password for ``ADDomainJoinUser`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-kerberosattributes.html#cfn-elasticmapreduce-cluster-kerberosattributes-addomainjoinpassword
            '''
            result = self._values.get("ad_domain_join_password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ad_domain_join_user(self) -> typing.Optional[builtins.str]:
            '''Required only when establishing a cross-realm trust with an Active Directory domain.

            A user with sufficient privileges to join resources to the domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-kerberosattributes.html#cfn-elasticmapreduce-cluster-kerberosattributes-addomainjoinuser
            '''
            result = self._values.get("ad_domain_join_user")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def cross_realm_trust_principal_password(self) -> typing.Optional[builtins.str]:
            '''Required only when establishing a cross-realm trust with a KDC in a different realm.

            The cross-realm principal password, which must be identical across realms.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-kerberosattributes.html#cfn-elasticmapreduce-cluster-kerberosattributes-crossrealmtrustprincipalpassword
            '''
            result = self._values.get("cross_realm_trust_principal_password")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KerberosAttributesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.KeyValueProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class KeyValueProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``KeyValue`` is a subproperty of the ``HadoopJarStepConfig`` property type.

            ``KeyValue`` is used to pass parameters to a step.

            :param key: The unique identifier of a key-value pair.
            :param value: The value part of the identified key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-keyvalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                key_value_property = emr.CfnCluster.KeyValueProperty(
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if key is not None:
                self._values["key"] = key
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''The unique identifier of a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-keyvalue.html#cfn-elasticmapreduce-cluster-keyvalue-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value part of the identified key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-keyvalue.html#cfn-elasticmapreduce-cluster-keyvalue-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KeyValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ManagedScalingPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={"compute_limits": "computeLimits"},
    )
    class ManagedScalingPolicyProperty:
        def __init__(
            self,
            *,
            compute_limits: typing.Optional[typing.Union["CfnCluster.ComputeLimitsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Managed scaling policy for an Amazon EMR cluster.

            The policy specifies the limits for resources that can be added or terminated from a cluster. The policy only applies to the core and task nodes. The master node cannot be scaled after initial configuration.

            :param compute_limits: The EC2 unit limits for a managed scaling policy. The managed scaling activity of a cluster is not allowed to go above or below these limits. The limit only applies to the core and task nodes. The master node cannot be scaled after initial configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-managedscalingpolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                managed_scaling_policy_property = emr.CfnCluster.ManagedScalingPolicyProperty(
                    compute_limits=emr.CfnCluster.ComputeLimitsProperty(
                        maximum_capacity_units=123,
                        minimum_capacity_units=123,
                        unit_type="unitType",
                
                        # the properties below are optional
                        maximum_core_capacity_units=123,
                        maximum_on_demand_capacity_units=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if compute_limits is not None:
                self._values["compute_limits"] = compute_limits

        @builtins.property
        def compute_limits(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.ComputeLimitsProperty", _IResolvable_da3f097b]]:
            '''The EC2 unit limits for a managed scaling policy.

            The managed scaling activity of a cluster is not allowed to go above or below these limits. The limit only applies to the core and task nodes. The master node cannot be scaled after initial configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-managedscalingpolicy.html#cfn-elasticmapreduce-cluster-managedscalingpolicy-computelimits
            '''
            result = self._values.get("compute_limits")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.ComputeLimitsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ManagedScalingPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.MetricDimensionProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class MetricDimensionProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''``MetricDimension`` is a subproperty of the ``CloudWatchAlarmDefinition`` property type.

            ``MetricDimension`` specifies a CloudWatch dimension, which is specified with a ``Key`` ``Value`` pair. The key is known as a ``Name`` in CloudWatch. By default, Amazon EMR uses one dimension whose ``Key`` is ``JobFlowID`` and ``Value`` is a variable representing the cluster ID, which is ``${emr.clusterId}`` . This enables the automatic scaling rule for EMR to bootstrap when the cluster ID becomes available during cluster creation.

            :param key: The dimension name.
            :param value: The dimension value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-metricdimension.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                metric_dimension_property = emr.CfnCluster.MetricDimensionProperty(
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "value": value,
            }

        @builtins.property
        def key(self) -> builtins.str:
            '''The dimension name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-metricdimension.html#cfn-elasticmapreduce-cluster-metricdimension-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The dimension value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-metricdimension.html#cfn-elasticmapreduce-cluster-metricdimension-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetricDimensionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.OnDemandProvisioningSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={"allocation_strategy": "allocationStrategy"},
    )
    class OnDemandProvisioningSpecificationProperty:
        def __init__(self, *, allocation_strategy: builtins.str) -> None:
            '''The launch specification for On-Demand Instances in the instance fleet, which determines the allocation strategy.

            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions. On-Demand Instances allocation strategy is available in Amazon EMR version 5.12.1 and later.

            :param allocation_strategy: Specifies the strategy to use in launching On-Demand instance fleets. Currently, the only option is ``lowest-price`` (the default), which launches the lowest price first.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-ondemandprovisioningspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                on_demand_provisioning_specification_property = emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                    allocation_strategy="allocationStrategy"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "allocation_strategy": allocation_strategy,
            }

        @builtins.property
        def allocation_strategy(self) -> builtins.str:
            '''Specifies the strategy to use in launching On-Demand instance fleets.

            Currently, the only option is ``lowest-price`` (the default), which launches the lowest price first.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-ondemandprovisioningspecification.html#cfn-elasticmapreduce-cluster-ondemandprovisioningspecification-allocationstrategy
            '''
            result = self._values.get("allocation_strategy")
            assert result is not None, "Required property 'allocation_strategy' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OnDemandProvisioningSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.PlacementTypeProperty",
        jsii_struct_bases=[],
        name_mapping={"availability_zone": "availabilityZone"},
    )
    class PlacementTypeProperty:
        def __init__(self, *, availability_zone: builtins.str) -> None:
            '''``PlacementType`` is a property of the ``AWS::EMR::Cluster`` resource.

            ``PlacementType`` determines the Amazon EC2 Availability Zone configuration of the cluster (job flow).

            :param availability_zone: The Amazon EC2 Availability Zone for the cluster. ``AvailabilityZone`` is used for uniform instance groups, while ``AvailabilityZones`` (plural) is used for instance fleets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-placementtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                placement_type_property = emr.CfnCluster.PlacementTypeProperty(
                    availability_zone="availabilityZone"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "availability_zone": availability_zone,
            }

        @builtins.property
        def availability_zone(self) -> builtins.str:
            '''The Amazon EC2 Availability Zone for the cluster.

            ``AvailabilityZone`` is used for uniform instance groups, while ``AvailabilityZones`` (plural) is used for instance fleets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-placementtype.html#cfn-elasticmapreduce-cluster-placementtype-availabilityzone
            '''
            result = self._values.get("availability_zone")
            assert result is not None, "Required property 'availability_zone' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PlacementTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ScalingActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "simple_scaling_policy_configuration": "simpleScalingPolicyConfiguration",
            "market": "market",
        },
    )
    class ScalingActionProperty:
        def __init__(
            self,
            *,
            simple_scaling_policy_configuration: typing.Union["CfnCluster.SimpleScalingPolicyConfigurationProperty", _IResolvable_da3f097b],
            market: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``ScalingAction`` is a subproperty of the ``ScalingRule`` property type.

            ``ScalingAction`` determines the type of adjustment the automatic scaling activity makes when triggered, and the periodicity of the adjustment.

            :param simple_scaling_policy_configuration: The type of adjustment the automatic scaling activity makes when triggered, and the periodicity of the adjustment.
            :param market: Not available for instance groups. Instance groups use the market type specified for the group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                scaling_action_property = emr.CfnCluster.ScalingActionProperty(
                    simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                        scaling_adjustment=123,
                
                        # the properties below are optional
                        adjustment_type="adjustmentType",
                        cool_down=123
                    ),
                
                    # the properties below are optional
                    market="market"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "simple_scaling_policy_configuration": simple_scaling_policy_configuration,
            }
            if market is not None:
                self._values["market"] = market

        @builtins.property
        def simple_scaling_policy_configuration(
            self,
        ) -> typing.Union["CfnCluster.SimpleScalingPolicyConfigurationProperty", _IResolvable_da3f097b]:
            '''The type of adjustment the automatic scaling activity makes when triggered, and the periodicity of the adjustment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingaction.html#cfn-elasticmapreduce-cluster-scalingaction-simplescalingpolicyconfiguration
            '''
            result = self._values.get("simple_scaling_policy_configuration")
            assert result is not None, "Required property 'simple_scaling_policy_configuration' is missing"
            return typing.cast(typing.Union["CfnCluster.SimpleScalingPolicyConfigurationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def market(self) -> typing.Optional[builtins.str]:
            '''Not available for instance groups.

            Instance groups use the market type specified for the group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingaction.html#cfn-elasticmapreduce-cluster-scalingaction-market
            '''
            result = self._values.get("market")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ScalingConstraintsProperty",
        jsii_struct_bases=[],
        name_mapping={"max_capacity": "maxCapacity", "min_capacity": "minCapacity"},
    )
    class ScalingConstraintsProperty:
        def __init__(
            self,
            *,
            max_capacity: jsii.Number,
            min_capacity: jsii.Number,
        ) -> None:
            '''``ScalingConstraints`` is a subproperty of the ``AutoScalingPolicy`` property type.

            ``ScalingConstraints`` defines the upper and lower EC2 instance limits for an automatic scaling policy. Automatic scaling activities triggered by automatic scaling rules will not cause an instance group to grow above or shrink below these limits.

            :param max_capacity: The upper boundary of EC2 instances in an instance group beyond which scaling activities are not allowed to grow. Scale-out activities will not add instances beyond this boundary.
            :param min_capacity: The lower boundary of EC2 instances in an instance group below which scaling activities are not allowed to shrink. Scale-in activities will not terminate instances below this boundary.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingconstraints.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                scaling_constraints_property = emr.CfnCluster.ScalingConstraintsProperty(
                    max_capacity=123,
                    min_capacity=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "max_capacity": max_capacity,
                "min_capacity": min_capacity,
            }

        @builtins.property
        def max_capacity(self) -> jsii.Number:
            '''The upper boundary of EC2 instances in an instance group beyond which scaling activities are not allowed to grow.

            Scale-out activities will not add instances beyond this boundary.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingconstraints.html#cfn-elasticmapreduce-cluster-scalingconstraints-maxcapacity
            '''
            result = self._values.get("max_capacity")
            assert result is not None, "Required property 'max_capacity' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def min_capacity(self) -> jsii.Number:
            '''The lower boundary of EC2 instances in an instance group below which scaling activities are not allowed to shrink.

            Scale-in activities will not terminate instances below this boundary.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingconstraints.html#cfn-elasticmapreduce-cluster-scalingconstraints-mincapacity
            '''
            result = self._values.get("min_capacity")
            assert result is not None, "Required property 'min_capacity' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingConstraintsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ScalingRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "action": "action",
            "name": "name",
            "trigger": "trigger",
            "description": "description",
        },
    )
    class ScalingRuleProperty:
        def __init__(
            self,
            *,
            action: typing.Union["CfnCluster.ScalingActionProperty", _IResolvable_da3f097b],
            name: builtins.str,
            trigger: typing.Union["CfnCluster.ScalingTriggerProperty", _IResolvable_da3f097b],
            description: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``ScalingRule`` is a subproperty of the ``AutoScalingPolicy`` property type.

            ``ScalingRule`` defines the scale-in or scale-out rules for scaling activity, including the CloudWatch metric alarm that triggers activity, how EC2 instances are added or removed, and the periodicity of adjustments. The automatic scaling policy for an instance group can comprise one or more automatic scaling rules.

            :param action: The conditions that trigger an automatic scaling activity.
            :param name: The name used to identify an automatic scaling rule. Rule names must be unique within a scaling policy.
            :param trigger: The CloudWatch alarm definition that determines when automatic scaling activity is triggered.
            :param description: A friendly, more verbose description of the automatic scaling rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                scaling_rule_property = emr.CfnCluster.ScalingRuleProperty(
                    action=emr.CfnCluster.ScalingActionProperty(
                        simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                            scaling_adjustment=123,
                
                            # the properties below are optional
                            adjustment_type="adjustmentType",
                            cool_down=123
                        ),
                
                        # the properties below are optional
                        market="market"
                    ),
                    name="name",
                    trigger=emr.CfnCluster.ScalingTriggerProperty(
                        cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                            comparison_operator="comparisonOperator",
                            metric_name="metricName",
                            period=123,
                            threshold=123,
                
                            # the properties below are optional
                            dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                key="key",
                                value="value"
                            )],
                            evaluation_periods=123,
                            namespace="namespace",
                            statistic="statistic",
                            unit="unit"
                        )
                    ),
                
                    # the properties below are optional
                    description="description"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "action": action,
                "name": name,
                "trigger": trigger,
            }
            if description is not None:
                self._values["description"] = description

        @builtins.property
        def action(
            self,
        ) -> typing.Union["CfnCluster.ScalingActionProperty", _IResolvable_da3f097b]:
            '''The conditions that trigger an automatic scaling activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingrule.html#cfn-elasticmapreduce-cluster-scalingrule-action
            '''
            result = self._values.get("action")
            assert result is not None, "Required property 'action' is missing"
            return typing.cast(typing.Union["CfnCluster.ScalingActionProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name used to identify an automatic scaling rule.

            Rule names must be unique within a scaling policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingrule.html#cfn-elasticmapreduce-cluster-scalingrule-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def trigger(
            self,
        ) -> typing.Union["CfnCluster.ScalingTriggerProperty", _IResolvable_da3f097b]:
            '''The CloudWatch alarm definition that determines when automatic scaling activity is triggered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingrule.html#cfn-elasticmapreduce-cluster-scalingrule-trigger
            '''
            result = self._values.get("trigger")
            assert result is not None, "Required property 'trigger' is missing"
            return typing.cast(typing.Union["CfnCluster.ScalingTriggerProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A friendly, more verbose description of the automatic scaling rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingrule.html#cfn-elasticmapreduce-cluster-scalingrule-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ScalingTriggerProperty",
        jsii_struct_bases=[],
        name_mapping={"cloud_watch_alarm_definition": "cloudWatchAlarmDefinition"},
    )
    class ScalingTriggerProperty:
        def __init__(
            self,
            *,
            cloud_watch_alarm_definition: typing.Union["CfnCluster.CloudWatchAlarmDefinitionProperty", _IResolvable_da3f097b],
        ) -> None:
            '''``ScalingTrigger`` is a subproperty of the ``ScalingRule`` property type.

            ``ScalingTrigger`` determines the conditions that trigger an automatic scaling activity.

            :param cloud_watch_alarm_definition: The definition of a CloudWatch metric alarm. When the defined alarm conditions are met along with other trigger parameters, scaling activity begins.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingtrigger.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                scaling_trigger_property = emr.CfnCluster.ScalingTriggerProperty(
                    cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                        comparison_operator="comparisonOperator",
                        metric_name="metricName",
                        period=123,
                        threshold=123,
                
                        # the properties below are optional
                        dimensions=[emr.CfnCluster.MetricDimensionProperty(
                            key="key",
                            value="value"
                        )],
                        evaluation_periods=123,
                        namespace="namespace",
                        statistic="statistic",
                        unit="unit"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cloud_watch_alarm_definition": cloud_watch_alarm_definition,
            }

        @builtins.property
        def cloud_watch_alarm_definition(
            self,
        ) -> typing.Union["CfnCluster.CloudWatchAlarmDefinitionProperty", _IResolvable_da3f097b]:
            '''The definition of a CloudWatch metric alarm.

            When the defined alarm conditions are met along with other trigger parameters, scaling activity begins.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scalingtrigger.html#cfn-elasticmapreduce-cluster-scalingtrigger-cloudwatchalarmdefinition
            '''
            result = self._values.get("cloud_watch_alarm_definition")
            assert result is not None, "Required property 'cloud_watch_alarm_definition' is missing"
            return typing.cast(typing.Union["CfnCluster.CloudWatchAlarmDefinitionProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingTriggerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.ScriptBootstrapActionConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"path": "path", "args": "args"},
    )
    class ScriptBootstrapActionConfigProperty:
        def __init__(
            self,
            *,
            path: builtins.str,
            args: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''``ScriptBootstrapActionConfig`` is a subproperty of the ``BootstrapActionConfig`` property type.

            ``ScriptBootstrapActionConfig`` specifies the arguments and location of the bootstrap script for EMR to run on all cluster nodes before it installs open-source big data applications on them.

            :param path: Location in Amazon S3 of the script to run during a bootstrap action.
            :param args: A list of command line arguments to pass to the bootstrap action script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scriptbootstrapactionconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                script_bootstrap_action_config_property = emr.CfnCluster.ScriptBootstrapActionConfigProperty(
                    path="path",
                
                    # the properties below are optional
                    args=["args"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "path": path,
            }
            if args is not None:
                self._values["args"] = args

        @builtins.property
        def path(self) -> builtins.str:
            '''Location in Amazon S3 of the script to run during a bootstrap action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scriptbootstrapactionconfig.html#cfn-elasticmapreduce-cluster-scriptbootstrapactionconfig-path
            '''
            result = self._values.get("path")
            assert result is not None, "Required property 'path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def args(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of command line arguments to pass to the bootstrap action script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-scriptbootstrapactionconfig.html#cfn-elasticmapreduce-cluster-scriptbootstrapactionconfig-args
            '''
            result = self._values.get("args")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScriptBootstrapActionConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.SimpleScalingPolicyConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "scaling_adjustment": "scalingAdjustment",
            "adjustment_type": "adjustmentType",
            "cool_down": "coolDown",
        },
    )
    class SimpleScalingPolicyConfigurationProperty:
        def __init__(
            self,
            *,
            scaling_adjustment: jsii.Number,
            adjustment_type: typing.Optional[builtins.str] = None,
            cool_down: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``SimpleScalingPolicyConfiguration`` is a subproperty of the ``ScalingAction`` property type.

            ``SimpleScalingPolicyConfiguration`` determines how an automatic scaling action adds or removes instances, the cooldown period, and the number of EC2 instances that are added each time the CloudWatch metric alarm condition is satisfied.

            :param scaling_adjustment: The amount by which to scale in or scale out, based on the specified ``AdjustmentType`` . A positive value adds to the instance group's EC2 instance count while a negative number removes instances. If ``AdjustmentType`` is set to ``EXACT_CAPACITY`` , the number should only be a positive integer. If ``AdjustmentType`` is set to ``PERCENT_CHANGE_IN_CAPACITY`` , the value should express the percentage as an integer. For example, -20 indicates a decrease in 20% increments of cluster capacity.
            :param adjustment_type: The way in which EC2 instances are added (if ``ScalingAdjustment`` is a positive number) or terminated (if ``ScalingAdjustment`` is a negative number) each time the scaling activity is triggered. ``CHANGE_IN_CAPACITY`` is the default. ``CHANGE_IN_CAPACITY`` indicates that the EC2 instance count increments or decrements by ``ScalingAdjustment`` , which should be expressed as an integer. ``PERCENT_CHANGE_IN_CAPACITY`` indicates the instance count increments or decrements by the percentage specified by ``ScalingAdjustment`` , which should be expressed as an integer. For example, 20 indicates an increase in 20% increments of cluster capacity. ``EXACT_CAPACITY`` indicates the scaling activity results in an instance group with the number of EC2 instances specified by ``ScalingAdjustment`` , which should be expressed as a positive integer.
            :param cool_down: The amount of time, in seconds, after a scaling activity completes before any further trigger-related scaling activities can start. The default value is 0.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-simplescalingpolicyconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                simple_scaling_policy_configuration_property = emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                    scaling_adjustment=123,
                
                    # the properties below are optional
                    adjustment_type="adjustmentType",
                    cool_down=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "scaling_adjustment": scaling_adjustment,
            }
            if adjustment_type is not None:
                self._values["adjustment_type"] = adjustment_type
            if cool_down is not None:
                self._values["cool_down"] = cool_down

        @builtins.property
        def scaling_adjustment(self) -> jsii.Number:
            '''The amount by which to scale in or scale out, based on the specified ``AdjustmentType`` .

            A positive value adds to the instance group's EC2 instance count while a negative number removes instances. If ``AdjustmentType`` is set to ``EXACT_CAPACITY`` , the number should only be a positive integer. If ``AdjustmentType`` is set to ``PERCENT_CHANGE_IN_CAPACITY`` , the value should express the percentage as an integer. For example, -20 indicates a decrease in 20% increments of cluster capacity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-simplescalingpolicyconfiguration.html#cfn-elasticmapreduce-cluster-simplescalingpolicyconfiguration-scalingadjustment
            '''
            result = self._values.get("scaling_adjustment")
            assert result is not None, "Required property 'scaling_adjustment' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def adjustment_type(self) -> typing.Optional[builtins.str]:
            '''The way in which EC2 instances are added (if ``ScalingAdjustment`` is a positive number) or terminated (if ``ScalingAdjustment`` is a negative number) each time the scaling activity is triggered.

            ``CHANGE_IN_CAPACITY`` is the default. ``CHANGE_IN_CAPACITY`` indicates that the EC2 instance count increments or decrements by ``ScalingAdjustment`` , which should be expressed as an integer. ``PERCENT_CHANGE_IN_CAPACITY`` indicates the instance count increments or decrements by the percentage specified by ``ScalingAdjustment`` , which should be expressed as an integer. For example, 20 indicates an increase in 20% increments of cluster capacity. ``EXACT_CAPACITY`` indicates the scaling activity results in an instance group with the number of EC2 instances specified by ``ScalingAdjustment`` , which should be expressed as a positive integer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-simplescalingpolicyconfiguration.html#cfn-elasticmapreduce-cluster-simplescalingpolicyconfiguration-adjustmenttype
            '''
            result = self._values.get("adjustment_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def cool_down(self) -> typing.Optional[jsii.Number]:
            '''The amount of time, in seconds, after a scaling activity completes before any further trigger-related scaling activities can start.

            The default value is 0.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-simplescalingpolicyconfiguration.html#cfn-elasticmapreduce-cluster-simplescalingpolicyconfiguration-cooldown
            '''
            result = self._values.get("cool_down")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SimpleScalingPolicyConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.SpotProvisioningSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "timeout_action": "timeoutAction",
            "timeout_duration_minutes": "timeoutDurationMinutes",
            "allocation_strategy": "allocationStrategy",
            "block_duration_minutes": "blockDurationMinutes",
        },
    )
    class SpotProvisioningSpecificationProperty:
        def __init__(
            self,
            *,
            timeout_action: builtins.str,
            timeout_duration_minutes: jsii.Number,
            allocation_strategy: typing.Optional[builtins.str] = None,
            block_duration_minutes: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``SpotProvisioningSpecification`` is a subproperty of the ``InstanceFleetProvisioningSpecifications`` property type.

            ``SpotProvisioningSpecification`` determines the launch specification for Spot instances in the instance fleet, which includes the defined duration and provisioning timeout behavior.
            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

            :param timeout_action: The action to take when ``TargetSpotCapacity`` has not been fulfilled when the ``TimeoutDurationMinutes`` has expired; that is, when all Spot Instances could not be provisioned within the Spot provisioning timeout. Valid values are ``TERMINATE_CLUSTER`` and ``SWITCH_TO_ON_DEMAND`` . SWITCH_TO_ON_DEMAND specifies that if no Spot Instances are available, On-Demand Instances should be provisioned to fulfill any remaining Spot capacity.
            :param timeout_duration_minutes: The spot provisioning timeout period in minutes. If Spot Instances are not provisioned within this time period, the ``TimeOutAction`` is taken. Minimum value is 5 and maximum value is 1440. The timeout applies only during initial provisioning, when the cluster is first created.
            :param allocation_strategy: Specifies the strategy to use in launching Spot Instance fleets. Currently, the only option is capacity-optimized (the default), which launches instances from Spot Instance pools with optimal capacity for the number of instances that are launching.
            :param block_duration_minutes: The defined duration for Spot Instances (also known as Spot blocks) in minutes. When specified, the Spot Instance does not terminate before the defined duration expires, and defined duration pricing for Spot Instances applies. Valid values are 60, 120, 180, 240, 300, or 360. The duration period starts as soon as a Spot Instance receives its instance ID. At the end of the duration, Amazon EC2 marks the Spot Instance for termination and provides a Spot Instance termination notice, which gives the instance a two-minute warning before it terminates. .. epigraph:: Spot Instances with a defined duration (also known as Spot blocks) are no longer available to new customers from July 1, 2021. For customers who have previously used the feature, we will continue to support Spot Instances with a defined duration until December 31, 2022.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-spotprovisioningspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                spot_provisioning_specification_property = emr.CfnCluster.SpotProvisioningSpecificationProperty(
                    timeout_action="timeoutAction",
                    timeout_duration_minutes=123,
                
                    # the properties below are optional
                    allocation_strategy="allocationStrategy",
                    block_duration_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "timeout_action": timeout_action,
                "timeout_duration_minutes": timeout_duration_minutes,
            }
            if allocation_strategy is not None:
                self._values["allocation_strategy"] = allocation_strategy
            if block_duration_minutes is not None:
                self._values["block_duration_minutes"] = block_duration_minutes

        @builtins.property
        def timeout_action(self) -> builtins.str:
            '''The action to take when ``TargetSpotCapacity`` has not been fulfilled when the ``TimeoutDurationMinutes`` has expired;

            that is, when all Spot Instances could not be provisioned within the Spot provisioning timeout. Valid values are ``TERMINATE_CLUSTER`` and ``SWITCH_TO_ON_DEMAND`` . SWITCH_TO_ON_DEMAND specifies that if no Spot Instances are available, On-Demand Instances should be provisioned to fulfill any remaining Spot capacity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-spotprovisioningspecification.html#cfn-elasticmapreduce-cluster-spotprovisioningspecification-timeoutaction
            '''
            result = self._values.get("timeout_action")
            assert result is not None, "Required property 'timeout_action' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def timeout_duration_minutes(self) -> jsii.Number:
            '''The spot provisioning timeout period in minutes.

            If Spot Instances are not provisioned within this time period, the ``TimeOutAction`` is taken. Minimum value is 5 and maximum value is 1440. The timeout applies only during initial provisioning, when the cluster is first created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-spotprovisioningspecification.html#cfn-elasticmapreduce-cluster-spotprovisioningspecification-timeoutdurationminutes
            '''
            result = self._values.get("timeout_duration_minutes")
            assert result is not None, "Required property 'timeout_duration_minutes' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def allocation_strategy(self) -> typing.Optional[builtins.str]:
            '''Specifies the strategy to use in launching Spot Instance fleets.

            Currently, the only option is capacity-optimized (the default), which launches instances from Spot Instance pools with optimal capacity for the number of instances that are launching.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-spotprovisioningspecification.html#cfn-elasticmapreduce-cluster-spotprovisioningspecification-allocationstrategy
            '''
            result = self._values.get("allocation_strategy")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def block_duration_minutes(self) -> typing.Optional[jsii.Number]:
            '''The defined duration for Spot Instances (also known as Spot blocks) in minutes.

            When specified, the Spot Instance does not terminate before the defined duration expires, and defined duration pricing for Spot Instances applies. Valid values are 60, 120, 180, 240, 300, or 360. The duration period starts as soon as a Spot Instance receives its instance ID. At the end of the duration, Amazon EC2 marks the Spot Instance for termination and provides a Spot Instance termination notice, which gives the instance a two-minute warning before it terminates.
            .. epigraph::

               Spot Instances with a defined duration (also known as Spot blocks) are no longer available to new customers from July 1, 2021. For customers who have previously used the feature, we will continue to support Spot Instances with a defined duration until December 31, 2022.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-spotprovisioningspecification.html#cfn-elasticmapreduce-cluster-spotprovisioningspecification-blockdurationminutes
            '''
            result = self._values.get("block_duration_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SpotProvisioningSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.StepConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "hadoop_jar_step": "hadoopJarStep",
            "name": "name",
            "action_on_failure": "actionOnFailure",
        },
    )
    class StepConfigProperty:
        def __init__(
            self,
            *,
            hadoop_jar_step: typing.Union["CfnCluster.HadoopJarStepConfigProperty", _IResolvable_da3f097b],
            name: builtins.str,
            action_on_failure: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``StepConfig`` is a property of the ``AWS::EMR::Cluster`` resource.

            The ``StepConfig`` property type specifies a cluster (job flow) step, which runs only on the master node. Steps are used to submit data processing jobs to the cluster.

            :param hadoop_jar_step: The JAR file used for the step.
            :param name: The name of the step.
            :param action_on_failure: The action to take when the cluster step fails. Possible values are ``CANCEL_AND_WAIT`` and ``CONTINUE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-stepconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                step_config_property = emr.CfnCluster.StepConfigProperty(
                    hadoop_jar_step=emr.CfnCluster.HadoopJarStepConfigProperty(
                        jar="jar",
                
                        # the properties below are optional
                        args=["args"],
                        main_class="mainClass",
                        step_properties=[emr.CfnCluster.KeyValueProperty(
                            key="key",
                            value="value"
                        )]
                    ),
                    name="name",
                
                    # the properties below are optional
                    action_on_failure="actionOnFailure"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "hadoop_jar_step": hadoop_jar_step,
                "name": name,
            }
            if action_on_failure is not None:
                self._values["action_on_failure"] = action_on_failure

        @builtins.property
        def hadoop_jar_step(
            self,
        ) -> typing.Union["CfnCluster.HadoopJarStepConfigProperty", _IResolvable_da3f097b]:
            '''The JAR file used for the step.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-stepconfig.html#cfn-elasticmapreduce-cluster-stepconfig-hadoopjarstep
            '''
            result = self._values.get("hadoop_jar_step")
            assert result is not None, "Required property 'hadoop_jar_step' is missing"
            return typing.cast(typing.Union["CfnCluster.HadoopJarStepConfigProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the step.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-stepconfig.html#cfn-elasticmapreduce-cluster-stepconfig-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def action_on_failure(self) -> typing.Optional[builtins.str]:
            '''The action to take when the cluster step fails.

            Possible values are ``CANCEL_AND_WAIT`` and ``CONTINUE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-stepconfig.html#cfn-elasticmapreduce-cluster-stepconfig-actiononfailure
            '''
            result = self._values.get("action_on_failure")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StepConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnCluster.VolumeSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "size_in_gb": "sizeInGb",
            "volume_type": "volumeType",
            "iops": "iops",
        },
    )
    class VolumeSpecificationProperty:
        def __init__(
            self,
            *,
            size_in_gb: jsii.Number,
            volume_type: builtins.str,
            iops: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``VolumeSpecification`` is a subproperty of the ``EbsBlockDeviceConfig`` property type.

            ``VolumeSecification`` determines the volume type, IOPS, and size (GiB) for EBS volumes attached to EC2 instances.

            :param size_in_gb: The volume size, in gibibytes (GiB). This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.
            :param volume_type: The volume type. Volume types supported are gp2, io1, and standard.
            :param iops: The number of I/O operations per second (IOPS) that the volume supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-volumespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                volume_specification_property = emr.CfnCluster.VolumeSpecificationProperty(
                    size_in_gb=123,
                    volume_type="volumeType",
                
                    # the properties below are optional
                    iops=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "size_in_gb": size_in_gb,
                "volume_type": volume_type,
            }
            if iops is not None:
                self._values["iops"] = iops

        @builtins.property
        def size_in_gb(self) -> jsii.Number:
            '''The volume size, in gibibytes (GiB).

            This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-volumespecification.html#cfn-elasticmapreduce-cluster-volumespecification-sizeingb
            '''
            result = self._values.get("size_in_gb")
            assert result is not None, "Required property 'size_in_gb' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def volume_type(self) -> builtins.str:
            '''The volume type.

            Volume types supported are gp2, io1, and standard.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-volumespecification.html#cfn-elasticmapreduce-cluster-volumespecification-volumetype
            '''
            result = self._values.get("volume_type")
            assert result is not None, "Required property 'volume_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def iops(self) -> typing.Optional[jsii.Number]:
            '''The number of I/O operations per second (IOPS) that the volume supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-volumespecification.html#cfn-elasticmapreduce-cluster-volumespecification-iops
            '''
            result = self._values.get("iops")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VolumeSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_emr.CfnClusterProps",
    jsii_struct_bases=[],
    name_mapping={
        "instances": "instances",
        "job_flow_role": "jobFlowRole",
        "name": "name",
        "service_role": "serviceRole",
        "additional_info": "additionalInfo",
        "applications": "applications",
        "auto_scaling_role": "autoScalingRole",
        "bootstrap_actions": "bootstrapActions",
        "configurations": "configurations",
        "custom_ami_id": "customAmiId",
        "ebs_root_volume_size": "ebsRootVolumeSize",
        "kerberos_attributes": "kerberosAttributes",
        "log_encryption_kms_key_id": "logEncryptionKmsKeyId",
        "log_uri": "logUri",
        "managed_scaling_policy": "managedScalingPolicy",
        "release_label": "releaseLabel",
        "scale_down_behavior": "scaleDownBehavior",
        "security_configuration": "securityConfiguration",
        "step_concurrency_level": "stepConcurrencyLevel",
        "steps": "steps",
        "tags": "tags",
        "visible_to_all_users": "visibleToAllUsers",
    },
)
class CfnClusterProps:
    def __init__(
        self,
        *,
        instances: typing.Union[CfnCluster.JobFlowInstancesConfigProperty, _IResolvable_da3f097b],
        job_flow_role: builtins.str,
        name: builtins.str,
        service_role: builtins.str,
        additional_info: typing.Any = None,
        applications: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnCluster.ApplicationProperty, _IResolvable_da3f097b]]]] = None,
        auto_scaling_role: typing.Optional[builtins.str] = None,
        bootstrap_actions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnCluster.BootstrapActionConfigProperty, _IResolvable_da3f097b]]]] = None,
        configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnCluster.ConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        custom_ami_id: typing.Optional[builtins.str] = None,
        ebs_root_volume_size: typing.Optional[jsii.Number] = None,
        kerberos_attributes: typing.Optional[typing.Union[CfnCluster.KerberosAttributesProperty, _IResolvable_da3f097b]] = None,
        log_encryption_kms_key_id: typing.Optional[builtins.str] = None,
        log_uri: typing.Optional[builtins.str] = None,
        managed_scaling_policy: typing.Optional[typing.Union[CfnCluster.ManagedScalingPolicyProperty, _IResolvable_da3f097b]] = None,
        release_label: typing.Optional[builtins.str] = None,
        scale_down_behavior: typing.Optional[builtins.str] = None,
        security_configuration: typing.Optional[builtins.str] = None,
        step_concurrency_level: typing.Optional[jsii.Number] = None,
        steps: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnCluster.StepConfigProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        visible_to_all_users: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnCluster``.

        :param instances: A specification of the number and type of Amazon EC2 instances.
        :param job_flow_role: Also called instance profile and EC2 role. An IAM role for an EMR cluster. The EC2 instances of the cluster assume this role. The default role is ``EMR_EC2_DefaultRole`` . In order to use the default role, you must have already created it using the CLI or console.
        :param name: The name of the cluster.
        :param service_role: The IAM role that Amazon EMR assumes in order to access AWS resources on your behalf.
        :param additional_info: A JSON string for selecting additional features.
        :param applications: The applications to install on this cluster, for example, Spark, Flink, Oozie, Zeppelin, and so on.
        :param auto_scaling_role: An IAM role for automatic scaling policies. The default role is ``EMR_AutoScaling_DefaultRole`` . The IAM role provides permissions that the automatic scaling feature requires to launch and terminate EC2 instances in an instance group.
        :param bootstrap_actions: A list of bootstrap actions to run before Hadoop starts on the cluster nodes.
        :param configurations: Applies only to Amazon EMR releases 4.x and later. The list of Configurations supplied to the EMR cluster.
        :param custom_ami_id: Available only in Amazon EMR version 5.7.0 and later. The ID of a custom Amazon EBS-backed Linux AMI if the cluster uses a custom AMI.
        :param ebs_root_volume_size: The size, in GiB, of the Amazon EBS root device volume of the Linux AMI that is used for each EC2 instance. Available in Amazon EMR version 4.x and later.
        :param kerberos_attributes: Attributes for Kerberos configuration when Kerberos authentication is enabled using a security configuration. For more information see `Use Kerberos Authentication <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html>`_ in the *Amazon EMR Management Guide* .
        :param log_encryption_kms_key_id: The AWS KMS key used for encrypting log files. This attribute is only available with EMR version 5.30.0 and later, excluding EMR 6.0.0.
        :param log_uri: The path to the Amazon S3 location where logs for this cluster are stored.
        :param managed_scaling_policy: Creates or updates a managed scaling policy for an Amazon EMR cluster. The managed scaling policy defines the limits for resources, such as EC2 instances that can be added or terminated from a cluster. The policy only applies to the core and task nodes. The master node cannot be scaled after initial configuration.
        :param release_label: The Amazon EMR release label, which determines the version of open-source application packages installed on the cluster. Release labels are in the form ``emr-x.x.x`` , where x.x.x is an Amazon EMR release version such as ``emr-5.14.0`` . For more information about Amazon EMR release versions and included application versions and features, see ` <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/>`_ . The release label applies only to Amazon EMR releases version 4.0 and later. Earlier versions use ``AmiVersion`` .
        :param scale_down_behavior: The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized. ``TERMINATE_AT_INSTANCE_HOUR`` indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. ``TERMINATE_AT_TASK_COMPLETION`` indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. ``TERMINATE_AT_TASK_COMPLETION`` is available only in Amazon EMR version 4.1.0 and later, and is the default for versions of Amazon EMR earlier than 5.1.0.
        :param security_configuration: The name of the security configuration applied to the cluster.
        :param step_concurrency_level: Specifies the number of steps that can be executed concurrently. The default value is ``1`` . The maximum value is ``256`` .
        :param steps: A list of steps to run.
        :param tags: A list of tags associated with a cluster.
        :param visible_to_all_users: Indicates whether the cluster is visible to all IAM users of the AWS account associated with the cluster. If this value is set to ``true`` , all IAM users of that AWS account can view and manage the cluster if they have the proper policy permissions set. If this value is ``false`` , only the IAM user that created the cluster can view and manage it. This value can be changed using the SetVisibleToAllUsers action. .. epigraph:: When you create clusters directly through the EMR console or API, this value is set to ``true`` by default. However, for ``AWS::EMR::Cluster`` resources in CloudFormation, the default is ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_emr as emr
            
            # additional_info: Any
            # configuration_property_: emr.CfnCluster.ConfigurationProperty
            
            cfn_cluster_props = emr.CfnClusterProps(
                instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
                    additional_master_security_groups=["additionalMasterSecurityGroups"],
                    additional_slave_security_groups=["additionalSlaveSecurityGroups"],
                    core_instance_fleet=emr.CfnCluster.InstanceFleetConfigProperty(
                        instance_type_configs=[emr.CfnCluster.InstanceTypeConfigProperty(
                            instance_type="instanceType",
            
                            # the properties below are optional
                            bid_price="bidPrice",
                            bid_price_as_percentage_of_on_demand_price=123,
                            configurations=[emr.CfnCluster.ConfigurationProperty(
                                classification="classification",
                                configuration_properties={
                                    "configuration_properties_key": "configurationProperties"
                                },
                                configurations=[configuration_property_]
                            )],
                            custom_ami_id="customAmiId",
                            ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                                ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                    volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                        size_in_gb=123,
                                        volume_type="volumeType",
            
                                        # the properties below are optional
                                        iops=123
                                    ),
            
                                    # the properties below are optional
                                    volumes_per_instance=123
                                )],
                                ebs_optimized=False
                            ),
                            weighted_capacity=123
                        )],
                        launch_specifications=emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty(
                            on_demand_specification=emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                                allocation_strategy="allocationStrategy"
                            ),
                            spot_specification=emr.CfnCluster.SpotProvisioningSpecificationProperty(
                                timeout_action="timeoutAction",
                                timeout_duration_minutes=123,
            
                                # the properties below are optional
                                allocation_strategy="allocationStrategy",
                                block_duration_minutes=123
                            )
                        ),
                        name="name",
                        target_on_demand_capacity=123,
                        target_spot_capacity=123
                    ),
                    core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                        instance_count=123,
                        instance_type="instanceType",
            
                        # the properties below are optional
                        auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                            constraints=emr.CfnCluster.ScalingConstraintsProperty(
                                max_capacity=123,
                                min_capacity=123
                            ),
                            rules=[emr.CfnCluster.ScalingRuleProperty(
                                action=emr.CfnCluster.ScalingActionProperty(
                                    simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                        scaling_adjustment=123,
            
                                        # the properties below are optional
                                        adjustment_type="adjustmentType",
                                        cool_down=123
                                    ),
            
                                    # the properties below are optional
                                    market="market"
                                ),
                                name="name",
                                trigger=emr.CfnCluster.ScalingTriggerProperty(
                                    cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                        comparison_operator="comparisonOperator",
                                        metric_name="metricName",
                                        period=123,
                                        threshold=123,
            
                                        # the properties below are optional
                                        dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                            key="key",
                                            value="value"
                                        )],
                                        evaluation_periods=123,
                                        namespace="namespace",
                                        statistic="statistic",
                                        unit="unit"
                                    )
                                ),
            
                                # the properties below are optional
                                description="description"
                            )]
                        ),
                        bid_price="bidPrice",
                        configurations=[emr.CfnCluster.ConfigurationProperty(
                            classification="classification",
                            configuration_properties={
                                "configuration_properties_key": "configurationProperties"
                            },
                            configurations=[configuration_property_]
                        )],
                        custom_ami_id="customAmiId",
                        ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                            ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                    size_in_gb=123,
                                    volume_type="volumeType",
            
                                    # the properties below are optional
                                    iops=123
                                ),
            
                                # the properties below are optional
                                volumes_per_instance=123
                            )],
                            ebs_optimized=False
                        ),
                        market="market",
                        name="name"
                    ),
                    ec2_key_name="ec2KeyName",
                    ec2_subnet_id="ec2SubnetId",
                    ec2_subnet_ids=["ec2SubnetIds"],
                    emr_managed_master_security_group="emrManagedMasterSecurityGroup",
                    emr_managed_slave_security_group="emrManagedSlaveSecurityGroup",
                    hadoop_version="hadoopVersion",
                    keep_job_flow_alive_when_no_steps=False,
                    master_instance_fleet=emr.CfnCluster.InstanceFleetConfigProperty(
                        instance_type_configs=[emr.CfnCluster.InstanceTypeConfigProperty(
                            instance_type="instanceType",
            
                            # the properties below are optional
                            bid_price="bidPrice",
                            bid_price_as_percentage_of_on_demand_price=123,
                            configurations=[emr.CfnCluster.ConfigurationProperty(
                                classification="classification",
                                configuration_properties={
                                    "configuration_properties_key": "configurationProperties"
                                },
                                configurations=[configuration_property_]
                            )],
                            custom_ami_id="customAmiId",
                            ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                                ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                    volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                        size_in_gb=123,
                                        volume_type="volumeType",
            
                                        # the properties below are optional
                                        iops=123
                                    ),
            
                                    # the properties below are optional
                                    volumes_per_instance=123
                                )],
                                ebs_optimized=False
                            ),
                            weighted_capacity=123
                        )],
                        launch_specifications=emr.CfnCluster.InstanceFleetProvisioningSpecificationsProperty(
                            on_demand_specification=emr.CfnCluster.OnDemandProvisioningSpecificationProperty(
                                allocation_strategy="allocationStrategy"
                            ),
                            spot_specification=emr.CfnCluster.SpotProvisioningSpecificationProperty(
                                timeout_action="timeoutAction",
                                timeout_duration_minutes=123,
            
                                # the properties below are optional
                                allocation_strategy="allocationStrategy",
                                block_duration_minutes=123
                            )
                        ),
                        name="name",
                        target_on_demand_capacity=123,
                        target_spot_capacity=123
                    ),
                    master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                        instance_count=123,
                        instance_type="instanceType",
            
                        # the properties below are optional
                        auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                            constraints=emr.CfnCluster.ScalingConstraintsProperty(
                                max_capacity=123,
                                min_capacity=123
                            ),
                            rules=[emr.CfnCluster.ScalingRuleProperty(
                                action=emr.CfnCluster.ScalingActionProperty(
                                    simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                        scaling_adjustment=123,
            
                                        # the properties below are optional
                                        adjustment_type="adjustmentType",
                                        cool_down=123
                                    ),
            
                                    # the properties below are optional
                                    market="market"
                                ),
                                name="name",
                                trigger=emr.CfnCluster.ScalingTriggerProperty(
                                    cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                        comparison_operator="comparisonOperator",
                                        metric_name="metricName",
                                        period=123,
                                        threshold=123,
            
                                        # the properties below are optional
                                        dimensions=[emr.CfnCluster.MetricDimensionProperty(
                                            key="key",
                                            value="value"
                                        )],
                                        evaluation_periods=123,
                                        namespace="namespace",
                                        statistic="statistic",
                                        unit="unit"
                                    )
                                ),
            
                                # the properties below are optional
                                description="description"
                            )]
                        ),
                        bid_price="bidPrice",
                        configurations=[emr.CfnCluster.ConfigurationProperty(
                            classification="classification",
                            configuration_properties={
                                "configuration_properties_key": "configurationProperties"
                            },
                            configurations=[configuration_property_]
                        )],
                        custom_ami_id="customAmiId",
                        ebs_configuration=emr.CfnCluster.EbsConfigurationProperty(
                            ebs_block_device_configs=[emr.CfnCluster.EbsBlockDeviceConfigProperty(
                                volume_specification=emr.CfnCluster.VolumeSpecificationProperty(
                                    size_in_gb=123,
                                    volume_type="volumeType",
            
                                    # the properties below are optional
                                    iops=123
                                ),
            
                                # the properties below are optional
                                volumes_per_instance=123
                            )],
                            ebs_optimized=False
                        ),
                        market="market",
                        name="name"
                    ),
                    placement=emr.CfnCluster.PlacementTypeProperty(
                        availability_zone="availabilityZone"
                    ),
                    service_access_security_group="serviceAccessSecurityGroup",
                    termination_protected=False
                ),
                job_flow_role="jobFlowRole",
                name="name",
                service_role="serviceRole",
            
                # the properties below are optional
                additional_info=additional_info,
                applications=[emr.CfnCluster.ApplicationProperty(
                    additional_info={
                        "additional_info_key": "additionalInfo"
                    },
                    args=["args"],
                    name="name",
                    version="version"
                )],
                auto_scaling_role="autoScalingRole",
                bootstrap_actions=[emr.CfnCluster.BootstrapActionConfigProperty(
                    name="name",
                    script_bootstrap_action=emr.CfnCluster.ScriptBootstrapActionConfigProperty(
                        path="path",
            
                        # the properties below are optional
                        args=["args"]
                    )
                )],
                configurations=[emr.CfnCluster.ConfigurationProperty(
                    classification="classification",
                    configuration_properties={
                        "configuration_properties_key": "configurationProperties"
                    },
                    configurations=[configuration_property_]
                )],
                custom_ami_id="customAmiId",
                ebs_root_volume_size=123,
                kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
                    kdc_admin_password="kdcAdminPassword",
                    realm="realm",
            
                    # the properties below are optional
                    ad_domain_join_password="adDomainJoinPassword",
                    ad_domain_join_user="adDomainJoinUser",
                    cross_realm_trust_principal_password="crossRealmTrustPrincipalPassword"
                ),
                log_encryption_kms_key_id="logEncryptionKmsKeyId",
                log_uri="logUri",
                managed_scaling_policy=emr.CfnCluster.ManagedScalingPolicyProperty(
                    compute_limits=emr.CfnCluster.ComputeLimitsProperty(
                        maximum_capacity_units=123,
                        minimum_capacity_units=123,
                        unit_type="unitType",
            
                        # the properties below are optional
                        maximum_core_capacity_units=123,
                        maximum_on_demand_capacity_units=123
                    )
                ),
                release_label="releaseLabel",
                scale_down_behavior="scaleDownBehavior",
                security_configuration="securityConfiguration",
                step_concurrency_level=123,
                steps=[emr.CfnCluster.StepConfigProperty(
                    hadoop_jar_step=emr.CfnCluster.HadoopJarStepConfigProperty(
                        jar="jar",
            
                        # the properties below are optional
                        args=["args"],
                        main_class="mainClass",
                        step_properties=[emr.CfnCluster.KeyValueProperty(
                            key="key",
                            value="value"
                        )]
                    ),
                    name="name",
            
                    # the properties below are optional
                    action_on_failure="actionOnFailure"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                visible_to_all_users=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instances": instances,
            "job_flow_role": job_flow_role,
            "name": name,
            "service_role": service_role,
        }
        if additional_info is not None:
            self._values["additional_info"] = additional_info
        if applications is not None:
            self._values["applications"] = applications
        if auto_scaling_role is not None:
            self._values["auto_scaling_role"] = auto_scaling_role
        if bootstrap_actions is not None:
            self._values["bootstrap_actions"] = bootstrap_actions
        if configurations is not None:
            self._values["configurations"] = configurations
        if custom_ami_id is not None:
            self._values["custom_ami_id"] = custom_ami_id
        if ebs_root_volume_size is not None:
            self._values["ebs_root_volume_size"] = ebs_root_volume_size
        if kerberos_attributes is not None:
            self._values["kerberos_attributes"] = kerberos_attributes
        if log_encryption_kms_key_id is not None:
            self._values["log_encryption_kms_key_id"] = log_encryption_kms_key_id
        if log_uri is not None:
            self._values["log_uri"] = log_uri
        if managed_scaling_policy is not None:
            self._values["managed_scaling_policy"] = managed_scaling_policy
        if release_label is not None:
            self._values["release_label"] = release_label
        if scale_down_behavior is not None:
            self._values["scale_down_behavior"] = scale_down_behavior
        if security_configuration is not None:
            self._values["security_configuration"] = security_configuration
        if step_concurrency_level is not None:
            self._values["step_concurrency_level"] = step_concurrency_level
        if steps is not None:
            self._values["steps"] = steps
        if tags is not None:
            self._values["tags"] = tags
        if visible_to_all_users is not None:
            self._values["visible_to_all_users"] = visible_to_all_users

    @builtins.property
    def instances(
        self,
    ) -> typing.Union[CfnCluster.JobFlowInstancesConfigProperty, _IResolvable_da3f097b]:
        '''A specification of the number and type of Amazon EC2 instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-instances
        '''
        result = self._values.get("instances")
        assert result is not None, "Required property 'instances' is missing"
        return typing.cast(typing.Union[CfnCluster.JobFlowInstancesConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def job_flow_role(self) -> builtins.str:
        '''Also called instance profile and EC2 role.

        An IAM role for an EMR cluster. The EC2 instances of the cluster assume this role. The default role is ``EMR_EC2_DefaultRole`` . In order to use the default role, you must have already created it using the CLI or console.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-jobflowrole
        '''
        result = self._values.get("job_flow_role")
        assert result is not None, "Required property 'job_flow_role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service_role(self) -> builtins.str:
        '''The IAM role that Amazon EMR assumes in order to access AWS resources on your behalf.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-servicerole
        '''
        result = self._values.get("service_role")
        assert result is not None, "Required property 'service_role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def additional_info(self) -> typing.Any:
        '''A JSON string for selecting additional features.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-additionalinfo
        '''
        result = self._values.get("additional_info")
        return typing.cast(typing.Any, result)

    @builtins.property
    def applications(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.ApplicationProperty, _IResolvable_da3f097b]]]]:
        '''The applications to install on this cluster, for example, Spark, Flink, Oozie, Zeppelin, and so on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-applications
        '''
        result = self._values.get("applications")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.ApplicationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def auto_scaling_role(self) -> typing.Optional[builtins.str]:
        '''An IAM role for automatic scaling policies.

        The default role is ``EMR_AutoScaling_DefaultRole`` . The IAM role provides permissions that the automatic scaling feature requires to launch and terminate EC2 instances in an instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-autoscalingrole
        '''
        result = self._values.get("auto_scaling_role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def bootstrap_actions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.BootstrapActionConfigProperty, _IResolvable_da3f097b]]]]:
        '''A list of bootstrap actions to run before Hadoop starts on the cluster nodes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-bootstrapactions
        '''
        result = self._values.get("bootstrap_actions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.BootstrapActionConfigProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.ConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''Applies only to Amazon EMR releases 4.x and later. The list of Configurations supplied to the EMR cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-configurations
        '''
        result = self._values.get("configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.ConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def custom_ami_id(self) -> typing.Optional[builtins.str]:
        '''Available only in Amazon EMR version 5.7.0 and later. The ID of a custom Amazon EBS-backed Linux AMI if the cluster uses a custom AMI.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-customamiid
        '''
        result = self._values.get("custom_ami_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ebs_root_volume_size(self) -> typing.Optional[jsii.Number]:
        '''The size, in GiB, of the Amazon EBS root device volume of the Linux AMI that is used for each EC2 instance.

        Available in Amazon EMR version 4.x and later.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-ebsrootvolumesize
        '''
        result = self._values.get("ebs_root_volume_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def kerberos_attributes(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.KerberosAttributesProperty, _IResolvable_da3f097b]]:
        '''Attributes for Kerberos configuration when Kerberos authentication is enabled using a security configuration.

        For more information see `Use Kerberos Authentication <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html>`_ in the *Amazon EMR Management Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-kerberosattributes
        '''
        result = self._values.get("kerberos_attributes")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.KerberosAttributesProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def log_encryption_kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The AWS KMS key used for encrypting log files.

        This attribute is only available with EMR version 5.30.0 and later, excluding EMR 6.0.0.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-logencryptionkmskeyid
        '''
        result = self._values.get("log_encryption_kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def log_uri(self) -> typing.Optional[builtins.str]:
        '''The path to the Amazon S3 location where logs for this cluster are stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-loguri
        '''
        result = self._values.get("log_uri")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def managed_scaling_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.ManagedScalingPolicyProperty, _IResolvable_da3f097b]]:
        '''Creates or updates a managed scaling policy for an Amazon EMR cluster.

        The managed scaling policy defines the limits for resources, such as EC2 instances that can be added or terminated from a cluster. The policy only applies to the core and task nodes. The master node cannot be scaled after initial configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-managedscalingpolicy
        '''
        result = self._values.get("managed_scaling_policy")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.ManagedScalingPolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def release_label(self) -> typing.Optional[builtins.str]:
        '''The Amazon EMR release label, which determines the version of open-source application packages installed on the cluster.

        Release labels are in the form ``emr-x.x.x`` , where x.x.x is an Amazon EMR release version such as ``emr-5.14.0`` . For more information about Amazon EMR release versions and included application versions and features, see ` <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/>`_ . The release label applies only to Amazon EMR releases version 4.0 and later. Earlier versions use ``AmiVersion`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-releaselabel
        '''
        result = self._values.get("release_label")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def scale_down_behavior(self) -> typing.Optional[builtins.str]:
        '''The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized.

        ``TERMINATE_AT_INSTANCE_HOUR`` indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. ``TERMINATE_AT_TASK_COMPLETION`` indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. ``TERMINATE_AT_TASK_COMPLETION`` is available only in Amazon EMR version 4.1.0 and later, and is the default for versions of Amazon EMR earlier than 5.1.0.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-scaledownbehavior
        '''
        result = self._values.get("scale_down_behavior")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def security_configuration(self) -> typing.Optional[builtins.str]:
        '''The name of the security configuration applied to the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration
        '''
        result = self._values.get("security_configuration")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def step_concurrency_level(self) -> typing.Optional[jsii.Number]:
        '''Specifies the number of steps that can be executed concurrently.

        The default value is ``1`` . The maximum value is ``256`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-stepconcurrencylevel
        '''
        result = self._values.get("step_concurrency_level")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def steps(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.StepConfigProperty, _IResolvable_da3f097b]]]]:
        '''A list of steps to run.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-steps
        '''
        result = self._values.get("steps")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.StepConfigProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags associated with a cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def visible_to_all_users(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether the cluster is visible to all IAM users of the AWS account associated with the cluster.

        If this value is set to ``true`` , all IAM users of that AWS account can view and manage the cluster if they have the proper policy permissions set. If this value is ``false`` , only the IAM user that created the cluster can view and manage it. This value can be changed using the SetVisibleToAllUsers action.
        .. epigraph::

           When you create clusters directly through the EMR console or API, this value is set to ``true`` by default. However, for ``AWS::EMR::Cluster`` resources in CloudFormation, the default is ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-visibletoallusers
        '''
        result = self._values.get("visible_to_all_users")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnClusterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnInstanceFleetConfig(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig",
):
    '''A CloudFormation ``AWS::EMR::InstanceFleetConfig``.

    Use ``InstanceFleetConfig`` to define instance fleets for an EMR cluster. A cluster can not use both instance fleets and instance groups. For more information, see `Configure Instance Fleets <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-instance-group-configuration.html>`_ in the *Amazon EMR Management Guide* .
    .. epigraph::

       The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions. > You can currently only add a task instance fleet to a cluster with this resource. If you use this resource, CloudFormation waits for the cluster launch to complete before adding the task instance fleet to the cluster. In order to add a task instance fleet to the cluster as part of the cluster launch and minimize delays in provisioning task nodes, use the ``TaskInstanceFleets`` subproperty for the `AWS::EMR::Cluster JobFlowInstancesConfig <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html>`_ property instead. To use this subproperty, see `AWS::EMR::Cluster <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html>`_ for examples.

    :cloudformationResource: AWS::EMR::InstanceFleetConfig
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_emr as emr
        
        # configuration_property_: emr.CfnInstanceFleetConfig.ConfigurationProperty
        
        cfn_instance_fleet_config = emr.CfnInstanceFleetConfig(self, "MyCfnInstanceFleetConfig",
            cluster_id="clusterId",
            instance_fleet_type="instanceFleetType",
        
            # the properties below are optional
            instance_type_configs=[emr.CfnInstanceFleetConfig.InstanceTypeConfigProperty(
                instance_type="instanceType",
        
                # the properties below are optional
                bid_price="bidPrice",
                bid_price_as_percentage_of_on_demand_price=123,
                configurations=[emr.CfnInstanceFleetConfig.ConfigurationProperty(
                    classification="classification",
                    configuration_properties={
                        "configuration_properties_key": "configurationProperties"
                    },
                    configurations=[configuration_property_]
                )],
                custom_ami_id="customAmiId",
                ebs_configuration=emr.CfnInstanceFleetConfig.EbsConfigurationProperty(
                    ebs_block_device_configs=[emr.CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty(
                        volume_specification=emr.CfnInstanceFleetConfig.VolumeSpecificationProperty(
                            size_in_gb=123,
                            volume_type="volumeType",
        
                            # the properties below are optional
                            iops=123
                        ),
        
                        # the properties below are optional
                        volumes_per_instance=123
                    )],
                    ebs_optimized=False
                ),
                weighted_capacity=123
            )],
            launch_specifications=emr.CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty(
                on_demand_specification=emr.CfnInstanceFleetConfig.OnDemandProvisioningSpecificationProperty(
                    allocation_strategy="allocationStrategy"
                ),
                spot_specification=emr.CfnInstanceFleetConfig.SpotProvisioningSpecificationProperty(
                    timeout_action="timeoutAction",
                    timeout_duration_minutes=123,
        
                    # the properties below are optional
                    allocation_strategy="allocationStrategy",
                    block_duration_minutes=123
                )
            ),
            name="name",
            target_on_demand_capacity=123,
            target_spot_capacity=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster_id: builtins.str,
        instance_fleet_type: builtins.str,
        instance_type_configs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceFleetConfig.InstanceTypeConfigProperty", _IResolvable_da3f097b]]]] = None,
        launch_specifications: typing.Optional[typing.Union["CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        target_on_demand_capacity: typing.Optional[jsii.Number] = None,
        target_spot_capacity: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Create a new ``AWS::EMR::InstanceFleetConfig``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param cluster_id: The unique identifier of the EMR cluster.
        :param instance_fleet_type: The node type that the instance fleet hosts. *Allowed Values* : TASK
        :param instance_type_configs: ``InstanceTypeConfigs`` determine the EC2 instances that Amazon EMR attempts to provision to fulfill On-Demand and Spot target capacities. .. epigraph:: The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.
        :param launch_specifications: The launch specification for the instance fleet.
        :param name: The friendly name of the instance fleet.
        :param target_on_demand_capacity: The target capacity of On-Demand units for the instance fleet, which determines how many On-Demand instances to provision. When the instance fleet launches, Amazon EMR tries to provision On-Demand instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When an On-Demand instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units. .. epigraph:: If not specified or set to 0, only Spot instances are provisioned for the instance fleet using ``TargetSpotCapacity`` . At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.
        :param target_spot_capacity: The target capacity of Spot units for the instance fleet, which determines how many Spot instances to provision. When the instance fleet launches, Amazon EMR tries to provision Spot instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When a Spot instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units. .. epigraph:: If not specified or set to 0, only On-Demand instances are provisioned for the instance fleet. At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.
        '''
        props = CfnInstanceFleetConfigProps(
            cluster_id=cluster_id,
            instance_fleet_type=instance_fleet_type,
            instance_type_configs=instance_type_configs,
            launch_specifications=launch_specifications,
            name=name,
            target_on_demand_capacity=target_on_demand_capacity,
            target_spot_capacity=target_spot_capacity,
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
    @jsii.member(jsii_name="clusterId")
    def cluster_id(self) -> builtins.str:
        '''The unique identifier of the EMR cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-clusterid
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterId"))

    @cluster_id.setter
    def cluster_id(self, value: builtins.str) -> None:
        jsii.set(self, "clusterId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceFleetType")
    def instance_fleet_type(self) -> builtins.str:
        '''The node type that the instance fleet hosts.

        *Allowed Values* : TASK

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancefleettype
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceFleetType"))

    @instance_fleet_type.setter
    def instance_fleet_type(self, value: builtins.str) -> None:
        jsii.set(self, "instanceFleetType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceTypeConfigs")
    def instance_type_configs(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.InstanceTypeConfigProperty", _IResolvable_da3f097b]]]]:
        '''``InstanceTypeConfigs`` determine the EC2 instances that Amazon EMR attempts to provision to fulfill On-Demand and Spot target capacities.

        .. epigraph::

           The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfigs
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.InstanceTypeConfigProperty", _IResolvable_da3f097b]]]], jsii.get(self, "instanceTypeConfigs"))

    @instance_type_configs.setter
    def instance_type_configs(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.InstanceTypeConfigProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "instanceTypeConfigs", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="launchSpecifications")
    def launch_specifications(
        self,
    ) -> typing.Optional[typing.Union["CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty", _IResolvable_da3f097b]]:
        '''The launch specification for the instance fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-launchspecifications
        '''
        return typing.cast(typing.Optional[typing.Union["CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty", _IResolvable_da3f097b]], jsii.get(self, "launchSpecifications"))

    @launch_specifications.setter
    def launch_specifications(
        self,
        value: typing.Optional[typing.Union["CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "launchSpecifications", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The friendly name of the instance fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetOnDemandCapacity")
    def target_on_demand_capacity(self) -> typing.Optional[jsii.Number]:
        '''The target capacity of On-Demand units for the instance fleet, which determines how many On-Demand instances to provision.

        When the instance fleet launches, Amazon EMR tries to provision On-Demand instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When an On-Demand instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units.
        .. epigraph::

           If not specified or set to 0, only Spot instances are provisioned for the instance fleet using ``TargetSpotCapacity`` . At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-targetondemandcapacity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "targetOnDemandCapacity"))

    @target_on_demand_capacity.setter
    def target_on_demand_capacity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "targetOnDemandCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetSpotCapacity")
    def target_spot_capacity(self) -> typing.Optional[jsii.Number]:
        '''The target capacity of Spot units for the instance fleet, which determines how many Spot instances to provision.

        When the instance fleet launches, Amazon EMR tries to provision Spot instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When a Spot instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units.
        .. epigraph::

           If not specified or set to 0, only On-Demand instances are provisioned for the instance fleet. At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-targetspotcapacity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "targetSpotCapacity"))

    @target_spot_capacity.setter
    def target_spot_capacity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "targetSpotCapacity", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig.ConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "classification": "classification",
            "configuration_properties": "configurationProperties",
            "configurations": "configurations",
        },
    )
    class ConfigurationProperty:
        def __init__(
            self,
            *,
            classification: typing.Optional[builtins.str] = None,
            configuration_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceFleetConfig.ConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''.. epigraph::

   Used only with Amazon EMR release 4.0 and later.

            ``Configuration`` specifies optional configurations for customizing open-source big data applications and environment parameters. A configuration consists of a classification, properties, and optional nested configurations. A classification refers to an application-specific configuration file. Properties are the settings you want to change in that file. For more information, see `Configuring Applications <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-configure-apps.html>`_ in the *Amazon EMR Release Guide* .

            :param classification: The classification within a configuration.
            :param configuration_properties: Within a configuration classification, a set of properties that represent the settings that you want to change in the configuration file. Duplicates not allowed.
            :param configurations: A list of additional configurations to apply within a configuration object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-configuration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                # configuration_property_: emr.CfnInstanceFleetConfig.ConfigurationProperty
                
                configuration_property = emr.CfnInstanceFleetConfig.ConfigurationProperty(
                    classification="classification",
                    configuration_properties={
                        "configuration_properties_key": "configurationProperties"
                    },
                    configurations=[emr.CfnInstanceFleetConfig.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if classification is not None:
                self._values["classification"] = classification
            if configuration_properties is not None:
                self._values["configuration_properties"] = configuration_properties
            if configurations is not None:
                self._values["configurations"] = configurations

        @builtins.property
        def classification(self) -> typing.Optional[builtins.str]:
            '''The classification within a configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-configuration.html#cfn-elasticmapreduce-instancefleetconfig-configuration-classification
            '''
            result = self._values.get("classification")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def configuration_properties(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''Within a configuration classification, a set of properties that represent the settings that you want to change in the configuration file.

            Duplicates not allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-configuration.html#cfn-elasticmapreduce-instancefleetconfig-configuration-configurationproperties
            '''
            result = self._values.get("configuration_properties")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.ConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''A list of additional configurations to apply within a configuration object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-configuration.html#cfn-elasticmapreduce-instancefleetconfig-configuration-configurations
            '''
            result = self._values.get("configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.ConfigurationProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "volume_specification": "volumeSpecification",
            "volumes_per_instance": "volumesPerInstance",
        },
    )
    class EbsBlockDeviceConfigProperty:
        def __init__(
            self,
            *,
            volume_specification: typing.Union["CfnInstanceFleetConfig.VolumeSpecificationProperty", _IResolvable_da3f097b],
            volumes_per_instance: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``EbsBlockDeviceConfig`` is a subproperty of the ``EbsConfiguration`` property type.

            ``EbsBlockDeviceConfig`` defines the number and type of EBS volumes to associate with all EC2 instances in an EMR cluster.

            :param volume_specification: EBS volume specifications such as volume type, IOPS, and size (GiB) that will be requested for the EBS volume attached to an EC2 instance in the cluster.
            :param volumes_per_instance: Number of EBS volumes with a specific volume configuration that will be associated with every instance in the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ebsblockdeviceconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                ebs_block_device_config_property = emr.CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty(
                    volume_specification=emr.CfnInstanceFleetConfig.VolumeSpecificationProperty(
                        size_in_gb=123,
                        volume_type="volumeType",
                
                        # the properties below are optional
                        iops=123
                    ),
                
                    # the properties below are optional
                    volumes_per_instance=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "volume_specification": volume_specification,
            }
            if volumes_per_instance is not None:
                self._values["volumes_per_instance"] = volumes_per_instance

        @builtins.property
        def volume_specification(
            self,
        ) -> typing.Union["CfnInstanceFleetConfig.VolumeSpecificationProperty", _IResolvable_da3f097b]:
            '''EBS volume specifications such as volume type, IOPS, and size (GiB) that will be requested for the EBS volume attached to an EC2 instance in the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ebsblockdeviceconfig.html#cfn-elasticmapreduce-instancefleetconfig-ebsblockdeviceconfig-volumespecification
            '''
            result = self._values.get("volume_specification")
            assert result is not None, "Required property 'volume_specification' is missing"
            return typing.cast(typing.Union["CfnInstanceFleetConfig.VolumeSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def volumes_per_instance(self) -> typing.Optional[jsii.Number]:
            '''Number of EBS volumes with a specific volume configuration that will be associated with every instance in the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ebsblockdeviceconfig.html#cfn-elasticmapreduce-instancefleetconfig-ebsblockdeviceconfig-volumesperinstance
            '''
            result = self._values.get("volumes_per_instance")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EbsBlockDeviceConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig.EbsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ebs_block_device_configs": "ebsBlockDeviceConfigs",
            "ebs_optimized": "ebsOptimized",
        },
    )
    class EbsConfigurationProperty:
        def __init__(
            self,
            *,
            ebs_block_device_configs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]] = None,
            ebs_optimized: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``EbsConfiguration`` determines the EBS volumes to attach to EMR cluster instances.

            :param ebs_block_device_configs: An array of Amazon EBS volume specifications attached to a cluster instance.
            :param ebs_optimized: Indicates whether an Amazon EBS volume is EBS-optimized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ebsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                ebs_configuration_property = emr.CfnInstanceFleetConfig.EbsConfigurationProperty(
                    ebs_block_device_configs=[emr.CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty(
                        volume_specification=emr.CfnInstanceFleetConfig.VolumeSpecificationProperty(
                            size_in_gb=123,
                            volume_type="volumeType",
                
                            # the properties below are optional
                            iops=123
                        ),
                
                        # the properties below are optional
                        volumes_per_instance=123
                    )],
                    ebs_optimized=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ebs_block_device_configs is not None:
                self._values["ebs_block_device_configs"] = ebs_block_device_configs
            if ebs_optimized is not None:
                self._values["ebs_optimized"] = ebs_optimized

        @builtins.property
        def ebs_block_device_configs(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]]:
            '''An array of Amazon EBS volume specifications attached to a cluster instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ebsconfiguration.html#cfn-elasticmapreduce-instancefleetconfig-ebsconfiguration-ebsblockdeviceconfigs
            '''
            result = self._values.get("ebs_block_device_configs")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ebs_optimized(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether an Amazon EBS volume is EBS-optimized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ebsconfiguration.html#cfn-elasticmapreduce-instancefleetconfig-ebsconfiguration-ebsoptimized
            '''
            result = self._values.get("ebs_optimized")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EbsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "on_demand_specification": "onDemandSpecification",
            "spot_specification": "spotSpecification",
        },
    )
    class InstanceFleetProvisioningSpecificationsProperty:
        def __init__(
            self,
            *,
            on_demand_specification: typing.Optional[typing.Union["CfnInstanceFleetConfig.OnDemandProvisioningSpecificationProperty", _IResolvable_da3f097b]] = None,
            spot_specification: typing.Optional[typing.Union["CfnInstanceFleetConfig.SpotProvisioningSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''.. epigraph::

   The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

            ``InstanceTypeConfig`` is a sub-property of ``InstanceFleetConfig`` . ``InstanceTypeConfig`` determines the EC2 instances that Amazon EMR attempts to provision to fulfill On-Demand and Spot target capacities.

            :param on_demand_specification: The launch specification for On-Demand Instances in the instance fleet, which determines the allocation strategy. .. epigraph:: The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions. On-Demand Instances allocation strategy is available in Amazon EMR version 5.12.1 and later.
            :param spot_specification: The launch specification for Spot Instances in the fleet, which determines the defined duration, provisioning timeout behavior, and allocation strategy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancefleetprovisioningspecifications.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                instance_fleet_provisioning_specifications_property = emr.CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty(
                    on_demand_specification=emr.CfnInstanceFleetConfig.OnDemandProvisioningSpecificationProperty(
                        allocation_strategy="allocationStrategy"
                    ),
                    spot_specification=emr.CfnInstanceFleetConfig.SpotProvisioningSpecificationProperty(
                        timeout_action="timeoutAction",
                        timeout_duration_minutes=123,
                
                        # the properties below are optional
                        allocation_strategy="allocationStrategy",
                        block_duration_minutes=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if on_demand_specification is not None:
                self._values["on_demand_specification"] = on_demand_specification
            if spot_specification is not None:
                self._values["spot_specification"] = spot_specification

        @builtins.property
        def on_demand_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnInstanceFleetConfig.OnDemandProvisioningSpecificationProperty", _IResolvable_da3f097b]]:
            '''The launch specification for On-Demand Instances in the instance fleet, which determines the allocation strategy.

            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions. On-Demand Instances allocation strategy is available in Amazon EMR version 5.12.1 and later.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancefleetprovisioningspecifications.html#cfn-elasticmapreduce-instancefleetconfig-instancefleetprovisioningspecifications-ondemandspecification
            '''
            result = self._values.get("on_demand_specification")
            return typing.cast(typing.Optional[typing.Union["CfnInstanceFleetConfig.OnDemandProvisioningSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def spot_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnInstanceFleetConfig.SpotProvisioningSpecificationProperty", _IResolvable_da3f097b]]:
            '''The launch specification for Spot Instances in the fleet, which determines the defined duration, provisioning timeout behavior, and allocation strategy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancefleetprovisioningspecifications.html#cfn-elasticmapreduce-instancefleetconfig-instancefleetprovisioningspecifications-spotspecification
            '''
            result = self._values.get("spot_specification")
            return typing.cast(typing.Optional[typing.Union["CfnInstanceFleetConfig.SpotProvisioningSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceFleetProvisioningSpecificationsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig.InstanceTypeConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "instance_type": "instanceType",
            "bid_price": "bidPrice",
            "bid_price_as_percentage_of_on_demand_price": "bidPriceAsPercentageOfOnDemandPrice",
            "configurations": "configurations",
            "custom_ami_id": "customAmiId",
            "ebs_configuration": "ebsConfiguration",
            "weighted_capacity": "weightedCapacity",
        },
    )
    class InstanceTypeConfigProperty:
        def __init__(
            self,
            *,
            instance_type: builtins.str,
            bid_price: typing.Optional[builtins.str] = None,
            bid_price_as_percentage_of_on_demand_price: typing.Optional[jsii.Number] = None,
            configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceFleetConfig.ConfigurationProperty", _IResolvable_da3f097b]]]] = None,
            custom_ami_id: typing.Optional[builtins.str] = None,
            ebs_configuration: typing.Optional[typing.Union["CfnInstanceFleetConfig.EbsConfigurationProperty", _IResolvable_da3f097b]] = None,
            weighted_capacity: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``InstanceType`` config is a subproperty of ``InstanceFleetConfig`` .

            An instance type configuration specifies each instance type in an instance fleet. The configuration determines the EC2 instances Amazon EMR attempts to provision to fulfill On-Demand and Spot target capacities.
            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

            :param instance_type: An EC2 instance type, such as ``m3.xlarge`` .
            :param bid_price: The bid price for each EC2 Spot Instance type as defined by ``InstanceType`` . Expressed in USD. If neither ``BidPrice`` nor ``BidPriceAsPercentageOfOnDemandPrice`` is provided, ``BidPriceAsPercentageOfOnDemandPrice`` defaults to 100%.
            :param bid_price_as_percentage_of_on_demand_price: The bid price, as a percentage of On-Demand price, for each EC2 Spot Instance as defined by ``InstanceType`` . Expressed as a number (for example, 20 specifies 20%). If neither ``BidPrice`` nor ``BidPriceAsPercentageOfOnDemandPrice`` is provided, ``BidPriceAsPercentageOfOnDemandPrice`` defaults to 100%.
            :param configurations: .. epigraph:: Amazon EMR releases 4.x or later. An optional configuration specification to be used when provisioning cluster instances, which can include configurations for applications and software bundled with Amazon EMR. A configuration consists of a classification, properties, and optional nested configurations. A classification refers to an application-specific configuration file. Properties are the settings you want to change in that file. For more information, see `Configuring Applications <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-configure-apps.html>`_ .
            :param custom_ami_id: The custom AMI ID to use for the instance type.
            :param ebs_configuration: The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by ``InstanceType`` .
            :param weighted_capacity: The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in ``InstanceFleetConfig`` . This value is 1 for a master instance fleet, and must be 1 or greater for core and task instance fleets. Defaults to 1 if not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancetypeconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                # configuration_property_: emr.CfnInstanceFleetConfig.ConfigurationProperty
                
                instance_type_config_property = emr.CfnInstanceFleetConfig.InstanceTypeConfigProperty(
                    instance_type="instanceType",
                
                    # the properties below are optional
                    bid_price="bidPrice",
                    bid_price_as_percentage_of_on_demand_price=123,
                    configurations=[emr.CfnInstanceFleetConfig.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )],
                    custom_ami_id="customAmiId",
                    ebs_configuration=emr.CfnInstanceFleetConfig.EbsConfigurationProperty(
                        ebs_block_device_configs=[emr.CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty(
                            volume_specification=emr.CfnInstanceFleetConfig.VolumeSpecificationProperty(
                                size_in_gb=123,
                                volume_type="volumeType",
                
                                # the properties below are optional
                                iops=123
                            ),
                
                            # the properties below are optional
                            volumes_per_instance=123
                        )],
                        ebs_optimized=False
                    ),
                    weighted_capacity=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_type": instance_type,
            }
            if bid_price is not None:
                self._values["bid_price"] = bid_price
            if bid_price_as_percentage_of_on_demand_price is not None:
                self._values["bid_price_as_percentage_of_on_demand_price"] = bid_price_as_percentage_of_on_demand_price
            if configurations is not None:
                self._values["configurations"] = configurations
            if custom_ami_id is not None:
                self._values["custom_ami_id"] = custom_ami_id
            if ebs_configuration is not None:
                self._values["ebs_configuration"] = ebs_configuration
            if weighted_capacity is not None:
                self._values["weighted_capacity"] = weighted_capacity

        @builtins.property
        def instance_type(self) -> builtins.str:
            '''An EC2 instance type, such as ``m3.xlarge`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancetypeconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfig-instancetype
            '''
            result = self._values.get("instance_type")
            assert result is not None, "Required property 'instance_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bid_price(self) -> typing.Optional[builtins.str]:
            '''The bid price for each EC2 Spot Instance type as defined by ``InstanceType`` .

            Expressed in USD. If neither ``BidPrice`` nor ``BidPriceAsPercentageOfOnDemandPrice`` is provided, ``BidPriceAsPercentageOfOnDemandPrice`` defaults to 100%.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancetypeconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfig-bidprice
            '''
            result = self._values.get("bid_price")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def bid_price_as_percentage_of_on_demand_price(
            self,
        ) -> typing.Optional[jsii.Number]:
            '''The bid price, as a percentage of On-Demand price, for each EC2 Spot Instance as defined by ``InstanceType`` .

            Expressed as a number (for example, 20 specifies 20%). If neither ``BidPrice`` nor ``BidPriceAsPercentageOfOnDemandPrice`` is provided, ``BidPriceAsPercentageOfOnDemandPrice`` defaults to 100%.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancetypeconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfig-bidpriceaspercentageofondemandprice
            '''
            result = self._values.get("bid_price_as_percentage_of_on_demand_price")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.ConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''.. epigraph::

   Amazon EMR releases 4.x or later.

            An optional configuration specification to be used when provisioning cluster instances, which can include configurations for applications and software bundled with Amazon EMR. A configuration consists of a classification, properties, and optional nested configurations. A classification refers to an application-specific configuration file. Properties are the settings you want to change in that file. For more information, see `Configuring Applications <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-configure-apps.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancetypeconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfig-configurations
            '''
            result = self._values.get("configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceFleetConfig.ConfigurationProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def custom_ami_id(self) -> typing.Optional[builtins.str]:
            '''The custom AMI ID to use for the instance type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancetypeconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfig-customamiid
            '''
            result = self._values.get("custom_ami_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ebs_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnInstanceFleetConfig.EbsConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration of Amazon Elastic Block Store (Amazon EBS) attached to each instance as defined by ``InstanceType`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancetypeconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfig-ebsconfiguration
            '''
            result = self._values.get("ebs_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnInstanceFleetConfig.EbsConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def weighted_capacity(self) -> typing.Optional[jsii.Number]:
            '''The number of units that a provisioned instance of this type provides toward fulfilling the target capacities defined in ``InstanceFleetConfig`` .

            This value is 1 for a master instance fleet, and must be 1 or greater for core and task instance fleets. Defaults to 1 if not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-instancetypeconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfig-weightedcapacity
            '''
            result = self._values.get("weighted_capacity")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceTypeConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig.OnDemandProvisioningSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={"allocation_strategy": "allocationStrategy"},
    )
    class OnDemandProvisioningSpecificationProperty:
        def __init__(self, *, allocation_strategy: builtins.str) -> None:
            '''The launch specification for On-Demand Instances in the instance fleet, which determines the allocation strategy.

            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions. On-Demand Instances allocation strategy is available in Amazon EMR version 5.12.1 and later.

            :param allocation_strategy: Specifies the strategy to use in launching On-Demand instance fleets. Currently, the only option is ``lowest-price`` (the default), which launches the lowest price first.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ondemandprovisioningspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                on_demand_provisioning_specification_property = emr.CfnInstanceFleetConfig.OnDemandProvisioningSpecificationProperty(
                    allocation_strategy="allocationStrategy"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "allocation_strategy": allocation_strategy,
            }

        @builtins.property
        def allocation_strategy(self) -> builtins.str:
            '''Specifies the strategy to use in launching On-Demand instance fleets.

            Currently, the only option is ``lowest-price`` (the default), which launches the lowest price first.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ondemandprovisioningspecification.html#cfn-elasticmapreduce-instancefleetconfig-ondemandprovisioningspecification-allocationstrategy
            '''
            result = self._values.get("allocation_strategy")
            assert result is not None, "Required property 'allocation_strategy' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OnDemandProvisioningSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig.SpotProvisioningSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "timeout_action": "timeoutAction",
            "timeout_duration_minutes": "timeoutDurationMinutes",
            "allocation_strategy": "allocationStrategy",
            "block_duration_minutes": "blockDurationMinutes",
        },
    )
    class SpotProvisioningSpecificationProperty:
        def __init__(
            self,
            *,
            timeout_action: builtins.str,
            timeout_duration_minutes: jsii.Number,
            allocation_strategy: typing.Optional[builtins.str] = None,
            block_duration_minutes: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``SpotProvisioningSpecification`` is a subproperty of the ``InstanceFleetProvisioningSpecifications`` property type.

            ``SpotProvisioningSpecification`` determines the launch specification for Spot instances in the instance fleet, which includes the defined duration and provisioning timeout behavior.
            .. epigraph::

               The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

            :param timeout_action: The action to take when ``TargetSpotCapacity`` has not been fulfilled when the ``TimeoutDurationMinutes`` has expired; that is, when all Spot Instances could not be provisioned within the Spot provisioning timeout. Valid values are ``TERMINATE_CLUSTER`` and ``SWITCH_TO_ON_DEMAND`` . SWITCH_TO_ON_DEMAND specifies that if no Spot Instances are available, On-Demand Instances should be provisioned to fulfill any remaining Spot capacity.
            :param timeout_duration_minutes: The spot provisioning timeout period in minutes. If Spot Instances are not provisioned within this time period, the ``TimeOutAction`` is taken. Minimum value is 5 and maximum value is 1440. The timeout applies only during initial provisioning, when the cluster is first created.
            :param allocation_strategy: Specifies the strategy to use in launching Spot Instance fleets. Currently, the only option is capacity-optimized (the default), which launches instances from Spot Instance pools with optimal capacity for the number of instances that are launching.
            :param block_duration_minutes: The defined duration for Spot Instances (also known as Spot blocks) in minutes. When specified, the Spot Instance does not terminate before the defined duration expires, and defined duration pricing for Spot Instances applies. Valid values are 60, 120, 180, 240, 300, or 360. The duration period starts as soon as a Spot Instance receives its instance ID. At the end of the duration, Amazon EC2 marks the Spot Instance for termination and provides a Spot Instance termination notice, which gives the instance a two-minute warning before it terminates. .. epigraph:: Spot Instances with a defined duration (also known as Spot blocks) are no longer available to new customers from July 1, 2021. For customers who have previously used the feature, we will continue to support Spot Instances with a defined duration until December 31, 2022.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-spotprovisioningspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                spot_provisioning_specification_property = emr.CfnInstanceFleetConfig.SpotProvisioningSpecificationProperty(
                    timeout_action="timeoutAction",
                    timeout_duration_minutes=123,
                
                    # the properties below are optional
                    allocation_strategy="allocationStrategy",
                    block_duration_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "timeout_action": timeout_action,
                "timeout_duration_minutes": timeout_duration_minutes,
            }
            if allocation_strategy is not None:
                self._values["allocation_strategy"] = allocation_strategy
            if block_duration_minutes is not None:
                self._values["block_duration_minutes"] = block_duration_minutes

        @builtins.property
        def timeout_action(self) -> builtins.str:
            '''The action to take when ``TargetSpotCapacity`` has not been fulfilled when the ``TimeoutDurationMinutes`` has expired;

            that is, when all Spot Instances could not be provisioned within the Spot provisioning timeout. Valid values are ``TERMINATE_CLUSTER`` and ``SWITCH_TO_ON_DEMAND`` . SWITCH_TO_ON_DEMAND specifies that if no Spot Instances are available, On-Demand Instances should be provisioned to fulfill any remaining Spot capacity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-spotprovisioningspecification.html#cfn-elasticmapreduce-instancefleetconfig-spotprovisioningspecification-timeoutaction
            '''
            result = self._values.get("timeout_action")
            assert result is not None, "Required property 'timeout_action' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def timeout_duration_minutes(self) -> jsii.Number:
            '''The spot provisioning timeout period in minutes.

            If Spot Instances are not provisioned within this time period, the ``TimeOutAction`` is taken. Minimum value is 5 and maximum value is 1440. The timeout applies only during initial provisioning, when the cluster is first created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-spotprovisioningspecification.html#cfn-elasticmapreduce-instancefleetconfig-spotprovisioningspecification-timeoutdurationminutes
            '''
            result = self._values.get("timeout_duration_minutes")
            assert result is not None, "Required property 'timeout_duration_minutes' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def allocation_strategy(self) -> typing.Optional[builtins.str]:
            '''Specifies the strategy to use in launching Spot Instance fleets.

            Currently, the only option is capacity-optimized (the default), which launches instances from Spot Instance pools with optimal capacity for the number of instances that are launching.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-spotprovisioningspecification.html#cfn-elasticmapreduce-instancefleetconfig-spotprovisioningspecification-allocationstrategy
            '''
            result = self._values.get("allocation_strategy")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def block_duration_minutes(self) -> typing.Optional[jsii.Number]:
            '''The defined duration for Spot Instances (also known as Spot blocks) in minutes.

            When specified, the Spot Instance does not terminate before the defined duration expires, and defined duration pricing for Spot Instances applies. Valid values are 60, 120, 180, 240, 300, or 360. The duration period starts as soon as a Spot Instance receives its instance ID. At the end of the duration, Amazon EC2 marks the Spot Instance for termination and provides a Spot Instance termination notice, which gives the instance a two-minute warning before it terminates.
            .. epigraph::

               Spot Instances with a defined duration (also known as Spot blocks) are no longer available to new customers from July 1, 2021. For customers who have previously used the feature, we will continue to support Spot Instances with a defined duration until December 31, 2022.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-spotprovisioningspecification.html#cfn-elasticmapreduce-instancefleetconfig-spotprovisioningspecification-blockdurationminutes
            '''
            result = self._values.get("block_duration_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SpotProvisioningSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfig.VolumeSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "size_in_gb": "sizeInGb",
            "volume_type": "volumeType",
            "iops": "iops",
        },
    )
    class VolumeSpecificationProperty:
        def __init__(
            self,
            *,
            size_in_gb: jsii.Number,
            volume_type: builtins.str,
            iops: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``VolumeSpecification`` is a subproperty of the ``EbsBlockDeviceConfig`` property type.

            ``VolumeSecification`` determines the volume type, IOPS, and size (GiB) for EBS volumes attached to EC2 instances.

            :param size_in_gb: The volume size, in gibibytes (GiB). This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.
            :param volume_type: The volume type. Volume types supported are gp2, io1, and standard.
            :param iops: The number of I/O operations per second (IOPS) that the volume supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-volumespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                volume_specification_property = emr.CfnInstanceFleetConfig.VolumeSpecificationProperty(
                    size_in_gb=123,
                    volume_type="volumeType",
                
                    # the properties below are optional
                    iops=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "size_in_gb": size_in_gb,
                "volume_type": volume_type,
            }
            if iops is not None:
                self._values["iops"] = iops

        @builtins.property
        def size_in_gb(self) -> jsii.Number:
            '''The volume size, in gibibytes (GiB).

            This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-volumespecification.html#cfn-elasticmapreduce-instancefleetconfig-volumespecification-sizeingb
            '''
            result = self._values.get("size_in_gb")
            assert result is not None, "Required property 'size_in_gb' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def volume_type(self) -> builtins.str:
            '''The volume type.

            Volume types supported are gp2, io1, and standard.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-volumespecification.html#cfn-elasticmapreduce-instancefleetconfig-volumespecification-volumetype
            '''
            result = self._values.get("volume_type")
            assert result is not None, "Required property 'volume_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def iops(self) -> typing.Optional[jsii.Number]:
            '''The number of I/O operations per second (IOPS) that the volume supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-volumespecification.html#cfn-elasticmapreduce-instancefleetconfig-volumespecification-iops
            '''
            result = self._values.get("iops")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VolumeSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_emr.CfnInstanceFleetConfigProps",
    jsii_struct_bases=[],
    name_mapping={
        "cluster_id": "clusterId",
        "instance_fleet_type": "instanceFleetType",
        "instance_type_configs": "instanceTypeConfigs",
        "launch_specifications": "launchSpecifications",
        "name": "name",
        "target_on_demand_capacity": "targetOnDemandCapacity",
        "target_spot_capacity": "targetSpotCapacity",
    },
)
class CfnInstanceFleetConfigProps:
    def __init__(
        self,
        *,
        cluster_id: builtins.str,
        instance_fleet_type: builtins.str,
        instance_type_configs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnInstanceFleetConfig.InstanceTypeConfigProperty, _IResolvable_da3f097b]]]] = None,
        launch_specifications: typing.Optional[typing.Union[CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        target_on_demand_capacity: typing.Optional[jsii.Number] = None,
        target_spot_capacity: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for defining a ``CfnInstanceFleetConfig``.

        :param cluster_id: The unique identifier of the EMR cluster.
        :param instance_fleet_type: The node type that the instance fleet hosts. *Allowed Values* : TASK
        :param instance_type_configs: ``InstanceTypeConfigs`` determine the EC2 instances that Amazon EMR attempts to provision to fulfill On-Demand and Spot target capacities. .. epigraph:: The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.
        :param launch_specifications: The launch specification for the instance fleet.
        :param name: The friendly name of the instance fleet.
        :param target_on_demand_capacity: The target capacity of On-Demand units for the instance fleet, which determines how many On-Demand instances to provision. When the instance fleet launches, Amazon EMR tries to provision On-Demand instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When an On-Demand instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units. .. epigraph:: If not specified or set to 0, only Spot instances are provisioned for the instance fleet using ``TargetSpotCapacity`` . At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.
        :param target_spot_capacity: The target capacity of Spot units for the instance fleet, which determines how many Spot instances to provision. When the instance fleet launches, Amazon EMR tries to provision Spot instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When a Spot instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units. .. epigraph:: If not specified or set to 0, only On-Demand instances are provisioned for the instance fleet. At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_emr as emr
            
            # configuration_property_: emr.CfnInstanceFleetConfig.ConfigurationProperty
            
            cfn_instance_fleet_config_props = emr.CfnInstanceFleetConfigProps(
                cluster_id="clusterId",
                instance_fleet_type="instanceFleetType",
            
                # the properties below are optional
                instance_type_configs=[emr.CfnInstanceFleetConfig.InstanceTypeConfigProperty(
                    instance_type="instanceType",
            
                    # the properties below are optional
                    bid_price="bidPrice",
                    bid_price_as_percentage_of_on_demand_price=123,
                    configurations=[emr.CfnInstanceFleetConfig.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )],
                    custom_ami_id="customAmiId",
                    ebs_configuration=emr.CfnInstanceFleetConfig.EbsConfigurationProperty(
                        ebs_block_device_configs=[emr.CfnInstanceFleetConfig.EbsBlockDeviceConfigProperty(
                            volume_specification=emr.CfnInstanceFleetConfig.VolumeSpecificationProperty(
                                size_in_gb=123,
                                volume_type="volumeType",
            
                                # the properties below are optional
                                iops=123
                            ),
            
                            # the properties below are optional
                            volumes_per_instance=123
                        )],
                        ebs_optimized=False
                    ),
                    weighted_capacity=123
                )],
                launch_specifications=emr.CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty(
                    on_demand_specification=emr.CfnInstanceFleetConfig.OnDemandProvisioningSpecificationProperty(
                        allocation_strategy="allocationStrategy"
                    ),
                    spot_specification=emr.CfnInstanceFleetConfig.SpotProvisioningSpecificationProperty(
                        timeout_action="timeoutAction",
                        timeout_duration_minutes=123,
            
                        # the properties below are optional
                        allocation_strategy="allocationStrategy",
                        block_duration_minutes=123
                    )
                ),
                name="name",
                target_on_demand_capacity=123,
                target_spot_capacity=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster_id": cluster_id,
            "instance_fleet_type": instance_fleet_type,
        }
        if instance_type_configs is not None:
            self._values["instance_type_configs"] = instance_type_configs
        if launch_specifications is not None:
            self._values["launch_specifications"] = launch_specifications
        if name is not None:
            self._values["name"] = name
        if target_on_demand_capacity is not None:
            self._values["target_on_demand_capacity"] = target_on_demand_capacity
        if target_spot_capacity is not None:
            self._values["target_spot_capacity"] = target_spot_capacity

    @builtins.property
    def cluster_id(self) -> builtins.str:
        '''The unique identifier of the EMR cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-clusterid
        '''
        result = self._values.get("cluster_id")
        assert result is not None, "Required property 'cluster_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_fleet_type(self) -> builtins.str:
        '''The node type that the instance fleet hosts.

        *Allowed Values* : TASK

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancefleettype
        '''
        result = self._values.get("instance_fleet_type")
        assert result is not None, "Required property 'instance_fleet_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_type_configs(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnInstanceFleetConfig.InstanceTypeConfigProperty, _IResolvable_da3f097b]]]]:
        '''``InstanceTypeConfigs`` determine the EC2 instances that Amazon EMR attempts to provision to fulfill On-Demand and Spot target capacities.

        .. epigraph::

           The instance fleet configuration is available only in Amazon EMR versions 4.8.0 and later, excluding 5.0.x versions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-instancetypeconfigs
        '''
        result = self._values.get("instance_type_configs")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnInstanceFleetConfig.InstanceTypeConfigProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def launch_specifications(
        self,
    ) -> typing.Optional[typing.Union[CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty, _IResolvable_da3f097b]]:
        '''The launch specification for the instance fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-launchspecifications
        '''
        result = self._values.get("launch_specifications")
        return typing.cast(typing.Optional[typing.Union[CfnInstanceFleetConfig.InstanceFleetProvisioningSpecificationsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The friendly name of the instance fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def target_on_demand_capacity(self) -> typing.Optional[jsii.Number]:
        '''The target capacity of On-Demand units for the instance fleet, which determines how many On-Demand instances to provision.

        When the instance fleet launches, Amazon EMR tries to provision On-Demand instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When an On-Demand instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units.
        .. epigraph::

           If not specified or set to 0, only Spot instances are provisioned for the instance fleet using ``TargetSpotCapacity`` . At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-targetondemandcapacity
        '''
        result = self._values.get("target_on_demand_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def target_spot_capacity(self) -> typing.Optional[jsii.Number]:
        '''The target capacity of Spot units for the instance fleet, which determines how many Spot instances to provision.

        When the instance fleet launches, Amazon EMR tries to provision Spot instances as specified by ``InstanceTypeConfig`` . Each instance configuration has a specified ``WeightedCapacity`` . When a Spot instance is provisioned, the ``WeightedCapacity`` units count toward the target capacity. Amazon EMR provisions instances until the target capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EMR can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the target capacity is exceeded by 3 units.
        .. epigraph::

           If not specified or set to 0, only On-Demand instances are provisioned for the instance fleet. At least one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` should be greater than 0. For a master instance fleet, only one of ``TargetSpotCapacity`` and ``TargetOnDemandCapacity`` can be specified, and its value must be 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-instancefleetconfig.html#cfn-elasticmapreduce-instancefleetconfig-targetspotcapacity
        '''
        result = self._values.get("target_spot_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnInstanceFleetConfigProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnInstanceGroupConfig(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig",
):
    '''A CloudFormation ``AWS::EMR::InstanceGroupConfig``.

    Use ``InstanceGroupConfig`` to define instance groups for an EMR cluster. A cluster can not use both instance groups and instance fleets. For more information, see `Create a Cluster with Instance Fleets or Uniform Instance Groups <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-instance-group-configuration.html>`_ in the *Amazon EMR Management Guide* .
    .. epigraph::

       You can currently only add task instance groups to a cluster with this resource. If you use this resource, CloudFormation waits for the cluster launch to complete before adding the task instance group to the cluster. In order to add task instance groups to the cluster as part of the cluster launch and minimize delays in provisioning task nodes, use the ``TaskInstanceGroups`` subproperty for the `AWS::EMR::Cluster JobFlowInstancesConfig <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-cluster-jobflowinstancesconfig.html>`_ property instead. To use this subproperty, see `AWS::EMR::Cluster <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html>`_ for examples.

    :cloudformationResource: AWS::EMR::InstanceGroupConfig
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_emr as emr
        
        # configuration_property_: emr.CfnInstanceGroupConfig.ConfigurationProperty
        
        cfn_instance_group_config = emr.CfnInstanceGroupConfig(self, "MyCfnInstanceGroupConfig",
            instance_count=123,
            instance_role="instanceRole",
            instance_type="instanceType",
            job_flow_id="jobFlowId",
        
            # the properties below are optional
            auto_scaling_policy=emr.CfnInstanceGroupConfig.AutoScalingPolicyProperty(
                constraints=emr.CfnInstanceGroupConfig.ScalingConstraintsProperty(
                    max_capacity=123,
                    min_capacity=123
                ),
                rules=[emr.CfnInstanceGroupConfig.ScalingRuleProperty(
                    action=emr.CfnInstanceGroupConfig.ScalingActionProperty(
                        simple_scaling_policy_configuration=emr.CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty(
                            scaling_adjustment=123,
        
                            # the properties below are optional
                            adjustment_type="adjustmentType",
                            cool_down=123
                        ),
        
                        # the properties below are optional
                        market="market"
                    ),
                    name="name",
                    trigger=emr.CfnInstanceGroupConfig.ScalingTriggerProperty(
                        cloud_watch_alarm_definition=emr.CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty(
                            comparison_operator="comparisonOperator",
                            metric_name="metricName",
                            period=123,
                            threshold=123,
        
                            # the properties below are optional
                            dimensions=[emr.CfnInstanceGroupConfig.MetricDimensionProperty(
                                key="key",
                                value="value"
                            )],
                            evaluation_periods=123,
                            namespace="namespace",
                            statistic="statistic",
                            unit="unit"
                        )
                    ),
        
                    # the properties below are optional
                    description="description"
                )]
            ),
            bid_price="bidPrice",
            configurations=[emr.CfnInstanceGroupConfig.ConfigurationProperty(
                classification="classification",
                configuration_properties={
                    "configuration_properties_key": "configurationProperties"
                },
                configurations=[configuration_property_]
            )],
            custom_ami_id="customAmiId",
            ebs_configuration=emr.CfnInstanceGroupConfig.EbsConfigurationProperty(
                ebs_block_device_configs=[emr.CfnInstanceGroupConfig.EbsBlockDeviceConfigProperty(
                    volume_specification=emr.CfnInstanceGroupConfig.VolumeSpecificationProperty(
                        size_in_gb=123,
                        volume_type="volumeType",
        
                        # the properties below are optional
                        iops=123
                    ),
        
                    # the properties below are optional
                    volumes_per_instance=123
                )],
                ebs_optimized=False
            ),
            market="market",
            name="name"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instance_count: jsii.Number,
        instance_role: builtins.str,
        instance_type: builtins.str,
        job_flow_id: builtins.str,
        auto_scaling_policy: typing.Optional[typing.Union["CfnInstanceGroupConfig.AutoScalingPolicyProperty", _IResolvable_da3f097b]] = None,
        bid_price: typing.Optional[builtins.str] = None,
        configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceGroupConfig.ConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        custom_ami_id: typing.Optional[builtins.str] = None,
        ebs_configuration: typing.Optional[typing.Union["CfnInstanceGroupConfig.EbsConfigurationProperty", _IResolvable_da3f097b]] = None,
        market: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::EMR::InstanceGroupConfig``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param instance_count: Target number of instances for the instance group.
        :param instance_role: The role of the instance group in the cluster. *Allowed Values* : TASK
        :param instance_type: The EC2 instance type for all instances in the instance group.
        :param job_flow_id: The ID of an Amazon EMR cluster that you want to associate this instance group with.
        :param auto_scaling_policy: ``AutoScalingPolicy`` is a subproperty of ``InstanceGroupConfig`` . ``AutoScalingPolicy`` defines how an instance group dynamically adds and terminates EC2 instances in response to the value of a CloudWatch metric. For more information, see `Using Automatic Scaling in Amazon EMR <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-automatic-scaling.html>`_ in the *Amazon EMR Management Guide* .
        :param bid_price: If specified, indicates that the instance group uses Spot Instances. This is the maximum price you are willing to pay for Spot Instances. Specify ``OnDemandPrice`` to set the amount equal to the On-Demand price, or specify an amount in USD.
        :param configurations: .. epigraph:: Amazon EMR releases 4.x or later. The list of configurations supplied for an EMR cluster instance group. You can specify a separate configuration for each instance group (master, core, and task).
        :param custom_ami_id: The custom AMI ID to use for the provisioned instance group.
        :param ebs_configuration: ``EbsConfiguration`` determines the EBS volumes to attach to EMR cluster instances.
        :param market: Market type of the EC2 instances used to create a cluster node.
        :param name: Friendly name given to the instance group.
        '''
        props = CfnInstanceGroupConfigProps(
            instance_count=instance_count,
            instance_role=instance_role,
            instance_type=instance_type,
            job_flow_id=job_flow_id,
            auto_scaling_policy=auto_scaling_policy,
            bid_price=bid_price,
            configurations=configurations,
            custom_ami_id=custom_ami_id,
            ebs_configuration=ebs_configuration,
            market=market,
            name=name,
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
    @jsii.member(jsii_name="instanceCount")
    def instance_count(self) -> jsii.Number:
        '''Target number of instances for the instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfiginstancecount-
        '''
        return typing.cast(jsii.Number, jsii.get(self, "instanceCount"))

    @instance_count.setter
    def instance_count(self, value: jsii.Number) -> None:
        jsii.set(self, "instanceCount", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceRole")
    def instance_role(self) -> builtins.str:
        '''The role of the instance group in the cluster.

        *Allowed Values* : TASK

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-instancerole
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceRole"))

    @instance_role.setter
    def instance_role(self, value: builtins.str) -> None:
        jsii.set(self, "instanceRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceType")
    def instance_type(self) -> builtins.str:
        '''The EC2 instance type for all instances in the instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-instancetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceType"))

    @instance_type.setter
    def instance_type(self, value: builtins.str) -> None:
        jsii.set(self, "instanceType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="jobFlowId")
    def job_flow_id(self) -> builtins.str:
        '''The ID of an Amazon EMR cluster that you want to associate this instance group with.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-jobflowid
        '''
        return typing.cast(builtins.str, jsii.get(self, "jobFlowId"))

    @job_flow_id.setter
    def job_flow_id(self, value: builtins.str) -> None:
        jsii.set(self, "jobFlowId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingPolicy")
    def auto_scaling_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnInstanceGroupConfig.AutoScalingPolicyProperty", _IResolvable_da3f097b]]:
        '''``AutoScalingPolicy`` is a subproperty of ``InstanceGroupConfig`` .

        ``AutoScalingPolicy`` defines how an instance group dynamically adds and terminates EC2 instances in response to the value of a CloudWatch metric. For more information, see `Using Automatic Scaling in Amazon EMR <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-automatic-scaling.html>`_ in the *Amazon EMR Management Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-elasticmapreduce-instancegroupconfig-autoscalingpolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnInstanceGroupConfig.AutoScalingPolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "autoScalingPolicy"))

    @auto_scaling_policy.setter
    def auto_scaling_policy(
        self,
        value: typing.Optional[typing.Union["CfnInstanceGroupConfig.AutoScalingPolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "autoScalingPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bidPrice")
    def bid_price(self) -> typing.Optional[builtins.str]:
        '''If specified, indicates that the instance group uses Spot Instances.

        This is the maximum price you are willing to pay for Spot Instances. Specify ``OnDemandPrice`` to set the amount equal to the On-Demand price, or specify an amount in USD.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-bidprice
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "bidPrice"))

    @bid_price.setter
    def bid_price(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "bidPrice", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="configurations")
    def configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.ConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''.. epigraph::

   Amazon EMR releases 4.x or later.

        The list of configurations supplied for an EMR cluster instance group. You can specify a separate configuration for each instance group (master, core, and task).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-configurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.ConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "configurations"))

    @configurations.setter
    def configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.ConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "configurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="customAmiId")
    def custom_ami_id(self) -> typing.Optional[builtins.str]:
        '''The custom AMI ID to use for the provisioned instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-customamiid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "customAmiId"))

    @custom_ami_id.setter
    def custom_ami_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "customAmiId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ebsConfiguration")
    def ebs_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnInstanceGroupConfig.EbsConfigurationProperty", _IResolvable_da3f097b]]:
        '''``EbsConfiguration`` determines the EBS volumes to attach to EMR cluster instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-ebsconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnInstanceGroupConfig.EbsConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "ebsConfiguration"))

    @ebs_configuration.setter
    def ebs_configuration(
        self,
        value: typing.Optional[typing.Union["CfnInstanceGroupConfig.EbsConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ebsConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="market")
    def market(self) -> typing.Optional[builtins.str]:
        '''Market type of the EC2 instances used to create a cluster node.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-market
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "market"))

    @market.setter
    def market(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "market", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''Friendly name given to the instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.AutoScalingPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={"constraints": "constraints", "rules": "rules"},
    )
    class AutoScalingPolicyProperty:
        def __init__(
            self,
            *,
            constraints: typing.Union["CfnInstanceGroupConfig.ScalingConstraintsProperty", _IResolvable_da3f097b],
            rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceGroupConfig.ScalingRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''``AutoScalingPolicy`` defines how an instance group dynamically adds and terminates EC2 instances in response to the value of a CloudWatch metric.

            For more information, see `Using Automatic Scaling in Amazon EMR <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-automatic-scaling.html>`_ in the *Amazon EMR Management Guide* .

            :param constraints: The upper and lower EC2 instance limits for an automatic scaling policy. Automatic scaling activity will not cause an instance group to grow above or below these limits.
            :param rules: The scale-in and scale-out rules that comprise the automatic scaling policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-autoscalingpolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                auto_scaling_policy_property = emr.CfnInstanceGroupConfig.AutoScalingPolicyProperty(
                    constraints=emr.CfnInstanceGroupConfig.ScalingConstraintsProperty(
                        max_capacity=123,
                        min_capacity=123
                    ),
                    rules=[emr.CfnInstanceGroupConfig.ScalingRuleProperty(
                        action=emr.CfnInstanceGroupConfig.ScalingActionProperty(
                            simple_scaling_policy_configuration=emr.CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty(
                                scaling_adjustment=123,
                
                                # the properties below are optional
                                adjustment_type="adjustmentType",
                                cool_down=123
                            ),
                
                            # the properties below are optional
                            market="market"
                        ),
                        name="name",
                        trigger=emr.CfnInstanceGroupConfig.ScalingTriggerProperty(
                            cloud_watch_alarm_definition=emr.CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty(
                                comparison_operator="comparisonOperator",
                                metric_name="metricName",
                                period=123,
                                threshold=123,
                
                                # the properties below are optional
                                dimensions=[emr.CfnInstanceGroupConfig.MetricDimensionProperty(
                                    key="key",
                                    value="value"
                                )],
                                evaluation_periods=123,
                                namespace="namespace",
                                statistic="statistic",
                                unit="unit"
                            )
                        ),
                
                        # the properties below are optional
                        description="description"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "constraints": constraints,
                "rules": rules,
            }

        @builtins.property
        def constraints(
            self,
        ) -> typing.Union["CfnInstanceGroupConfig.ScalingConstraintsProperty", _IResolvable_da3f097b]:
            '''The upper and lower EC2 instance limits for an automatic scaling policy.

            Automatic scaling activity will not cause an instance group to grow above or below these limits.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-autoscalingpolicy.html#cfn-elasticmapreduce-instancegroupconfig-autoscalingpolicy-constraints
            '''
            result = self._values.get("constraints")
            assert result is not None, "Required property 'constraints' is missing"
            return typing.cast(typing.Union["CfnInstanceGroupConfig.ScalingConstraintsProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def rules(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.ScalingRuleProperty", _IResolvable_da3f097b]]]:
            '''The scale-in and scale-out rules that comprise the automatic scaling policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-autoscalingpolicy.html#cfn-elasticmapreduce-instancegroupconfig-autoscalingpolicy-rules
            '''
            result = self._values.get("rules")
            assert result is not None, "Required property 'rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.ScalingRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AutoScalingPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "comparison_operator": "comparisonOperator",
            "metric_name": "metricName",
            "period": "period",
            "threshold": "threshold",
            "dimensions": "dimensions",
            "evaluation_periods": "evaluationPeriods",
            "namespace": "namespace",
            "statistic": "statistic",
            "unit": "unit",
        },
    )
    class CloudWatchAlarmDefinitionProperty:
        def __init__(
            self,
            *,
            comparison_operator: builtins.str,
            metric_name: builtins.str,
            period: jsii.Number,
            threshold: jsii.Number,
            dimensions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceGroupConfig.MetricDimensionProperty", _IResolvable_da3f097b]]]] = None,
            evaluation_periods: typing.Optional[jsii.Number] = None,
            namespace: typing.Optional[builtins.str] = None,
            statistic: typing.Optional[builtins.str] = None,
            unit: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``CloudWatchAlarmDefinition`` is a subproperty of the ``ScalingTrigger`` property, which determines when to trigger an automatic scaling activity.

            Scaling activity begins when you satisfy the defined alarm conditions.

            :param comparison_operator: Determines how the metric specified by ``MetricName`` is compared to the value specified by ``Threshold`` .
            :param metric_name: The name of the CloudWatch metric that is watched to determine an alarm condition.
            :param period: The period, in seconds, over which the statistic is applied. EMR CloudWatch metrics are emitted every five minutes (300 seconds), so if an EMR CloudWatch metric is specified, specify ``300`` .
            :param threshold: The value against which the specified statistic is compared.
            :param dimensions: A CloudWatch metric dimension.
            :param evaluation_periods: The number of periods, in five-minute increments, during which the alarm condition must exist before the alarm triggers automatic scaling activity. The default value is ``1`` .
            :param namespace: The namespace for the CloudWatch metric. The default is ``AWS/ElasticMapReduce`` .
            :param statistic: The statistic to apply to the metric associated with the alarm. The default is ``AVERAGE`` .
            :param unit: The unit of measure associated with the CloudWatch metric being watched. The value specified for ``Unit`` must correspond to the units specified in the CloudWatch metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                cloud_watch_alarm_definition_property = emr.CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty(
                    comparison_operator="comparisonOperator",
                    metric_name="metricName",
                    period=123,
                    threshold=123,
                
                    # the properties below are optional
                    dimensions=[emr.CfnInstanceGroupConfig.MetricDimensionProperty(
                        key="key",
                        value="value"
                    )],
                    evaluation_periods=123,
                    namespace="namespace",
                    statistic="statistic",
                    unit="unit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "comparison_operator": comparison_operator,
                "metric_name": metric_name,
                "period": period,
                "threshold": threshold,
            }
            if dimensions is not None:
                self._values["dimensions"] = dimensions
            if evaluation_periods is not None:
                self._values["evaluation_periods"] = evaluation_periods
            if namespace is not None:
                self._values["namespace"] = namespace
            if statistic is not None:
                self._values["statistic"] = statistic
            if unit is not None:
                self._values["unit"] = unit

        @builtins.property
        def comparison_operator(self) -> builtins.str:
            '''Determines how the metric specified by ``MetricName`` is compared to the value specified by ``Threshold`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-comparisonoperator
            '''
            result = self._values.get("comparison_operator")
            assert result is not None, "Required property 'comparison_operator' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def metric_name(self) -> builtins.str:
            '''The name of the CloudWatch metric that is watched to determine an alarm condition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-metricname
            '''
            result = self._values.get("metric_name")
            assert result is not None, "Required property 'metric_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def period(self) -> jsii.Number:
            '''The period, in seconds, over which the statistic is applied.

            EMR CloudWatch metrics are emitted every five minutes (300 seconds), so if an EMR CloudWatch metric is specified, specify ``300`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-period
            '''
            result = self._values.get("period")
            assert result is not None, "Required property 'period' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def threshold(self) -> jsii.Number:
            '''The value against which the specified statistic is compared.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-threshold
            '''
            result = self._values.get("threshold")
            assert result is not None, "Required property 'threshold' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def dimensions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.MetricDimensionProperty", _IResolvable_da3f097b]]]]:
            '''A CloudWatch metric dimension.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-dimensions
            '''
            result = self._values.get("dimensions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.MetricDimensionProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def evaluation_periods(self) -> typing.Optional[jsii.Number]:
            '''The number of periods, in five-minute increments, during which the alarm condition must exist before the alarm triggers automatic scaling activity.

            The default value is ``1`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-evaluationperiods
            '''
            result = self._values.get("evaluation_periods")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def namespace(self) -> typing.Optional[builtins.str]:
            '''The namespace for the CloudWatch metric.

            The default is ``AWS/ElasticMapReduce`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-namespace
            '''
            result = self._values.get("namespace")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def statistic(self) -> typing.Optional[builtins.str]:
            '''The statistic to apply to the metric associated with the alarm.

            The default is ``AVERAGE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-statistic
            '''
            result = self._values.get("statistic")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def unit(self) -> typing.Optional[builtins.str]:
            '''The unit of measure associated with the CloudWatch metric being watched.

            The value specified for ``Unit`` must correspond to the units specified in the CloudWatch metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition.html#cfn-elasticmapreduce-instancegroupconfig-cloudwatchalarmdefinition-unit
            '''
            result = self._values.get("unit")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CloudWatchAlarmDefinitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.ConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "classification": "classification",
            "configuration_properties": "configurationProperties",
            "configurations": "configurations",
        },
    )
    class ConfigurationProperty:
        def __init__(
            self,
            *,
            classification: typing.Optional[builtins.str] = None,
            configuration_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceGroupConfig.ConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''``Configurations`` is a property of the ``AWS::EMR::Cluster`` resource that specifies the configuration of applications on an Amazon EMR cluster.

            Configurations are optional. You can use them to have EMR customize applications and software bundled with Amazon EMR when a cluster is created. A configuration consists of a classification, properties, and optional nested configurations. A classification refers to an application-specific configuration file. Properties are the settings you want to change in that file. For more information, see `Configuring Applications <https://docs.aws.amazon.com/emr/latest/ReleaseGuide/emr-configure-apps.html>`_ .
            .. epigraph::

               Applies only to Amazon EMR releases 4.0 and later.

            :param classification: The classification within a configuration.
            :param configuration_properties: Within a configuration classification, a set of properties that represent the settings that you want to change in the configuration file. Duplicates not allowed.
            :param configurations: A list of additional configurations to apply within a configuration object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-cluster-configuration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                # configuration_property_: emr.CfnInstanceGroupConfig.ConfigurationProperty
                
                configuration_property = emr.CfnInstanceGroupConfig.ConfigurationProperty(
                    classification="classification",
                    configuration_properties={
                        "configuration_properties_key": "configurationProperties"
                    },
                    configurations=[emr.CfnInstanceGroupConfig.ConfigurationProperty(
                        classification="classification",
                        configuration_properties={
                            "configuration_properties_key": "configurationProperties"
                        },
                        configurations=[configuration_property_]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if classification is not None:
                self._values["classification"] = classification
            if configuration_properties is not None:
                self._values["configuration_properties"] = configuration_properties
            if configurations is not None:
                self._values["configurations"] = configurations

        @builtins.property
        def classification(self) -> typing.Optional[builtins.str]:
            '''The classification within a configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-cluster-configuration.html#cfn-emr-cluster-configuration-classification
            '''
            result = self._values.get("classification")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def configuration_properties(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''Within a configuration classification, a set of properties that represent the settings that you want to change in the configuration file.

            Duplicates not allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-cluster-configuration.html#cfn-emr-cluster-configuration-configurationproperties
            '''
            result = self._values.get("configuration_properties")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.ConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''A list of additional configurations to apply within a configuration object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-cluster-configuration.html#cfn-emr-cluster-configuration-configurations
            '''
            result = self._values.get("configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.ConfigurationProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.EbsBlockDeviceConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "volume_specification": "volumeSpecification",
            "volumes_per_instance": "volumesPerInstance",
        },
    )
    class EbsBlockDeviceConfigProperty:
        def __init__(
            self,
            *,
            volume_specification: typing.Union["CfnInstanceGroupConfig.VolumeSpecificationProperty", _IResolvable_da3f097b],
            volumes_per_instance: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Configuration of requested EBS block device associated with the instance group with count of volumes that will be associated to every instance.

            :param volume_specification: EBS volume specifications such as volume type, IOPS, and size (GiB) that will be requested for the EBS volume attached to an EC2 instance in the cluster.
            :param volumes_per_instance: Number of EBS volumes with a specific volume configuration that will be associated with every instance in the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration-ebsblockdeviceconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                ebs_block_device_config_property = emr.CfnInstanceGroupConfig.EbsBlockDeviceConfigProperty(
                    volume_specification=emr.CfnInstanceGroupConfig.VolumeSpecificationProperty(
                        size_in_gb=123,
                        volume_type="volumeType",
                
                        # the properties below are optional
                        iops=123
                    ),
                
                    # the properties below are optional
                    volumes_per_instance=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "volume_specification": volume_specification,
            }
            if volumes_per_instance is not None:
                self._values["volumes_per_instance"] = volumes_per_instance

        @builtins.property
        def volume_specification(
            self,
        ) -> typing.Union["CfnInstanceGroupConfig.VolumeSpecificationProperty", _IResolvable_da3f097b]:
            '''EBS volume specifications such as volume type, IOPS, and size (GiB) that will be requested for the EBS volume attached to an EC2 instance in the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration-ebsblockdeviceconfig.html#cfn-emr-ebsconfiguration-ebsblockdeviceconfig-volumespecification
            '''
            result = self._values.get("volume_specification")
            assert result is not None, "Required property 'volume_specification' is missing"
            return typing.cast(typing.Union["CfnInstanceGroupConfig.VolumeSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def volumes_per_instance(self) -> typing.Optional[jsii.Number]:
            '''Number of EBS volumes with a specific volume configuration that will be associated with every instance in the instance group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration-ebsblockdeviceconfig.html#cfn-emr-ebsconfiguration-ebsblockdeviceconfig-volumesperinstance
            '''
            result = self._values.get("volumes_per_instance")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EbsBlockDeviceConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.EbsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ebs_block_device_configs": "ebsBlockDeviceConfigs",
            "ebs_optimized": "ebsOptimized",
        },
    )
    class EbsConfigurationProperty:
        def __init__(
            self,
            *,
            ebs_block_device_configs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnInstanceGroupConfig.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]] = None,
            ebs_optimized: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The Amazon EBS configuration of a cluster instance.

            :param ebs_block_device_configs: An array of Amazon EBS volume specifications attached to a cluster instance.
            :param ebs_optimized: Indicates whether an Amazon EBS volume is EBS-optimized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                ebs_configuration_property = emr.CfnInstanceGroupConfig.EbsConfigurationProperty(
                    ebs_block_device_configs=[emr.CfnInstanceGroupConfig.EbsBlockDeviceConfigProperty(
                        volume_specification=emr.CfnInstanceGroupConfig.VolumeSpecificationProperty(
                            size_in_gb=123,
                            volume_type="volumeType",
                
                            # the properties below are optional
                            iops=123
                        ),
                
                        # the properties below are optional
                        volumes_per_instance=123
                    )],
                    ebs_optimized=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ebs_block_device_configs is not None:
                self._values["ebs_block_device_configs"] = ebs_block_device_configs
            if ebs_optimized is not None:
                self._values["ebs_optimized"] = ebs_optimized

        @builtins.property
        def ebs_block_device_configs(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]]:
            '''An array of Amazon EBS volume specifications attached to a cluster instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration.html#cfn-emr-ebsconfiguration-ebsblockdeviceconfigs
            '''
            result = self._values.get("ebs_block_device_configs")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnInstanceGroupConfig.EbsBlockDeviceConfigProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def ebs_optimized(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether an Amazon EBS volume is EBS-optimized.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration.html#cfn-emr-ebsconfiguration-ebsoptimized
            '''
            result = self._values.get("ebs_optimized")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EbsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.MetricDimensionProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class MetricDimensionProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''``MetricDimension`` is a subproperty of the ``CloudWatchAlarmDefinition`` property type.

            ``MetricDimension`` specifies a CloudWatch dimension, which is specified with a ``Key`` ``Value`` pair. The key is known as a ``Name`` in CloudWatch. By default, Amazon EMR uses one dimension whose ``Key`` is ``JobFlowID`` and ``Value`` is a variable representing the cluster ID, which is ``${emr.clusterId}`` . This enables the automatic scaling rule for EMR to bootstrap when the cluster ID becomes available during cluster creation.

            :param key: The dimension name.
            :param value: The dimension value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-metricdimension.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                metric_dimension_property = emr.CfnInstanceGroupConfig.MetricDimensionProperty(
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "value": value,
            }

        @builtins.property
        def key(self) -> builtins.str:
            '''The dimension name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-metricdimension.html#cfn-elasticmapreduce-instancegroupconfig-metricdimension-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The dimension value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-metricdimension.html#cfn-elasticmapreduce-instancegroupconfig-metricdimension-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetricDimensionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.ScalingActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "simple_scaling_policy_configuration": "simpleScalingPolicyConfiguration",
            "market": "market",
        },
    )
    class ScalingActionProperty:
        def __init__(
            self,
            *,
            simple_scaling_policy_configuration: typing.Union["CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty", _IResolvable_da3f097b],
            market: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``ScalingAction`` is a subproperty of the ``ScalingRule`` property type.

            ``ScalingAction`` determines the type of adjustment the automatic scaling activity makes when triggered, and the periodicity of the adjustment.

            :param simple_scaling_policy_configuration: The type of adjustment the automatic scaling activity makes when triggered, and the periodicity of the adjustment.
            :param market: Not available for instance groups. Instance groups use the market type specified for the group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                scaling_action_property = emr.CfnInstanceGroupConfig.ScalingActionProperty(
                    simple_scaling_policy_configuration=emr.CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty(
                        scaling_adjustment=123,
                
                        # the properties below are optional
                        adjustment_type="adjustmentType",
                        cool_down=123
                    ),
                
                    # the properties below are optional
                    market="market"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "simple_scaling_policy_configuration": simple_scaling_policy_configuration,
            }
            if market is not None:
                self._values["market"] = market

        @builtins.property
        def simple_scaling_policy_configuration(
            self,
        ) -> typing.Union["CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty", _IResolvable_da3f097b]:
            '''The type of adjustment the automatic scaling activity makes when triggered, and the periodicity of the adjustment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingaction.html#cfn-elasticmapreduce-instancegroupconfig-scalingaction-simplescalingpolicyconfiguration
            '''
            result = self._values.get("simple_scaling_policy_configuration")
            assert result is not None, "Required property 'simple_scaling_policy_configuration' is missing"
            return typing.cast(typing.Union["CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def market(self) -> typing.Optional[builtins.str]:
            '''Not available for instance groups.

            Instance groups use the market type specified for the group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingaction.html#cfn-elasticmapreduce-instancegroupconfig-scalingaction-market
            '''
            result = self._values.get("market")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.ScalingConstraintsProperty",
        jsii_struct_bases=[],
        name_mapping={"max_capacity": "maxCapacity", "min_capacity": "minCapacity"},
    )
    class ScalingConstraintsProperty:
        def __init__(
            self,
            *,
            max_capacity: jsii.Number,
            min_capacity: jsii.Number,
        ) -> None:
            '''``ScalingConstraints`` is a subproperty of the ``AutoScalingPolicy`` property type.

            ``ScalingConstraints`` defines the upper and lower EC2 instance limits for an automatic scaling policy. Automatic scaling activities triggered by automatic scaling rules will not cause an instance group to grow above or shrink below these limits.

            :param max_capacity: The upper boundary of EC2 instances in an instance group beyond which scaling activities are not allowed to grow. Scale-out activities will not add instances beyond this boundary.
            :param min_capacity: The lower boundary of EC2 instances in an instance group below which scaling activities are not allowed to shrink. Scale-in activities will not terminate instances below this boundary.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingconstraints.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                scaling_constraints_property = emr.CfnInstanceGroupConfig.ScalingConstraintsProperty(
                    max_capacity=123,
                    min_capacity=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "max_capacity": max_capacity,
                "min_capacity": min_capacity,
            }

        @builtins.property
        def max_capacity(self) -> jsii.Number:
            '''The upper boundary of EC2 instances in an instance group beyond which scaling activities are not allowed to grow.

            Scale-out activities will not add instances beyond this boundary.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingconstraints.html#cfn-elasticmapreduce-instancegroupconfig-scalingconstraints-maxcapacity
            '''
            result = self._values.get("max_capacity")
            assert result is not None, "Required property 'max_capacity' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def min_capacity(self) -> jsii.Number:
            '''The lower boundary of EC2 instances in an instance group below which scaling activities are not allowed to shrink.

            Scale-in activities will not terminate instances below this boundary.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingconstraints.html#cfn-elasticmapreduce-instancegroupconfig-scalingconstraints-mincapacity
            '''
            result = self._values.get("min_capacity")
            assert result is not None, "Required property 'min_capacity' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingConstraintsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.ScalingRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "action": "action",
            "name": "name",
            "trigger": "trigger",
            "description": "description",
        },
    )
    class ScalingRuleProperty:
        def __init__(
            self,
            *,
            action: typing.Union["CfnInstanceGroupConfig.ScalingActionProperty", _IResolvable_da3f097b],
            name: builtins.str,
            trigger: typing.Union["CfnInstanceGroupConfig.ScalingTriggerProperty", _IResolvable_da3f097b],
            description: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``ScalingRule`` is a subproperty of the ``AutoScalingPolicy`` property type.

            ``ScalingRule`` defines the scale-in or scale-out rules for scaling activity, including the CloudWatch metric alarm that triggers activity, how EC2 instances are added or removed, and the periodicity of adjustments. The automatic scaling policy for an instance group can comprise one or more automatic scaling rules.

            :param action: The conditions that trigger an automatic scaling activity.
            :param name: The name used to identify an automatic scaling rule. Rule names must be unique within a scaling policy.
            :param trigger: The CloudWatch alarm definition that determines when automatic scaling activity is triggered.
            :param description: A friendly, more verbose description of the automatic scaling rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                scaling_rule_property = emr.CfnInstanceGroupConfig.ScalingRuleProperty(
                    action=emr.CfnInstanceGroupConfig.ScalingActionProperty(
                        simple_scaling_policy_configuration=emr.CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty(
                            scaling_adjustment=123,
                
                            # the properties below are optional
                            adjustment_type="adjustmentType",
                            cool_down=123
                        ),
                
                        # the properties below are optional
                        market="market"
                    ),
                    name="name",
                    trigger=emr.CfnInstanceGroupConfig.ScalingTriggerProperty(
                        cloud_watch_alarm_definition=emr.CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty(
                            comparison_operator="comparisonOperator",
                            metric_name="metricName",
                            period=123,
                            threshold=123,
                
                            # the properties below are optional
                            dimensions=[emr.CfnInstanceGroupConfig.MetricDimensionProperty(
                                key="key",
                                value="value"
                            )],
                            evaluation_periods=123,
                            namespace="namespace",
                            statistic="statistic",
                            unit="unit"
                        )
                    ),
                
                    # the properties below are optional
                    description="description"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "action": action,
                "name": name,
                "trigger": trigger,
            }
            if description is not None:
                self._values["description"] = description

        @builtins.property
        def action(
            self,
        ) -> typing.Union["CfnInstanceGroupConfig.ScalingActionProperty", _IResolvable_da3f097b]:
            '''The conditions that trigger an automatic scaling activity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingrule.html#cfn-elasticmapreduce-instancegroupconfig-scalingrule-action
            '''
            result = self._values.get("action")
            assert result is not None, "Required property 'action' is missing"
            return typing.cast(typing.Union["CfnInstanceGroupConfig.ScalingActionProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name used to identify an automatic scaling rule.

            Rule names must be unique within a scaling policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingrule.html#cfn-elasticmapreduce-instancegroupconfig-scalingrule-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def trigger(
            self,
        ) -> typing.Union["CfnInstanceGroupConfig.ScalingTriggerProperty", _IResolvable_da3f097b]:
            '''The CloudWatch alarm definition that determines when automatic scaling activity is triggered.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingrule.html#cfn-elasticmapreduce-instancegroupconfig-scalingrule-trigger
            '''
            result = self._values.get("trigger")
            assert result is not None, "Required property 'trigger' is missing"
            return typing.cast(typing.Union["CfnInstanceGroupConfig.ScalingTriggerProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''A friendly, more verbose description of the automatic scaling rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingrule.html#cfn-elasticmapreduce-instancegroupconfig-scalingrule-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.ScalingTriggerProperty",
        jsii_struct_bases=[],
        name_mapping={"cloud_watch_alarm_definition": "cloudWatchAlarmDefinition"},
    )
    class ScalingTriggerProperty:
        def __init__(
            self,
            *,
            cloud_watch_alarm_definition: typing.Union["CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty", _IResolvable_da3f097b],
        ) -> None:
            '''``ScalingTrigger`` is a subproperty of the ``ScalingRule`` property type.

            ``ScalingTrigger`` determines the conditions that trigger an automatic scaling activity.

            :param cloud_watch_alarm_definition: The definition of a CloudWatch metric alarm. When the defined alarm conditions are met along with other trigger parameters, scaling activity begins.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingtrigger.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                scaling_trigger_property = emr.CfnInstanceGroupConfig.ScalingTriggerProperty(
                    cloud_watch_alarm_definition=emr.CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty(
                        comparison_operator="comparisonOperator",
                        metric_name="metricName",
                        period=123,
                        threshold=123,
                
                        # the properties below are optional
                        dimensions=[emr.CfnInstanceGroupConfig.MetricDimensionProperty(
                            key="key",
                            value="value"
                        )],
                        evaluation_periods=123,
                        namespace="namespace",
                        statistic="statistic",
                        unit="unit"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cloud_watch_alarm_definition": cloud_watch_alarm_definition,
            }

        @builtins.property
        def cloud_watch_alarm_definition(
            self,
        ) -> typing.Union["CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty", _IResolvable_da3f097b]:
            '''The definition of a CloudWatch metric alarm.

            When the defined alarm conditions are met along with other trigger parameters, scaling activity begins.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingtrigger.html#cfn-elasticmapreduce-instancegroupconfig-scalingtrigger-cloudwatchalarmdefinition
            '''
            result = self._values.get("cloud_watch_alarm_definition")
            assert result is not None, "Required property 'cloud_watch_alarm_definition' is missing"
            return typing.cast(typing.Union["CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingTriggerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "scaling_adjustment": "scalingAdjustment",
            "adjustment_type": "adjustmentType",
            "cool_down": "coolDown",
        },
    )
    class SimpleScalingPolicyConfigurationProperty:
        def __init__(
            self,
            *,
            scaling_adjustment: jsii.Number,
            adjustment_type: typing.Optional[builtins.str] = None,
            cool_down: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``SimpleScalingPolicyConfiguration`` is a subproperty of the ``ScalingAction`` property type.

            ``SimpleScalingPolicyConfiguration`` determines how an automatic scaling action adds or removes instances, the cooldown period, and the number of EC2 instances that are added each time the CloudWatch metric alarm condition is satisfied.

            :param scaling_adjustment: The amount by which to scale in or scale out, based on the specified ``AdjustmentType`` . A positive value adds to the instance group's EC2 instance count while a negative number removes instances. If ``AdjustmentType`` is set to ``EXACT_CAPACITY`` , the number should only be a positive integer. If ``AdjustmentType`` is set to ``PERCENT_CHANGE_IN_CAPACITY`` , the value should express the percentage as an integer. For example, -20 indicates a decrease in 20% increments of cluster capacity.
            :param adjustment_type: The way in which EC2 instances are added (if ``ScalingAdjustment`` is a positive number) or terminated (if ``ScalingAdjustment`` is a negative number) each time the scaling activity is triggered. ``CHANGE_IN_CAPACITY`` is the default. ``CHANGE_IN_CAPACITY`` indicates that the EC2 instance count increments or decrements by ``ScalingAdjustment`` , which should be expressed as an integer. ``PERCENT_CHANGE_IN_CAPACITY`` indicates the instance count increments or decrements by the percentage specified by ``ScalingAdjustment`` , which should be expressed as an integer. For example, 20 indicates an increase in 20% increments of cluster capacity. ``EXACT_CAPACITY`` indicates the scaling activity results in an instance group with the number of EC2 instances specified by ``ScalingAdjustment`` , which should be expressed as a positive integer.
            :param cool_down: The amount of time, in seconds, after a scaling activity completes before any further trigger-related scaling activities can start. The default value is 0.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-simplescalingpolicyconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                simple_scaling_policy_configuration_property = emr.CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty(
                    scaling_adjustment=123,
                
                    # the properties below are optional
                    adjustment_type="adjustmentType",
                    cool_down=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "scaling_adjustment": scaling_adjustment,
            }
            if adjustment_type is not None:
                self._values["adjustment_type"] = adjustment_type
            if cool_down is not None:
                self._values["cool_down"] = cool_down

        @builtins.property
        def scaling_adjustment(self) -> jsii.Number:
            '''The amount by which to scale in or scale out, based on the specified ``AdjustmentType`` .

            A positive value adds to the instance group's EC2 instance count while a negative number removes instances. If ``AdjustmentType`` is set to ``EXACT_CAPACITY`` , the number should only be a positive integer. If ``AdjustmentType`` is set to ``PERCENT_CHANGE_IN_CAPACITY`` , the value should express the percentage as an integer. For example, -20 indicates a decrease in 20% increments of cluster capacity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-simplescalingpolicyconfiguration.html#cfn-elasticmapreduce-instancegroupconfig-simplescalingpolicyconfiguration-scalingadjustment
            '''
            result = self._values.get("scaling_adjustment")
            assert result is not None, "Required property 'scaling_adjustment' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def adjustment_type(self) -> typing.Optional[builtins.str]:
            '''The way in which EC2 instances are added (if ``ScalingAdjustment`` is a positive number) or terminated (if ``ScalingAdjustment`` is a negative number) each time the scaling activity is triggered.

            ``CHANGE_IN_CAPACITY`` is the default. ``CHANGE_IN_CAPACITY`` indicates that the EC2 instance count increments or decrements by ``ScalingAdjustment`` , which should be expressed as an integer. ``PERCENT_CHANGE_IN_CAPACITY`` indicates the instance count increments or decrements by the percentage specified by ``ScalingAdjustment`` , which should be expressed as an integer. For example, 20 indicates an increase in 20% increments of cluster capacity. ``EXACT_CAPACITY`` indicates the scaling activity results in an instance group with the number of EC2 instances specified by ``ScalingAdjustment`` , which should be expressed as a positive integer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-simplescalingpolicyconfiguration.html#cfn-elasticmapreduce-instancegroupconfig-simplescalingpolicyconfiguration-adjustmenttype
            '''
            result = self._values.get("adjustment_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def cool_down(self) -> typing.Optional[jsii.Number]:
            '''The amount of time, in seconds, after a scaling activity completes before any further trigger-related scaling activities can start.

            The default value is 0.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-simplescalingpolicyconfiguration.html#cfn-elasticmapreduce-instancegroupconfig-simplescalingpolicyconfiguration-cooldown
            '''
            result = self._values.get("cool_down")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SimpleScalingPolicyConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfig.VolumeSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "size_in_gb": "sizeInGb",
            "volume_type": "volumeType",
            "iops": "iops",
        },
    )
    class VolumeSpecificationProperty:
        def __init__(
            self,
            *,
            size_in_gb: jsii.Number,
            volume_type: builtins.str,
            iops: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``VolumeSpecification`` is a subproperty of the ``EbsBlockDeviceConfig`` property type.

            ``VolumeSecification`` determines the volume type, IOPS, and size (GiB) for EBS volumes attached to EC2 instances.

            :param size_in_gb: The volume size, in gibibytes (GiB). This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.
            :param volume_type: The volume type. Volume types supported are gp2, io1, and standard.
            :param iops: The number of I/O operations per second (IOPS) that the volume supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration-ebsblockdeviceconfig-volumespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                volume_specification_property = emr.CfnInstanceGroupConfig.VolumeSpecificationProperty(
                    size_in_gb=123,
                    volume_type="volumeType",
                
                    # the properties below are optional
                    iops=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "size_in_gb": size_in_gb,
                "volume_type": volume_type,
            }
            if iops is not None:
                self._values["iops"] = iops

        @builtins.property
        def size_in_gb(self) -> jsii.Number:
            '''The volume size, in gibibytes (GiB).

            This can be a number from 1 - 1024. If the volume type is EBS-optimized, the minimum value is 10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration-ebsblockdeviceconfig-volumespecification.html#cfn-emr-ebsconfiguration-ebsblockdeviceconfig-volumespecification-sizeingb
            '''
            result = self._values.get("size_in_gb")
            assert result is not None, "Required property 'size_in_gb' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def volume_type(self) -> builtins.str:
            '''The volume type.

            Volume types supported are gp2, io1, and standard.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration-ebsblockdeviceconfig-volumespecification.html#cfn-emr-ebsconfiguration-ebsblockdeviceconfig-volumespecification-volumetype
            '''
            result = self._values.get("volume_type")
            assert result is not None, "Required property 'volume_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def iops(self) -> typing.Optional[jsii.Number]:
            '''The number of I/O operations per second (IOPS) that the volume supports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-emr-ebsconfiguration-ebsblockdeviceconfig-volumespecification.html#cfn-emr-ebsconfiguration-ebsblockdeviceconfig-volumespecification-iops
            '''
            result = self._values.get("iops")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VolumeSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_emr.CfnInstanceGroupConfigProps",
    jsii_struct_bases=[],
    name_mapping={
        "instance_count": "instanceCount",
        "instance_role": "instanceRole",
        "instance_type": "instanceType",
        "job_flow_id": "jobFlowId",
        "auto_scaling_policy": "autoScalingPolicy",
        "bid_price": "bidPrice",
        "configurations": "configurations",
        "custom_ami_id": "customAmiId",
        "ebs_configuration": "ebsConfiguration",
        "market": "market",
        "name": "name",
    },
)
class CfnInstanceGroupConfigProps:
    def __init__(
        self,
        *,
        instance_count: jsii.Number,
        instance_role: builtins.str,
        instance_type: builtins.str,
        job_flow_id: builtins.str,
        auto_scaling_policy: typing.Optional[typing.Union[CfnInstanceGroupConfig.AutoScalingPolicyProperty, _IResolvable_da3f097b]] = None,
        bid_price: typing.Optional[builtins.str] = None,
        configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnInstanceGroupConfig.ConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        custom_ami_id: typing.Optional[builtins.str] = None,
        ebs_configuration: typing.Optional[typing.Union[CfnInstanceGroupConfig.EbsConfigurationProperty, _IResolvable_da3f097b]] = None,
        market: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnInstanceGroupConfig``.

        :param instance_count: Target number of instances for the instance group.
        :param instance_role: The role of the instance group in the cluster. *Allowed Values* : TASK
        :param instance_type: The EC2 instance type for all instances in the instance group.
        :param job_flow_id: The ID of an Amazon EMR cluster that you want to associate this instance group with.
        :param auto_scaling_policy: ``AutoScalingPolicy`` is a subproperty of ``InstanceGroupConfig`` . ``AutoScalingPolicy`` defines how an instance group dynamically adds and terminates EC2 instances in response to the value of a CloudWatch metric. For more information, see `Using Automatic Scaling in Amazon EMR <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-automatic-scaling.html>`_ in the *Amazon EMR Management Guide* .
        :param bid_price: If specified, indicates that the instance group uses Spot Instances. This is the maximum price you are willing to pay for Spot Instances. Specify ``OnDemandPrice`` to set the amount equal to the On-Demand price, or specify an amount in USD.
        :param configurations: .. epigraph:: Amazon EMR releases 4.x or later. The list of configurations supplied for an EMR cluster instance group. You can specify a separate configuration for each instance group (master, core, and task).
        :param custom_ami_id: The custom AMI ID to use for the provisioned instance group.
        :param ebs_configuration: ``EbsConfiguration`` determines the EBS volumes to attach to EMR cluster instances.
        :param market: Market type of the EC2 instances used to create a cluster node.
        :param name: Friendly name given to the instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_emr as emr
            
            # configuration_property_: emr.CfnInstanceGroupConfig.ConfigurationProperty
            
            cfn_instance_group_config_props = emr.CfnInstanceGroupConfigProps(
                instance_count=123,
                instance_role="instanceRole",
                instance_type="instanceType",
                job_flow_id="jobFlowId",
            
                # the properties below are optional
                auto_scaling_policy=emr.CfnInstanceGroupConfig.AutoScalingPolicyProperty(
                    constraints=emr.CfnInstanceGroupConfig.ScalingConstraintsProperty(
                        max_capacity=123,
                        min_capacity=123
                    ),
                    rules=[emr.CfnInstanceGroupConfig.ScalingRuleProperty(
                        action=emr.CfnInstanceGroupConfig.ScalingActionProperty(
                            simple_scaling_policy_configuration=emr.CfnInstanceGroupConfig.SimpleScalingPolicyConfigurationProperty(
                                scaling_adjustment=123,
            
                                # the properties below are optional
                                adjustment_type="adjustmentType",
                                cool_down=123
                            ),
            
                            # the properties below are optional
                            market="market"
                        ),
                        name="name",
                        trigger=emr.CfnInstanceGroupConfig.ScalingTriggerProperty(
                            cloud_watch_alarm_definition=emr.CfnInstanceGroupConfig.CloudWatchAlarmDefinitionProperty(
                                comparison_operator="comparisonOperator",
                                metric_name="metricName",
                                period=123,
                                threshold=123,
            
                                # the properties below are optional
                                dimensions=[emr.CfnInstanceGroupConfig.MetricDimensionProperty(
                                    key="key",
                                    value="value"
                                )],
                                evaluation_periods=123,
                                namespace="namespace",
                                statistic="statistic",
                                unit="unit"
                            )
                        ),
            
                        # the properties below are optional
                        description="description"
                    )]
                ),
                bid_price="bidPrice",
                configurations=[emr.CfnInstanceGroupConfig.ConfigurationProperty(
                    classification="classification",
                    configuration_properties={
                        "configuration_properties_key": "configurationProperties"
                    },
                    configurations=[configuration_property_]
                )],
                custom_ami_id="customAmiId",
                ebs_configuration=emr.CfnInstanceGroupConfig.EbsConfigurationProperty(
                    ebs_block_device_configs=[emr.CfnInstanceGroupConfig.EbsBlockDeviceConfigProperty(
                        volume_specification=emr.CfnInstanceGroupConfig.VolumeSpecificationProperty(
                            size_in_gb=123,
                            volume_type="volumeType",
            
                            # the properties below are optional
                            iops=123
                        ),
            
                        # the properties below are optional
                        volumes_per_instance=123
                    )],
                    ebs_optimized=False
                ),
                market="market",
                name="name"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instance_count": instance_count,
            "instance_role": instance_role,
            "instance_type": instance_type,
            "job_flow_id": job_flow_id,
        }
        if auto_scaling_policy is not None:
            self._values["auto_scaling_policy"] = auto_scaling_policy
        if bid_price is not None:
            self._values["bid_price"] = bid_price
        if configurations is not None:
            self._values["configurations"] = configurations
        if custom_ami_id is not None:
            self._values["custom_ami_id"] = custom_ami_id
        if ebs_configuration is not None:
            self._values["ebs_configuration"] = ebs_configuration
        if market is not None:
            self._values["market"] = market
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def instance_count(self) -> jsii.Number:
        '''Target number of instances for the instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfiginstancecount-
        '''
        result = self._values.get("instance_count")
        assert result is not None, "Required property 'instance_count' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def instance_role(self) -> builtins.str:
        '''The role of the instance group in the cluster.

        *Allowed Values* : TASK

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-instancerole
        '''
        result = self._values.get("instance_role")
        assert result is not None, "Required property 'instance_role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_type(self) -> builtins.str:
        '''The EC2 instance type for all instances in the instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-instancetype
        '''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def job_flow_id(self) -> builtins.str:
        '''The ID of an Amazon EMR cluster that you want to associate this instance group with.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-jobflowid
        '''
        result = self._values.get("job_flow_id")
        assert result is not None, "Required property 'job_flow_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auto_scaling_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnInstanceGroupConfig.AutoScalingPolicyProperty, _IResolvable_da3f097b]]:
        '''``AutoScalingPolicy`` is a subproperty of ``InstanceGroupConfig`` .

        ``AutoScalingPolicy`` defines how an instance group dynamically adds and terminates EC2 instances in response to the value of a CloudWatch metric. For more information, see `Using Automatic Scaling in Amazon EMR <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-automatic-scaling.html>`_ in the *Amazon EMR Management Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-elasticmapreduce-instancegroupconfig-autoscalingpolicy
        '''
        result = self._values.get("auto_scaling_policy")
        return typing.cast(typing.Optional[typing.Union[CfnInstanceGroupConfig.AutoScalingPolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def bid_price(self) -> typing.Optional[builtins.str]:
        '''If specified, indicates that the instance group uses Spot Instances.

        This is the maximum price you are willing to pay for Spot Instances. Specify ``OnDemandPrice`` to set the amount equal to the On-Demand price, or specify an amount in USD.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-bidprice
        '''
        result = self._values.get("bid_price")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnInstanceGroupConfig.ConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''.. epigraph::

   Amazon EMR releases 4.x or later.

        The list of configurations supplied for an EMR cluster instance group. You can specify a separate configuration for each instance group (master, core, and task).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-configurations
        '''
        result = self._values.get("configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnInstanceGroupConfig.ConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def custom_ami_id(self) -> typing.Optional[builtins.str]:
        '''The custom AMI ID to use for the provisioned instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-customamiid
        '''
        result = self._values.get("custom_ami_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ebs_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnInstanceGroupConfig.EbsConfigurationProperty, _IResolvable_da3f097b]]:
        '''``EbsConfiguration`` determines the EBS volumes to attach to EMR cluster instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-ebsconfiguration
        '''
        result = self._values.get("ebs_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnInstanceGroupConfig.EbsConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def market(self) -> typing.Optional[builtins.str]:
        '''Market type of the EC2 instances used to create a cluster node.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-market
        '''
        result = self._values.get("market")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''Friendly name given to the instance group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-instancegroupconfig.html#cfn-emr-instancegroupconfig-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnInstanceGroupConfigProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSecurityConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_emr.CfnSecurityConfiguration",
):
    '''A CloudFormation ``AWS::EMR::SecurityConfiguration``.

    Use a ``SecurityConfiguration`` resource to configure data encryption, Kerberos authentication (available in Amazon EMR release version 5.10.0 and later), and Amazon S3 authorization for EMRFS (available in EMR 5.10.0 and later). You can re-use a security configuration for any number of clusters in your account. For more information and example security configuration JSON objects, see `Create a Security Configuration <https://docs.aws.amazon.com//emr/latest/ManagementGuide/emr-create-security-configuration.html>`_ in the *Amazon EMR Management Guide* .

    :cloudformationResource: AWS::EMR::SecurityConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-securityconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_emr as emr
        
        # security_configuration: Any
        
        cfn_security_configuration = emr.CfnSecurityConfiguration(self, "MyCfnSecurityConfiguration",
            security_configuration=security_configuration,
        
            # the properties below are optional
            name="name"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        security_configuration: typing.Any,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::EMR::SecurityConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param security_configuration: The security configuration details in JSON format.
        :param name: The name of the security configuration.
        '''
        props = CfnSecurityConfigurationProps(
            security_configuration=security_configuration, name=name
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
    @jsii.member(jsii_name="securityConfiguration")
    def security_configuration(self) -> typing.Any:
        '''The security configuration details in JSON format.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-securityconfiguration.html#cfn-emr-securityconfiguration-securityconfiguration
        '''
        return typing.cast(typing.Any, jsii.get(self, "securityConfiguration"))

    @security_configuration.setter
    def security_configuration(self, value: typing.Any) -> None:
        jsii.set(self, "securityConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the security configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-securityconfiguration.html#cfn-emr-securityconfiguration-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_emr.CfnSecurityConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={"security_configuration": "securityConfiguration", "name": "name"},
)
class CfnSecurityConfigurationProps:
    def __init__(
        self,
        *,
        security_configuration: typing.Any,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnSecurityConfiguration``.

        :param security_configuration: The security configuration details in JSON format.
        :param name: The name of the security configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-securityconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_emr as emr
            
            # security_configuration: Any
            
            cfn_security_configuration_props = emr.CfnSecurityConfigurationProps(
                security_configuration=security_configuration,
            
                # the properties below are optional
                name="name"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "security_configuration": security_configuration,
        }
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def security_configuration(self) -> typing.Any:
        '''The security configuration details in JSON format.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-securityconfiguration.html#cfn-emr-securityconfiguration-securityconfiguration
        '''
        result = self._values.get("security_configuration")
        assert result is not None, "Required property 'security_configuration' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the security configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-securityconfiguration.html#cfn-emr-securityconfiguration-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSecurityConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStep(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_emr.CfnStep",
):
    '''A CloudFormation ``AWS::EMR::Step``.

    Use ``Step`` to specify a cluster (job flow) step, which runs only on the master node. Steps are used to submit data processing jobs to a cluster.

    :cloudformationResource: AWS::EMR::Step
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_emr as emr
        
        cfn_step = emr.CfnStep(self, "MyCfnStep",
            action_on_failure="actionOnFailure",
            hadoop_jar_step=emr.CfnStep.HadoopJarStepConfigProperty(
                jar="jar",
        
                # the properties below are optional
                args=["args"],
                main_class="mainClass",
                step_properties=[emr.CfnStep.KeyValueProperty(
                    key="key",
                    value="value"
                )]
            ),
            job_flow_id="jobFlowId",
            name="name"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        action_on_failure: builtins.str,
        hadoop_jar_step: typing.Union["CfnStep.HadoopJarStepConfigProperty", _IResolvable_da3f097b],
        job_flow_id: builtins.str,
        name: builtins.str,
    ) -> None:
        '''Create a new ``AWS::EMR::Step``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param action_on_failure: This specifies what action to take when the cluster step fails. Possible values are ``CANCEL_AND_WAIT`` and ``CONTINUE`` .
        :param hadoop_jar_step: The ``HadoopJarStepConfig`` property type specifies a job flow step consisting of a JAR file whose main function will be executed. The main function submits a job for the cluster to execute as a step on the master node, and then waits for the job to finish or fail before executing subsequent steps.
        :param job_flow_id: A string that uniquely identifies the cluster (job flow).
        :param name: The name of the cluster step.
        '''
        props = CfnStepProps(
            action_on_failure=action_on_failure,
            hadoop_jar_step=hadoop_jar_step,
            job_flow_id=job_flow_id,
            name=name,
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
    @jsii.member(jsii_name="actionOnFailure")
    def action_on_failure(self) -> builtins.str:
        '''This specifies what action to take when the cluster step fails.

        Possible values are ``CANCEL_AND_WAIT`` and ``CONTINUE`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html#cfn-elasticmapreduce-step-actiononfailure
        '''
        return typing.cast(builtins.str, jsii.get(self, "actionOnFailure"))

    @action_on_failure.setter
    def action_on_failure(self, value: builtins.str) -> None:
        jsii.set(self, "actionOnFailure", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hadoopJarStep")
    def hadoop_jar_step(
        self,
    ) -> typing.Union["CfnStep.HadoopJarStepConfigProperty", _IResolvable_da3f097b]:
        '''The ``HadoopJarStepConfig`` property type specifies a job flow step consisting of a JAR file whose main function will be executed.

        The main function submits a job for the cluster to execute as a step on the master node, and then waits for the job to finish or fail before executing subsequent steps.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html#cfn-elasticmapreduce-step-hadoopjarstep
        '''
        return typing.cast(typing.Union["CfnStep.HadoopJarStepConfigProperty", _IResolvable_da3f097b], jsii.get(self, "hadoopJarStep"))

    @hadoop_jar_step.setter
    def hadoop_jar_step(
        self,
        value: typing.Union["CfnStep.HadoopJarStepConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "hadoopJarStep", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="jobFlowId")
    def job_flow_id(self) -> builtins.str:
        '''A string that uniquely identifies the cluster (job flow).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html#cfn-elasticmapreduce-step-jobflowid
        '''
        return typing.cast(builtins.str, jsii.get(self, "jobFlowId"))

    @job_flow_id.setter
    def job_flow_id(self, value: builtins.str) -> None:
        jsii.set(self, "jobFlowId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the cluster step.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html#cfn-elasticmapreduce-step-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnStep.HadoopJarStepConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "jar": "jar",
            "args": "args",
            "main_class": "mainClass",
            "step_properties": "stepProperties",
        },
    )
    class HadoopJarStepConfigProperty:
        def __init__(
            self,
            *,
            jar: builtins.str,
            args: typing.Optional[typing.Sequence[builtins.str]] = None,
            main_class: typing.Optional[builtins.str] = None,
            step_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnStep.KeyValueProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A job flow step consisting of a JAR file whose main function will be executed.

            The main function submits a job for Hadoop to execute and waits for the job to finish or fail.

            :param jar: A path to a JAR file run during the step.
            :param args: A list of command line arguments passed to the JAR file's main function when executed.
            :param main_class: The name of the main class in the specified Java file. If not specified, the JAR file should specify a Main-Class in its manifest file.
            :param step_properties: A list of Java properties that are set when the step runs. You can use these properties to pass key value pairs to your main function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-step-hadoopjarstepconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                hadoop_jar_step_config_property = emr.CfnStep.HadoopJarStepConfigProperty(
                    jar="jar",
                
                    # the properties below are optional
                    args=["args"],
                    main_class="mainClass",
                    step_properties=[emr.CfnStep.KeyValueProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "jar": jar,
            }
            if args is not None:
                self._values["args"] = args
            if main_class is not None:
                self._values["main_class"] = main_class
            if step_properties is not None:
                self._values["step_properties"] = step_properties

        @builtins.property
        def jar(self) -> builtins.str:
            '''A path to a JAR file run during the step.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-step-hadoopjarstepconfig.html#cfn-elasticmapreduce-step-hadoopjarstepconfig-jar
            '''
            result = self._values.get("jar")
            assert result is not None, "Required property 'jar' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def args(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of command line arguments passed to the JAR file's main function when executed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-step-hadoopjarstepconfig.html#cfn-elasticmapreduce-step-hadoopjarstepconfig-args
            '''
            result = self._values.get("args")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def main_class(self) -> typing.Optional[builtins.str]:
            '''The name of the main class in the specified Java file.

            If not specified, the JAR file should specify a Main-Class in its manifest file.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-step-hadoopjarstepconfig.html#cfn-elasticmapreduce-step-hadoopjarstepconfig-mainclass
            '''
            result = self._values.get("main_class")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def step_properties(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStep.KeyValueProperty", _IResolvable_da3f097b]]]]:
            '''A list of Java properties that are set when the step runs.

            You can use these properties to pass key value pairs to your main function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-step-hadoopjarstepconfig.html#cfn-elasticmapreduce-step-hadoopjarstepconfig-stepproperties
            '''
            result = self._values.get("step_properties")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnStep.KeyValueProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HadoopJarStepConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_emr.CfnStep.KeyValueProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class KeyValueProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``KeyValue`` is a subproperty of the ``HadoopJarStepConfig`` property type.

            ``KeyValue`` is used to pass parameters to a step.

            :param key: The unique identifier of a key-value pair.
            :param value: The value part of the identified key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-step-keyvalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_emr as emr
                
                key_value_property = emr.CfnStep.KeyValueProperty(
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if key is not None:
                self._values["key"] = key
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''The unique identifier of a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-step-keyvalue.html#cfn-elasticmapreduce-step-keyvalue-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value part of the identified key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-step-keyvalue.html#cfn-elasticmapreduce-step-keyvalue-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KeyValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_emr.CfnStepProps",
    jsii_struct_bases=[],
    name_mapping={
        "action_on_failure": "actionOnFailure",
        "hadoop_jar_step": "hadoopJarStep",
        "job_flow_id": "jobFlowId",
        "name": "name",
    },
)
class CfnStepProps:
    def __init__(
        self,
        *,
        action_on_failure: builtins.str,
        hadoop_jar_step: typing.Union[CfnStep.HadoopJarStepConfigProperty, _IResolvable_da3f097b],
        job_flow_id: builtins.str,
        name: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnStep``.

        :param action_on_failure: This specifies what action to take when the cluster step fails. Possible values are ``CANCEL_AND_WAIT`` and ``CONTINUE`` .
        :param hadoop_jar_step: The ``HadoopJarStepConfig`` property type specifies a job flow step consisting of a JAR file whose main function will be executed. The main function submits a job for the cluster to execute as a step on the master node, and then waits for the job to finish or fail before executing subsequent steps.
        :param job_flow_id: A string that uniquely identifies the cluster (job flow).
        :param name: The name of the cluster step.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_emr as emr
            
            cfn_step_props = emr.CfnStepProps(
                action_on_failure="actionOnFailure",
                hadoop_jar_step=emr.CfnStep.HadoopJarStepConfigProperty(
                    jar="jar",
            
                    # the properties below are optional
                    args=["args"],
                    main_class="mainClass",
                    step_properties=[emr.CfnStep.KeyValueProperty(
                        key="key",
                        value="value"
                    )]
                ),
                job_flow_id="jobFlowId",
                name="name"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "action_on_failure": action_on_failure,
            "hadoop_jar_step": hadoop_jar_step,
            "job_flow_id": job_flow_id,
            "name": name,
        }

    @builtins.property
    def action_on_failure(self) -> builtins.str:
        '''This specifies what action to take when the cluster step fails.

        Possible values are ``CANCEL_AND_WAIT`` and ``CONTINUE`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html#cfn-elasticmapreduce-step-actiononfailure
        '''
        result = self._values.get("action_on_failure")
        assert result is not None, "Required property 'action_on_failure' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def hadoop_jar_step(
        self,
    ) -> typing.Union[CfnStep.HadoopJarStepConfigProperty, _IResolvable_da3f097b]:
        '''The ``HadoopJarStepConfig`` property type specifies a job flow step consisting of a JAR file whose main function will be executed.

        The main function submits a job for the cluster to execute as a step on the master node, and then waits for the job to finish or fail before executing subsequent steps.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html#cfn-elasticmapreduce-step-hadoopjarstep
        '''
        result = self._values.get("hadoop_jar_step")
        assert result is not None, "Required property 'hadoop_jar_step' is missing"
        return typing.cast(typing.Union[CfnStep.HadoopJarStepConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def job_flow_id(self) -> builtins.str:
        '''A string that uniquely identifies the cluster (job flow).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html#cfn-elasticmapreduce-step-jobflowid
        '''
        result = self._values.get("job_flow_id")
        assert result is not None, "Required property 'job_flow_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the cluster step.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-step.html#cfn-elasticmapreduce-step-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStepProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStudio(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_emr.CfnStudio",
):
    '''A CloudFormation ``AWS::EMR::Studio``.

    The ``AWS::EMR::Studio`` resource specifies an Amazon EMR Studio. An EMR Studio is a web-based, integrated development environment for fully managed Jupyter notebooks that run on Amazon EMR clusters. For more information, see the `*Amazon EMR Management Guide* <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio.html>`_ .

    :cloudformationResource: AWS::EMR::Studio
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_emr as emr
        
        cfn_studio = emr.CfnStudio(self, "MyCfnStudio",
            auth_mode="authMode",
            default_s3_location="defaultS3Location",
            engine_security_group_id="engineSecurityGroupId",
            name="name",
            service_role="serviceRole",
            subnet_ids=["subnetIds"],
            vpc_id="vpcId",
            workspace_security_group_id="workspaceSecurityGroupId",
        
            # the properties below are optional
            description="description",
            idp_auth_url="idpAuthUrl",
            idp_relay_state_parameter_name="idpRelayStateParameterName",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            user_role="userRole"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auth_mode: builtins.str,
        default_s3_location: builtins.str,
        engine_security_group_id: builtins.str,
        name: builtins.str,
        service_role: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        vpc_id: builtins.str,
        workspace_security_group_id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        idp_auth_url: typing.Optional[builtins.str] = None,
        idp_relay_state_parameter_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        user_role: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::EMR::Studio``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param auth_mode: Specifies whether the Studio authenticates users using AWS SSO or IAM.
        :param default_s3_location: The Amazon S3 location to back up EMR Studio Workspaces and notebook files.
        :param engine_security_group_id: The ID of the Amazon EMR Studio Engine security group. The Engine security group allows inbound network traffic from the Workspace security group, and it must be in the same VPC specified by ``VpcId`` .
        :param name: A descriptive name for the Amazon EMR Studio.
        :param service_role: The Amazon Resource Name (ARN) of the IAM role that will be assumed by the Amazon EMR Studio. The service role provides a way for Amazon EMR Studio to interoperate with other AWS services.
        :param subnet_ids: A list of subnet IDs to associate with the Amazon EMR Studio. A Studio can have a maximum of 5 subnets. The subnets must belong to the VPC specified by ``VpcId`` . Studio users can create a Workspace in any of the specified subnets.
        :param vpc_id: The ID of the Amazon Virtual Private Cloud (Amazon VPC) to associate with the Studio.
        :param workspace_security_group_id: The ID of the Workspace security group associated with the Amazon EMR Studio. The Workspace security group allows outbound network traffic to resources in the Engine security group and to the internet.
        :param description: A detailed description of the Amazon EMR Studio.
        :param idp_auth_url: Your identity provider's authentication endpoint. Amazon EMR Studio redirects federated users to this endpoint for authentication when logging in to a Studio with the Studio URL.
        :param idp_relay_state_parameter_name: The name of your identity provider's ``RelayState`` parameter.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        :param user_role: The Amazon Resource Name (ARN) of the IAM user role that will be assumed by users and groups logged in to a Studio. The permissions attached to this IAM role can be scoped down for each user or group using session policies. You only need to specify ``UserRole`` when you set ``AuthMode`` to ``SSO`` .
        '''
        props = CfnStudioProps(
            auth_mode=auth_mode,
            default_s3_location=default_s3_location,
            engine_security_group_id=engine_security_group_id,
            name=name,
            service_role=service_role,
            subnet_ids=subnet_ids,
            vpc_id=vpc_id,
            workspace_security_group_id=workspace_security_group_id,
            description=description,
            idp_auth_url=idp_auth_url,
            idp_relay_state_parameter_name=idp_relay_state_parameter_name,
            tags=tags,
            user_role=user_role,
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
        '''The Amazon Resource Name (ARN) of the Amazon EMR Studio.

        For example: ``arn:aws:elasticmapreduce:us-east-1:653XXXXXXXXX:studio/es-EXAMPLE12345678XXXXXXXXXXX`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStudioId")
    def attr_studio_id(self) -> builtins.str:
        '''The ID of the Amazon EMR Studio.

        For example: ``es-EXAMPLE12345678XXXXXXXXXXX`` .

        :cloudformationAttribute: StudioId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStudioId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrUrl")
    def attr_url(self) -> builtins.str:
        '''The unique access URL of the Amazon EMR Studio.

        For example: ``https://es-EXAMPLE12345678XXXXXXXXXXX.emrstudio-prod.us-east-1.amazonaws.com`` .

        :cloudformationAttribute: Url
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="authMode")
    def auth_mode(self) -> builtins.str:
        '''Specifies whether the Studio authenticates users using AWS SSO or IAM.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-authmode
        '''
        return typing.cast(builtins.str, jsii.get(self, "authMode"))

    @auth_mode.setter
    def auth_mode(self, value: builtins.str) -> None:
        jsii.set(self, "authMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultS3Location")
    def default_s3_location(self) -> builtins.str:
        '''The Amazon S3 location to back up EMR Studio Workspaces and notebook files.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-defaults3location
        '''
        return typing.cast(builtins.str, jsii.get(self, "defaultS3Location"))

    @default_s3_location.setter
    def default_s3_location(self, value: builtins.str) -> None:
        jsii.set(self, "defaultS3Location", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineSecurityGroupId")
    def engine_security_group_id(self) -> builtins.str:
        '''The ID of the Amazon EMR Studio Engine security group.

        The Engine security group allows inbound network traffic from the Workspace security group, and it must be in the same VPC specified by ``VpcId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-enginesecuritygroupid
        '''
        return typing.cast(builtins.str, jsii.get(self, "engineSecurityGroupId"))

    @engine_security_group_id.setter
    def engine_security_group_id(self, value: builtins.str) -> None:
        jsii.set(self, "engineSecurityGroupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A descriptive name for the Amazon EMR Studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceRole")
    def service_role(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role that will be assumed by the Amazon EMR Studio.

        The service role provides a way for Amazon EMR Studio to interoperate with other AWS services.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-servicerole
        '''
        return typing.cast(builtins.str, jsii.get(self, "serviceRole"))

    @service_role.setter
    def service_role(self, value: builtins.str) -> None:
        jsii.set(self, "serviceRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetIds")
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''A list of subnet IDs to associate with the Amazon EMR Studio.

        A Studio can have a maximum of 5 subnets. The subnets must belong to the VPC specified by ``VpcId`` . Studio users can create a Workspace in any of the specified subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-subnetids
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "subnetIds"))

    @subnet_ids.setter
    def subnet_ids(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "subnetIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcId")
    def vpc_id(self) -> builtins.str:
        '''The ID of the Amazon Virtual Private Cloud (Amazon VPC) to associate with the Studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-vpcid
        '''
        return typing.cast(builtins.str, jsii.get(self, "vpcId"))

    @vpc_id.setter
    def vpc_id(self, value: builtins.str) -> None:
        jsii.set(self, "vpcId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workspaceSecurityGroupId")
    def workspace_security_group_id(self) -> builtins.str:
        '''The ID of the Workspace security group associated with the Amazon EMR Studio.

        The Workspace security group allows outbound network traffic to resources in the Engine security group and to the internet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-workspacesecuritygroupid
        '''
        return typing.cast(builtins.str, jsii.get(self, "workspaceSecurityGroupId"))

    @workspace_security_group_id.setter
    def workspace_security_group_id(self, value: builtins.str) -> None:
        jsii.set(self, "workspaceSecurityGroupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A detailed description of the Amazon EMR Studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="idpAuthUrl")
    def idp_auth_url(self) -> typing.Optional[builtins.str]:
        '''Your identity provider's authentication endpoint.

        Amazon EMR Studio redirects federated users to this endpoint for authentication when logging in to a Studio with the Studio URL.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-idpauthurl
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "idpAuthUrl"))

    @idp_auth_url.setter
    def idp_auth_url(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "idpAuthUrl", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="idpRelayStateParameterName")
    def idp_relay_state_parameter_name(self) -> typing.Optional[builtins.str]:
        '''The name of your identity provider's ``RelayState`` parameter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-idprelaystateparametername
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "idpRelayStateParameterName"))

    @idp_relay_state_parameter_name.setter
    def idp_relay_state_parameter_name(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "idpRelayStateParameterName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userRole")
    def user_role(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the IAM user role that will be assumed by users and groups logged in to a Studio.

        The permissions attached to this IAM role can be scoped down for each user or group using session policies. You only need to specify ``UserRole`` when you set ``AuthMode`` to ``SSO`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-userrole
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "userRole"))

    @user_role.setter
    def user_role(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "userRole", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_emr.CfnStudioProps",
    jsii_struct_bases=[],
    name_mapping={
        "auth_mode": "authMode",
        "default_s3_location": "defaultS3Location",
        "engine_security_group_id": "engineSecurityGroupId",
        "name": "name",
        "service_role": "serviceRole",
        "subnet_ids": "subnetIds",
        "vpc_id": "vpcId",
        "workspace_security_group_id": "workspaceSecurityGroupId",
        "description": "description",
        "idp_auth_url": "idpAuthUrl",
        "idp_relay_state_parameter_name": "idpRelayStateParameterName",
        "tags": "tags",
        "user_role": "userRole",
    },
)
class CfnStudioProps:
    def __init__(
        self,
        *,
        auth_mode: builtins.str,
        default_s3_location: builtins.str,
        engine_security_group_id: builtins.str,
        name: builtins.str,
        service_role: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        vpc_id: builtins.str,
        workspace_security_group_id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        idp_auth_url: typing.Optional[builtins.str] = None,
        idp_relay_state_parameter_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        user_role: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnStudio``.

        :param auth_mode: Specifies whether the Studio authenticates users using AWS SSO or IAM.
        :param default_s3_location: The Amazon S3 location to back up EMR Studio Workspaces and notebook files.
        :param engine_security_group_id: The ID of the Amazon EMR Studio Engine security group. The Engine security group allows inbound network traffic from the Workspace security group, and it must be in the same VPC specified by ``VpcId`` .
        :param name: A descriptive name for the Amazon EMR Studio.
        :param service_role: The Amazon Resource Name (ARN) of the IAM role that will be assumed by the Amazon EMR Studio. The service role provides a way for Amazon EMR Studio to interoperate with other AWS services.
        :param subnet_ids: A list of subnet IDs to associate with the Amazon EMR Studio. A Studio can have a maximum of 5 subnets. The subnets must belong to the VPC specified by ``VpcId`` . Studio users can create a Workspace in any of the specified subnets.
        :param vpc_id: The ID of the Amazon Virtual Private Cloud (Amazon VPC) to associate with the Studio.
        :param workspace_security_group_id: The ID of the Workspace security group associated with the Amazon EMR Studio. The Workspace security group allows outbound network traffic to resources in the Engine security group and to the internet.
        :param description: A detailed description of the Amazon EMR Studio.
        :param idp_auth_url: Your identity provider's authentication endpoint. Amazon EMR Studio redirects federated users to this endpoint for authentication when logging in to a Studio with the Studio URL.
        :param idp_relay_state_parameter_name: The name of your identity provider's ``RelayState`` parameter.
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        :param user_role: The Amazon Resource Name (ARN) of the IAM user role that will be assumed by users and groups logged in to a Studio. The permissions attached to this IAM role can be scoped down for each user or group using session policies. You only need to specify ``UserRole`` when you set ``AuthMode`` to ``SSO`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_emr as emr
            
            cfn_studio_props = emr.CfnStudioProps(
                auth_mode="authMode",
                default_s3_location="defaultS3Location",
                engine_security_group_id="engineSecurityGroupId",
                name="name",
                service_role="serviceRole",
                subnet_ids=["subnetIds"],
                vpc_id="vpcId",
                workspace_security_group_id="workspaceSecurityGroupId",
            
                # the properties below are optional
                description="description",
                idp_auth_url="idpAuthUrl",
                idp_relay_state_parameter_name="idpRelayStateParameterName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                user_role="userRole"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "auth_mode": auth_mode,
            "default_s3_location": default_s3_location,
            "engine_security_group_id": engine_security_group_id,
            "name": name,
            "service_role": service_role,
            "subnet_ids": subnet_ids,
            "vpc_id": vpc_id,
            "workspace_security_group_id": workspace_security_group_id,
        }
        if description is not None:
            self._values["description"] = description
        if idp_auth_url is not None:
            self._values["idp_auth_url"] = idp_auth_url
        if idp_relay_state_parameter_name is not None:
            self._values["idp_relay_state_parameter_name"] = idp_relay_state_parameter_name
        if tags is not None:
            self._values["tags"] = tags
        if user_role is not None:
            self._values["user_role"] = user_role

    @builtins.property
    def auth_mode(self) -> builtins.str:
        '''Specifies whether the Studio authenticates users using AWS SSO or IAM.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-authmode
        '''
        result = self._values.get("auth_mode")
        assert result is not None, "Required property 'auth_mode' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def default_s3_location(self) -> builtins.str:
        '''The Amazon S3 location to back up EMR Studio Workspaces and notebook files.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-defaults3location
        '''
        result = self._values.get("default_s3_location")
        assert result is not None, "Required property 'default_s3_location' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def engine_security_group_id(self) -> builtins.str:
        '''The ID of the Amazon EMR Studio Engine security group.

        The Engine security group allows inbound network traffic from the Workspace security group, and it must be in the same VPC specified by ``VpcId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-enginesecuritygroupid
        '''
        result = self._values.get("engine_security_group_id")
        assert result is not None, "Required property 'engine_security_group_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''A descriptive name for the Amazon EMR Studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service_role(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role that will be assumed by the Amazon EMR Studio.

        The service role provides a way for Amazon EMR Studio to interoperate with other AWS services.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-servicerole
        '''
        result = self._values.get("service_role")
        assert result is not None, "Required property 'service_role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''A list of subnet IDs to associate with the Amazon EMR Studio.

        A Studio can have a maximum of 5 subnets. The subnets must belong to the VPC specified by ``VpcId`` . Studio users can create a Workspace in any of the specified subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-subnetids
        '''
        result = self._values.get("subnet_ids")
        assert result is not None, "Required property 'subnet_ids' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def vpc_id(self) -> builtins.str:
        '''The ID of the Amazon Virtual Private Cloud (Amazon VPC) to associate with the Studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-vpcid
        '''
        result = self._values.get("vpc_id")
        assert result is not None, "Required property 'vpc_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def workspace_security_group_id(self) -> builtins.str:
        '''The ID of the Workspace security group associated with the Amazon EMR Studio.

        The Workspace security group allows outbound network traffic to resources in the Engine security group and to the internet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-workspacesecuritygroupid
        '''
        result = self._values.get("workspace_security_group_id")
        assert result is not None, "Required property 'workspace_security_group_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A detailed description of the Amazon EMR Studio.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def idp_auth_url(self) -> typing.Optional[builtins.str]:
        '''Your identity provider's authentication endpoint.

        Amazon EMR Studio redirects federated users to this endpoint for authentication when logging in to a Studio with the Studio URL.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-idpauthurl
        '''
        result = self._values.get("idp_auth_url")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def idp_relay_state_parameter_name(self) -> typing.Optional[builtins.str]:
        '''The name of your identity provider's ``RelayState`` parameter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-idprelaystateparametername
        '''
        result = self._values.get("idp_relay_state_parameter_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def user_role(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the IAM user role that will be assumed by users and groups logged in to a Studio.

        The permissions attached to this IAM role can be scoped down for each user or group using session policies. You only need to specify ``UserRole`` when you set ``AuthMode`` to ``SSO`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studio.html#cfn-emr-studio-userrole
        '''
        result = self._values.get("user_role")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStudioProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStudioSessionMapping(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_emr.CfnStudioSessionMapping",
):
    '''A CloudFormation ``AWS::EMR::StudioSessionMapping``.

    The ``AWS::EMR::StudioSessionMapping`` resource is an Amazon EMR resource type that maps a user or group to the Amazon EMR Studio specified by ``StudioId`` , and applies a session policy that defines Studio permissions for that user or group.

    :cloudformationResource: AWS::EMR::StudioSessionMapping
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_emr as emr
        
        cfn_studio_session_mapping = emr.CfnStudioSessionMapping(self, "MyCfnStudioSessionMapping",
            identity_name="identityName",
            identity_type="identityType",
            session_policy_arn="sessionPolicyArn",
            studio_id="studioId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        identity_name: builtins.str,
        identity_type: builtins.str,
        session_policy_arn: builtins.str,
        studio_id: builtins.str,
    ) -> None:
        '''Create a new ``AWS::EMR::StudioSessionMapping``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param identity_name: The name of the user or group. For more information, see `UserName <https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName>`_ and `DisplayName <https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName>`_ in the *AWS SSO Identity Store API Reference* .
        :param identity_type: Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.
        :param session_policy_arn: The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group. Session policies refine Studio user permissions without the need to use multiple IAM user roles. For more information, see `Create an EMR Studio user role with session policies <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html>`_ in the *Amazon EMR Management Guide* .
        :param studio_id: The ID of the Amazon EMR Studio to which the user or group will be mapped.
        '''
        props = CfnStudioSessionMappingProps(
            identity_name=identity_name,
            identity_type=identity_type,
            session_policy_arn=session_policy_arn,
            studio_id=studio_id,
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
    @jsii.member(jsii_name="identityName")
    def identity_name(self) -> builtins.str:
        '''The name of the user or group.

        For more information, see `UserName <https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName>`_ and `DisplayName <https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName>`_ in the *AWS SSO Identity Store API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html#cfn-emr-studiosessionmapping-identityname
        '''
        return typing.cast(builtins.str, jsii.get(self, "identityName"))

    @identity_name.setter
    def identity_name(self, value: builtins.str) -> None:
        jsii.set(self, "identityName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="identityType")
    def identity_type(self) -> builtins.str:
        '''Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html#cfn-emr-studiosessionmapping-identitytype
        '''
        return typing.cast(builtins.str, jsii.get(self, "identityType"))

    @identity_type.setter
    def identity_type(self, value: builtins.str) -> None:
        jsii.set(self, "identityType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sessionPolicyArn")
    def session_policy_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group.

        Session policies refine Studio user permissions without the need to use multiple IAM user roles. For more information, see `Create an EMR Studio user role with session policies <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html>`_ in the *Amazon EMR Management Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html#cfn-emr-studiosessionmapping-sessionpolicyarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "sessionPolicyArn"))

    @session_policy_arn.setter
    def session_policy_arn(self, value: builtins.str) -> None:
        jsii.set(self, "sessionPolicyArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="studioId")
    def studio_id(self) -> builtins.str:
        '''The ID of the Amazon EMR Studio to which the user or group will be mapped.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html#cfn-emr-studiosessionmapping-studioid
        '''
        return typing.cast(builtins.str, jsii.get(self, "studioId"))

    @studio_id.setter
    def studio_id(self, value: builtins.str) -> None:
        jsii.set(self, "studioId", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_emr.CfnStudioSessionMappingProps",
    jsii_struct_bases=[],
    name_mapping={
        "identity_name": "identityName",
        "identity_type": "identityType",
        "session_policy_arn": "sessionPolicyArn",
        "studio_id": "studioId",
    },
)
class CfnStudioSessionMappingProps:
    def __init__(
        self,
        *,
        identity_name: builtins.str,
        identity_type: builtins.str,
        session_policy_arn: builtins.str,
        studio_id: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnStudioSessionMapping``.

        :param identity_name: The name of the user or group. For more information, see `UserName <https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName>`_ and `DisplayName <https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName>`_ in the *AWS SSO Identity Store API Reference* .
        :param identity_type: Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.
        :param session_policy_arn: The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group. Session policies refine Studio user permissions without the need to use multiple IAM user roles. For more information, see `Create an EMR Studio user role with session policies <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html>`_ in the *Amazon EMR Management Guide* .
        :param studio_id: The ID of the Amazon EMR Studio to which the user or group will be mapped.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_emr as emr
            
            cfn_studio_session_mapping_props = emr.CfnStudioSessionMappingProps(
                identity_name="identityName",
                identity_type="identityType",
                session_policy_arn="sessionPolicyArn",
                studio_id="studioId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "identity_name": identity_name,
            "identity_type": identity_type,
            "session_policy_arn": session_policy_arn,
            "studio_id": studio_id,
        }

    @builtins.property
    def identity_name(self) -> builtins.str:
        '''The name of the user or group.

        For more information, see `UserName <https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName>`_ and `DisplayName <https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName>`_ in the *AWS SSO Identity Store API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html#cfn-emr-studiosessionmapping-identityname
        '''
        result = self._values.get("identity_name")
        assert result is not None, "Required property 'identity_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def identity_type(self) -> builtins.str:
        '''Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html#cfn-emr-studiosessionmapping-identitytype
        '''
        result = self._values.get("identity_type")
        assert result is not None, "Required property 'identity_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def session_policy_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group.

        Session policies refine Studio user permissions without the need to use multiple IAM user roles. For more information, see `Create an EMR Studio user role with session policies <https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html>`_ in the *Amazon EMR Management Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html#cfn-emr-studiosessionmapping-sessionpolicyarn
        '''
        result = self._values.get("session_policy_arn")
        assert result is not None, "Required property 'session_policy_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def studio_id(self) -> builtins.str:
        '''The ID of the Amazon EMR Studio to which the user or group will be mapped.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-studiosessionmapping.html#cfn-emr-studiosessionmapping-studioid
        '''
        result = self._values.get("studio_id")
        assert result is not None, "Required property 'studio_id' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStudioSessionMappingProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnCluster",
    "CfnClusterProps",
    "CfnInstanceFleetConfig",
    "CfnInstanceFleetConfigProps",
    "CfnInstanceGroupConfig",
    "CfnInstanceGroupConfigProps",
    "CfnSecurityConfiguration",
    "CfnSecurityConfigurationProps",
    "CfnStep",
    "CfnStepProps",
    "CfnStudio",
    "CfnStudioProps",
    "CfnStudioSessionMapping",
    "CfnStudioSessionMappingProps",
]

publication.publish()
