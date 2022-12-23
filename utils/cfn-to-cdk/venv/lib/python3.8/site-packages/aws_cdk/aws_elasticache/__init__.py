'''
# Amazon ElastiCache Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_elasticache as elasticache
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-elasticache-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::ElastiCache](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_ElastiCache.html).

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
class CfnCacheCluster(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnCacheCluster",
):
    '''A CloudFormation ``AWS::ElastiCache::CacheCluster``.

    The AWS::ElastiCache::CacheCluster type creates an Amazon ElastiCache cache cluster.

    :cloudformationResource: AWS::ElastiCache::CacheCluster
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_cache_cluster = elasticache.CfnCacheCluster(self, "MyCfnCacheCluster",
            cache_node_type="cacheNodeType",
            engine="engine",
            num_cache_nodes=123,
        
            # the properties below are optional
            auto_minor_version_upgrade=False,
            az_mode="azMode",
            cache_parameter_group_name="cacheParameterGroupName",
            cache_security_group_names=["cacheSecurityGroupNames"],
            cache_subnet_group_name="cacheSubnetGroupName",
            cluster_name="clusterName",
            engine_version="engineVersion",
            log_delivery_configurations=[elasticache.CfnCacheCluster.LogDeliveryConfigurationRequestProperty(
                destination_details=elasticache.CfnCacheCluster.DestinationDetailsProperty(
                    cloud_watch_logs_details=elasticache.CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty(
                        log_group="logGroup"
                    ),
                    kinesis_firehose_details=elasticache.CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty(
                        delivery_stream="deliveryStream"
                    )
                ),
                destination_type="destinationType",
                log_format="logFormat",
                log_type="logType"
            )],
            notification_topic_arn="notificationTopicArn",
            port=123,
            preferred_availability_zone="preferredAvailabilityZone",
            preferred_availability_zones=["preferredAvailabilityZones"],
            preferred_maintenance_window="preferredMaintenanceWindow",
            snapshot_arns=["snapshotArns"],
            snapshot_name="snapshotName",
            snapshot_retention_limit=123,
            snapshot_window="snapshotWindow",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            vpc_security_group_ids=["vpcSecurityGroupIds"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cache_node_type: builtins.str,
        engine: builtins.str,
        num_cache_nodes: jsii.Number,
        auto_minor_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        az_mode: typing.Optional[builtins.str] = None,
        cache_parameter_group_name: typing.Optional[builtins.str] = None,
        cache_security_group_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        cache_subnet_group_name: typing.Optional[builtins.str] = None,
        cluster_name: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        log_delivery_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCacheCluster.LogDeliveryConfigurationRequestProperty", _IResolvable_da3f097b]]]] = None,
        notification_topic_arn: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        preferred_availability_zone: typing.Optional[builtins.str] = None,
        preferred_availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        snapshot_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        snapshot_name: typing.Optional[builtins.str] = None,
        snapshot_retention_limit: typing.Optional[jsii.Number] = None,
        snapshot_window: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::CacheCluster``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param cache_node_type: The compute and memory capacity of the nodes in the node group (shard). The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts. Changing the CacheNodeType of a Memcached instance is currently not supported. If you need to scale using Memcached, we recommend forcing a replacement update by changing the ``LogicalResourceId`` of the resource. - General purpose: - Current generation: *M6g node types:* ``cache.m6g.large`` , ``cache.m6g.xlarge`` , ``cache.m6g.2xlarge`` , ``cache.m6g.4xlarge`` , ``cache.m6g.8xlarge`` , ``cache.m6g.12xlarge`` , ``cache.m6g.16xlarge`` , ``cache.m6g.24xlarge`` *M5 node types:* ``cache.m5.large`` , ``cache.m5.xlarge`` , ``cache.m5.2xlarge`` , ``cache.m5.4xlarge`` , ``cache.m5.12xlarge`` , ``cache.m5.24xlarge`` *M4 node types:* ``cache.m4.large`` , ``cache.m4.xlarge`` , ``cache.m4.2xlarge`` , ``cache.m4.4xlarge`` , ``cache.m4.10xlarge`` *T4g node types:* ``cache.t4g.micro`` , ``cache.t4g.small`` , ``cache.t4g.medium`` *T3 node types:* ``cache.t3.micro`` , ``cache.t3.small`` , ``cache.t3.medium`` *T2 node types:* ``cache.t2.micro`` , ``cache.t2.small`` , ``cache.t2.medium`` - Previous generation: (not recommended) *T1 node types:* ``cache.t1.micro`` *M1 node types:* ``cache.m1.small`` , ``cache.m1.medium`` , ``cache.m1.large`` , ``cache.m1.xlarge`` *M3 node types:* ``cache.m3.medium`` , ``cache.m3.large`` , ``cache.m3.xlarge`` , ``cache.m3.2xlarge`` - Compute optimized: - Previous generation: (not recommended) *C1 node types:* ``cache.c1.xlarge`` - Memory optimized: - Current generation: *R6gd node types:* ``cache.r6gd.xlarge`` , ``cache.r6gd.2xlarge`` , ``cache.r6gd.4xlarge`` , ``cache.r6gd.8xlarge`` , ``cache.r6gd.12xlarge`` , ``cache.r6gd.16xlarge`` .. epigraph:: The ``r6gd`` family is available in the following regions: ``us-east-2`` , ``us-east-1`` , ``us-west-2`` , ``us-west-1`` , ``eu-west-1`` , ``eu-central-1`` , ``ap-northeast-1`` , ``ap-southeast-1`` , ``ap-southeast-2`` . *R6g node types:* ``cache.r6g.large`` , ``cache.r6g.xlarge`` , ``cache.r6g.2xlarge`` , ``cache.r6g.4xlarge`` , ``cache.r6g.8xlarge`` , ``cache.r6g.12xlarge`` , ``cache.r6g.16xlarge`` , ``cache.r6g.24xlarge`` *R5 node types:* ``cache.r5.large`` , ``cache.r5.xlarge`` , ``cache.r5.2xlarge`` , ``cache.r5.4xlarge`` , ``cache.r5.12xlarge`` , ``cache.r5.24xlarge`` *R4 node types:* ``cache.r4.large`` , ``cache.r4.xlarge`` , ``cache.r4.2xlarge`` , ``cache.r4.4xlarge`` , ``cache.r4.8xlarge`` , ``cache.r4.16xlarge`` - Previous generation: (not recommended) *M2 node types:* ``cache.m2.xlarge`` , ``cache.m2.2xlarge`` , ``cache.m2.4xlarge`` *R3 node types:* ``cache.r3.large`` , ``cache.r3.xlarge`` , ``cache.r3.2xlarge`` , ``cache.r3.4xlarge`` , ``cache.r3.8xlarge`` For region availability, see `Supported Node Types by Amazon Region <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion>`_ *Additional node type info* - All current generation instance types are created in Amazon VPC by default. - Redis append-only files (AOF) are not supported for T1 or T2 instances. - Redis Multi-AZ with automatic failover is not supported on T1 instances. - Redis configuration variables ``appendonly`` and ``appendfsync`` are not supported on Redis version 2.8.22 and later.
        :param engine: The name of the cache engine to be used for this cluster. Valid values for this parameter are: ``memcached`` | ``redis``
        :param num_cache_nodes: The number of cache nodes that the cache cluster should have. .. epigraph:: However, if the ``PreferredAvailabilityZone`` and ``PreferredAvailabilityZones`` properties were not previously specified and you don't specify any new values, an update requires `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .
        :param auto_minor_version_upgrade: If you are running Redis engine version 6.0 or later, set this parameter to yes if you want to opt-in to the next minor version upgrade campaign. This parameter is disabled for previous versions.
        :param az_mode: Specifies whether the nodes in this Memcached cluster are created in a single Availability Zone or created across multiple Availability Zones in the cluster's region. This parameter is only supported for Memcached clusters. If the ``AZMode`` and ``PreferredAvailabilityZones`` are not specified, ElastiCache assumes ``single-az`` mode.
        :param cache_parameter_group_name: The name of the parameter group to associate with this cluster. If this argument is omitted, the default parameter group for the specified engine is used. You cannot use any parameter group which has ``cluster-enabled='yes'`` when creating a cluster.
        :param cache_security_group_names: A list of security group names to associate with this cluster. Use this parameter only when you are creating a cluster outside of an Amazon Virtual Private Cloud (Amazon VPC).
        :param cache_subnet_group_name: The name of the subnet group to be used for the cluster. Use this parameter only when you are creating a cluster in an Amazon Virtual Private Cloud (Amazon VPC). .. epigraph:: If you're going to launch your cluster in an Amazon VPC, you need to create a subnet group before you start creating a cluster. For more information, see `AWS::ElastiCache::SubnetGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html>`_ .
        :param cluster_name: A name for the cache cluster. If you don't specify a name, AWSCloudFormation generates a unique physical ID and uses that ID for the cache cluster. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . The name must contain 1 to 50 alphanumeric characters or hyphens. The name must start with a letter and cannot end with a hyphen or contain two consecutive hyphens.
        :param engine_version: The version number of the cache engine to be used for this cluster. To view the supported cache engine versions, use the DescribeCacheEngineVersions operation. *Important:* You can upgrade to a newer engine version (see `Selecting a Cache Engine and Version <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SelectEngine.html#VersionManagement>`_ ), but you cannot downgrade to an earlier engine version. If you want to use an earlier engine version, you must delete the existing cluster or replication group and create it anew with the earlier engine version.
        :param log_delivery_configurations: Specifies the destination, format and type of the logs.
        :param notification_topic_arn: The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent. .. epigraph:: The Amazon SNS topic owner must be the same as the cluster owner.
        :param port: The port number on which each of the cache nodes accepts connections.
        :param preferred_availability_zone: The EC2 Availability Zone in which the cluster is created. All nodes belonging to this cluster are placed in the preferred Availability Zone. If you want to create your nodes across multiple Availability Zones, use ``PreferredAvailabilityZones`` . Default: System chosen Availability Zone.
        :param preferred_availability_zones: A list of the Availability Zones in which cache nodes are created. The order of the zones in the list is not important. This option is only supported on Memcached. .. epigraph:: If you are creating your cluster in an Amazon VPC (recommended) you can only locate nodes in Availability Zones that are associated with the subnets in the selected subnet group. The number of Availability Zones listed must equal the value of ``NumCacheNodes`` . If you want all the nodes in the same Availability Zone, use ``PreferredAvailabilityZone`` instead, or repeat the Availability Zone multiple times in the list. Default: System chosen Availability Zones.
        :param preferred_maintenance_window: Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for ``ddd`` are: Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for ``ddd`` are: - ``sun`` - ``mon`` - ``tue`` - ``wed`` - ``thu`` - ``fri`` - ``sat`` Example: ``sun:23:00-mon:01:30``
        :param snapshot_arns: A single-element string list containing an Amazon Resource Name (ARN) that uniquely identifies a Redis RDB snapshot file stored in Amazon S3. The snapshot file is used to populate the node group (shard). The Amazon S3 object name in the ARN cannot contain any commas. .. epigraph:: This parameter is only valid if the ``Engine`` parameter is ``redis`` . Example of an Amazon S3 ARN: ``arn:aws:s3:::my_bucket/snapshot1.rdb``
        :param snapshot_name: The name of a Redis snapshot from which to restore data into the new node group (shard). The snapshot status changes to ``restoring`` while the new node group (shard) is being created. .. epigraph:: This parameter is only valid if the ``Engine`` parameter is ``redis`` .
        :param snapshot_retention_limit: The number of days for which ElastiCache retains automatic snapshots before deleting them. For example, if you set ``SnapshotRetentionLimit`` to 5, a snapshot taken today is retained for 5 days before being deleted. .. epigraph:: This parameter is only valid if the ``Engine`` parameter is ``redis`` . Default: 0 (i.e., automatic backups are disabled for this cache cluster).
        :param snapshot_window: The daily time range (in UTC) during which ElastiCache begins taking a daily snapshot of your node group (shard). Example: ``05:00-09:00`` If you do not specify this parameter, ElastiCache automatically chooses an appropriate time range. .. epigraph:: This parameter is only valid if the ``Engine`` parameter is ``redis`` .
        :param tags: A list of tags to be added to this resource.
        :param vpc_security_group_ids: One or more VPC security groups associated with the cluster. Use this parameter only when you are creating a cluster in an Amazon Virtual Private Cloud (Amazon VPC).
        '''
        props = CfnCacheClusterProps(
            cache_node_type=cache_node_type,
            engine=engine,
            num_cache_nodes=num_cache_nodes,
            auto_minor_version_upgrade=auto_minor_version_upgrade,
            az_mode=az_mode,
            cache_parameter_group_name=cache_parameter_group_name,
            cache_security_group_names=cache_security_group_names,
            cache_subnet_group_name=cache_subnet_group_name,
            cluster_name=cluster_name,
            engine_version=engine_version,
            log_delivery_configurations=log_delivery_configurations,
            notification_topic_arn=notification_topic_arn,
            port=port,
            preferred_availability_zone=preferred_availability_zone,
            preferred_availability_zones=preferred_availability_zones,
            preferred_maintenance_window=preferred_maintenance_window,
            snapshot_arns=snapshot_arns,
            snapshot_name=snapshot_name,
            snapshot_retention_limit=snapshot_retention_limit,
            snapshot_window=snapshot_window,
            tags=tags,
            vpc_security_group_ids=vpc_security_group_ids,
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
    @jsii.member(jsii_name="attrConfigurationEndpointAddress")
    def attr_configuration_endpoint_address(self) -> builtins.str:
        '''The DNS hostname of the cache node.

        .. epigraph::

           Redis (cluster mode disabled) replication groups don't have this attribute. Therefore, ``Fn::GetAtt`` returns a value for this attribute only if the replication group is clustered. Otherwise, ``Fn::GetAtt`` fails.

        :cloudformationAttribute: ConfigurationEndpoint.Address
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrConfigurationEndpointAddress"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrConfigurationEndpointPort")
    def attr_configuration_endpoint_port(self) -> builtins.str:
        '''The port number of the configuration endpoint for the Memcached cache cluster.

        .. epigraph::

           Redis (cluster mode disabled) replication groups don't have this attribute. Therefore, ``Fn::GetAtt`` returns a value for this attribute only if the replication group is clustered. Otherwise, ``Fn::GetAtt`` fails.

        :cloudformationAttribute: ConfigurationEndpoint.Port
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrConfigurationEndpointPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRedisEndpointAddress")
    def attr_redis_endpoint_address(self) -> builtins.str:
        '''The DNS address of the configuration endpoint for the Redis cache cluster.

        :cloudformationAttribute: RedisEndpoint.Address
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRedisEndpointAddress"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRedisEndpointPort")
    def attr_redis_endpoint_port(self) -> builtins.str:
        '''The port number of the configuration endpoint for the Redis cache cluster.

        :cloudformationAttribute: RedisEndpoint.Port
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRedisEndpointPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A list of tags to be added to this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheNodeType")
    def cache_node_type(self) -> builtins.str:
        '''The compute and memory capacity of the nodes in the node group (shard).

        The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts. Changing the CacheNodeType of a Memcached instance is currently not supported. If you need to scale using Memcached, we recommend forcing a replacement update by changing the ``LogicalResourceId`` of the resource.

        - General purpose:
        - Current generation:

        *M6g node types:* ``cache.m6g.large`` , ``cache.m6g.xlarge`` , ``cache.m6g.2xlarge`` , ``cache.m6g.4xlarge`` , ``cache.m6g.8xlarge`` , ``cache.m6g.12xlarge`` , ``cache.m6g.16xlarge`` , ``cache.m6g.24xlarge``

        *M5 node types:* ``cache.m5.large`` , ``cache.m5.xlarge`` , ``cache.m5.2xlarge`` , ``cache.m5.4xlarge`` , ``cache.m5.12xlarge`` , ``cache.m5.24xlarge``

        *M4 node types:* ``cache.m4.large`` , ``cache.m4.xlarge`` , ``cache.m4.2xlarge`` , ``cache.m4.4xlarge`` , ``cache.m4.10xlarge``

        *T4g node types:* ``cache.t4g.micro`` , ``cache.t4g.small`` , ``cache.t4g.medium``

        *T3 node types:* ``cache.t3.micro`` , ``cache.t3.small`` , ``cache.t3.medium``

        *T2 node types:* ``cache.t2.micro`` , ``cache.t2.small`` , ``cache.t2.medium``

        - Previous generation: (not recommended)

        *T1 node types:* ``cache.t1.micro``

        *M1 node types:* ``cache.m1.small`` , ``cache.m1.medium`` , ``cache.m1.large`` , ``cache.m1.xlarge``

        *M3 node types:* ``cache.m3.medium`` , ``cache.m3.large`` , ``cache.m3.xlarge`` , ``cache.m3.2xlarge``

        - Compute optimized:
        - Previous generation: (not recommended)

        *C1 node types:* ``cache.c1.xlarge``

        - Memory optimized:
        - Current generation:

        *R6gd node types:* ``cache.r6gd.xlarge`` , ``cache.r6gd.2xlarge`` , ``cache.r6gd.4xlarge`` , ``cache.r6gd.8xlarge`` , ``cache.r6gd.12xlarge`` , ``cache.r6gd.16xlarge``
        .. epigraph::

           The ``r6gd`` family is available in the following regions: ``us-east-2`` , ``us-east-1`` , ``us-west-2`` , ``us-west-1`` , ``eu-west-1`` , ``eu-central-1`` , ``ap-northeast-1`` , ``ap-southeast-1`` , ``ap-southeast-2`` .

        *R6g node types:* ``cache.r6g.large`` , ``cache.r6g.xlarge`` , ``cache.r6g.2xlarge`` , ``cache.r6g.4xlarge`` , ``cache.r6g.8xlarge`` , ``cache.r6g.12xlarge`` , ``cache.r6g.16xlarge`` , ``cache.r6g.24xlarge``

        *R5 node types:* ``cache.r5.large`` , ``cache.r5.xlarge`` , ``cache.r5.2xlarge`` , ``cache.r5.4xlarge`` , ``cache.r5.12xlarge`` , ``cache.r5.24xlarge``

        *R4 node types:* ``cache.r4.large`` , ``cache.r4.xlarge`` , ``cache.r4.2xlarge`` , ``cache.r4.4xlarge`` , ``cache.r4.8xlarge`` , ``cache.r4.16xlarge``

        - Previous generation: (not recommended)

        *M2 node types:* ``cache.m2.xlarge`` , ``cache.m2.2xlarge`` , ``cache.m2.4xlarge``

        *R3 node types:* ``cache.r3.large`` , ``cache.r3.xlarge`` , ``cache.r3.2xlarge`` , ``cache.r3.4xlarge`` , ``cache.r3.8xlarge``

        For region availability, see `Supported Node Types by Amazon Region <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion>`_

        *Additional node type info*

        - All current generation instance types are created in Amazon VPC by default.
        - Redis append-only files (AOF) are not supported for T1 or T2 instances.
        - Redis Multi-AZ with automatic failover is not supported on T1 instances.
        - Redis configuration variables ``appendonly`` and ``appendfsync`` are not supported on Redis version 2.8.22 and later.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-cachenodetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "cacheNodeType"))

    @cache_node_type.setter
    def cache_node_type(self, value: builtins.str) -> None:
        jsii.set(self, "cacheNodeType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engine")
    def engine(self) -> builtins.str:
        '''The name of the cache engine to be used for this cluster.

        Valid values for this parameter are: ``memcached`` | ``redis``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-engine
        '''
        return typing.cast(builtins.str, jsii.get(self, "engine"))

    @engine.setter
    def engine(self, value: builtins.str) -> None:
        jsii.set(self, "engine", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="numCacheNodes")
    def num_cache_nodes(self) -> jsii.Number:
        '''The number of cache nodes that the cache cluster should have.

        .. epigraph::

           However, if the ``PreferredAvailabilityZone`` and ``PreferredAvailabilityZones`` properties were not previously specified and you don't specify any new values, an update requires `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-numcachenodes
        '''
        return typing.cast(jsii.Number, jsii.get(self, "numCacheNodes"))

    @num_cache_nodes.setter
    def num_cache_nodes(self, value: jsii.Number) -> None:
        jsii.set(self, "numCacheNodes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoMinorVersionUpgrade")
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If you are running Redis engine version 6.0 or later, set this parameter to yes if you want to opt-in to the next minor version upgrade campaign. This parameter is disabled for previous versions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-autominorversionupgrade
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "autoMinorVersionUpgrade"))

    @auto_minor_version_upgrade.setter
    def auto_minor_version_upgrade(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "autoMinorVersionUpgrade", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="azMode")
    def az_mode(self) -> typing.Optional[builtins.str]:
        '''Specifies whether the nodes in this Memcached cluster are created in a single Availability Zone or created across multiple Availability Zones in the cluster's region.

        This parameter is only supported for Memcached clusters.

        If the ``AZMode`` and ``PreferredAvailabilityZones`` are not specified, ElastiCache assumes ``single-az`` mode.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-azmode
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "azMode"))

    @az_mode.setter
    def az_mode(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "azMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheParameterGroupName")
    def cache_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the parameter group to associate with this cluster.

        If this argument is omitted, the default parameter group for the specified engine is used. You cannot use any parameter group which has ``cluster-enabled='yes'`` when creating a cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-cacheparametergroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cacheParameterGroupName"))

    @cache_parameter_group_name.setter
    def cache_parameter_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cacheParameterGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheSecurityGroupNames")
    def cache_security_group_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of security group names to associate with this cluster.

        Use this parameter only when you are creating a cluster outside of an Amazon Virtual Private Cloud (Amazon VPC).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-cachesecuritygroupnames
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "cacheSecurityGroupNames"))

    @cache_security_group_names.setter
    def cache_security_group_names(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "cacheSecurityGroupNames", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheSubnetGroupName")
    def cache_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the subnet group to be used for the cluster.

        Use this parameter only when you are creating a cluster in an Amazon Virtual Private Cloud (Amazon VPC).
        .. epigraph::

           If you're going to launch your cluster in an Amazon VPC, you need to create a subnet group before you start creating a cluster. For more information, see `AWS::ElastiCache::SubnetGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-cachesubnetgroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cacheSubnetGroupName"))

    @cache_subnet_group_name.setter
    def cache_subnet_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cacheSubnetGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterName")
    def cluster_name(self) -> typing.Optional[builtins.str]:
        '''A name for the cache cluster.

        If you don't specify a name, AWSCloudFormation generates a unique physical ID and uses that ID for the cache cluster. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .

        The name must contain 1 to 50 alphanumeric characters or hyphens. The name must start with a letter and cannot end with a hyphen or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-clustername
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "clusterName"))

    @cluster_name.setter
    def cluster_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "clusterName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineVersion")
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The version number of the cache engine to be used for this cluster.

        To view the supported cache engine versions, use the DescribeCacheEngineVersions operation.

        *Important:* You can upgrade to a newer engine version (see `Selecting a Cache Engine and Version <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SelectEngine.html#VersionManagement>`_ ), but you cannot downgrade to an earlier engine version. If you want to use an earlier engine version, you must delete the existing cluster or replication group and create it anew with the earlier engine version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-engineversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "engineVersion"))

    @engine_version.setter
    def engine_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "engineVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logDeliveryConfigurations")
    def log_delivery_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCacheCluster.LogDeliveryConfigurationRequestProperty", _IResolvable_da3f097b]]]]:
        '''Specifies the destination, format and type of the logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-logdeliveryconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCacheCluster.LogDeliveryConfigurationRequestProperty", _IResolvable_da3f097b]]]], jsii.get(self, "logDeliveryConfigurations"))

    @log_delivery_configurations.setter
    def log_delivery_configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCacheCluster.LogDeliveryConfigurationRequestProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "logDeliveryConfigurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationTopicArn")
    def notification_topic_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent.

        .. epigraph::

           The Amazon SNS topic owner must be the same as the cluster owner.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-notificationtopicarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "notificationTopicArn"))

    @notification_topic_arn.setter
    def notification_topic_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "notificationTopicArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="port")
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port number on which each of the cache nodes accepts connections.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-port
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "port"))

    @port.setter
    def port(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "port", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredAvailabilityZone")
    def preferred_availability_zone(self) -> typing.Optional[builtins.str]:
        '''The EC2 Availability Zone in which the cluster is created.

        All nodes belonging to this cluster are placed in the preferred Availability Zone. If you want to create your nodes across multiple Availability Zones, use ``PreferredAvailabilityZones`` .

        Default: System chosen Availability Zone.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-preferredavailabilityzone
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preferredAvailabilityZone"))

    @preferred_availability_zone.setter
    def preferred_availability_zone(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "preferredAvailabilityZone", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredAvailabilityZones")
    def preferred_availability_zones(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of the Availability Zones in which cache nodes are created.

        The order of the zones in the list is not important.

        This option is only supported on Memcached.
        .. epigraph::

           If you are creating your cluster in an Amazon VPC (recommended) you can only locate nodes in Availability Zones that are associated with the subnets in the selected subnet group.

           The number of Availability Zones listed must equal the value of ``NumCacheNodes`` .

        If you want all the nodes in the same Availability Zone, use ``PreferredAvailabilityZone`` instead, or repeat the Availability Zone multiple times in the list.

        Default: System chosen Availability Zones.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-preferredavailabilityzones
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "preferredAvailabilityZones"))

    @preferred_availability_zones.setter
    def preferred_availability_zones(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "preferredAvailabilityZones", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredMaintenanceWindow")
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''Specifies the weekly time range during which maintenance on the cluster is performed.

        It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for ``ddd`` are:

        Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period.

        Valid values for ``ddd`` are:

        - ``sun``
        - ``mon``
        - ``tue``
        - ``wed``
        - ``thu``
        - ``fri``
        - ``sat``

        Example: ``sun:23:00-mon:01:30``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-preferredmaintenancewindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preferredMaintenanceWindow"))

    @preferred_maintenance_window.setter
    def preferred_maintenance_window(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "preferredMaintenanceWindow", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotArns")
    def snapshot_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A single-element string list containing an Amazon Resource Name (ARN) that uniquely identifies a Redis RDB snapshot file stored in Amazon S3.

        The snapshot file is used to populate the node group (shard). The Amazon S3 object name in the ARN cannot contain any commas.
        .. epigraph::

           This parameter is only valid if the ``Engine`` parameter is ``redis`` .

        Example of an Amazon S3 ARN: ``arn:aws:s3:::my_bucket/snapshot1.rdb``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-snapshotarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "snapshotArns"))

    @snapshot_arns.setter
    def snapshot_arns(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "snapshotArns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotName")
    def snapshot_name(self) -> typing.Optional[builtins.str]:
        '''The name of a Redis snapshot from which to restore data into the new node group (shard).

        The snapshot status changes to ``restoring`` while the new node group (shard) is being created.
        .. epigraph::

           This parameter is only valid if the ``Engine`` parameter is ``redis`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-snapshotname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "snapshotName"))

    @snapshot_name.setter
    def snapshot_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "snapshotName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotRetentionLimit")
    def snapshot_retention_limit(self) -> typing.Optional[jsii.Number]:
        '''The number of days for which ElastiCache retains automatic snapshots before deleting them.

        For example, if you set ``SnapshotRetentionLimit`` to 5, a snapshot taken today is retained for 5 days before being deleted.
        .. epigraph::

           This parameter is only valid if the ``Engine`` parameter is ``redis`` .

        Default: 0 (i.e., automatic backups are disabled for this cache cluster).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-snapshotretentionlimit
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "snapshotRetentionLimit"))

    @snapshot_retention_limit.setter
    def snapshot_retention_limit(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "snapshotRetentionLimit", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotWindow")
    def snapshot_window(self) -> typing.Optional[builtins.str]:
        '''The daily time range (in UTC) during which ElastiCache begins taking a daily snapshot of your node group (shard).

        Example: ``05:00-09:00``

        If you do not specify this parameter, ElastiCache automatically chooses an appropriate time range.
        .. epigraph::

           This parameter is only valid if the ``Engine`` parameter is ``redis`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-snapshotwindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "snapshotWindow"))

    @snapshot_window.setter
    def snapshot_window(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "snapshotWindow", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcSecurityGroupIds")
    def vpc_security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more VPC security groups associated with the cluster.

        Use this parameter only when you are creating a cluster in an Amazon Virtual Private Cloud (Amazon VPC).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-vpcsecuritygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "vpcSecurityGroupIds"))

    @vpc_security_group_ids.setter
    def vpc_security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "vpcSecurityGroupIds", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={"log_group": "logGroup"},
    )
    class CloudWatchLogsDestinationDetailsProperty:
        def __init__(self, *, log_group: builtins.str) -> None:
            '''Configuration details of a CloudWatch Logs destination.

            Note that this field is marked as required but only if CloudWatch Logs was chosen as the destination.

            :param log_group: The name of the CloudWatch Logs log group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-cloudwatchlogsdestinationdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                cloud_watch_logs_destination_details_property = elasticache.CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty(
                    log_group="logGroup"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "log_group": log_group,
            }

        @builtins.property
        def log_group(self) -> builtins.str:
            '''The name of the CloudWatch Logs log group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-cloudwatchlogsdestinationdetails.html#cfn-elasticache-cachecluster-cloudwatchlogsdestinationdetails-loggroup
            '''
            result = self._values.get("log_group")
            assert result is not None, "Required property 'log_group' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CloudWatchLogsDestinationDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnCacheCluster.DestinationDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_logs_details": "cloudWatchLogsDetails",
            "kinesis_firehose_details": "kinesisFirehoseDetails",
        },
    )
    class DestinationDetailsProperty:
        def __init__(
            self,
            *,
            cloud_watch_logs_details: typing.Optional[typing.Union["CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty", _IResolvable_da3f097b]] = None,
            kinesis_firehose_details: typing.Optional[typing.Union["CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Configuration details of either a CloudWatch Logs destination or Kinesis Data Firehose destination.

            :param cloud_watch_logs_details: The configuration details of the CloudWatch Logs destination. Note that this field is marked as required but only if CloudWatch Logs was chosen as the destination.
            :param kinesis_firehose_details: The configuration details of the Kinesis Data Firehose destination. Note that this field is marked as required but only if Kinesis Data Firehose was chosen as the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-destinationdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                destination_details_property = elasticache.CfnCacheCluster.DestinationDetailsProperty(
                    cloud_watch_logs_details=elasticache.CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty(
                        log_group="logGroup"
                    ),
                    kinesis_firehose_details=elasticache.CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty(
                        delivery_stream="deliveryStream"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cloud_watch_logs_details is not None:
                self._values["cloud_watch_logs_details"] = cloud_watch_logs_details
            if kinesis_firehose_details is not None:
                self._values["kinesis_firehose_details"] = kinesis_firehose_details

        @builtins.property
        def cloud_watch_logs_details(
            self,
        ) -> typing.Optional[typing.Union["CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty", _IResolvable_da3f097b]]:
            '''The configuration details of the CloudWatch Logs destination.

            Note that this field is marked as required but only if CloudWatch Logs was chosen as the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-destinationdetails.html#cfn-elasticache-cachecluster-destinationdetails-cloudwatchlogsdetails
            '''
            result = self._values.get("cloud_watch_logs_details")
            return typing.cast(typing.Optional[typing.Union["CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def kinesis_firehose_details(
            self,
        ) -> typing.Optional[typing.Union["CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty", _IResolvable_da3f097b]]:
            '''The configuration details of the Kinesis Data Firehose destination.

            Note that this field is marked as required but only if Kinesis Data Firehose was chosen as the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-destinationdetails.html#cfn-elasticache-cachecluster-destinationdetails-kinesisfirehosedetails
            '''
            result = self._values.get("kinesis_firehose_details")
            return typing.cast(typing.Optional[typing.Union["CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DestinationDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={"delivery_stream": "deliveryStream"},
    )
    class KinesisFirehoseDestinationDetailsProperty:
        def __init__(self, *, delivery_stream: builtins.str) -> None:
            '''The configuration details of the Kinesis Data Firehose destination.

            Note that this field is marked as required but only if Kinesis Data Firehose was chosen as the destination.

            :param delivery_stream: The name of the Kinesis Data Firehose delivery stream.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-kinesisfirehosedestinationdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                kinesis_firehose_destination_details_property = elasticache.CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty(
                    delivery_stream="deliveryStream"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "delivery_stream": delivery_stream,
            }

        @builtins.property
        def delivery_stream(self) -> builtins.str:
            '''The name of the Kinesis Data Firehose delivery stream.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-kinesisfirehosedestinationdetails.html#cfn-elasticache-cachecluster-kinesisfirehosedestinationdetails-deliverystream
            '''
            result = self._values.get("delivery_stream")
            assert result is not None, "Required property 'delivery_stream' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KinesisFirehoseDestinationDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnCacheCluster.LogDeliveryConfigurationRequestProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_details": "destinationDetails",
            "destination_type": "destinationType",
            "log_format": "logFormat",
            "log_type": "logType",
        },
    )
    class LogDeliveryConfigurationRequestProperty:
        def __init__(
            self,
            *,
            destination_details: typing.Union["CfnCacheCluster.DestinationDetailsProperty", _IResolvable_da3f097b],
            destination_type: builtins.str,
            log_format: builtins.str,
            log_type: builtins.str,
        ) -> None:
            '''Specifies the destination, format and type of the logs.

            :param destination_details: Configuration details of either a CloudWatch Logs destination or Kinesis Data Firehose destination.
            :param destination_type: Specify either CloudWatch Logs or Kinesis Data Firehose as the destination type. Valid values are either ``cloudwatch-logs`` or ``kinesis-firehose`` .
            :param log_format: Valid values are either ``json`` or ``text`` .
            :param log_type: Valid value is either ``slow-log`` , which refers to `slow-log <https://docs.aws.amazon.com/https://redis.io/commands/slowlog>`_ or ``engine-log`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-logdeliveryconfigurationrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                log_delivery_configuration_request_property = elasticache.CfnCacheCluster.LogDeliveryConfigurationRequestProperty(
                    destination_details=elasticache.CfnCacheCluster.DestinationDetailsProperty(
                        cloud_watch_logs_details=elasticache.CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty(
                            log_group="logGroup"
                        ),
                        kinesis_firehose_details=elasticache.CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty(
                            delivery_stream="deliveryStream"
                        )
                    ),
                    destination_type="destinationType",
                    log_format="logFormat",
                    log_type="logType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_details": destination_details,
                "destination_type": destination_type,
                "log_format": log_format,
                "log_type": log_type,
            }

        @builtins.property
        def destination_details(
            self,
        ) -> typing.Union["CfnCacheCluster.DestinationDetailsProperty", _IResolvable_da3f097b]:
            '''Configuration details of either a CloudWatch Logs destination or Kinesis Data Firehose destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-logdeliveryconfigurationrequest.html#cfn-elasticache-cachecluster-logdeliveryconfigurationrequest-destinationdetails
            '''
            result = self._values.get("destination_details")
            assert result is not None, "Required property 'destination_details' is missing"
            return typing.cast(typing.Union["CfnCacheCluster.DestinationDetailsProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def destination_type(self) -> builtins.str:
            '''Specify either CloudWatch Logs or Kinesis Data Firehose as the destination type.

            Valid values are either ``cloudwatch-logs`` or ``kinesis-firehose`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-logdeliveryconfigurationrequest.html#cfn-elasticache-cachecluster-logdeliveryconfigurationrequest-destinationtype
            '''
            result = self._values.get("destination_type")
            assert result is not None, "Required property 'destination_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def log_format(self) -> builtins.str:
            '''Valid values are either ``json`` or ``text`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-logdeliveryconfigurationrequest.html#cfn-elasticache-cachecluster-logdeliveryconfigurationrequest-logformat
            '''
            result = self._values.get("log_format")
            assert result is not None, "Required property 'log_format' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def log_type(self) -> builtins.str:
            '''Valid value is either ``slow-log`` , which refers to `slow-log <https://docs.aws.amazon.com/https://redis.io/commands/slowlog>`_ or ``engine-log`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cachecluster-logdeliveryconfigurationrequest.html#cfn-elasticache-cachecluster-logdeliveryconfigurationrequest-logtype
            '''
            result = self._values.get("log_type")
            assert result is not None, "Required property 'log_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogDeliveryConfigurationRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnCacheClusterProps",
    jsii_struct_bases=[],
    name_mapping={
        "cache_node_type": "cacheNodeType",
        "engine": "engine",
        "num_cache_nodes": "numCacheNodes",
        "auto_minor_version_upgrade": "autoMinorVersionUpgrade",
        "az_mode": "azMode",
        "cache_parameter_group_name": "cacheParameterGroupName",
        "cache_security_group_names": "cacheSecurityGroupNames",
        "cache_subnet_group_name": "cacheSubnetGroupName",
        "cluster_name": "clusterName",
        "engine_version": "engineVersion",
        "log_delivery_configurations": "logDeliveryConfigurations",
        "notification_topic_arn": "notificationTopicArn",
        "port": "port",
        "preferred_availability_zone": "preferredAvailabilityZone",
        "preferred_availability_zones": "preferredAvailabilityZones",
        "preferred_maintenance_window": "preferredMaintenanceWindow",
        "snapshot_arns": "snapshotArns",
        "snapshot_name": "snapshotName",
        "snapshot_retention_limit": "snapshotRetentionLimit",
        "snapshot_window": "snapshotWindow",
        "tags": "tags",
        "vpc_security_group_ids": "vpcSecurityGroupIds",
    },
)
class CfnCacheClusterProps:
    def __init__(
        self,
        *,
        cache_node_type: builtins.str,
        engine: builtins.str,
        num_cache_nodes: jsii.Number,
        auto_minor_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        az_mode: typing.Optional[builtins.str] = None,
        cache_parameter_group_name: typing.Optional[builtins.str] = None,
        cache_security_group_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        cache_subnet_group_name: typing.Optional[builtins.str] = None,
        cluster_name: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        log_delivery_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnCacheCluster.LogDeliveryConfigurationRequestProperty, _IResolvable_da3f097b]]]] = None,
        notification_topic_arn: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        preferred_availability_zone: typing.Optional[builtins.str] = None,
        preferred_availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        snapshot_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        snapshot_name: typing.Optional[builtins.str] = None,
        snapshot_retention_limit: typing.Optional[jsii.Number] = None,
        snapshot_window: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnCacheCluster``.

        :param cache_node_type: The compute and memory capacity of the nodes in the node group (shard). The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts. Changing the CacheNodeType of a Memcached instance is currently not supported. If you need to scale using Memcached, we recommend forcing a replacement update by changing the ``LogicalResourceId`` of the resource. - General purpose: - Current generation: *M6g node types:* ``cache.m6g.large`` , ``cache.m6g.xlarge`` , ``cache.m6g.2xlarge`` , ``cache.m6g.4xlarge`` , ``cache.m6g.8xlarge`` , ``cache.m6g.12xlarge`` , ``cache.m6g.16xlarge`` , ``cache.m6g.24xlarge`` *M5 node types:* ``cache.m5.large`` , ``cache.m5.xlarge`` , ``cache.m5.2xlarge`` , ``cache.m5.4xlarge`` , ``cache.m5.12xlarge`` , ``cache.m5.24xlarge`` *M4 node types:* ``cache.m4.large`` , ``cache.m4.xlarge`` , ``cache.m4.2xlarge`` , ``cache.m4.4xlarge`` , ``cache.m4.10xlarge`` *T4g node types:* ``cache.t4g.micro`` , ``cache.t4g.small`` , ``cache.t4g.medium`` *T3 node types:* ``cache.t3.micro`` , ``cache.t3.small`` , ``cache.t3.medium`` *T2 node types:* ``cache.t2.micro`` , ``cache.t2.small`` , ``cache.t2.medium`` - Previous generation: (not recommended) *T1 node types:* ``cache.t1.micro`` *M1 node types:* ``cache.m1.small`` , ``cache.m1.medium`` , ``cache.m1.large`` , ``cache.m1.xlarge`` *M3 node types:* ``cache.m3.medium`` , ``cache.m3.large`` , ``cache.m3.xlarge`` , ``cache.m3.2xlarge`` - Compute optimized: - Previous generation: (not recommended) *C1 node types:* ``cache.c1.xlarge`` - Memory optimized: - Current generation: *R6gd node types:* ``cache.r6gd.xlarge`` , ``cache.r6gd.2xlarge`` , ``cache.r6gd.4xlarge`` , ``cache.r6gd.8xlarge`` , ``cache.r6gd.12xlarge`` , ``cache.r6gd.16xlarge`` .. epigraph:: The ``r6gd`` family is available in the following regions: ``us-east-2`` , ``us-east-1`` , ``us-west-2`` , ``us-west-1`` , ``eu-west-1`` , ``eu-central-1`` , ``ap-northeast-1`` , ``ap-southeast-1`` , ``ap-southeast-2`` . *R6g node types:* ``cache.r6g.large`` , ``cache.r6g.xlarge`` , ``cache.r6g.2xlarge`` , ``cache.r6g.4xlarge`` , ``cache.r6g.8xlarge`` , ``cache.r6g.12xlarge`` , ``cache.r6g.16xlarge`` , ``cache.r6g.24xlarge`` *R5 node types:* ``cache.r5.large`` , ``cache.r5.xlarge`` , ``cache.r5.2xlarge`` , ``cache.r5.4xlarge`` , ``cache.r5.12xlarge`` , ``cache.r5.24xlarge`` *R4 node types:* ``cache.r4.large`` , ``cache.r4.xlarge`` , ``cache.r4.2xlarge`` , ``cache.r4.4xlarge`` , ``cache.r4.8xlarge`` , ``cache.r4.16xlarge`` - Previous generation: (not recommended) *M2 node types:* ``cache.m2.xlarge`` , ``cache.m2.2xlarge`` , ``cache.m2.4xlarge`` *R3 node types:* ``cache.r3.large`` , ``cache.r3.xlarge`` , ``cache.r3.2xlarge`` , ``cache.r3.4xlarge`` , ``cache.r3.8xlarge`` For region availability, see `Supported Node Types by Amazon Region <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion>`_ *Additional node type info* - All current generation instance types are created in Amazon VPC by default. - Redis append-only files (AOF) are not supported for T1 or T2 instances. - Redis Multi-AZ with automatic failover is not supported on T1 instances. - Redis configuration variables ``appendonly`` and ``appendfsync`` are not supported on Redis version 2.8.22 and later.
        :param engine: The name of the cache engine to be used for this cluster. Valid values for this parameter are: ``memcached`` | ``redis``
        :param num_cache_nodes: The number of cache nodes that the cache cluster should have. .. epigraph:: However, if the ``PreferredAvailabilityZone`` and ``PreferredAvailabilityZones`` properties were not previously specified and you don't specify any new values, an update requires `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .
        :param auto_minor_version_upgrade: If you are running Redis engine version 6.0 or later, set this parameter to yes if you want to opt-in to the next minor version upgrade campaign. This parameter is disabled for previous versions.
        :param az_mode: Specifies whether the nodes in this Memcached cluster are created in a single Availability Zone or created across multiple Availability Zones in the cluster's region. This parameter is only supported for Memcached clusters. If the ``AZMode`` and ``PreferredAvailabilityZones`` are not specified, ElastiCache assumes ``single-az`` mode.
        :param cache_parameter_group_name: The name of the parameter group to associate with this cluster. If this argument is omitted, the default parameter group for the specified engine is used. You cannot use any parameter group which has ``cluster-enabled='yes'`` when creating a cluster.
        :param cache_security_group_names: A list of security group names to associate with this cluster. Use this parameter only when you are creating a cluster outside of an Amazon Virtual Private Cloud (Amazon VPC).
        :param cache_subnet_group_name: The name of the subnet group to be used for the cluster. Use this parameter only when you are creating a cluster in an Amazon Virtual Private Cloud (Amazon VPC). .. epigraph:: If you're going to launch your cluster in an Amazon VPC, you need to create a subnet group before you start creating a cluster. For more information, see `AWS::ElastiCache::SubnetGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html>`_ .
        :param cluster_name: A name for the cache cluster. If you don't specify a name, AWSCloudFormation generates a unique physical ID and uses that ID for the cache cluster. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . The name must contain 1 to 50 alphanumeric characters or hyphens. The name must start with a letter and cannot end with a hyphen or contain two consecutive hyphens.
        :param engine_version: The version number of the cache engine to be used for this cluster. To view the supported cache engine versions, use the DescribeCacheEngineVersions operation. *Important:* You can upgrade to a newer engine version (see `Selecting a Cache Engine and Version <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SelectEngine.html#VersionManagement>`_ ), but you cannot downgrade to an earlier engine version. If you want to use an earlier engine version, you must delete the existing cluster or replication group and create it anew with the earlier engine version.
        :param log_delivery_configurations: Specifies the destination, format and type of the logs.
        :param notification_topic_arn: The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent. .. epigraph:: The Amazon SNS topic owner must be the same as the cluster owner.
        :param port: The port number on which each of the cache nodes accepts connections.
        :param preferred_availability_zone: The EC2 Availability Zone in which the cluster is created. All nodes belonging to this cluster are placed in the preferred Availability Zone. If you want to create your nodes across multiple Availability Zones, use ``PreferredAvailabilityZones`` . Default: System chosen Availability Zone.
        :param preferred_availability_zones: A list of the Availability Zones in which cache nodes are created. The order of the zones in the list is not important. This option is only supported on Memcached. .. epigraph:: If you are creating your cluster in an Amazon VPC (recommended) you can only locate nodes in Availability Zones that are associated with the subnets in the selected subnet group. The number of Availability Zones listed must equal the value of ``NumCacheNodes`` . If you want all the nodes in the same Availability Zone, use ``PreferredAvailabilityZone`` instead, or repeat the Availability Zone multiple times in the list. Default: System chosen Availability Zones.
        :param preferred_maintenance_window: Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for ``ddd`` are: Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for ``ddd`` are: - ``sun`` - ``mon`` - ``tue`` - ``wed`` - ``thu`` - ``fri`` - ``sat`` Example: ``sun:23:00-mon:01:30``
        :param snapshot_arns: A single-element string list containing an Amazon Resource Name (ARN) that uniquely identifies a Redis RDB snapshot file stored in Amazon S3. The snapshot file is used to populate the node group (shard). The Amazon S3 object name in the ARN cannot contain any commas. .. epigraph:: This parameter is only valid if the ``Engine`` parameter is ``redis`` . Example of an Amazon S3 ARN: ``arn:aws:s3:::my_bucket/snapshot1.rdb``
        :param snapshot_name: The name of a Redis snapshot from which to restore data into the new node group (shard). The snapshot status changes to ``restoring`` while the new node group (shard) is being created. .. epigraph:: This parameter is only valid if the ``Engine`` parameter is ``redis`` .
        :param snapshot_retention_limit: The number of days for which ElastiCache retains automatic snapshots before deleting them. For example, if you set ``SnapshotRetentionLimit`` to 5, a snapshot taken today is retained for 5 days before being deleted. .. epigraph:: This parameter is only valid if the ``Engine`` parameter is ``redis`` . Default: 0 (i.e., automatic backups are disabled for this cache cluster).
        :param snapshot_window: The daily time range (in UTC) during which ElastiCache begins taking a daily snapshot of your node group (shard). Example: ``05:00-09:00`` If you do not specify this parameter, ElastiCache automatically chooses an appropriate time range. .. epigraph:: This parameter is only valid if the ``Engine`` parameter is ``redis`` .
        :param tags: A list of tags to be added to this resource.
        :param vpc_security_group_ids: One or more VPC security groups associated with the cluster. Use this parameter only when you are creating a cluster in an Amazon Virtual Private Cloud (Amazon VPC).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_cache_cluster_props = elasticache.CfnCacheClusterProps(
                cache_node_type="cacheNodeType",
                engine="engine",
                num_cache_nodes=123,
            
                # the properties below are optional
                auto_minor_version_upgrade=False,
                az_mode="azMode",
                cache_parameter_group_name="cacheParameterGroupName",
                cache_security_group_names=["cacheSecurityGroupNames"],
                cache_subnet_group_name="cacheSubnetGroupName",
                cluster_name="clusterName",
                engine_version="engineVersion",
                log_delivery_configurations=[elasticache.CfnCacheCluster.LogDeliveryConfigurationRequestProperty(
                    destination_details=elasticache.CfnCacheCluster.DestinationDetailsProperty(
                        cloud_watch_logs_details=elasticache.CfnCacheCluster.CloudWatchLogsDestinationDetailsProperty(
                            log_group="logGroup"
                        ),
                        kinesis_firehose_details=elasticache.CfnCacheCluster.KinesisFirehoseDestinationDetailsProperty(
                            delivery_stream="deliveryStream"
                        )
                    ),
                    destination_type="destinationType",
                    log_format="logFormat",
                    log_type="logType"
                )],
                notification_topic_arn="notificationTopicArn",
                port=123,
                preferred_availability_zone="preferredAvailabilityZone",
                preferred_availability_zones=["preferredAvailabilityZones"],
                preferred_maintenance_window="preferredMaintenanceWindow",
                snapshot_arns=["snapshotArns"],
                snapshot_name="snapshotName",
                snapshot_retention_limit=123,
                snapshot_window="snapshotWindow",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                vpc_security_group_ids=["vpcSecurityGroupIds"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cache_node_type": cache_node_type,
            "engine": engine,
            "num_cache_nodes": num_cache_nodes,
        }
        if auto_minor_version_upgrade is not None:
            self._values["auto_minor_version_upgrade"] = auto_minor_version_upgrade
        if az_mode is not None:
            self._values["az_mode"] = az_mode
        if cache_parameter_group_name is not None:
            self._values["cache_parameter_group_name"] = cache_parameter_group_name
        if cache_security_group_names is not None:
            self._values["cache_security_group_names"] = cache_security_group_names
        if cache_subnet_group_name is not None:
            self._values["cache_subnet_group_name"] = cache_subnet_group_name
        if cluster_name is not None:
            self._values["cluster_name"] = cluster_name
        if engine_version is not None:
            self._values["engine_version"] = engine_version
        if log_delivery_configurations is not None:
            self._values["log_delivery_configurations"] = log_delivery_configurations
        if notification_topic_arn is not None:
            self._values["notification_topic_arn"] = notification_topic_arn
        if port is not None:
            self._values["port"] = port
        if preferred_availability_zone is not None:
            self._values["preferred_availability_zone"] = preferred_availability_zone
        if preferred_availability_zones is not None:
            self._values["preferred_availability_zones"] = preferred_availability_zones
        if preferred_maintenance_window is not None:
            self._values["preferred_maintenance_window"] = preferred_maintenance_window
        if snapshot_arns is not None:
            self._values["snapshot_arns"] = snapshot_arns
        if snapshot_name is not None:
            self._values["snapshot_name"] = snapshot_name
        if snapshot_retention_limit is not None:
            self._values["snapshot_retention_limit"] = snapshot_retention_limit
        if snapshot_window is not None:
            self._values["snapshot_window"] = snapshot_window
        if tags is not None:
            self._values["tags"] = tags
        if vpc_security_group_ids is not None:
            self._values["vpc_security_group_ids"] = vpc_security_group_ids

    @builtins.property
    def cache_node_type(self) -> builtins.str:
        '''The compute and memory capacity of the nodes in the node group (shard).

        The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts. Changing the CacheNodeType of a Memcached instance is currently not supported. If you need to scale using Memcached, we recommend forcing a replacement update by changing the ``LogicalResourceId`` of the resource.

        - General purpose:
        - Current generation:

        *M6g node types:* ``cache.m6g.large`` , ``cache.m6g.xlarge`` , ``cache.m6g.2xlarge`` , ``cache.m6g.4xlarge`` , ``cache.m6g.8xlarge`` , ``cache.m6g.12xlarge`` , ``cache.m6g.16xlarge`` , ``cache.m6g.24xlarge``

        *M5 node types:* ``cache.m5.large`` , ``cache.m5.xlarge`` , ``cache.m5.2xlarge`` , ``cache.m5.4xlarge`` , ``cache.m5.12xlarge`` , ``cache.m5.24xlarge``

        *M4 node types:* ``cache.m4.large`` , ``cache.m4.xlarge`` , ``cache.m4.2xlarge`` , ``cache.m4.4xlarge`` , ``cache.m4.10xlarge``

        *T4g node types:* ``cache.t4g.micro`` , ``cache.t4g.small`` , ``cache.t4g.medium``

        *T3 node types:* ``cache.t3.micro`` , ``cache.t3.small`` , ``cache.t3.medium``

        *T2 node types:* ``cache.t2.micro`` , ``cache.t2.small`` , ``cache.t2.medium``

        - Previous generation: (not recommended)

        *T1 node types:* ``cache.t1.micro``

        *M1 node types:* ``cache.m1.small`` , ``cache.m1.medium`` , ``cache.m1.large`` , ``cache.m1.xlarge``

        *M3 node types:* ``cache.m3.medium`` , ``cache.m3.large`` , ``cache.m3.xlarge`` , ``cache.m3.2xlarge``

        - Compute optimized:
        - Previous generation: (not recommended)

        *C1 node types:* ``cache.c1.xlarge``

        - Memory optimized:
        - Current generation:

        *R6gd node types:* ``cache.r6gd.xlarge`` , ``cache.r6gd.2xlarge`` , ``cache.r6gd.4xlarge`` , ``cache.r6gd.8xlarge`` , ``cache.r6gd.12xlarge`` , ``cache.r6gd.16xlarge``
        .. epigraph::

           The ``r6gd`` family is available in the following regions: ``us-east-2`` , ``us-east-1`` , ``us-west-2`` , ``us-west-1`` , ``eu-west-1`` , ``eu-central-1`` , ``ap-northeast-1`` , ``ap-southeast-1`` , ``ap-southeast-2`` .

        *R6g node types:* ``cache.r6g.large`` , ``cache.r6g.xlarge`` , ``cache.r6g.2xlarge`` , ``cache.r6g.4xlarge`` , ``cache.r6g.8xlarge`` , ``cache.r6g.12xlarge`` , ``cache.r6g.16xlarge`` , ``cache.r6g.24xlarge``

        *R5 node types:* ``cache.r5.large`` , ``cache.r5.xlarge`` , ``cache.r5.2xlarge`` , ``cache.r5.4xlarge`` , ``cache.r5.12xlarge`` , ``cache.r5.24xlarge``

        *R4 node types:* ``cache.r4.large`` , ``cache.r4.xlarge`` , ``cache.r4.2xlarge`` , ``cache.r4.4xlarge`` , ``cache.r4.8xlarge`` , ``cache.r4.16xlarge``

        - Previous generation: (not recommended)

        *M2 node types:* ``cache.m2.xlarge`` , ``cache.m2.2xlarge`` , ``cache.m2.4xlarge``

        *R3 node types:* ``cache.r3.large`` , ``cache.r3.xlarge`` , ``cache.r3.2xlarge`` , ``cache.r3.4xlarge`` , ``cache.r3.8xlarge``

        For region availability, see `Supported Node Types by Amazon Region <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion>`_

        *Additional node type info*

        - All current generation instance types are created in Amazon VPC by default.
        - Redis append-only files (AOF) are not supported for T1 or T2 instances.
        - Redis Multi-AZ with automatic failover is not supported on T1 instances.
        - Redis configuration variables ``appendonly`` and ``appendfsync`` are not supported on Redis version 2.8.22 and later.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-cachenodetype
        '''
        result = self._values.get("cache_node_type")
        assert result is not None, "Required property 'cache_node_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def engine(self) -> builtins.str:
        '''The name of the cache engine to be used for this cluster.

        Valid values for this parameter are: ``memcached`` | ``redis``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-engine
        '''
        result = self._values.get("engine")
        assert result is not None, "Required property 'engine' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def num_cache_nodes(self) -> jsii.Number:
        '''The number of cache nodes that the cache cluster should have.

        .. epigraph::

           However, if the ``PreferredAvailabilityZone`` and ``PreferredAvailabilityZones`` properties were not previously specified and you don't specify any new values, an update requires `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-numcachenodes
        '''
        result = self._values.get("num_cache_nodes")
        assert result is not None, "Required property 'num_cache_nodes' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If you are running Redis engine version 6.0 or later, set this parameter to yes if you want to opt-in to the next minor version upgrade campaign. This parameter is disabled for previous versions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-autominorversionupgrade
        '''
        result = self._values.get("auto_minor_version_upgrade")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def az_mode(self) -> typing.Optional[builtins.str]:
        '''Specifies whether the nodes in this Memcached cluster are created in a single Availability Zone or created across multiple Availability Zones in the cluster's region.

        This parameter is only supported for Memcached clusters.

        If the ``AZMode`` and ``PreferredAvailabilityZones`` are not specified, ElastiCache assumes ``single-az`` mode.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-azmode
        '''
        result = self._values.get("az_mode")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cache_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the parameter group to associate with this cluster.

        If this argument is omitted, the default parameter group for the specified engine is used. You cannot use any parameter group which has ``cluster-enabled='yes'`` when creating a cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-cacheparametergroupname
        '''
        result = self._values.get("cache_parameter_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cache_security_group_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of security group names to associate with this cluster.

        Use this parameter only when you are creating a cluster outside of an Amazon Virtual Private Cloud (Amazon VPC).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-cachesecuritygroupnames
        '''
        result = self._values.get("cache_security_group_names")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def cache_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the subnet group to be used for the cluster.

        Use this parameter only when you are creating a cluster in an Amazon Virtual Private Cloud (Amazon VPC).
        .. epigraph::

           If you're going to launch your cluster in an Amazon VPC, you need to create a subnet group before you start creating a cluster. For more information, see `AWS::ElastiCache::SubnetGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-cachesubnetgroupname
        '''
        result = self._values.get("cache_subnet_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cluster_name(self) -> typing.Optional[builtins.str]:
        '''A name for the cache cluster.

        If you don't specify a name, AWSCloudFormation generates a unique physical ID and uses that ID for the cache cluster. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .

        The name must contain 1 to 50 alphanumeric characters or hyphens. The name must start with a letter and cannot end with a hyphen or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-clustername
        '''
        result = self._values.get("cluster_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The version number of the cache engine to be used for this cluster.

        To view the supported cache engine versions, use the DescribeCacheEngineVersions operation.

        *Important:* You can upgrade to a newer engine version (see `Selecting a Cache Engine and Version <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SelectEngine.html#VersionManagement>`_ ), but you cannot downgrade to an earlier engine version. If you want to use an earlier engine version, you must delete the existing cluster or replication group and create it anew with the earlier engine version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-engineversion
        '''
        result = self._values.get("engine_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def log_delivery_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCacheCluster.LogDeliveryConfigurationRequestProperty, _IResolvable_da3f097b]]]]:
        '''Specifies the destination, format and type of the logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-logdeliveryconfigurations
        '''
        result = self._values.get("log_delivery_configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCacheCluster.LogDeliveryConfigurationRequestProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def notification_topic_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent.

        .. epigraph::

           The Amazon SNS topic owner must be the same as the cluster owner.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-notificationtopicarn
        '''
        result = self._values.get("notification_topic_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port number on which each of the cache nodes accepts connections.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-port
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def preferred_availability_zone(self) -> typing.Optional[builtins.str]:
        '''The EC2 Availability Zone in which the cluster is created.

        All nodes belonging to this cluster are placed in the preferred Availability Zone. If you want to create your nodes across multiple Availability Zones, use ``PreferredAvailabilityZones`` .

        Default: System chosen Availability Zone.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-preferredavailabilityzone
        '''
        result = self._values.get("preferred_availability_zone")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def preferred_availability_zones(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of the Availability Zones in which cache nodes are created.

        The order of the zones in the list is not important.

        This option is only supported on Memcached.
        .. epigraph::

           If you are creating your cluster in an Amazon VPC (recommended) you can only locate nodes in Availability Zones that are associated with the subnets in the selected subnet group.

           The number of Availability Zones listed must equal the value of ``NumCacheNodes`` .

        If you want all the nodes in the same Availability Zone, use ``PreferredAvailabilityZone`` instead, or repeat the Availability Zone multiple times in the list.

        Default: System chosen Availability Zones.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-preferredavailabilityzones
        '''
        result = self._values.get("preferred_availability_zones")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''Specifies the weekly time range during which maintenance on the cluster is performed.

        It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for ``ddd`` are:

        Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period.

        Valid values for ``ddd`` are:

        - ``sun``
        - ``mon``
        - ``tue``
        - ``wed``
        - ``thu``
        - ``fri``
        - ``sat``

        Example: ``sun:23:00-mon:01:30``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-preferredmaintenancewindow
        '''
        result = self._values.get("preferred_maintenance_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def snapshot_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A single-element string list containing an Amazon Resource Name (ARN) that uniquely identifies a Redis RDB snapshot file stored in Amazon S3.

        The snapshot file is used to populate the node group (shard). The Amazon S3 object name in the ARN cannot contain any commas.
        .. epigraph::

           This parameter is only valid if the ``Engine`` parameter is ``redis`` .

        Example of an Amazon S3 ARN: ``arn:aws:s3:::my_bucket/snapshot1.rdb``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-snapshotarns
        '''
        result = self._values.get("snapshot_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def snapshot_name(self) -> typing.Optional[builtins.str]:
        '''The name of a Redis snapshot from which to restore data into the new node group (shard).

        The snapshot status changes to ``restoring`` while the new node group (shard) is being created.
        .. epigraph::

           This parameter is only valid if the ``Engine`` parameter is ``redis`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-snapshotname
        '''
        result = self._values.get("snapshot_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def snapshot_retention_limit(self) -> typing.Optional[jsii.Number]:
        '''The number of days for which ElastiCache retains automatic snapshots before deleting them.

        For example, if you set ``SnapshotRetentionLimit`` to 5, a snapshot taken today is retained for 5 days before being deleted.
        .. epigraph::

           This parameter is only valid if the ``Engine`` parameter is ``redis`` .

        Default: 0 (i.e., automatic backups are disabled for this cache cluster).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-snapshotretentionlimit
        '''
        result = self._values.get("snapshot_retention_limit")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def snapshot_window(self) -> typing.Optional[builtins.str]:
        '''The daily time range (in UTC) during which ElastiCache begins taking a daily snapshot of your node group (shard).

        Example: ``05:00-09:00``

        If you do not specify this parameter, ElastiCache automatically chooses an appropriate time range.
        .. epigraph::

           This parameter is only valid if the ``Engine`` parameter is ``redis`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-snapshotwindow
        '''
        result = self._values.get("snapshot_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags to be added to this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def vpc_security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more VPC security groups associated with the cluster.

        Use this parameter only when you are creating a cluster in an Amazon Virtual Private Cloud (Amazon VPC).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html#cfn-elasticache-cachecluster-vpcsecuritygroupids
        '''
        result = self._values.get("vpc_security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCacheClusterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnGlobalReplicationGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnGlobalReplicationGroup",
):
    '''A CloudFormation ``AWS::ElastiCache::GlobalReplicationGroup``.

    Consists of a primary cluster that accepts writes and an associated secondary cluster that resides in a different Amazon region. The secondary cluster accepts only reads. The primary cluster automatically replicates updates to the secondary cluster.

    - The *GlobalReplicationGroupIdSuffix* represents the name of the Global datastore, which is what you use to associate a secondary cluster.

    :cloudformationResource: AWS::ElastiCache::GlobalReplicationGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_global_replication_group = elasticache.CfnGlobalReplicationGroup(self, "MyCfnGlobalReplicationGroup",
            members=[elasticache.CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty(
                replication_group_id="replicationGroupId",
                replication_group_region="replicationGroupRegion",
                role="role"
            )],
        
            # the properties below are optional
            automatic_failover_enabled=False,
            cache_node_type="cacheNodeType",
            cache_parameter_group_name="cacheParameterGroupName",
            engine_version="engineVersion",
            global_node_group_count=123,
            global_replication_group_description="globalReplicationGroupDescription",
            global_replication_group_id_suffix="globalReplicationGroupIdSuffix",
            regional_configurations=[elasticache.CfnGlobalReplicationGroup.RegionalConfigurationProperty(
                replication_group_id="replicationGroupId",
                replication_group_region="replicationGroupRegion",
                resharding_configurations=[elasticache.CfnGlobalReplicationGroup.ReshardingConfigurationProperty(
                    node_group_id="nodeGroupId",
                    preferred_availability_zones=["preferredAvailabilityZones"]
                )]
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        members: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty", _IResolvable_da3f097b]]],
        automatic_failover_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        cache_node_type: typing.Optional[builtins.str] = None,
        cache_parameter_group_name: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        global_node_group_count: typing.Optional[jsii.Number] = None,
        global_replication_group_description: typing.Optional[builtins.str] = None,
        global_replication_group_id_suffix: typing.Optional[builtins.str] = None,
        regional_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnGlobalReplicationGroup.RegionalConfigurationProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::GlobalReplicationGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param members: The replication groups that comprise the Global datastore.
        :param automatic_failover_enabled: Specifies whether a read-only replica is automatically promoted to read/write primary if the existing primary fails. ``AutomaticFailoverEnabled`` must be enabled for Redis (cluster mode enabled) replication groups.
        :param cache_node_type: The cache node type of the Global datastore.
        :param cache_parameter_group_name: The name of the cache parameter group to use with the Global datastore. It must be compatible with the major engine version used by the Global datastore.
        :param engine_version: The Elasticache Redis engine version.
        :param global_node_group_count: The number of node groups that comprise the Global Datastore.
        :param global_replication_group_description: The optional description of the Global datastore.
        :param global_replication_group_id_suffix: The suffix name of a Global Datastore. The suffix guarantees uniqueness of the Global Datastore name across multiple regions.
        :param regional_configurations: The Amazon Regions that comprise the Global Datastore.
        '''
        props = CfnGlobalReplicationGroupProps(
            members=members,
            automatic_failover_enabled=automatic_failover_enabled,
            cache_node_type=cache_node_type,
            cache_parameter_group_name=cache_parameter_group_name,
            engine_version=engine_version,
            global_node_group_count=global_node_group_count,
            global_replication_group_description=global_replication_group_description,
            global_replication_group_id_suffix=global_replication_group_id_suffix,
            regional_configurations=regional_configurations,
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
    @jsii.member(jsii_name="attrGlobalReplicationGroupId")
    def attr_global_replication_group_id(self) -> builtins.str:
        '''The ID used to associate a secondary cluster to the Global Replication Group.

        :cloudformationAttribute: GlobalReplicationGroupId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrGlobalReplicationGroupId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''The status of the Global Datastore.

        Can be ``Creating`` , ``Modifying`` , ``Available`` , ``Deleting`` or ``Primary-Only`` . Primary-only status indicates the global datastore contains only a primary cluster. Either all secondary clusters are deleted or not successfully created.

        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="members")
    def members(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty", _IResolvable_da3f097b]]]:
        '''The replication groups that comprise the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-members
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty", _IResolvable_da3f097b]]], jsii.get(self, "members"))

    @members.setter
    def members(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "members", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="automaticFailoverEnabled")
    def automatic_failover_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether a read-only replica is automatically promoted to read/write primary if the existing primary fails.

        ``AutomaticFailoverEnabled`` must be enabled for Redis (cluster mode enabled) replication groups.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-automaticfailoverenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "automaticFailoverEnabled"))

    @automatic_failover_enabled.setter
    def automatic_failover_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "automaticFailoverEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheNodeType")
    def cache_node_type(self) -> typing.Optional[builtins.str]:
        '''The cache node type of the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-cachenodetype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cacheNodeType"))

    @cache_node_type.setter
    def cache_node_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cacheNodeType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheParameterGroupName")
    def cache_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the cache parameter group to use with the Global datastore.

        It must be compatible with the major engine version used by the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-cacheparametergroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cacheParameterGroupName"))

    @cache_parameter_group_name.setter
    def cache_parameter_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cacheParameterGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineVersion")
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The Elasticache Redis engine version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-engineversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "engineVersion"))

    @engine_version.setter
    def engine_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "engineVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="globalNodeGroupCount")
    def global_node_group_count(self) -> typing.Optional[jsii.Number]:
        '''The number of node groups that comprise the Global Datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-globalnodegroupcount
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "globalNodeGroupCount"))

    @global_node_group_count.setter
    def global_node_group_count(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "globalNodeGroupCount", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="globalReplicationGroupDescription")
    def global_replication_group_description(self) -> typing.Optional[builtins.str]:
        '''The optional description of the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-globalreplicationgroupdescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "globalReplicationGroupDescription"))

    @global_replication_group_description.setter
    def global_replication_group_description(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "globalReplicationGroupDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="globalReplicationGroupIdSuffix")
    def global_replication_group_id_suffix(self) -> typing.Optional[builtins.str]:
        '''The suffix name of a Global Datastore.

        The suffix guarantees uniqueness of the Global Datastore name across multiple regions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-globalreplicationgroupidsuffix
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "globalReplicationGroupIdSuffix"))

    @global_replication_group_id_suffix.setter
    def global_replication_group_id_suffix(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "globalReplicationGroupIdSuffix", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="regionalConfigurations")
    def regional_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGlobalReplicationGroup.RegionalConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''The Amazon Regions that comprise the Global Datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-regionalconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGlobalReplicationGroup.RegionalConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "regionalConfigurations"))

    @regional_configurations.setter
    def regional_configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGlobalReplicationGroup.RegionalConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "regionalConfigurations", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty",
        jsii_struct_bases=[],
        name_mapping={
            "replication_group_id": "replicationGroupId",
            "replication_group_region": "replicationGroupRegion",
            "role": "role",
        },
    )
    class GlobalReplicationGroupMemberProperty:
        def __init__(
            self,
            *,
            replication_group_id: typing.Optional[builtins.str] = None,
            replication_group_region: typing.Optional[builtins.str] = None,
            role: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A member of a Global datastore.

            It contains the Replication Group Id, the Amazon region and the role of the replication group.

            :param replication_group_id: The replication group id of the Global datastore member.
            :param replication_group_region: The Amazon region of the Global datastore member.
            :param role: Indicates the role of the replication group, ``PRIMARY`` or ``SECONDARY`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-globalreplicationgroupmember.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                global_replication_group_member_property = elasticache.CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty(
                    replication_group_id="replicationGroupId",
                    replication_group_region="replicationGroupRegion",
                    role="role"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if replication_group_id is not None:
                self._values["replication_group_id"] = replication_group_id
            if replication_group_region is not None:
                self._values["replication_group_region"] = replication_group_region
            if role is not None:
                self._values["role"] = role

        @builtins.property
        def replication_group_id(self) -> typing.Optional[builtins.str]:
            '''The replication group id of the Global datastore member.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-globalreplicationgroupmember.html#cfn-elasticache-globalreplicationgroup-globalreplicationgroupmember-replicationgroupid
            '''
            result = self._values.get("replication_group_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def replication_group_region(self) -> typing.Optional[builtins.str]:
            '''The Amazon region of the Global datastore member.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-globalreplicationgroupmember.html#cfn-elasticache-globalreplicationgroup-globalreplicationgroupmember-replicationgroupregion
            '''
            result = self._values.get("replication_group_region")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def role(self) -> typing.Optional[builtins.str]:
            '''Indicates the role of the replication group, ``PRIMARY`` or ``SECONDARY`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-globalreplicationgroupmember.html#cfn-elasticache-globalreplicationgroup-globalreplicationgroupmember-role
            '''
            result = self._values.get("role")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GlobalReplicationGroupMemberProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnGlobalReplicationGroup.RegionalConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "replication_group_id": "replicationGroupId",
            "replication_group_region": "replicationGroupRegion",
            "resharding_configurations": "reshardingConfigurations",
        },
    )
    class RegionalConfigurationProperty:
        def __init__(
            self,
            *,
            replication_group_id: typing.Optional[builtins.str] = None,
            replication_group_region: typing.Optional[builtins.str] = None,
            resharding_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnGlobalReplicationGroup.ReshardingConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A list of the replication groups.

            :param replication_group_id: The name of the secondary cluster.
            :param replication_group_region: The Amazon region where the cluster is stored.
            :param resharding_configurations: A list of PreferredAvailabilityZones objects that specifies the configuration of a node group in the resharded cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-regionalconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                regional_configuration_property = elasticache.CfnGlobalReplicationGroup.RegionalConfigurationProperty(
                    replication_group_id="replicationGroupId",
                    replication_group_region="replicationGroupRegion",
                    resharding_configurations=[elasticache.CfnGlobalReplicationGroup.ReshardingConfigurationProperty(
                        node_group_id="nodeGroupId",
                        preferred_availability_zones=["preferredAvailabilityZones"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if replication_group_id is not None:
                self._values["replication_group_id"] = replication_group_id
            if replication_group_region is not None:
                self._values["replication_group_region"] = replication_group_region
            if resharding_configurations is not None:
                self._values["resharding_configurations"] = resharding_configurations

        @builtins.property
        def replication_group_id(self) -> typing.Optional[builtins.str]:
            '''The name of the secondary cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-regionalconfiguration.html#cfn-elasticache-globalreplicationgroup-regionalconfiguration-replicationgroupid
            '''
            result = self._values.get("replication_group_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def replication_group_region(self) -> typing.Optional[builtins.str]:
            '''The Amazon region where the cluster is stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-regionalconfiguration.html#cfn-elasticache-globalreplicationgroup-regionalconfiguration-replicationgroupregion
            '''
            result = self._values.get("replication_group_region")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def resharding_configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGlobalReplicationGroup.ReshardingConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''A list of PreferredAvailabilityZones objects that specifies the configuration of a node group in the resharded cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-regionalconfiguration.html#cfn-elasticache-globalreplicationgroup-regionalconfiguration-reshardingconfigurations
            '''
            result = self._values.get("resharding_configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGlobalReplicationGroup.ReshardingConfigurationProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RegionalConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnGlobalReplicationGroup.ReshardingConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "node_group_id": "nodeGroupId",
            "preferred_availability_zones": "preferredAvailabilityZones",
        },
    )
    class ReshardingConfigurationProperty:
        def __init__(
            self,
            *,
            node_group_id: typing.Optional[builtins.str] = None,
            preferred_availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''A list of ``PreferredAvailabilityZones`` objects that specifies the configuration of a node group in the resharded cluster.

            :param node_group_id: Either the ElastiCache for Redis supplied 4-digit id or a user supplied id for the node group these configuration values apply to.
            :param preferred_availability_zones: A list of preferred availability zones for the nodes in this cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-reshardingconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                resharding_configuration_property = elasticache.CfnGlobalReplicationGroup.ReshardingConfigurationProperty(
                    node_group_id="nodeGroupId",
                    preferred_availability_zones=["preferredAvailabilityZones"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if node_group_id is not None:
                self._values["node_group_id"] = node_group_id
            if preferred_availability_zones is not None:
                self._values["preferred_availability_zones"] = preferred_availability_zones

        @builtins.property
        def node_group_id(self) -> typing.Optional[builtins.str]:
            '''Either the ElastiCache for Redis supplied 4-digit id or a user supplied id for the node group these configuration values apply to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-reshardingconfiguration.html#cfn-elasticache-globalreplicationgroup-reshardingconfiguration-nodegroupid
            '''
            result = self._values.get("node_group_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def preferred_availability_zones(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of preferred availability zones for the nodes in this cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-globalreplicationgroup-reshardingconfiguration.html#cfn-elasticache-globalreplicationgroup-reshardingconfiguration-preferredavailabilityzones
            '''
            result = self._values.get("preferred_availability_zones")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReshardingConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnGlobalReplicationGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "members": "members",
        "automatic_failover_enabled": "automaticFailoverEnabled",
        "cache_node_type": "cacheNodeType",
        "cache_parameter_group_name": "cacheParameterGroupName",
        "engine_version": "engineVersion",
        "global_node_group_count": "globalNodeGroupCount",
        "global_replication_group_description": "globalReplicationGroupDescription",
        "global_replication_group_id_suffix": "globalReplicationGroupIdSuffix",
        "regional_configurations": "regionalConfigurations",
    },
)
class CfnGlobalReplicationGroupProps:
    def __init__(
        self,
        *,
        members: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty, _IResolvable_da3f097b]]],
        automatic_failover_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        cache_node_type: typing.Optional[builtins.str] = None,
        cache_parameter_group_name: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        global_node_group_count: typing.Optional[jsii.Number] = None,
        global_replication_group_description: typing.Optional[builtins.str] = None,
        global_replication_group_id_suffix: typing.Optional[builtins.str] = None,
        regional_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnGlobalReplicationGroup.RegionalConfigurationProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnGlobalReplicationGroup``.

        :param members: The replication groups that comprise the Global datastore.
        :param automatic_failover_enabled: Specifies whether a read-only replica is automatically promoted to read/write primary if the existing primary fails. ``AutomaticFailoverEnabled`` must be enabled for Redis (cluster mode enabled) replication groups.
        :param cache_node_type: The cache node type of the Global datastore.
        :param cache_parameter_group_name: The name of the cache parameter group to use with the Global datastore. It must be compatible with the major engine version used by the Global datastore.
        :param engine_version: The Elasticache Redis engine version.
        :param global_node_group_count: The number of node groups that comprise the Global Datastore.
        :param global_replication_group_description: The optional description of the Global datastore.
        :param global_replication_group_id_suffix: The suffix name of a Global Datastore. The suffix guarantees uniqueness of the Global Datastore name across multiple regions.
        :param regional_configurations: The Amazon Regions that comprise the Global Datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_global_replication_group_props = elasticache.CfnGlobalReplicationGroupProps(
                members=[elasticache.CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty(
                    replication_group_id="replicationGroupId",
                    replication_group_region="replicationGroupRegion",
                    role="role"
                )],
            
                # the properties below are optional
                automatic_failover_enabled=False,
                cache_node_type="cacheNodeType",
                cache_parameter_group_name="cacheParameterGroupName",
                engine_version="engineVersion",
                global_node_group_count=123,
                global_replication_group_description="globalReplicationGroupDescription",
                global_replication_group_id_suffix="globalReplicationGroupIdSuffix",
                regional_configurations=[elasticache.CfnGlobalReplicationGroup.RegionalConfigurationProperty(
                    replication_group_id="replicationGroupId",
                    replication_group_region="replicationGroupRegion",
                    resharding_configurations=[elasticache.CfnGlobalReplicationGroup.ReshardingConfigurationProperty(
                        node_group_id="nodeGroupId",
                        preferred_availability_zones=["preferredAvailabilityZones"]
                    )]
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "members": members,
        }
        if automatic_failover_enabled is not None:
            self._values["automatic_failover_enabled"] = automatic_failover_enabled
        if cache_node_type is not None:
            self._values["cache_node_type"] = cache_node_type
        if cache_parameter_group_name is not None:
            self._values["cache_parameter_group_name"] = cache_parameter_group_name
        if engine_version is not None:
            self._values["engine_version"] = engine_version
        if global_node_group_count is not None:
            self._values["global_node_group_count"] = global_node_group_count
        if global_replication_group_description is not None:
            self._values["global_replication_group_description"] = global_replication_group_description
        if global_replication_group_id_suffix is not None:
            self._values["global_replication_group_id_suffix"] = global_replication_group_id_suffix
        if regional_configurations is not None:
            self._values["regional_configurations"] = regional_configurations

    @builtins.property
    def members(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty, _IResolvable_da3f097b]]]:
        '''The replication groups that comprise the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-members
        '''
        result = self._values.get("members")
        assert result is not None, "Required property 'members' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnGlobalReplicationGroup.GlobalReplicationGroupMemberProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def automatic_failover_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether a read-only replica is automatically promoted to read/write primary if the existing primary fails.

        ``AutomaticFailoverEnabled`` must be enabled for Redis (cluster mode enabled) replication groups.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-automaticfailoverenabled
        '''
        result = self._values.get("automatic_failover_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def cache_node_type(self) -> typing.Optional[builtins.str]:
        '''The cache node type of the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-cachenodetype
        '''
        result = self._values.get("cache_node_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cache_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the cache parameter group to use with the Global datastore.

        It must be compatible with the major engine version used by the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-cacheparametergroupname
        '''
        result = self._values.get("cache_parameter_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The Elasticache Redis engine version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-engineversion
        '''
        result = self._values.get("engine_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def global_node_group_count(self) -> typing.Optional[jsii.Number]:
        '''The number of node groups that comprise the Global Datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-globalnodegroupcount
        '''
        result = self._values.get("global_node_group_count")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def global_replication_group_description(self) -> typing.Optional[builtins.str]:
        '''The optional description of the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-globalreplicationgroupdescription
        '''
        result = self._values.get("global_replication_group_description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def global_replication_group_id_suffix(self) -> typing.Optional[builtins.str]:
        '''The suffix name of a Global Datastore.

        The suffix guarantees uniqueness of the Global Datastore name across multiple regions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-globalreplicationgroupidsuffix
        '''
        result = self._values.get("global_replication_group_id_suffix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def regional_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnGlobalReplicationGroup.RegionalConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''The Amazon Regions that comprise the Global Datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-globalreplicationgroup.html#cfn-elasticache-globalreplicationgroup-regionalconfigurations
        '''
        result = self._values.get("regional_configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnGlobalReplicationGroup.RegionalConfigurationProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnGlobalReplicationGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnParameterGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnParameterGroup",
):
    '''A CloudFormation ``AWS::ElastiCache::ParameterGroup``.

    The ``AWS::ElastiCache::ParameterGroup`` type creates a new cache parameter group. Cache parameter groups control the parameters for a cache cluster.

    :cloudformationResource: AWS::ElastiCache::ParameterGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_parameter_group = elasticache.CfnParameterGroup(self, "MyCfnParameterGroup",
            cache_parameter_group_family="cacheParameterGroupFamily",
            description="description",
        
            # the properties below are optional
            properties={
                "properties_key": "properties"
            },
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
        cache_parameter_group_family: builtins.str,
        description: builtins.str,
        properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::ParameterGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param cache_parameter_group_family: The name of the cache parameter group family that this cache parameter group is compatible with. Valid values are: ``memcached1.4`` | ``memcached1.5`` | ``memcached1.6`` | ``redis2.6`` | ``redis2.8`` | ``redis3.2`` | ``redis4.0`` | ``redis5.0`` | ``redis6.x``
        :param description: The description for this cache parameter group.
        :param properties: A comma-delimited list of parameter name/value pairs. For more information, see `ModifyCacheParameterGroup <https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ModifyCacheParameterGroup.html>`_ in the *Amazon ElastiCache API Reference Guide* . For example:: "Properties" : { "cas_disabled" : "1", "chunk_size_growth_factor" : "1.02" }
        :param tags: A tag that can be added to an ElastiCache parameter group. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your parameter groups. A tag with a null Value is permitted.
        '''
        props = CfnParameterGroupProps(
            cache_parameter_group_family=cache_parameter_group_family,
            description=description,
            properties=properties,
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
        '''A tag that can be added to an ElastiCache parameter group.

        Tags are composed of a Key/Value pair. You can use tags to categorize and track all your parameter groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html#cfn-elasticache-parametergroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheParameterGroupFamily")
    def cache_parameter_group_family(self) -> builtins.str:
        '''The name of the cache parameter group family that this cache parameter group is compatible with.

        Valid values are: ``memcached1.4`` | ``memcached1.5`` | ``memcached1.6`` | ``redis2.6`` | ``redis2.8`` | ``redis3.2`` | ``redis4.0`` | ``redis5.0`` | ``redis6.x``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html#cfn-elasticache-parametergroup-cacheparametergroupfamily
        '''
        return typing.cast(builtins.str, jsii.get(self, "cacheParameterGroupFamily"))

    @cache_parameter_group_family.setter
    def cache_parameter_group_family(self, value: builtins.str) -> None:
        jsii.set(self, "cacheParameterGroupFamily", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> builtins.str:
        '''The description for this cache parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html#cfn-elasticache-parametergroup-description
        '''
        return typing.cast(builtins.str, jsii.get(self, "description"))

    @description.setter
    def description(self, value: builtins.str) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="properties")
    def properties(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''A comma-delimited list of parameter name/value pairs.

        For more information, see `ModifyCacheParameterGroup <https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ModifyCacheParameterGroup.html>`_ in the *Amazon ElastiCache API Reference Guide* .

        For example::

           "Properties" : { "cas_disabled" : "1", "chunk_size_growth_factor" : "1.02"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html#cfn-elasticache-parametergroup-properties
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], jsii.get(self, "properties"))

    @properties.setter
    def properties(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]],
    ) -> None:
        jsii.set(self, "properties", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnParameterGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "cache_parameter_group_family": "cacheParameterGroupFamily",
        "description": "description",
        "properties": "properties",
        "tags": "tags",
    },
)
class CfnParameterGroupProps:
    def __init__(
        self,
        *,
        cache_parameter_group_family: builtins.str,
        description: builtins.str,
        properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnParameterGroup``.

        :param cache_parameter_group_family: The name of the cache parameter group family that this cache parameter group is compatible with. Valid values are: ``memcached1.4`` | ``memcached1.5`` | ``memcached1.6`` | ``redis2.6`` | ``redis2.8`` | ``redis3.2`` | ``redis4.0`` | ``redis5.0`` | ``redis6.x``
        :param description: The description for this cache parameter group.
        :param properties: A comma-delimited list of parameter name/value pairs. For more information, see `ModifyCacheParameterGroup <https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ModifyCacheParameterGroup.html>`_ in the *Amazon ElastiCache API Reference Guide* . For example:: "Properties" : { "cas_disabled" : "1", "chunk_size_growth_factor" : "1.02" }
        :param tags: A tag that can be added to an ElastiCache parameter group. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your parameter groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_parameter_group_props = elasticache.CfnParameterGroupProps(
                cache_parameter_group_family="cacheParameterGroupFamily",
                description="description",
            
                # the properties below are optional
                properties={
                    "properties_key": "properties"
                },
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cache_parameter_group_family": cache_parameter_group_family,
            "description": description,
        }
        if properties is not None:
            self._values["properties"] = properties
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def cache_parameter_group_family(self) -> builtins.str:
        '''The name of the cache parameter group family that this cache parameter group is compatible with.

        Valid values are: ``memcached1.4`` | ``memcached1.5`` | ``memcached1.6`` | ``redis2.6`` | ``redis2.8`` | ``redis3.2`` | ``redis4.0`` | ``redis5.0`` | ``redis6.x``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html#cfn-elasticache-parametergroup-cacheparametergroupfamily
        '''
        result = self._values.get("cache_parameter_group_family")
        assert result is not None, "Required property 'cache_parameter_group_family' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> builtins.str:
        '''The description for this cache parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html#cfn-elasticache-parametergroup-description
        '''
        result = self._values.get("description")
        assert result is not None, "Required property 'description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def properties(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''A comma-delimited list of parameter name/value pairs.

        For more information, see `ModifyCacheParameterGroup <https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ModifyCacheParameterGroup.html>`_ in the *Amazon ElastiCache API Reference Guide* .

        For example::

           "Properties" : { "cas_disabled" : "1", "chunk_size_growth_factor" : "1.02"
           }

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html#cfn-elasticache-parametergroup-properties
        '''
        result = self._values.get("properties")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A tag that can be added to an ElastiCache parameter group.

        Tags are composed of a Key/Value pair. You can use tags to categorize and track all your parameter groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-parameter-group.html#cfn-elasticache-parametergroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnParameterGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnReplicationGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnReplicationGroup",
):
    '''A CloudFormation ``AWS::ElastiCache::ReplicationGroup``.

    The ``AWS::ElastiCache::ReplicationGroup`` resource creates an Amazon ElastiCache Redis replication group. A Redis (cluster mode disabled) replication group is a collection of cache clusters, where one of the clusters is a primary read-write cluster and the others are read-only replicas.

    A Redis (cluster mode enabled) cluster is comprised of from 1 to 90 shards (API/CLI: node groups). Each shard has a primary node and up to 5 read-only replica nodes. The configuration can range from 90 shards and 0 replicas to 15 shards and 5 replicas, which is the maximum number or replicas allowed.

    The node or shard limit can be increased to a maximum of 500 per cluster if the Redis engine version is 5.0.6 or higher. For example, you can choose to configure a 500 node cluster that ranges between 83 shards (one primary and 5 replicas per shard) and 500 shards (single primary and no replicas). Make sure there are enough available IP addresses to accommodate the increase. Common pitfalls include the subnets in the subnet group have too small a CIDR range or the subnets are shared and heavily used by other clusters. For more information, see `Creating a Subnet Group <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SubnetGroups.Creating.html>`_ . For versions below 5.0.6, the limit is 250 per cluster.

    To request a limit increase, see `Amazon Service Limits <https://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html>`_ and choose the limit type *Nodes per cluster per instance type* .

    :cloudformationResource: AWS::ElastiCache::ReplicationGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_replication_group = elasticache.CfnReplicationGroup(self, "MyCfnReplicationGroup",
            replication_group_description="replicationGroupDescription",
        
            # the properties below are optional
            at_rest_encryption_enabled=False,
            auth_token="authToken",
            automatic_failover_enabled=False,
            auto_minor_version_upgrade=False,
            cache_node_type="cacheNodeType",
            cache_parameter_group_name="cacheParameterGroupName",
            cache_security_group_names=["cacheSecurityGroupNames"],
            cache_subnet_group_name="cacheSubnetGroupName",
            data_tiering_enabled=False,
            engine="engine",
            engine_version="engineVersion",
            global_replication_group_id="globalReplicationGroupId",
            kms_key_id="kmsKeyId",
            log_delivery_configurations=[elasticache.CfnReplicationGroup.LogDeliveryConfigurationRequestProperty(
                destination_details=elasticache.CfnReplicationGroup.DestinationDetailsProperty(
                    cloud_watch_logs_details=elasticache.CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty(
                        log_group="logGroup"
                    ),
                    kinesis_firehose_details=elasticache.CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty(
                        delivery_stream="deliveryStream"
                    )
                ),
                destination_type="destinationType",
                log_format="logFormat",
                log_type="logType"
            )],
            multi_az_enabled=False,
            node_group_configuration=[elasticache.CfnReplicationGroup.NodeGroupConfigurationProperty(
                node_group_id="nodeGroupId",
                primary_availability_zone="primaryAvailabilityZone",
                replica_availability_zones=["replicaAvailabilityZones"],
                replica_count=123,
                slots="slots"
            )],
            notification_topic_arn="notificationTopicArn",
            num_cache_clusters=123,
            num_node_groups=123,
            port=123,
            preferred_cache_cluster_aZs=["preferredCacheClusterAZs"],
            preferred_maintenance_window="preferredMaintenanceWindow",
            primary_cluster_id="primaryClusterId",
            replicas_per_node_group=123,
            replication_group_id="replicationGroupId",
            security_group_ids=["securityGroupIds"],
            snapshot_arns=["snapshotArns"],
            snapshot_name="snapshotName",
            snapshot_retention_limit=123,
            snapshotting_cluster_id="snapshottingClusterId",
            snapshot_window="snapshotWindow",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            transit_encryption_enabled=False,
            user_group_ids=["userGroupIds"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        replication_group_description: builtins.str,
        at_rest_encryption_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        auth_token: typing.Optional[builtins.str] = None,
        automatic_failover_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        auto_minor_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        cache_node_type: typing.Optional[builtins.str] = None,
        cache_parameter_group_name: typing.Optional[builtins.str] = None,
        cache_security_group_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        cache_subnet_group_name: typing.Optional[builtins.str] = None,
        data_tiering_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        engine: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        global_replication_group_id: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        log_delivery_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnReplicationGroup.LogDeliveryConfigurationRequestProperty", _IResolvable_da3f097b]]]] = None,
        multi_az_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        node_group_configuration: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnReplicationGroup.NodeGroupConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        notification_topic_arn: typing.Optional[builtins.str] = None,
        num_cache_clusters: typing.Optional[jsii.Number] = None,
        num_node_groups: typing.Optional[jsii.Number] = None,
        port: typing.Optional[jsii.Number] = None,
        preferred_cache_cluster_a_zs: typing.Optional[typing.Sequence[builtins.str]] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        primary_cluster_id: typing.Optional[builtins.str] = None,
        replicas_per_node_group: typing.Optional[jsii.Number] = None,
        replication_group_id: typing.Optional[builtins.str] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        snapshot_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        snapshot_name: typing.Optional[builtins.str] = None,
        snapshot_retention_limit: typing.Optional[jsii.Number] = None,
        snapshotting_cluster_id: typing.Optional[builtins.str] = None,
        snapshot_window: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        transit_encryption_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        user_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::ReplicationGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param replication_group_description: A user-created description for the replication group.
        :param at_rest_encryption_enabled: A flag that enables encryption at rest when set to ``true`` . You cannot modify the value of ``AtRestEncryptionEnabled`` after the replication group is created. To enable encryption at rest on a replication group you must set ``AtRestEncryptionEnabled`` to ``true`` when you create the replication group. *Required:* Only available when creating a replication group in an Amazon VPC using redis version ``3.2.6`` or ``4.x`` onward. Default: ``false``
        :param auth_token: *Reserved parameter.* The password used to access a password protected server. ``AuthToken`` can be specified only on replication groups where ``TransitEncryptionEnabled`` is ``true`` . For more information, see `Authenticating Users with the Redis AUTH Command <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html>`_ . .. epigraph:: For HIPAA compliance, you must specify ``TransitEncryptionEnabled`` as ``true`` , an ``AuthToken`` , and a ``CacheSubnetGroup`` . Password constraints: - Must be only printable ASCII characters. - Must be at least 16 characters and no more than 128 characters in length. - Cannot contain any of the following characters: '/', '"', or '@'. For more information, see `AUTH password <https://docs.aws.amazon.com/http://redis.io/commands/AUTH>`_ at http://redis.io/commands/AUTH.
        :param automatic_failover_enabled: Specifies whether a read-only replica is automatically promoted to read/write primary if the existing primary fails. ``AutomaticFailoverEnabled`` must be enabled for Redis (cluster mode enabled) replication groups. Default: false
        :param auto_minor_version_upgrade: If you are running Redis engine version 6.0 or later, set this parameter to yes if you want to opt-in to the next minor version upgrade campaign. This parameter is disabled for previous versions.
        :param cache_node_type: The compute and memory capacity of the nodes in the node group (shard). The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts. - General purpose: - Current generation: *M6g node types:* ``cache.m6g.large`` , ``cache.m6g.xlarge`` , ``cache.m6g.2xlarge`` , ``cache.m6g.4xlarge`` , ``cache.m6g.12xlarge`` , ``cache.m6g.24xlarge`` *M5 node types:* ``cache.m5.large`` , ``cache.m5.xlarge`` , ``cache.m5.2xlarge`` , ``cache.m5.4xlarge`` , ``cache.m5.12xlarge`` , ``cache.m5.24xlarge`` *M4 node types:* ``cache.m4.large`` , ``cache.m4.xlarge`` , ``cache.m4.2xlarge`` , ``cache.m4.4xlarge`` , ``cache.m4.10xlarge`` *T4g node types:* ``cache.t4g.micro`` , ``cache.t4g.small`` , ``cache.t4g.medium`` *T3 node types:* ``cache.t3.micro`` , ``cache.t3.small`` , ``cache.t3.medium`` *T2 node types:* ``cache.t2.micro`` , ``cache.t2.small`` , ``cache.t2.medium`` - Previous generation: (not recommended) *T1 node types:* ``cache.t1.micro`` *M1 node types:* ``cache.m1.small`` , ``cache.m1.medium`` , ``cache.m1.large`` , ``cache.m1.xlarge`` *M3 node types:* ``cache.m3.medium`` , ``cache.m3.large`` , ``cache.m3.xlarge`` , ``cache.m3.2xlarge`` - Compute optimized: - Previous generation: (not recommended) *C1 node types:* ``cache.c1.xlarge`` - Memory optimized: - Current generation: *R6gd node types:* ``cache.r6gd.xlarge`` , ``cache.r6gd.2xlarge`` , ``cache.r6gd.4xlarge`` , ``cache.r6gd.8xlarge`` , ``cache.r6gd.12xlarge`` , ``cache.r6gd.16xlarge`` .. epigraph:: The ``r6gd`` family is available in the following regions: ``us-east-2`` , ``us-east-1`` , ``us-west-2`` , ``us-west-1`` , ``eu-west-1`` , ``eu-central-1`` , ``ap-northeast-1`` , ``ap-southeast-1`` , ``ap-southeast-2`` . *R6g node types:* ``cache.r6g.large`` , ``cache.r6g.xlarge`` , ``cache.r6g.2xlarge`` , ``cache.r6g.4xlarge`` , ``cache.r6g.12xlarge`` , ``cache.r6g.24xlarge`` *R5 node types:* ``cache.r5.large`` , ``cache.r5.xlarge`` , ``cache.r5.2xlarge`` , ``cache.r5.4xlarge`` , ``cache.r5.12xlarge`` , ``cache.r5.24xlarge`` *R4 node types:* ``cache.r4.large`` , ``cache.r4.xlarge`` , ``cache.r4.2xlarge`` , ``cache.r4.4xlarge`` , ``cache.r4.8xlarge`` , ``cache.r4.16xlarge`` - Previous generation: (not recommended) *M2 node types:* ``cache.m2.xlarge`` , ``cache.m2.2xlarge`` , ``cache.m2.4xlarge`` *R3 node types:* ``cache.r3.large`` , ``cache.r3.xlarge`` , ``cache.r3.2xlarge`` , ``cache.r3.4xlarge`` , ``cache.r3.8xlarge`` For region availability, see `Supported Node Types by Amazon Region <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion>`_
        :param cache_parameter_group_name: The name of the parameter group to associate with this replication group. If this argument is omitted, the default cache parameter group for the specified engine is used. If you are running Redis version 3.2.4 or later, only one node group (shard), and want to use a default parameter group, we recommend that you specify the parameter group by name. - To create a Redis (cluster mode disabled) replication group, use ``CacheParameterGroupName=default.redis3.2`` . - To create a Redis (cluster mode enabled) replication group, use ``CacheParameterGroupName=default.redis3.2.cluster.on`` .
        :param cache_security_group_names: A list of cache security group names to associate with this replication group.
        :param cache_subnet_group_name: The name of the cache subnet group to be used for the replication group. .. epigraph:: If you're going to launch your cluster in an Amazon VPC, you need to create a subnet group before you start creating a cluster. For more information, see `AWS::ElastiCache::SubnetGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html>`_ .
        :param data_tiering_enabled: Enables data tiering. Data tiering is only supported for replication groups using the r6gd node type. This parameter must be set to true when using r6gd nodes. For more information, see `Data tiering <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/data-tiering.html>`_ .
        :param engine: The name of the cache engine to be used for the clusters in this replication group. Must be Redis.
        :param engine_version: The version number of the cache engine to be used for the clusters in this replication group. To view the supported cache engine versions, use the ``DescribeCacheEngineVersions`` operation. *Important:* You can upgrade to a newer engine version (see `Selecting a Cache Engine and Version <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SelectEngine.html#VersionManagement>`_ ) in the *ElastiCache User Guide* , but you cannot downgrade to an earlier engine version. If you want to use an earlier engine version, you must delete the existing cluster or replication group and create it anew with the earlier engine version.
        :param global_replication_group_id: The name of the Global datastore.
        :param kms_key_id: The ID of the KMS key used to encrypt the disk on the cluster.
        :param log_delivery_configurations: Specifies the destination, format and type of the logs.
        :param multi_az_enabled: A flag indicating if you have Multi-AZ enabled to enhance fault tolerance. For more information, see `Minimizing Downtime: Multi-AZ <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html>`_ .
        :param node_group_configuration: ``NodeGroupConfiguration`` is a property of the ``AWS::ElastiCache::ReplicationGroup`` resource that configures an Amazon ElastiCache (ElastiCache) Redis cluster node group. If you set `UseOnlineResharding <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ to ``true`` , you can update ``NodeGroupConfiguration`` without interruption. When ``UseOnlineResharding`` is set to ``false`` , or is not specified, updating ``NodeGroupConfiguration`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .
        :param notification_topic_arn: The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent. .. epigraph:: The Amazon SNS topic owner must be the same as the cluster owner.
        :param num_cache_clusters: The number of clusters this replication group initially has. This parameter is not used if there is more than one node group (shard). You should use ``ReplicasPerNodeGroup`` instead. If ``AutomaticFailoverEnabled`` is ``true`` , the value of this parameter must be at least 2. If ``AutomaticFailoverEnabled`` is ``false`` you can omit this parameter (it will default to 1), or you can explicitly set it to a value between 2 and 6. The maximum permitted value for ``NumCacheClusters`` is 6 (1 primary plus 5 replicas).
        :param num_node_groups: An optional parameter that specifies the number of node groups (shards) for this Redis (cluster mode enabled) replication group. For Redis (cluster mode disabled) either omit this parameter or set it to 1. If you set `UseOnlineResharding <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ to ``true`` , you can update ``NumNodeGroups`` without interruption. When ``UseOnlineResharding`` is set to ``false`` , or is not specified, updating ``NumNodeGroups`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ . Default: 1
        :param port: The port number on which each member of the replication group accepts connections.
        :param preferred_cache_cluster_a_zs: A list of EC2 Availability Zones in which the replication group's clusters are created. The order of the Availability Zones in the list is the order in which clusters are allocated. The primary cluster is created in the first AZ in the list. This parameter is not used if there is more than one node group (shard). You should use ``NodeGroupConfiguration`` instead. .. epigraph:: If you are creating your replication group in an Amazon VPC (recommended), you can only locate clusters in Availability Zones associated with the subnets in the selected subnet group. The number of Availability Zones listed must equal the value of ``NumCacheClusters`` . Default: system chosen Availability Zones.
        :param preferred_maintenance_window: Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for ``ddd`` are: - ``sun`` - ``mon`` - ``tue`` - ``wed`` - ``thu`` - ``fri`` - ``sat`` Example: ``sun:23:00-mon:01:30``
        :param primary_cluster_id: The identifier of the cluster that serves as the primary for this replication group. This cluster must already exist and have a status of ``available`` . This parameter is not required if ``NumCacheClusters`` , ``NumNodeGroups`` , or ``ReplicasPerNodeGroup`` is specified.
        :param replicas_per_node_group: An optional parameter that specifies the number of replica nodes in each node group (shard). Valid values are 0 to 5.
        :param replication_group_id: The replication group identifier. This parameter is stored as a lowercase string. Constraints: - A name must contain from 1 to 40 alphanumeric characters or hyphens. - The first character must be a letter. - A name cannot end with a hyphen or contain two consecutive hyphens.
        :param security_group_ids: One or more Amazon VPC security groups associated with this replication group. Use this parameter only when you are creating a replication group in an Amazon Virtual Private Cloud (Amazon VPC).
        :param snapshot_arns: A list of Amazon Resource Names (ARN) that uniquely identify the Redis RDB snapshot files stored in Amazon S3. The snapshot files are used to populate the new replication group. The Amazon S3 object name in the ARN cannot contain any commas. The new replication group will have the number of node groups (console: shards) specified by the parameter *NumNodeGroups* or the number of node groups configured by *NodeGroupConfiguration* regardless of the number of ARNs specified here. Example of an Amazon S3 ARN: ``arn:aws:s3:::my_bucket/snapshot1.rdb``
        :param snapshot_name: The name of a snapshot from which to restore data into the new replication group. The snapshot status changes to ``restoring`` while the new replication group is being created.
        :param snapshot_retention_limit: The number of days for which ElastiCache retains automatic snapshots before deleting them. For example, if you set ``SnapshotRetentionLimit`` to 5, a snapshot that was taken today is retained for 5 days before being deleted. Default: 0 (i.e., automatic backups are disabled for this cluster).
        :param snapshotting_cluster_id: The cluster ID that is used as the daily snapshot source for the replication group. This parameter cannot be set for Redis (cluster mode enabled) replication groups.
        :param snapshot_window: The daily time range (in UTC) during which ElastiCache begins taking a daily snapshot of your node group (shard). Example: ``05:00-09:00`` If you do not specify this parameter, ElastiCache automatically chooses an appropriate time range.
        :param tags: A list of tags to be added to this resource. Tags are comma-separated key,value pairs (e.g. Key= ``myKey`` , Value= ``myKeyValue`` . You can include multiple tags as shown following: Key= ``myKey`` , Value= ``myKeyValue`` Key= ``mySecondKey`` , Value= ``mySecondKeyValue`` . Tags on replication groups will be replicated to all nodes.
        :param transit_encryption_enabled: A flag that enables in-transit encryption when set to ``true`` . You cannot modify the value of ``TransitEncryptionEnabled`` after the cluster is created. To enable in-transit encryption on a cluster you must set ``TransitEncryptionEnabled`` to ``true`` when you create a cluster. This parameter is valid only if the ``Engine`` parameter is ``redis`` , the ``EngineVersion`` parameter is ``3.2.6`` or ``4.x`` onward, and the cluster is being created in an Amazon VPC. If you enable in-transit encryption, you must also specify a value for ``CacheSubnetGroup`` . *Required:* Only available when creating a replication group in an Amazon VPC using redis version ``3.2.6`` or ``4.x`` onward. Default: ``false`` .. epigraph:: For HIPAA compliance, you must specify ``TransitEncryptionEnabled`` as ``true`` , an ``AuthToken`` , and a ``CacheSubnetGroup`` .
        :param user_group_ids: The list of user groups to associate with the replication group.
        '''
        props = CfnReplicationGroupProps(
            replication_group_description=replication_group_description,
            at_rest_encryption_enabled=at_rest_encryption_enabled,
            auth_token=auth_token,
            automatic_failover_enabled=automatic_failover_enabled,
            auto_minor_version_upgrade=auto_minor_version_upgrade,
            cache_node_type=cache_node_type,
            cache_parameter_group_name=cache_parameter_group_name,
            cache_security_group_names=cache_security_group_names,
            cache_subnet_group_name=cache_subnet_group_name,
            data_tiering_enabled=data_tiering_enabled,
            engine=engine,
            engine_version=engine_version,
            global_replication_group_id=global_replication_group_id,
            kms_key_id=kms_key_id,
            log_delivery_configurations=log_delivery_configurations,
            multi_az_enabled=multi_az_enabled,
            node_group_configuration=node_group_configuration,
            notification_topic_arn=notification_topic_arn,
            num_cache_clusters=num_cache_clusters,
            num_node_groups=num_node_groups,
            port=port,
            preferred_cache_cluster_a_zs=preferred_cache_cluster_a_zs,
            preferred_maintenance_window=preferred_maintenance_window,
            primary_cluster_id=primary_cluster_id,
            replicas_per_node_group=replicas_per_node_group,
            replication_group_id=replication_group_id,
            security_group_ids=security_group_ids,
            snapshot_arns=snapshot_arns,
            snapshot_name=snapshot_name,
            snapshot_retention_limit=snapshot_retention_limit,
            snapshotting_cluster_id=snapshotting_cluster_id,
            snapshot_window=snapshot_window,
            tags=tags,
            transit_encryption_enabled=transit_encryption_enabled,
            user_group_ids=user_group_ids,
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
    @jsii.member(jsii_name="attrConfigurationEndPointAddress")
    def attr_configuration_end_point_address(self) -> builtins.str:
        '''The DNS hostname of the cache node.

        .. epigraph::

           Redis (cluster mode disabled) replication groups don't have this attribute. Therefore, ``Fn::GetAtt`` returns a value for this attribute only if the replication group is clustered. Otherwise, ``Fn::GetAtt`` fails. For Redis (cluster mode disabled) replication groups, use the ``PrimaryEndpoint`` or ``ReadEndpoint`` attributes.

        :cloudformationAttribute: ConfigurationEndPoint.Address
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrConfigurationEndPointAddress"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrConfigurationEndPointPort")
    def attr_configuration_end_point_port(self) -> builtins.str:
        '''The port number that the cache engine is listening on.

        :cloudformationAttribute: ConfigurationEndPoint.Port
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrConfigurationEndPointPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPrimaryEndPointAddress")
    def attr_primary_end_point_address(self) -> builtins.str:
        '''The DNS address of the primary read-write cache node.

        :cloudformationAttribute: PrimaryEndPoint.Address
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPrimaryEndPointAddress"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPrimaryEndPointPort")
    def attr_primary_end_point_port(self) -> builtins.str:
        '''The number of the port that the primary read-write cache engine is listening on.

        :cloudformationAttribute: PrimaryEndPoint.Port
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPrimaryEndPointPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReadEndPointAddresses")
    def attr_read_end_point_addresses(self) -> builtins.str:
        '''A string with a list of endpoints for the primary and read-only replicas.

        The order of the addresses maps to the order of the ports from the ``ReadEndPoint.Ports`` attribute.

        :cloudformationAttribute: ReadEndPoint.Addresses
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrReadEndPointAddresses"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReadEndPointAddressesList")
    def attr_read_end_point_addresses_list(self) -> typing.List[builtins.str]:
        '''A string with a list of endpoints for the read-only replicas.

        The order of the addresses maps to the order of the ports from the ``ReadEndPoint.Ports`` attribute.

        :cloudformationAttribute: ReadEndPoint.Addresses.List
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrReadEndPointAddressesList"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReadEndPointPorts")
    def attr_read_end_point_ports(self) -> builtins.str:
        '''A string with a list of ports for the read-only replicas.

        The order of the ports maps to the order of the addresses from the ``ReadEndPoint.Addresses`` attribute.

        :cloudformationAttribute: ReadEndPoint.Ports
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrReadEndPointPorts"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReadEndPointPortsList")
    def attr_read_end_point_ports_list(self) -> typing.List[builtins.str]:
        '''A string with a list of ports for the read-only replicas.

        The order of the ports maps to the order of the addresses from the ReadEndPoint.Addresses attribute.

        :cloudformationAttribute: ReadEndPoint.Ports.List
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrReadEndPointPortsList"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReaderEndPointAddress")
    def attr_reader_end_point_address(self) -> builtins.str:
        '''The address of the reader endpoint.

        :cloudformationAttribute: ReaderEndPoint.Address
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrReaderEndPointAddress"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReaderEndPointPort")
    def attr_reader_end_point_port(self) -> builtins.str:
        '''The port used by the reader endpoint.

        :cloudformationAttribute: ReaderEndPoint.Port
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrReaderEndPointPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A list of tags to be added to this resource.

        Tags are comma-separated key,value pairs (e.g. Key= ``myKey`` , Value= ``myKeyValue`` . You can include multiple tags as shown following: Key= ``myKey`` , Value= ``myKeyValue`` Key= ``mySecondKey`` , Value= ``mySecondKeyValue`` . Tags on replication groups will be replicated to all nodes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationGroupDescription")
    def replication_group_description(self) -> builtins.str:
        '''A user-created description for the replication group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-replicationgroupdescription
        '''
        return typing.cast(builtins.str, jsii.get(self, "replicationGroupDescription"))

    @replication_group_description.setter
    def replication_group_description(self, value: builtins.str) -> None:
        jsii.set(self, "replicationGroupDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="atRestEncryptionEnabled")
    def at_rest_encryption_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''A flag that enables encryption at rest when set to ``true`` .

        You cannot modify the value of ``AtRestEncryptionEnabled`` after the replication group is created. To enable encryption at rest on a replication group you must set ``AtRestEncryptionEnabled`` to ``true`` when you create the replication group.

        *Required:* Only available when creating a replication group in an Amazon VPC using redis version ``3.2.6`` or ``4.x`` onward.

        Default: ``false``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-atrestencryptionenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "atRestEncryptionEnabled"))

    @at_rest_encryption_enabled.setter
    def at_rest_encryption_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "atRestEncryptionEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="authToken")
    def auth_token(self) -> typing.Optional[builtins.str]:
        '''*Reserved parameter.* The password used to access a password protected server.

        ``AuthToken`` can be specified only on replication groups where ``TransitEncryptionEnabled`` is ``true`` . For more information, see `Authenticating Users with the Redis AUTH Command <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html>`_ .
        .. epigraph::

           For HIPAA compliance, you must specify ``TransitEncryptionEnabled`` as ``true`` , an ``AuthToken`` , and a ``CacheSubnetGroup`` .

        Password constraints:

        - Must be only printable ASCII characters.
        - Must be at least 16 characters and no more than 128 characters in length.
        - Cannot contain any of the following characters: '/', '"', or '@'.

        For more information, see `AUTH password <https://docs.aws.amazon.com/http://redis.io/commands/AUTH>`_ at http://redis.io/commands/AUTH.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-authtoken
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "authToken"))

    @auth_token.setter
    def auth_token(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "authToken", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="automaticFailoverEnabled")
    def automatic_failover_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether a read-only replica is automatically promoted to read/write primary if the existing primary fails.

        ``AutomaticFailoverEnabled`` must be enabled for Redis (cluster mode enabled) replication groups.

        Default: false

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-automaticfailoverenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "automaticFailoverEnabled"))

    @automatic_failover_enabled.setter
    def automatic_failover_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "automaticFailoverEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoMinorVersionUpgrade")
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If you are running Redis engine version 6.0 or later, set this parameter to yes if you want to opt-in to the next minor version upgrade campaign. This parameter is disabled for previous versions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-autominorversionupgrade
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "autoMinorVersionUpgrade"))

    @auto_minor_version_upgrade.setter
    def auto_minor_version_upgrade(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "autoMinorVersionUpgrade", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheNodeType")
    def cache_node_type(self) -> typing.Optional[builtins.str]:
        '''The compute and memory capacity of the nodes in the node group (shard).

        The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts.

        - General purpose:
        - Current generation:

        *M6g node types:* ``cache.m6g.large`` , ``cache.m6g.xlarge`` , ``cache.m6g.2xlarge`` , ``cache.m6g.4xlarge`` , ``cache.m6g.12xlarge`` , ``cache.m6g.24xlarge``

        *M5 node types:* ``cache.m5.large`` , ``cache.m5.xlarge`` , ``cache.m5.2xlarge`` , ``cache.m5.4xlarge`` , ``cache.m5.12xlarge`` , ``cache.m5.24xlarge``

        *M4 node types:* ``cache.m4.large`` , ``cache.m4.xlarge`` , ``cache.m4.2xlarge`` , ``cache.m4.4xlarge`` , ``cache.m4.10xlarge``

        *T4g node types:* ``cache.t4g.micro`` , ``cache.t4g.small`` , ``cache.t4g.medium``

        *T3 node types:* ``cache.t3.micro`` , ``cache.t3.small`` , ``cache.t3.medium``

        *T2 node types:* ``cache.t2.micro`` , ``cache.t2.small`` , ``cache.t2.medium``

        - Previous generation: (not recommended)

        *T1 node types:* ``cache.t1.micro``

        *M1 node types:* ``cache.m1.small`` , ``cache.m1.medium`` , ``cache.m1.large`` , ``cache.m1.xlarge``

        *M3 node types:* ``cache.m3.medium`` , ``cache.m3.large`` , ``cache.m3.xlarge`` , ``cache.m3.2xlarge``

        - Compute optimized:
        - Previous generation: (not recommended)

        *C1 node types:* ``cache.c1.xlarge``

        - Memory optimized:
        - Current generation:

        *R6gd node types:* ``cache.r6gd.xlarge`` , ``cache.r6gd.2xlarge`` , ``cache.r6gd.4xlarge`` , ``cache.r6gd.8xlarge`` , ``cache.r6gd.12xlarge`` , ``cache.r6gd.16xlarge``
        .. epigraph::

           The ``r6gd`` family is available in the following regions: ``us-east-2`` , ``us-east-1`` , ``us-west-2`` , ``us-west-1`` , ``eu-west-1`` , ``eu-central-1`` , ``ap-northeast-1`` , ``ap-southeast-1`` , ``ap-southeast-2`` .

        *R6g node types:* ``cache.r6g.large`` , ``cache.r6g.xlarge`` , ``cache.r6g.2xlarge`` , ``cache.r6g.4xlarge`` , ``cache.r6g.12xlarge`` , ``cache.r6g.24xlarge``

        *R5 node types:* ``cache.r5.large`` , ``cache.r5.xlarge`` , ``cache.r5.2xlarge`` , ``cache.r5.4xlarge`` , ``cache.r5.12xlarge`` , ``cache.r5.24xlarge``

        *R4 node types:* ``cache.r4.large`` , ``cache.r4.xlarge`` , ``cache.r4.2xlarge`` , ``cache.r4.4xlarge`` , ``cache.r4.8xlarge`` , ``cache.r4.16xlarge``

        - Previous generation: (not recommended)

        *M2 node types:* ``cache.m2.xlarge`` , ``cache.m2.2xlarge`` , ``cache.m2.4xlarge``

        *R3 node types:* ``cache.r3.large`` , ``cache.r3.xlarge`` , ``cache.r3.2xlarge`` , ``cache.r3.4xlarge`` , ``cache.r3.8xlarge``

        For region availability, see `Supported Node Types by Amazon Region <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachenodetype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cacheNodeType"))

    @cache_node_type.setter
    def cache_node_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cacheNodeType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheParameterGroupName")
    def cache_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the parameter group to associate with this replication group.

        If this argument is omitted, the default cache parameter group for the specified engine is used.

        If you are running Redis version 3.2.4 or later, only one node group (shard), and want to use a default parameter group, we recommend that you specify the parameter group by name.

        - To create a Redis (cluster mode disabled) replication group, use ``CacheParameterGroupName=default.redis3.2`` .
        - To create a Redis (cluster mode enabled) replication group, use ``CacheParameterGroupName=default.redis3.2.cluster.on`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cacheparametergroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cacheParameterGroupName"))

    @cache_parameter_group_name.setter
    def cache_parameter_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cacheParameterGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheSecurityGroupNames")
    def cache_security_group_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of cache security group names to associate with this replication group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachesecuritygroupnames
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "cacheSecurityGroupNames"))

    @cache_security_group_names.setter
    def cache_security_group_names(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "cacheSecurityGroupNames", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheSubnetGroupName")
    def cache_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the cache subnet group to be used for the replication group.

        .. epigraph::

           If you're going to launch your cluster in an Amazon VPC, you need to create a subnet group before you start creating a cluster. For more information, see `AWS::ElastiCache::SubnetGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachesubnetgroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cacheSubnetGroupName"))

    @cache_subnet_group_name.setter
    def cache_subnet_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cacheSubnetGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataTieringEnabled")
    def data_tiering_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables data tiering.

        Data tiering is only supported for replication groups using the r6gd node type. This parameter must be set to true when using r6gd nodes. For more information, see `Data tiering <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/data-tiering.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-datatieringenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "dataTieringEnabled"))

    @data_tiering_enabled.setter
    def data_tiering_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "dataTieringEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engine")
    def engine(self) -> typing.Optional[builtins.str]:
        '''The name of the cache engine to be used for the clusters in this replication group.

        Must be Redis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-engine
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "engine"))

    @engine.setter
    def engine(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "engine", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineVersion")
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The version number of the cache engine to be used for the clusters in this replication group.

        To view the supported cache engine versions, use the ``DescribeCacheEngineVersions`` operation.

        *Important:* You can upgrade to a newer engine version (see `Selecting a Cache Engine and Version <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SelectEngine.html#VersionManagement>`_ ) in the *ElastiCache User Guide* , but you cannot downgrade to an earlier engine version. If you want to use an earlier engine version, you must delete the existing cluster or replication group and create it anew with the earlier engine version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-engineversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "engineVersion"))

    @engine_version.setter
    def engine_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "engineVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="globalReplicationGroupId")
    def global_replication_group_id(self) -> typing.Optional[builtins.str]:
        '''The name of the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-globalreplicationgroupid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "globalReplicationGroupId"))

    @global_replication_group_id.setter
    def global_replication_group_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "globalReplicationGroupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the KMS key used to encrypt the disk on the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logDeliveryConfigurations")
    def log_delivery_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationGroup.LogDeliveryConfigurationRequestProperty", _IResolvable_da3f097b]]]]:
        '''Specifies the destination, format and type of the logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-logdeliveryconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationGroup.LogDeliveryConfigurationRequestProperty", _IResolvable_da3f097b]]]], jsii.get(self, "logDeliveryConfigurations"))

    @log_delivery_configurations.setter
    def log_delivery_configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationGroup.LogDeliveryConfigurationRequestProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "logDeliveryConfigurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="multiAzEnabled")
    def multi_az_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''A flag indicating if you have Multi-AZ enabled to enhance fault tolerance.

        For more information, see `Minimizing Downtime: Multi-AZ <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-multiazenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "multiAzEnabled"))

    @multi_az_enabled.setter
    def multi_az_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "multiAzEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodeGroupConfiguration")
    def node_group_configuration(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationGroup.NodeGroupConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''``NodeGroupConfiguration`` is a property of the ``AWS::ElastiCache::ReplicationGroup`` resource that configures an Amazon ElastiCache (ElastiCache) Redis cluster node group.

        If you set `UseOnlineResharding <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ to ``true`` , you can update ``NodeGroupConfiguration`` without interruption. When ``UseOnlineResharding`` is set to ``false`` , or is not specified, updating ``NodeGroupConfiguration`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-nodegroupconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationGroup.NodeGroupConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "nodeGroupConfiguration"))

    @node_group_configuration.setter
    def node_group_configuration(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationGroup.NodeGroupConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "nodeGroupConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationTopicArn")
    def notification_topic_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent.

        .. epigraph::

           The Amazon SNS topic owner must be the same as the cluster owner.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-notificationtopicarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "notificationTopicArn"))

    @notification_topic_arn.setter
    def notification_topic_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "notificationTopicArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="numCacheClusters")
    def num_cache_clusters(self) -> typing.Optional[jsii.Number]:
        '''The number of clusters this replication group initially has.

        This parameter is not used if there is more than one node group (shard). You should use ``ReplicasPerNodeGroup`` instead.

        If ``AutomaticFailoverEnabled`` is ``true`` , the value of this parameter must be at least 2. If ``AutomaticFailoverEnabled`` is ``false`` you can omit this parameter (it will default to 1), or you can explicitly set it to a value between 2 and 6.

        The maximum permitted value for ``NumCacheClusters`` is 6 (1 primary plus 5 replicas).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-numcacheclusters
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "numCacheClusters"))

    @num_cache_clusters.setter
    def num_cache_clusters(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "numCacheClusters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="numNodeGroups")
    def num_node_groups(self) -> typing.Optional[jsii.Number]:
        '''An optional parameter that specifies the number of node groups (shards) for this Redis (cluster mode enabled) replication group.

        For Redis (cluster mode disabled) either omit this parameter or set it to 1.

        If you set `UseOnlineResharding <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ to ``true`` , you can update ``NumNodeGroups`` without interruption. When ``UseOnlineResharding`` is set to ``false`` , or is not specified, updating ``NumNodeGroups`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .

        Default: 1

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-numnodegroups
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "numNodeGroups"))

    @num_node_groups.setter
    def num_node_groups(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "numNodeGroups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="port")
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port number on which each member of the replication group accepts connections.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-port
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "port"))

    @port.setter
    def port(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "port", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredCacheClusterAZs")
    def preferred_cache_cluster_a_zs(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of EC2 Availability Zones in which the replication group's clusters are created.

        The order of the Availability Zones in the list is the order in which clusters are allocated. The primary cluster is created in the first AZ in the list.

        This parameter is not used if there is more than one node group (shard). You should use ``NodeGroupConfiguration`` instead.
        .. epigraph::

           If you are creating your replication group in an Amazon VPC (recommended), you can only locate clusters in Availability Zones associated with the subnets in the selected subnet group.

           The number of Availability Zones listed must equal the value of ``NumCacheClusters`` .

        Default: system chosen Availability Zones.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-preferredcacheclusterazs
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "preferredCacheClusterAZs"))

    @preferred_cache_cluster_a_zs.setter
    def preferred_cache_cluster_a_zs(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "preferredCacheClusterAZs", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredMaintenanceWindow")
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''Specifies the weekly time range during which maintenance on the cluster is performed.

        It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period.

        Valid values for ``ddd`` are:

        - ``sun``
        - ``mon``
        - ``tue``
        - ``wed``
        - ``thu``
        - ``fri``
        - ``sat``

        Example: ``sun:23:00-mon:01:30``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-preferredmaintenancewindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preferredMaintenanceWindow"))

    @preferred_maintenance_window.setter
    def preferred_maintenance_window(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "preferredMaintenanceWindow", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="primaryClusterId")
    def primary_cluster_id(self) -> typing.Optional[builtins.str]:
        '''The identifier of the cluster that serves as the primary for this replication group.

        This cluster must already exist and have a status of ``available`` .

        This parameter is not required if ``NumCacheClusters`` , ``NumNodeGroups`` , or ``ReplicasPerNodeGroup`` is specified.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-primaryclusterid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "primaryClusterId"))

    @primary_cluster_id.setter
    def primary_cluster_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "primaryClusterId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicasPerNodeGroup")
    def replicas_per_node_group(self) -> typing.Optional[jsii.Number]:
        '''An optional parameter that specifies the number of replica nodes in each node group (shard).

        Valid values are 0 to 5.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-replicaspernodegroup
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "replicasPerNodeGroup"))

    @replicas_per_node_group.setter
    def replicas_per_node_group(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "replicasPerNodeGroup", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationGroupId")
    def replication_group_id(self) -> typing.Optional[builtins.str]:
        '''The replication group identifier. This parameter is stored as a lowercase string.

        Constraints:

        - A name must contain from 1 to 40 alphanumeric characters or hyphens.
        - The first character must be a letter.
        - A name cannot end with a hyphen or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-replicationgroupid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "replicationGroupId"))

    @replication_group_id.setter
    def replication_group_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "replicationGroupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroupIds")
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more Amazon VPC security groups associated with this replication group.

        Use this parameter only when you are creating a replication group in an Amazon Virtual Private Cloud (Amazon VPC).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-securitygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "securityGroupIds"))

    @security_group_ids.setter
    def security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "securityGroupIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotArns")
    def snapshot_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Amazon Resource Names (ARN) that uniquely identify the Redis RDB snapshot files stored in Amazon S3.

        The snapshot files are used to populate the new replication group. The Amazon S3 object name in the ARN cannot contain any commas. The new replication group will have the number of node groups (console: shards) specified by the parameter *NumNodeGroups* or the number of node groups configured by *NodeGroupConfiguration* regardless of the number of ARNs specified here.

        Example of an Amazon S3 ARN: ``arn:aws:s3:::my_bucket/snapshot1.rdb``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshotarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "snapshotArns"))

    @snapshot_arns.setter
    def snapshot_arns(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "snapshotArns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotName")
    def snapshot_name(self) -> typing.Optional[builtins.str]:
        '''The name of a snapshot from which to restore data into the new replication group.

        The snapshot status changes to ``restoring`` while the new replication group is being created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshotname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "snapshotName"))

    @snapshot_name.setter
    def snapshot_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "snapshotName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotRetentionLimit")
    def snapshot_retention_limit(self) -> typing.Optional[jsii.Number]:
        '''The number of days for which ElastiCache retains automatic snapshots before deleting them.

        For example, if you set ``SnapshotRetentionLimit`` to 5, a snapshot that was taken today is retained for 5 days before being deleted.

        Default: 0 (i.e., automatic backups are disabled for this cluster).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshotretentionlimit
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "snapshotRetentionLimit"))

    @snapshot_retention_limit.setter
    def snapshot_retention_limit(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "snapshotRetentionLimit", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshottingClusterId")
    def snapshotting_cluster_id(self) -> typing.Optional[builtins.str]:
        '''The cluster ID that is used as the daily snapshot source for the replication group.

        This parameter cannot be set for Redis (cluster mode enabled) replication groups.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshottingclusterid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "snapshottingClusterId"))

    @snapshotting_cluster_id.setter
    def snapshotting_cluster_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "snapshottingClusterId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotWindow")
    def snapshot_window(self) -> typing.Optional[builtins.str]:
        '''The daily time range (in UTC) during which ElastiCache begins taking a daily snapshot of your node group (shard).

        Example: ``05:00-09:00``

        If you do not specify this parameter, ElastiCache automatically chooses an appropriate time range.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshotwindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "snapshotWindow"))

    @snapshot_window.setter
    def snapshot_window(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "snapshotWindow", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="transitEncryptionEnabled")
    def transit_encryption_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''A flag that enables in-transit encryption when set to ``true`` .

        You cannot modify the value of ``TransitEncryptionEnabled`` after the cluster is created. To enable in-transit encryption on a cluster you must set ``TransitEncryptionEnabled`` to ``true`` when you create a cluster.

        This parameter is valid only if the ``Engine`` parameter is ``redis`` , the ``EngineVersion`` parameter is ``3.2.6`` or ``4.x`` onward, and the cluster is being created in an Amazon VPC.

        If you enable in-transit encryption, you must also specify a value for ``CacheSubnetGroup`` .

        *Required:* Only available when creating a replication group in an Amazon VPC using redis version ``3.2.6`` or ``4.x`` onward.

        Default: ``false``
        .. epigraph::

           For HIPAA compliance, you must specify ``TransitEncryptionEnabled`` as ``true`` , an ``AuthToken`` , and a ``CacheSubnetGroup`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-transitencryptionenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "transitEncryptionEnabled"))

    @transit_encryption_enabled.setter
    def transit_encryption_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "transitEncryptionEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userGroupIds")
    def user_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of user groups to associate with the replication group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-usergroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "userGroupIds"))

    @user_group_ids.setter
    def user_group_ids(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "userGroupIds", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={"log_group": "logGroup"},
    )
    class CloudWatchLogsDestinationDetailsProperty:
        def __init__(self, *, log_group: builtins.str) -> None:
            '''The configuration details of the CloudWatch Logs destination.

            Note that this field is marked as required but only if CloudWatch Logs was chosen as the destination.

            :param log_group: The name of the CloudWatch Logs log group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-cloudwatchlogsdestinationdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                cloud_watch_logs_destination_details_property = elasticache.CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty(
                    log_group="logGroup"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "log_group": log_group,
            }

        @builtins.property
        def log_group(self) -> builtins.str:
            '''The name of the CloudWatch Logs log group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-cloudwatchlogsdestinationdetails.html#cfn-elasticache-replicationgroup-cloudwatchlogsdestinationdetails-loggroup
            '''
            result = self._values.get("log_group")
            assert result is not None, "Required property 'log_group' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CloudWatchLogsDestinationDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnReplicationGroup.DestinationDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_logs_details": "cloudWatchLogsDetails",
            "kinesis_firehose_details": "kinesisFirehoseDetails",
        },
    )
    class DestinationDetailsProperty:
        def __init__(
            self,
            *,
            cloud_watch_logs_details: typing.Optional[typing.Union["CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty", _IResolvable_da3f097b]] = None,
            kinesis_firehose_details: typing.Optional[typing.Union["CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Configuration details of either a CloudWatch Logs destination or Kinesis Data Firehose destination.

            :param cloud_watch_logs_details: The configuration details of the CloudWatch Logs destination. Note that this field is marked as required but only if CloudWatch Logs was chosen as the destination.
            :param kinesis_firehose_details: The configuration details of the Kinesis Data Firehose destination. Note that this field is marked as required but only if Kinesis Data Firehose was chosen as the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-destinationdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                destination_details_property = elasticache.CfnReplicationGroup.DestinationDetailsProperty(
                    cloud_watch_logs_details=elasticache.CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty(
                        log_group="logGroup"
                    ),
                    kinesis_firehose_details=elasticache.CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty(
                        delivery_stream="deliveryStream"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cloud_watch_logs_details is not None:
                self._values["cloud_watch_logs_details"] = cloud_watch_logs_details
            if kinesis_firehose_details is not None:
                self._values["kinesis_firehose_details"] = kinesis_firehose_details

        @builtins.property
        def cloud_watch_logs_details(
            self,
        ) -> typing.Optional[typing.Union["CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty", _IResolvable_da3f097b]]:
            '''The configuration details of the CloudWatch Logs destination.

            Note that this field is marked as required but only if CloudWatch Logs was chosen as the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-destinationdetails.html#cfn-elasticache-replicationgroup-destinationdetails-cloudwatchlogsdetails
            '''
            result = self._values.get("cloud_watch_logs_details")
            return typing.cast(typing.Optional[typing.Union["CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def kinesis_firehose_details(
            self,
        ) -> typing.Optional[typing.Union["CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty", _IResolvable_da3f097b]]:
            '''The configuration details of the Kinesis Data Firehose destination.

            Note that this field is marked as required but only if Kinesis Data Firehose was chosen as the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-destinationdetails.html#cfn-elasticache-replicationgroup-destinationdetails-kinesisfirehosedetails
            '''
            result = self._values.get("kinesis_firehose_details")
            return typing.cast(typing.Optional[typing.Union["CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DestinationDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={"delivery_stream": "deliveryStream"},
    )
    class KinesisFirehoseDestinationDetailsProperty:
        def __init__(self, *, delivery_stream: builtins.str) -> None:
            '''The configuration details of the Kinesis Data Firehose destination.

            Note that this field is marked as required but only if Kinesis Data Firehose was chosen as the destination.

            :param delivery_stream: The name of the Kinesis Data Firehose delivery stream.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-kinesisfirehosedestinationdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                kinesis_firehose_destination_details_property = elasticache.CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty(
                    delivery_stream="deliveryStream"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "delivery_stream": delivery_stream,
            }

        @builtins.property
        def delivery_stream(self) -> builtins.str:
            '''The name of the Kinesis Data Firehose delivery stream.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-kinesisfirehosedestinationdetails.html#cfn-elasticache-replicationgroup-kinesisfirehosedestinationdetails-deliverystream
            '''
            result = self._values.get("delivery_stream")
            assert result is not None, "Required property 'delivery_stream' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KinesisFirehoseDestinationDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnReplicationGroup.LogDeliveryConfigurationRequestProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_details": "destinationDetails",
            "destination_type": "destinationType",
            "log_format": "logFormat",
            "log_type": "logType",
        },
    )
    class LogDeliveryConfigurationRequestProperty:
        def __init__(
            self,
            *,
            destination_details: typing.Union["CfnReplicationGroup.DestinationDetailsProperty", _IResolvable_da3f097b],
            destination_type: builtins.str,
            log_format: builtins.str,
            log_type: builtins.str,
        ) -> None:
            '''Specifies the destination, format and type of the logs.

            :param destination_details: Configuration details of either a CloudWatch Logs destination or Kinesis Data Firehose destination.
            :param destination_type: Specify either CloudWatch Logs or Kinesis Data Firehose as the destination type. Valid values are either ``cloudwatch-logs`` or ``kinesis-firehose`` .
            :param log_format: Valid values are either ``json`` or ``text`` .
            :param log_type: Valid value is either ``slow-log`` , which refers to `slow-log <https://docs.aws.amazon.com/https://redis.io/commands/slowlog>`_ or ``engine-log`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-logdeliveryconfigurationrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                log_delivery_configuration_request_property = elasticache.CfnReplicationGroup.LogDeliveryConfigurationRequestProperty(
                    destination_details=elasticache.CfnReplicationGroup.DestinationDetailsProperty(
                        cloud_watch_logs_details=elasticache.CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty(
                            log_group="logGroup"
                        ),
                        kinesis_firehose_details=elasticache.CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty(
                            delivery_stream="deliveryStream"
                        )
                    ),
                    destination_type="destinationType",
                    log_format="logFormat",
                    log_type="logType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_details": destination_details,
                "destination_type": destination_type,
                "log_format": log_format,
                "log_type": log_type,
            }

        @builtins.property
        def destination_details(
            self,
        ) -> typing.Union["CfnReplicationGroup.DestinationDetailsProperty", _IResolvable_da3f097b]:
            '''Configuration details of either a CloudWatch Logs destination or Kinesis Data Firehose destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-logdeliveryconfigurationrequest.html#cfn-elasticache-replicationgroup-logdeliveryconfigurationrequest-destinationdetails
            '''
            result = self._values.get("destination_details")
            assert result is not None, "Required property 'destination_details' is missing"
            return typing.cast(typing.Union["CfnReplicationGroup.DestinationDetailsProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def destination_type(self) -> builtins.str:
            '''Specify either CloudWatch Logs or Kinesis Data Firehose as the destination type.

            Valid values are either ``cloudwatch-logs`` or ``kinesis-firehose`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-logdeliveryconfigurationrequest.html#cfn-elasticache-replicationgroup-logdeliveryconfigurationrequest-destinationtype
            '''
            result = self._values.get("destination_type")
            assert result is not None, "Required property 'destination_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def log_format(self) -> builtins.str:
            '''Valid values are either ``json`` or ``text`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-logdeliveryconfigurationrequest.html#cfn-elasticache-replicationgroup-logdeliveryconfigurationrequest-logformat
            '''
            result = self._values.get("log_format")
            assert result is not None, "Required property 'log_format' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def log_type(self) -> builtins.str:
            '''Valid value is either ``slow-log`` , which refers to `slow-log <https://docs.aws.amazon.com/https://redis.io/commands/slowlog>`_ or ``engine-log`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-logdeliveryconfigurationrequest.html#cfn-elasticache-replicationgroup-logdeliveryconfigurationrequest-logtype
            '''
            result = self._values.get("log_type")
            assert result is not None, "Required property 'log_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogDeliveryConfigurationRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticache.CfnReplicationGroup.NodeGroupConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "node_group_id": "nodeGroupId",
            "primary_availability_zone": "primaryAvailabilityZone",
            "replica_availability_zones": "replicaAvailabilityZones",
            "replica_count": "replicaCount",
            "slots": "slots",
        },
    )
    class NodeGroupConfigurationProperty:
        def __init__(
            self,
            *,
            node_group_id: typing.Optional[builtins.str] = None,
            primary_availability_zone: typing.Optional[builtins.str] = None,
            replica_availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
            replica_count: typing.Optional[jsii.Number] = None,
            slots: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``NodeGroupConfiguration`` is a property of the ``AWS::ElastiCache::ReplicationGroup`` resource that configures an Amazon ElastiCache (ElastiCache) Redis cluster node group.

            :param node_group_id: Either the ElastiCache for Redis supplied 4-digit id or a user supplied id for the node group these configuration values apply to.
            :param primary_availability_zone: The Availability Zone where the primary node of this node group (shard) is launched.
            :param replica_availability_zones: A list of Availability Zones to be used for the read replicas. The number of Availability Zones in this list must match the value of ``ReplicaCount`` or ``ReplicasPerNodeGroup`` if not specified.
            :param replica_count: The number of read replica nodes in this node group (shard).
            :param slots: A string of comma-separated values where the first set of values are the slot numbers (zero based), and the second set of values are the keyspaces for each slot. The following example specifies three slots (numbered 0, 1, and 2): ``0,1,2,0-4999,5000-9999,10000-16,383`` . If you don't specify a value, ElastiCache allocates keys equally among each slot. When you use an ``UseOnlineResharding`` update policy to update the number of node groups without interruption, ElastiCache evenly distributes the keyspaces between the specified number of slots. This cannot be updated later. Therefore, after updating the number of node groups in this way, you should remove the value specified for the ``Slots`` property of each ``NodeGroupConfiguration`` from the stack template, as it no longer reflects the actual values in each node group. For more information, see `UseOnlineResharding Policy <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticache as elasticache
                
                node_group_configuration_property = elasticache.CfnReplicationGroup.NodeGroupConfigurationProperty(
                    node_group_id="nodeGroupId",
                    primary_availability_zone="primaryAvailabilityZone",
                    replica_availability_zones=["replicaAvailabilityZones"],
                    replica_count=123,
                    slots="slots"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if node_group_id is not None:
                self._values["node_group_id"] = node_group_id
            if primary_availability_zone is not None:
                self._values["primary_availability_zone"] = primary_availability_zone
            if replica_availability_zones is not None:
                self._values["replica_availability_zones"] = replica_availability_zones
            if replica_count is not None:
                self._values["replica_count"] = replica_count
            if slots is not None:
                self._values["slots"] = slots

        @builtins.property
        def node_group_id(self) -> typing.Optional[builtins.str]:
            '''Either the ElastiCache for Redis supplied 4-digit id or a user supplied id for the node group these configuration values apply to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html#cfn-elasticache-replicationgroup-nodegroupconfiguration-nodegroupid
            '''
            result = self._values.get("node_group_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def primary_availability_zone(self) -> typing.Optional[builtins.str]:
            '''The Availability Zone where the primary node of this node group (shard) is launched.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html#cfn-elasticache-replicationgroup-nodegroupconfiguration-primaryavailabilityzone
            '''
            result = self._values.get("primary_availability_zone")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def replica_availability_zones(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of Availability Zones to be used for the read replicas.

            The number of Availability Zones in this list must match the value of ``ReplicaCount`` or ``ReplicasPerNodeGroup`` if not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html#cfn-elasticache-replicationgroup-nodegroupconfiguration-replicaavailabilityzones
            '''
            result = self._values.get("replica_availability_zones")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def replica_count(self) -> typing.Optional[jsii.Number]:
            '''The number of read replica nodes in this node group (shard).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html#cfn-elasticache-replicationgroup-nodegroupconfiguration-replicacount
            '''
            result = self._values.get("replica_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def slots(self) -> typing.Optional[builtins.str]:
            '''A string of comma-separated values where the first set of values are the slot numbers (zero based), and the second set of values are the keyspaces for each slot.

            The following example specifies three slots (numbered 0, 1, and 2): ``0,1,2,0-4999,5000-9999,10000-16,383`` .

            If you don't specify a value, ElastiCache allocates keys equally among each slot.

            When you use an ``UseOnlineResharding`` update policy to update the number of node groups without interruption, ElastiCache evenly distributes the keyspaces between the specified number of slots. This cannot be updated later. Therefore, after updating the number of node groups in this way, you should remove the value specified for the ``Slots`` property of each ``NodeGroupConfiguration`` from the stack template, as it no longer reflects the actual values in each node group. For more information, see `UseOnlineResharding Policy <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html#cfn-elasticache-replicationgroup-nodegroupconfiguration-slots
            '''
            result = self._values.get("slots")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NodeGroupConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnReplicationGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "replication_group_description": "replicationGroupDescription",
        "at_rest_encryption_enabled": "atRestEncryptionEnabled",
        "auth_token": "authToken",
        "automatic_failover_enabled": "automaticFailoverEnabled",
        "auto_minor_version_upgrade": "autoMinorVersionUpgrade",
        "cache_node_type": "cacheNodeType",
        "cache_parameter_group_name": "cacheParameterGroupName",
        "cache_security_group_names": "cacheSecurityGroupNames",
        "cache_subnet_group_name": "cacheSubnetGroupName",
        "data_tiering_enabled": "dataTieringEnabled",
        "engine": "engine",
        "engine_version": "engineVersion",
        "global_replication_group_id": "globalReplicationGroupId",
        "kms_key_id": "kmsKeyId",
        "log_delivery_configurations": "logDeliveryConfigurations",
        "multi_az_enabled": "multiAzEnabled",
        "node_group_configuration": "nodeGroupConfiguration",
        "notification_topic_arn": "notificationTopicArn",
        "num_cache_clusters": "numCacheClusters",
        "num_node_groups": "numNodeGroups",
        "port": "port",
        "preferred_cache_cluster_a_zs": "preferredCacheClusterAZs",
        "preferred_maintenance_window": "preferredMaintenanceWindow",
        "primary_cluster_id": "primaryClusterId",
        "replicas_per_node_group": "replicasPerNodeGroup",
        "replication_group_id": "replicationGroupId",
        "security_group_ids": "securityGroupIds",
        "snapshot_arns": "snapshotArns",
        "snapshot_name": "snapshotName",
        "snapshot_retention_limit": "snapshotRetentionLimit",
        "snapshotting_cluster_id": "snapshottingClusterId",
        "snapshot_window": "snapshotWindow",
        "tags": "tags",
        "transit_encryption_enabled": "transitEncryptionEnabled",
        "user_group_ids": "userGroupIds",
    },
)
class CfnReplicationGroupProps:
    def __init__(
        self,
        *,
        replication_group_description: builtins.str,
        at_rest_encryption_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        auth_token: typing.Optional[builtins.str] = None,
        automatic_failover_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        auto_minor_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        cache_node_type: typing.Optional[builtins.str] = None,
        cache_parameter_group_name: typing.Optional[builtins.str] = None,
        cache_security_group_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        cache_subnet_group_name: typing.Optional[builtins.str] = None,
        data_tiering_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        engine: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        global_replication_group_id: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        log_delivery_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnReplicationGroup.LogDeliveryConfigurationRequestProperty, _IResolvable_da3f097b]]]] = None,
        multi_az_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        node_group_configuration: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnReplicationGroup.NodeGroupConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        notification_topic_arn: typing.Optional[builtins.str] = None,
        num_cache_clusters: typing.Optional[jsii.Number] = None,
        num_node_groups: typing.Optional[jsii.Number] = None,
        port: typing.Optional[jsii.Number] = None,
        preferred_cache_cluster_a_zs: typing.Optional[typing.Sequence[builtins.str]] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        primary_cluster_id: typing.Optional[builtins.str] = None,
        replicas_per_node_group: typing.Optional[jsii.Number] = None,
        replication_group_id: typing.Optional[builtins.str] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        snapshot_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        snapshot_name: typing.Optional[builtins.str] = None,
        snapshot_retention_limit: typing.Optional[jsii.Number] = None,
        snapshotting_cluster_id: typing.Optional[builtins.str] = None,
        snapshot_window: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        transit_encryption_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        user_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnReplicationGroup``.

        :param replication_group_description: A user-created description for the replication group.
        :param at_rest_encryption_enabled: A flag that enables encryption at rest when set to ``true`` . You cannot modify the value of ``AtRestEncryptionEnabled`` after the replication group is created. To enable encryption at rest on a replication group you must set ``AtRestEncryptionEnabled`` to ``true`` when you create the replication group. *Required:* Only available when creating a replication group in an Amazon VPC using redis version ``3.2.6`` or ``4.x`` onward. Default: ``false``
        :param auth_token: *Reserved parameter.* The password used to access a password protected server. ``AuthToken`` can be specified only on replication groups where ``TransitEncryptionEnabled`` is ``true`` . For more information, see `Authenticating Users with the Redis AUTH Command <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html>`_ . .. epigraph:: For HIPAA compliance, you must specify ``TransitEncryptionEnabled`` as ``true`` , an ``AuthToken`` , and a ``CacheSubnetGroup`` . Password constraints: - Must be only printable ASCII characters. - Must be at least 16 characters and no more than 128 characters in length. - Cannot contain any of the following characters: '/', '"', or '@'. For more information, see `AUTH password <https://docs.aws.amazon.com/http://redis.io/commands/AUTH>`_ at http://redis.io/commands/AUTH.
        :param automatic_failover_enabled: Specifies whether a read-only replica is automatically promoted to read/write primary if the existing primary fails. ``AutomaticFailoverEnabled`` must be enabled for Redis (cluster mode enabled) replication groups. Default: false
        :param auto_minor_version_upgrade: If you are running Redis engine version 6.0 or later, set this parameter to yes if you want to opt-in to the next minor version upgrade campaign. This parameter is disabled for previous versions.
        :param cache_node_type: The compute and memory capacity of the nodes in the node group (shard). The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts. - General purpose: - Current generation: *M6g node types:* ``cache.m6g.large`` , ``cache.m6g.xlarge`` , ``cache.m6g.2xlarge`` , ``cache.m6g.4xlarge`` , ``cache.m6g.12xlarge`` , ``cache.m6g.24xlarge`` *M5 node types:* ``cache.m5.large`` , ``cache.m5.xlarge`` , ``cache.m5.2xlarge`` , ``cache.m5.4xlarge`` , ``cache.m5.12xlarge`` , ``cache.m5.24xlarge`` *M4 node types:* ``cache.m4.large`` , ``cache.m4.xlarge`` , ``cache.m4.2xlarge`` , ``cache.m4.4xlarge`` , ``cache.m4.10xlarge`` *T4g node types:* ``cache.t4g.micro`` , ``cache.t4g.small`` , ``cache.t4g.medium`` *T3 node types:* ``cache.t3.micro`` , ``cache.t3.small`` , ``cache.t3.medium`` *T2 node types:* ``cache.t2.micro`` , ``cache.t2.small`` , ``cache.t2.medium`` - Previous generation: (not recommended) *T1 node types:* ``cache.t1.micro`` *M1 node types:* ``cache.m1.small`` , ``cache.m1.medium`` , ``cache.m1.large`` , ``cache.m1.xlarge`` *M3 node types:* ``cache.m3.medium`` , ``cache.m3.large`` , ``cache.m3.xlarge`` , ``cache.m3.2xlarge`` - Compute optimized: - Previous generation: (not recommended) *C1 node types:* ``cache.c1.xlarge`` - Memory optimized: - Current generation: *R6gd node types:* ``cache.r6gd.xlarge`` , ``cache.r6gd.2xlarge`` , ``cache.r6gd.4xlarge`` , ``cache.r6gd.8xlarge`` , ``cache.r6gd.12xlarge`` , ``cache.r6gd.16xlarge`` .. epigraph:: The ``r6gd`` family is available in the following regions: ``us-east-2`` , ``us-east-1`` , ``us-west-2`` , ``us-west-1`` , ``eu-west-1`` , ``eu-central-1`` , ``ap-northeast-1`` , ``ap-southeast-1`` , ``ap-southeast-2`` . *R6g node types:* ``cache.r6g.large`` , ``cache.r6g.xlarge`` , ``cache.r6g.2xlarge`` , ``cache.r6g.4xlarge`` , ``cache.r6g.12xlarge`` , ``cache.r6g.24xlarge`` *R5 node types:* ``cache.r5.large`` , ``cache.r5.xlarge`` , ``cache.r5.2xlarge`` , ``cache.r5.4xlarge`` , ``cache.r5.12xlarge`` , ``cache.r5.24xlarge`` *R4 node types:* ``cache.r4.large`` , ``cache.r4.xlarge`` , ``cache.r4.2xlarge`` , ``cache.r4.4xlarge`` , ``cache.r4.8xlarge`` , ``cache.r4.16xlarge`` - Previous generation: (not recommended) *M2 node types:* ``cache.m2.xlarge`` , ``cache.m2.2xlarge`` , ``cache.m2.4xlarge`` *R3 node types:* ``cache.r3.large`` , ``cache.r3.xlarge`` , ``cache.r3.2xlarge`` , ``cache.r3.4xlarge`` , ``cache.r3.8xlarge`` For region availability, see `Supported Node Types by Amazon Region <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion>`_
        :param cache_parameter_group_name: The name of the parameter group to associate with this replication group. If this argument is omitted, the default cache parameter group for the specified engine is used. If you are running Redis version 3.2.4 or later, only one node group (shard), and want to use a default parameter group, we recommend that you specify the parameter group by name. - To create a Redis (cluster mode disabled) replication group, use ``CacheParameterGroupName=default.redis3.2`` . - To create a Redis (cluster mode enabled) replication group, use ``CacheParameterGroupName=default.redis3.2.cluster.on`` .
        :param cache_security_group_names: A list of cache security group names to associate with this replication group.
        :param cache_subnet_group_name: The name of the cache subnet group to be used for the replication group. .. epigraph:: If you're going to launch your cluster in an Amazon VPC, you need to create a subnet group before you start creating a cluster. For more information, see `AWS::ElastiCache::SubnetGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html>`_ .
        :param data_tiering_enabled: Enables data tiering. Data tiering is only supported for replication groups using the r6gd node type. This parameter must be set to true when using r6gd nodes. For more information, see `Data tiering <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/data-tiering.html>`_ .
        :param engine: The name of the cache engine to be used for the clusters in this replication group. Must be Redis.
        :param engine_version: The version number of the cache engine to be used for the clusters in this replication group. To view the supported cache engine versions, use the ``DescribeCacheEngineVersions`` operation. *Important:* You can upgrade to a newer engine version (see `Selecting a Cache Engine and Version <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SelectEngine.html#VersionManagement>`_ ) in the *ElastiCache User Guide* , but you cannot downgrade to an earlier engine version. If you want to use an earlier engine version, you must delete the existing cluster or replication group and create it anew with the earlier engine version.
        :param global_replication_group_id: The name of the Global datastore.
        :param kms_key_id: The ID of the KMS key used to encrypt the disk on the cluster.
        :param log_delivery_configurations: Specifies the destination, format and type of the logs.
        :param multi_az_enabled: A flag indicating if you have Multi-AZ enabled to enhance fault tolerance. For more information, see `Minimizing Downtime: Multi-AZ <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html>`_ .
        :param node_group_configuration: ``NodeGroupConfiguration`` is a property of the ``AWS::ElastiCache::ReplicationGroup`` resource that configures an Amazon ElastiCache (ElastiCache) Redis cluster node group. If you set `UseOnlineResharding <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ to ``true`` , you can update ``NodeGroupConfiguration`` without interruption. When ``UseOnlineResharding`` is set to ``false`` , or is not specified, updating ``NodeGroupConfiguration`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .
        :param notification_topic_arn: The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent. .. epigraph:: The Amazon SNS topic owner must be the same as the cluster owner.
        :param num_cache_clusters: The number of clusters this replication group initially has. This parameter is not used if there is more than one node group (shard). You should use ``ReplicasPerNodeGroup`` instead. If ``AutomaticFailoverEnabled`` is ``true`` , the value of this parameter must be at least 2. If ``AutomaticFailoverEnabled`` is ``false`` you can omit this parameter (it will default to 1), or you can explicitly set it to a value between 2 and 6. The maximum permitted value for ``NumCacheClusters`` is 6 (1 primary plus 5 replicas).
        :param num_node_groups: An optional parameter that specifies the number of node groups (shards) for this Redis (cluster mode enabled) replication group. For Redis (cluster mode disabled) either omit this parameter or set it to 1. If you set `UseOnlineResharding <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ to ``true`` , you can update ``NumNodeGroups`` without interruption. When ``UseOnlineResharding`` is set to ``false`` , or is not specified, updating ``NumNodeGroups`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ . Default: 1
        :param port: The port number on which each member of the replication group accepts connections.
        :param preferred_cache_cluster_a_zs: A list of EC2 Availability Zones in which the replication group's clusters are created. The order of the Availability Zones in the list is the order in which clusters are allocated. The primary cluster is created in the first AZ in the list. This parameter is not used if there is more than one node group (shard). You should use ``NodeGroupConfiguration`` instead. .. epigraph:: If you are creating your replication group in an Amazon VPC (recommended), you can only locate clusters in Availability Zones associated with the subnets in the selected subnet group. The number of Availability Zones listed must equal the value of ``NumCacheClusters`` . Default: system chosen Availability Zones.
        :param preferred_maintenance_window: Specifies the weekly time range during which maintenance on the cluster is performed. It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period. Valid values for ``ddd`` are: - ``sun`` - ``mon`` - ``tue`` - ``wed`` - ``thu`` - ``fri`` - ``sat`` Example: ``sun:23:00-mon:01:30``
        :param primary_cluster_id: The identifier of the cluster that serves as the primary for this replication group. This cluster must already exist and have a status of ``available`` . This parameter is not required if ``NumCacheClusters`` , ``NumNodeGroups`` , or ``ReplicasPerNodeGroup`` is specified.
        :param replicas_per_node_group: An optional parameter that specifies the number of replica nodes in each node group (shard). Valid values are 0 to 5.
        :param replication_group_id: The replication group identifier. This parameter is stored as a lowercase string. Constraints: - A name must contain from 1 to 40 alphanumeric characters or hyphens. - The first character must be a letter. - A name cannot end with a hyphen or contain two consecutive hyphens.
        :param security_group_ids: One or more Amazon VPC security groups associated with this replication group. Use this parameter only when you are creating a replication group in an Amazon Virtual Private Cloud (Amazon VPC).
        :param snapshot_arns: A list of Amazon Resource Names (ARN) that uniquely identify the Redis RDB snapshot files stored in Amazon S3. The snapshot files are used to populate the new replication group. The Amazon S3 object name in the ARN cannot contain any commas. The new replication group will have the number of node groups (console: shards) specified by the parameter *NumNodeGroups* or the number of node groups configured by *NodeGroupConfiguration* regardless of the number of ARNs specified here. Example of an Amazon S3 ARN: ``arn:aws:s3:::my_bucket/snapshot1.rdb``
        :param snapshot_name: The name of a snapshot from which to restore data into the new replication group. The snapshot status changes to ``restoring`` while the new replication group is being created.
        :param snapshot_retention_limit: The number of days for which ElastiCache retains automatic snapshots before deleting them. For example, if you set ``SnapshotRetentionLimit`` to 5, a snapshot that was taken today is retained for 5 days before being deleted. Default: 0 (i.e., automatic backups are disabled for this cluster).
        :param snapshotting_cluster_id: The cluster ID that is used as the daily snapshot source for the replication group. This parameter cannot be set for Redis (cluster mode enabled) replication groups.
        :param snapshot_window: The daily time range (in UTC) during which ElastiCache begins taking a daily snapshot of your node group (shard). Example: ``05:00-09:00`` If you do not specify this parameter, ElastiCache automatically chooses an appropriate time range.
        :param tags: A list of tags to be added to this resource. Tags are comma-separated key,value pairs (e.g. Key= ``myKey`` , Value= ``myKeyValue`` . You can include multiple tags as shown following: Key= ``myKey`` , Value= ``myKeyValue`` Key= ``mySecondKey`` , Value= ``mySecondKeyValue`` . Tags on replication groups will be replicated to all nodes.
        :param transit_encryption_enabled: A flag that enables in-transit encryption when set to ``true`` . You cannot modify the value of ``TransitEncryptionEnabled`` after the cluster is created. To enable in-transit encryption on a cluster you must set ``TransitEncryptionEnabled`` to ``true`` when you create a cluster. This parameter is valid only if the ``Engine`` parameter is ``redis`` , the ``EngineVersion`` parameter is ``3.2.6`` or ``4.x`` onward, and the cluster is being created in an Amazon VPC. If you enable in-transit encryption, you must also specify a value for ``CacheSubnetGroup`` . *Required:* Only available when creating a replication group in an Amazon VPC using redis version ``3.2.6`` or ``4.x`` onward. Default: ``false`` .. epigraph:: For HIPAA compliance, you must specify ``TransitEncryptionEnabled`` as ``true`` , an ``AuthToken`` , and a ``CacheSubnetGroup`` .
        :param user_group_ids: The list of user groups to associate with the replication group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_replication_group_props = elasticache.CfnReplicationGroupProps(
                replication_group_description="replicationGroupDescription",
            
                # the properties below are optional
                at_rest_encryption_enabled=False,
                auth_token="authToken",
                automatic_failover_enabled=False,
                auto_minor_version_upgrade=False,
                cache_node_type="cacheNodeType",
                cache_parameter_group_name="cacheParameterGroupName",
                cache_security_group_names=["cacheSecurityGroupNames"],
                cache_subnet_group_name="cacheSubnetGroupName",
                data_tiering_enabled=False,
                engine="engine",
                engine_version="engineVersion",
                global_replication_group_id="globalReplicationGroupId",
                kms_key_id="kmsKeyId",
                log_delivery_configurations=[elasticache.CfnReplicationGroup.LogDeliveryConfigurationRequestProperty(
                    destination_details=elasticache.CfnReplicationGroup.DestinationDetailsProperty(
                        cloud_watch_logs_details=elasticache.CfnReplicationGroup.CloudWatchLogsDestinationDetailsProperty(
                            log_group="logGroup"
                        ),
                        kinesis_firehose_details=elasticache.CfnReplicationGroup.KinesisFirehoseDestinationDetailsProperty(
                            delivery_stream="deliveryStream"
                        )
                    ),
                    destination_type="destinationType",
                    log_format="logFormat",
                    log_type="logType"
                )],
                multi_az_enabled=False,
                node_group_configuration=[elasticache.CfnReplicationGroup.NodeGroupConfigurationProperty(
                    node_group_id="nodeGroupId",
                    primary_availability_zone="primaryAvailabilityZone",
                    replica_availability_zones=["replicaAvailabilityZones"],
                    replica_count=123,
                    slots="slots"
                )],
                notification_topic_arn="notificationTopicArn",
                num_cache_clusters=123,
                num_node_groups=123,
                port=123,
                preferred_cache_cluster_aZs=["preferredCacheClusterAZs"],
                preferred_maintenance_window="preferredMaintenanceWindow",
                primary_cluster_id="primaryClusterId",
                replicas_per_node_group=123,
                replication_group_id="replicationGroupId",
                security_group_ids=["securityGroupIds"],
                snapshot_arns=["snapshotArns"],
                snapshot_name="snapshotName",
                snapshot_retention_limit=123,
                snapshotting_cluster_id="snapshottingClusterId",
                snapshot_window="snapshotWindow",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                transit_encryption_enabled=False,
                user_group_ids=["userGroupIds"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "replication_group_description": replication_group_description,
        }
        if at_rest_encryption_enabled is not None:
            self._values["at_rest_encryption_enabled"] = at_rest_encryption_enabled
        if auth_token is not None:
            self._values["auth_token"] = auth_token
        if automatic_failover_enabled is not None:
            self._values["automatic_failover_enabled"] = automatic_failover_enabled
        if auto_minor_version_upgrade is not None:
            self._values["auto_minor_version_upgrade"] = auto_minor_version_upgrade
        if cache_node_type is not None:
            self._values["cache_node_type"] = cache_node_type
        if cache_parameter_group_name is not None:
            self._values["cache_parameter_group_name"] = cache_parameter_group_name
        if cache_security_group_names is not None:
            self._values["cache_security_group_names"] = cache_security_group_names
        if cache_subnet_group_name is not None:
            self._values["cache_subnet_group_name"] = cache_subnet_group_name
        if data_tiering_enabled is not None:
            self._values["data_tiering_enabled"] = data_tiering_enabled
        if engine is not None:
            self._values["engine"] = engine
        if engine_version is not None:
            self._values["engine_version"] = engine_version
        if global_replication_group_id is not None:
            self._values["global_replication_group_id"] = global_replication_group_id
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if log_delivery_configurations is not None:
            self._values["log_delivery_configurations"] = log_delivery_configurations
        if multi_az_enabled is not None:
            self._values["multi_az_enabled"] = multi_az_enabled
        if node_group_configuration is not None:
            self._values["node_group_configuration"] = node_group_configuration
        if notification_topic_arn is not None:
            self._values["notification_topic_arn"] = notification_topic_arn
        if num_cache_clusters is not None:
            self._values["num_cache_clusters"] = num_cache_clusters
        if num_node_groups is not None:
            self._values["num_node_groups"] = num_node_groups
        if port is not None:
            self._values["port"] = port
        if preferred_cache_cluster_a_zs is not None:
            self._values["preferred_cache_cluster_a_zs"] = preferred_cache_cluster_a_zs
        if preferred_maintenance_window is not None:
            self._values["preferred_maintenance_window"] = preferred_maintenance_window
        if primary_cluster_id is not None:
            self._values["primary_cluster_id"] = primary_cluster_id
        if replicas_per_node_group is not None:
            self._values["replicas_per_node_group"] = replicas_per_node_group
        if replication_group_id is not None:
            self._values["replication_group_id"] = replication_group_id
        if security_group_ids is not None:
            self._values["security_group_ids"] = security_group_ids
        if snapshot_arns is not None:
            self._values["snapshot_arns"] = snapshot_arns
        if snapshot_name is not None:
            self._values["snapshot_name"] = snapshot_name
        if snapshot_retention_limit is not None:
            self._values["snapshot_retention_limit"] = snapshot_retention_limit
        if snapshotting_cluster_id is not None:
            self._values["snapshotting_cluster_id"] = snapshotting_cluster_id
        if snapshot_window is not None:
            self._values["snapshot_window"] = snapshot_window
        if tags is not None:
            self._values["tags"] = tags
        if transit_encryption_enabled is not None:
            self._values["transit_encryption_enabled"] = transit_encryption_enabled
        if user_group_ids is not None:
            self._values["user_group_ids"] = user_group_ids

    @builtins.property
    def replication_group_description(self) -> builtins.str:
        '''A user-created description for the replication group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-replicationgroupdescription
        '''
        result = self._values.get("replication_group_description")
        assert result is not None, "Required property 'replication_group_description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def at_rest_encryption_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''A flag that enables encryption at rest when set to ``true`` .

        You cannot modify the value of ``AtRestEncryptionEnabled`` after the replication group is created. To enable encryption at rest on a replication group you must set ``AtRestEncryptionEnabled`` to ``true`` when you create the replication group.

        *Required:* Only available when creating a replication group in an Amazon VPC using redis version ``3.2.6`` or ``4.x`` onward.

        Default: ``false``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-atrestencryptionenabled
        '''
        result = self._values.get("at_rest_encryption_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def auth_token(self) -> typing.Optional[builtins.str]:
        '''*Reserved parameter.* The password used to access a password protected server.

        ``AuthToken`` can be specified only on replication groups where ``TransitEncryptionEnabled`` is ``true`` . For more information, see `Authenticating Users with the Redis AUTH Command <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html>`_ .
        .. epigraph::

           For HIPAA compliance, you must specify ``TransitEncryptionEnabled`` as ``true`` , an ``AuthToken`` , and a ``CacheSubnetGroup`` .

        Password constraints:

        - Must be only printable ASCII characters.
        - Must be at least 16 characters and no more than 128 characters in length.
        - Cannot contain any of the following characters: '/', '"', or '@'.

        For more information, see `AUTH password <https://docs.aws.amazon.com/http://redis.io/commands/AUTH>`_ at http://redis.io/commands/AUTH.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-authtoken
        '''
        result = self._values.get("auth_token")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def automatic_failover_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether a read-only replica is automatically promoted to read/write primary if the existing primary fails.

        ``AutomaticFailoverEnabled`` must be enabled for Redis (cluster mode enabled) replication groups.

        Default: false

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-automaticfailoverenabled
        '''
        result = self._values.get("automatic_failover_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If you are running Redis engine version 6.0 or later, set this parameter to yes if you want to opt-in to the next minor version upgrade campaign. This parameter is disabled for previous versions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-autominorversionupgrade
        '''
        result = self._values.get("auto_minor_version_upgrade")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def cache_node_type(self) -> typing.Optional[builtins.str]:
        '''The compute and memory capacity of the nodes in the node group (shard).

        The following node types are supported by ElastiCache. Generally speaking, the current generation types provide more memory and computational power at lower cost when compared to their equivalent previous generation counterparts.

        - General purpose:
        - Current generation:

        *M6g node types:* ``cache.m6g.large`` , ``cache.m6g.xlarge`` , ``cache.m6g.2xlarge`` , ``cache.m6g.4xlarge`` , ``cache.m6g.12xlarge`` , ``cache.m6g.24xlarge``

        *M5 node types:* ``cache.m5.large`` , ``cache.m5.xlarge`` , ``cache.m5.2xlarge`` , ``cache.m5.4xlarge`` , ``cache.m5.12xlarge`` , ``cache.m5.24xlarge``

        *M4 node types:* ``cache.m4.large`` , ``cache.m4.xlarge`` , ``cache.m4.2xlarge`` , ``cache.m4.4xlarge`` , ``cache.m4.10xlarge``

        *T4g node types:* ``cache.t4g.micro`` , ``cache.t4g.small`` , ``cache.t4g.medium``

        *T3 node types:* ``cache.t3.micro`` , ``cache.t3.small`` , ``cache.t3.medium``

        *T2 node types:* ``cache.t2.micro`` , ``cache.t2.small`` , ``cache.t2.medium``

        - Previous generation: (not recommended)

        *T1 node types:* ``cache.t1.micro``

        *M1 node types:* ``cache.m1.small`` , ``cache.m1.medium`` , ``cache.m1.large`` , ``cache.m1.xlarge``

        *M3 node types:* ``cache.m3.medium`` , ``cache.m3.large`` , ``cache.m3.xlarge`` , ``cache.m3.2xlarge``

        - Compute optimized:
        - Previous generation: (not recommended)

        *C1 node types:* ``cache.c1.xlarge``

        - Memory optimized:
        - Current generation:

        *R6gd node types:* ``cache.r6gd.xlarge`` , ``cache.r6gd.2xlarge`` , ``cache.r6gd.4xlarge`` , ``cache.r6gd.8xlarge`` , ``cache.r6gd.12xlarge`` , ``cache.r6gd.16xlarge``
        .. epigraph::

           The ``r6gd`` family is available in the following regions: ``us-east-2`` , ``us-east-1`` , ``us-west-2`` , ``us-west-1`` , ``eu-west-1`` , ``eu-central-1`` , ``ap-northeast-1`` , ``ap-southeast-1`` , ``ap-southeast-2`` .

        *R6g node types:* ``cache.r6g.large`` , ``cache.r6g.xlarge`` , ``cache.r6g.2xlarge`` , ``cache.r6g.4xlarge`` , ``cache.r6g.12xlarge`` , ``cache.r6g.24xlarge``

        *R5 node types:* ``cache.r5.large`` , ``cache.r5.xlarge`` , ``cache.r5.2xlarge`` , ``cache.r5.4xlarge`` , ``cache.r5.12xlarge`` , ``cache.r5.24xlarge``

        *R4 node types:* ``cache.r4.large`` , ``cache.r4.xlarge`` , ``cache.r4.2xlarge`` , ``cache.r4.4xlarge`` , ``cache.r4.8xlarge`` , ``cache.r4.16xlarge``

        - Previous generation: (not recommended)

        *M2 node types:* ``cache.m2.xlarge`` , ``cache.m2.2xlarge`` , ``cache.m2.4xlarge``

        *R3 node types:* ``cache.r3.large`` , ``cache.r3.xlarge`` , ``cache.r3.2xlarge`` , ``cache.r3.4xlarge`` , ``cache.r3.8xlarge``

        For region availability, see `Supported Node Types by Amazon Region <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html#CacheNodes.SupportedTypesByRegion>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachenodetype
        '''
        result = self._values.get("cache_node_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cache_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the parameter group to associate with this replication group.

        If this argument is omitted, the default cache parameter group for the specified engine is used.

        If you are running Redis version 3.2.4 or later, only one node group (shard), and want to use a default parameter group, we recommend that you specify the parameter group by name.

        - To create a Redis (cluster mode disabled) replication group, use ``CacheParameterGroupName=default.redis3.2`` .
        - To create a Redis (cluster mode enabled) replication group, use ``CacheParameterGroupName=default.redis3.2.cluster.on`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cacheparametergroupname
        '''
        result = self._values.get("cache_parameter_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cache_security_group_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of cache security group names to associate with this replication group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachesecuritygroupnames
        '''
        result = self._values.get("cache_security_group_names")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def cache_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the cache subnet group to be used for the replication group.

        .. epigraph::

           If you're going to launch your cluster in an Amazon VPC, you need to create a subnet group before you start creating a cluster. For more information, see `AWS::ElastiCache::SubnetGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachesubnetgroupname
        '''
        result = self._values.get("cache_subnet_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def data_tiering_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables data tiering.

        Data tiering is only supported for replication groups using the r6gd node type. This parameter must be set to true when using r6gd nodes. For more information, see `Data tiering <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/data-tiering.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-datatieringenabled
        '''
        result = self._values.get("data_tiering_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def engine(self) -> typing.Optional[builtins.str]:
        '''The name of the cache engine to be used for the clusters in this replication group.

        Must be Redis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-engine
        '''
        result = self._values.get("engine")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The version number of the cache engine to be used for the clusters in this replication group.

        To view the supported cache engine versions, use the ``DescribeCacheEngineVersions`` operation.

        *Important:* You can upgrade to a newer engine version (see `Selecting a Cache Engine and Version <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/SelectEngine.html#VersionManagement>`_ ) in the *ElastiCache User Guide* , but you cannot downgrade to an earlier engine version. If you want to use an earlier engine version, you must delete the existing cluster or replication group and create it anew with the earlier engine version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-engineversion
        '''
        result = self._values.get("engine_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def global_replication_group_id(self) -> typing.Optional[builtins.str]:
        '''The name of the Global datastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-globalreplicationgroupid
        '''
        result = self._values.get("global_replication_group_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the KMS key used to encrypt the disk on the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def log_delivery_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnReplicationGroup.LogDeliveryConfigurationRequestProperty, _IResolvable_da3f097b]]]]:
        '''Specifies the destination, format and type of the logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-logdeliveryconfigurations
        '''
        result = self._values.get("log_delivery_configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnReplicationGroup.LogDeliveryConfigurationRequestProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def multi_az_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''A flag indicating if you have Multi-AZ enabled to enhance fault tolerance.

        For more information, see `Minimizing Downtime: Multi-AZ <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-multiazenabled
        '''
        result = self._values.get("multi_az_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def node_group_configuration(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnReplicationGroup.NodeGroupConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''``NodeGroupConfiguration`` is a property of the ``AWS::ElastiCache::ReplicationGroup`` resource that configures an Amazon ElastiCache (ElastiCache) Redis cluster node group.

        If you set `UseOnlineResharding <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ to ``true`` , you can update ``NodeGroupConfiguration`` without interruption. When ``UseOnlineResharding`` is set to ``false`` , or is not specified, updating ``NodeGroupConfiguration`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-nodegroupconfiguration
        '''
        result = self._values.get("node_group_configuration")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnReplicationGroup.NodeGroupConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def notification_topic_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic to which notifications are sent.

        .. epigraph::

           The Amazon SNS topic owner must be the same as the cluster owner.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-notificationtopicarn
        '''
        result = self._values.get("notification_topic_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def num_cache_clusters(self) -> typing.Optional[jsii.Number]:
        '''The number of clusters this replication group initially has.

        This parameter is not used if there is more than one node group (shard). You should use ``ReplicasPerNodeGroup`` instead.

        If ``AutomaticFailoverEnabled`` is ``true`` , the value of this parameter must be at least 2. If ``AutomaticFailoverEnabled`` is ``false`` you can omit this parameter (it will default to 1), or you can explicitly set it to a value between 2 and 6.

        The maximum permitted value for ``NumCacheClusters`` is 6 (1 primary plus 5 replicas).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-numcacheclusters
        '''
        result = self._values.get("num_cache_clusters")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def num_node_groups(self) -> typing.Optional[jsii.Number]:
        '''An optional parameter that specifies the number of node groups (shards) for this Redis (cluster mode enabled) replication group.

        For Redis (cluster mode disabled) either omit this parameter or set it to 1.

        If you set `UseOnlineResharding <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-useonlineresharding>`_ to ``true`` , you can update ``NumNodeGroups`` without interruption. When ``UseOnlineResharding`` is set to ``false`` , or is not specified, updating ``NumNodeGroups`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .

        Default: 1

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-numnodegroups
        '''
        result = self._values.get("num_node_groups")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port number on which each member of the replication group accepts connections.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-port
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def preferred_cache_cluster_a_zs(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of EC2 Availability Zones in which the replication group's clusters are created.

        The order of the Availability Zones in the list is the order in which clusters are allocated. The primary cluster is created in the first AZ in the list.

        This parameter is not used if there is more than one node group (shard). You should use ``NodeGroupConfiguration`` instead.
        .. epigraph::

           If you are creating your replication group in an Amazon VPC (recommended), you can only locate clusters in Availability Zones associated with the subnets in the selected subnet group.

           The number of Availability Zones listed must equal the value of ``NumCacheClusters`` .

        Default: system chosen Availability Zones.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-preferredcacheclusterazs
        '''
        result = self._values.get("preferred_cache_cluster_a_zs")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''Specifies the weekly time range during which maintenance on the cluster is performed.

        It is specified as a range in the format ddd:hh24:mi-ddd:hh24:mi (24H Clock UTC). The minimum maintenance window is a 60 minute period.

        Valid values for ``ddd`` are:

        - ``sun``
        - ``mon``
        - ``tue``
        - ``wed``
        - ``thu``
        - ``fri``
        - ``sat``

        Example: ``sun:23:00-mon:01:30``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-preferredmaintenancewindow
        '''
        result = self._values.get("preferred_maintenance_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def primary_cluster_id(self) -> typing.Optional[builtins.str]:
        '''The identifier of the cluster that serves as the primary for this replication group.

        This cluster must already exist and have a status of ``available`` .

        This parameter is not required if ``NumCacheClusters`` , ``NumNodeGroups`` , or ``ReplicasPerNodeGroup`` is specified.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-primaryclusterid
        '''
        result = self._values.get("primary_cluster_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def replicas_per_node_group(self) -> typing.Optional[jsii.Number]:
        '''An optional parameter that specifies the number of replica nodes in each node group (shard).

        Valid values are 0 to 5.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-replicaspernodegroup
        '''
        result = self._values.get("replicas_per_node_group")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def replication_group_id(self) -> typing.Optional[builtins.str]:
        '''The replication group identifier. This parameter is stored as a lowercase string.

        Constraints:

        - A name must contain from 1 to 40 alphanumeric characters or hyphens.
        - The first character must be a letter.
        - A name cannot end with a hyphen or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-replicationgroupid
        '''
        result = self._values.get("replication_group_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more Amazon VPC security groups associated with this replication group.

        Use this parameter only when you are creating a replication group in an Amazon Virtual Private Cloud (Amazon VPC).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-securitygroupids
        '''
        result = self._values.get("security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def snapshot_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Amazon Resource Names (ARN) that uniquely identify the Redis RDB snapshot files stored in Amazon S3.

        The snapshot files are used to populate the new replication group. The Amazon S3 object name in the ARN cannot contain any commas. The new replication group will have the number of node groups (console: shards) specified by the parameter *NumNodeGroups* or the number of node groups configured by *NodeGroupConfiguration* regardless of the number of ARNs specified here.

        Example of an Amazon S3 ARN: ``arn:aws:s3:::my_bucket/snapshot1.rdb``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshotarns
        '''
        result = self._values.get("snapshot_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def snapshot_name(self) -> typing.Optional[builtins.str]:
        '''The name of a snapshot from which to restore data into the new replication group.

        The snapshot status changes to ``restoring`` while the new replication group is being created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshotname
        '''
        result = self._values.get("snapshot_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def snapshot_retention_limit(self) -> typing.Optional[jsii.Number]:
        '''The number of days for which ElastiCache retains automatic snapshots before deleting them.

        For example, if you set ``SnapshotRetentionLimit`` to 5, a snapshot that was taken today is retained for 5 days before being deleted.

        Default: 0 (i.e., automatic backups are disabled for this cluster).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshotretentionlimit
        '''
        result = self._values.get("snapshot_retention_limit")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def snapshotting_cluster_id(self) -> typing.Optional[builtins.str]:
        '''The cluster ID that is used as the daily snapshot source for the replication group.

        This parameter cannot be set for Redis (cluster mode enabled) replication groups.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshottingclusterid
        '''
        result = self._values.get("snapshotting_cluster_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def snapshot_window(self) -> typing.Optional[builtins.str]:
        '''The daily time range (in UTC) during which ElastiCache begins taking a daily snapshot of your node group (shard).

        Example: ``05:00-09:00``

        If you do not specify this parameter, ElastiCache automatically chooses an appropriate time range.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-snapshotwindow
        '''
        result = self._values.get("snapshot_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags to be added to this resource.

        Tags are comma-separated key,value pairs (e.g. Key= ``myKey`` , Value= ``myKeyValue`` . You can include multiple tags as shown following: Key= ``myKey`` , Value= ``myKeyValue`` Key= ``mySecondKey`` , Value= ``mySecondKeyValue`` . Tags on replication groups will be replicated to all nodes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def transit_encryption_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''A flag that enables in-transit encryption when set to ``true`` .

        You cannot modify the value of ``TransitEncryptionEnabled`` after the cluster is created. To enable in-transit encryption on a cluster you must set ``TransitEncryptionEnabled`` to ``true`` when you create a cluster.

        This parameter is valid only if the ``Engine`` parameter is ``redis`` , the ``EngineVersion`` parameter is ``3.2.6`` or ``4.x`` onward, and the cluster is being created in an Amazon VPC.

        If you enable in-transit encryption, you must also specify a value for ``CacheSubnetGroup`` .

        *Required:* Only available when creating a replication group in an Amazon VPC using redis version ``3.2.6`` or ``4.x`` onward.

        Default: ``false``
        .. epigraph::

           For HIPAA compliance, you must specify ``TransitEncryptionEnabled`` as ``true`` , an ``AuthToken`` , and a ``CacheSubnetGroup`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-transitencryptionenabled
        '''
        result = self._values.get("transit_encryption_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def user_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of user groups to associate with the replication group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-usergroupids
        '''
        result = self._values.get("user_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnReplicationGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSecurityGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnSecurityGroup",
):
    '''A CloudFormation ``AWS::ElastiCache::SecurityGroup``.

    The ``AWS::ElastiCache::SecurityGroup`` resource creates a cache security group. For more information about cache security groups, go to `CacheSecurityGroups <https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/VPCs.html>`_ in the *Amazon ElastiCache User Guide* or go to `CreateCacheSecurityGroup <https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateCacheSecurityGroup.html>`_ in the *Amazon ElastiCache API Reference Guide* .

    For more information, see `CreateCacheSubnetGroup <https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateCacheSubnetGroup.html>`_ .

    :cloudformationResource: AWS::ElastiCache::SecurityGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_security_group = elasticache.CfnSecurityGroup(self, "MyCfnSecurityGroup",
            description="description",
        
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
        description: builtins.str,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::SecurityGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: A description for the cache security group.
        :param tags: A tag that can be added to an ElastiCache security group. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your security groups. A tag with a null Value is permitted.
        '''
        props = CfnSecurityGroupProps(description=description, tags=tags)

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
        '''A tag that can be added to an ElastiCache security group.

        Tags are composed of a Key/Value pair. You can use tags to categorize and track all your security groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group.html#cfn-elasticache-securitygroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> builtins.str:
        '''A description for the cache security group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group.html#cfn-elasticache-securitygroup-description
        '''
        return typing.cast(builtins.str, jsii.get(self, "description"))

    @description.setter
    def description(self, value: builtins.str) -> None:
        jsii.set(self, "description", value)


@jsii.implements(_IInspectable_c2943556)
class CfnSecurityGroupIngress(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnSecurityGroupIngress",
):
    '''A CloudFormation ``AWS::ElastiCache::SecurityGroupIngress``.

    The AWS::ElastiCache::SecurityGroupIngress type authorizes ingress to a cache security group from hosts in specified Amazon EC2 security groups. For more information about ElastiCache security group ingress, go to `AuthorizeCacheSecurityGroupIngress <https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_AuthorizeCacheSecurityGroupIngress.html>`_ in the *Amazon ElastiCache API Reference Guide* .
    .. epigraph::

       Updates are not supported.

    :cloudformationResource: AWS::ElastiCache::SecurityGroupIngress
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group-ingress.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_security_group_ingress = elasticache.CfnSecurityGroupIngress(self, "MyCfnSecurityGroupIngress",
            cache_security_group_name="cacheSecurityGroupName",
            ec2_security_group_name="ec2SecurityGroupName",
        
            # the properties below are optional
            ec2_security_group_owner_id="ec2SecurityGroupOwnerId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cache_security_group_name: builtins.str,
        ec2_security_group_name: builtins.str,
        ec2_security_group_owner_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::SecurityGroupIngress``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param cache_security_group_name: The name of the Cache Security Group to authorize.
        :param ec2_security_group_name: Name of the EC2 Security Group to include in the authorization.
        :param ec2_security_group_owner_id: Specifies the Amazon Account ID of the owner of the EC2 security group specified in the EC2SecurityGroupName property. The Amazon access key ID is not an acceptable value.
        '''
        props = CfnSecurityGroupIngressProps(
            cache_security_group_name=cache_security_group_name,
            ec2_security_group_name=ec2_security_group_name,
            ec2_security_group_owner_id=ec2_security_group_owner_id,
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
    @jsii.member(jsii_name="cacheSecurityGroupName")
    def cache_security_group_name(self) -> builtins.str:
        '''The name of the Cache Security Group to authorize.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group-ingress.html#cfn-elasticache-securitygroupingress-cachesecuritygroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "cacheSecurityGroupName"))

    @cache_security_group_name.setter
    def cache_security_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "cacheSecurityGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ec2SecurityGroupName")
    def ec2_security_group_name(self) -> builtins.str:
        '''Name of the EC2 Security Group to include in the authorization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group-ingress.html#cfn-elasticache-securitygroupingress-ec2securitygroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "ec2SecurityGroupName"))

    @ec2_security_group_name.setter
    def ec2_security_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "ec2SecurityGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ec2SecurityGroupOwnerId")
    def ec2_security_group_owner_id(self) -> typing.Optional[builtins.str]:
        '''Specifies the Amazon Account ID of the owner of the EC2 security group specified in the EC2SecurityGroupName property.

        The Amazon access key ID is not an acceptable value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group-ingress.html#cfn-elasticache-securitygroupingress-ec2securitygroupownerid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "ec2SecurityGroupOwnerId"))

    @ec2_security_group_owner_id.setter
    def ec2_security_group_owner_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "ec2SecurityGroupOwnerId", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnSecurityGroupIngressProps",
    jsii_struct_bases=[],
    name_mapping={
        "cache_security_group_name": "cacheSecurityGroupName",
        "ec2_security_group_name": "ec2SecurityGroupName",
        "ec2_security_group_owner_id": "ec2SecurityGroupOwnerId",
    },
)
class CfnSecurityGroupIngressProps:
    def __init__(
        self,
        *,
        cache_security_group_name: builtins.str,
        ec2_security_group_name: builtins.str,
        ec2_security_group_owner_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnSecurityGroupIngress``.

        :param cache_security_group_name: The name of the Cache Security Group to authorize.
        :param ec2_security_group_name: Name of the EC2 Security Group to include in the authorization.
        :param ec2_security_group_owner_id: Specifies the Amazon Account ID of the owner of the EC2 security group specified in the EC2SecurityGroupName property. The Amazon access key ID is not an acceptable value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group-ingress.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_security_group_ingress_props = elasticache.CfnSecurityGroupIngressProps(
                cache_security_group_name="cacheSecurityGroupName",
                ec2_security_group_name="ec2SecurityGroupName",
            
                # the properties below are optional
                ec2_security_group_owner_id="ec2SecurityGroupOwnerId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cache_security_group_name": cache_security_group_name,
            "ec2_security_group_name": ec2_security_group_name,
        }
        if ec2_security_group_owner_id is not None:
            self._values["ec2_security_group_owner_id"] = ec2_security_group_owner_id

    @builtins.property
    def cache_security_group_name(self) -> builtins.str:
        '''The name of the Cache Security Group to authorize.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group-ingress.html#cfn-elasticache-securitygroupingress-cachesecuritygroupname
        '''
        result = self._values.get("cache_security_group_name")
        assert result is not None, "Required property 'cache_security_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def ec2_security_group_name(self) -> builtins.str:
        '''Name of the EC2 Security Group to include in the authorization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group-ingress.html#cfn-elasticache-securitygroupingress-ec2securitygroupname
        '''
        result = self._values.get("ec2_security_group_name")
        assert result is not None, "Required property 'ec2_security_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def ec2_security_group_owner_id(self) -> typing.Optional[builtins.str]:
        '''Specifies the Amazon Account ID of the owner of the EC2 security group specified in the EC2SecurityGroupName property.

        The Amazon access key ID is not an acceptable value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group-ingress.html#cfn-elasticache-securitygroupingress-ec2securitygroupownerid
        '''
        result = self._values.get("ec2_security_group_owner_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSecurityGroupIngressProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnSecurityGroupProps",
    jsii_struct_bases=[],
    name_mapping={"description": "description", "tags": "tags"},
)
class CfnSecurityGroupProps:
    def __init__(
        self,
        *,
        description: builtins.str,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSecurityGroup``.

        :param description: A description for the cache security group.
        :param tags: A tag that can be added to an ElastiCache security group. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your security groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_security_group_props = elasticache.CfnSecurityGroupProps(
                description="description",
            
                # the properties below are optional
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "description": description,
        }
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def description(self) -> builtins.str:
        '''A description for the cache security group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group.html#cfn-elasticache-securitygroup-description
        '''
        result = self._values.get("description")
        assert result is not None, "Required property 'description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A tag that can be added to an ElastiCache security group.

        Tags are composed of a Key/Value pair. You can use tags to categorize and track all your security groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-security-group.html#cfn-elasticache-securitygroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSecurityGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSubnetGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnSubnetGroup",
):
    '''A CloudFormation ``AWS::ElastiCache::SubnetGroup``.

    Creates a cache subnet group. For more information about cache subnet groups, go to Cache Subnet Groups in the *Amazon ElastiCache User Guide* or go to `CreateCacheSubnetGroup <https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateCacheSubnetGroup.html>`_ in the *Amazon ElastiCache API Reference Guide* .

    :cloudformationResource: AWS::ElastiCache::SubnetGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_subnet_group = elasticache.CfnSubnetGroup(self, "MyCfnSubnetGroup",
            description="description",
            subnet_ids=["subnetIds"],
        
            # the properties below are optional
            cache_subnet_group_name="cacheSubnetGroupName",
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
        description: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        cache_subnet_group_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::SubnetGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: The description for the cache subnet group.
        :param subnet_ids: The EC2 subnet IDs for the cache subnet group.
        :param cache_subnet_group_name: The name for the cache subnet group. This value is stored as a lowercase string. Constraints: Must contain no more than 255 alphanumeric characters or hyphens. Example: ``mysubnetgroup``
        :param tags: A tag that can be added to an ElastiCache subnet group. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your subnet groups. A tag with a null Value is permitted.
        '''
        props = CfnSubnetGroupProps(
            description=description,
            subnet_ids=subnet_ids,
            cache_subnet_group_name=cache_subnet_group_name,
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
        '''A tag that can be added to an ElastiCache subnet group.

        Tags are composed of a Key/Value pair. You can use tags to categorize and track all your subnet groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html#cfn-elasticache-subnetgroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> builtins.str:
        '''The description for the cache subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html#cfn-elasticache-subnetgroup-description
        '''
        return typing.cast(builtins.str, jsii.get(self, "description"))

    @description.setter
    def description(self, value: builtins.str) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetIds")
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''The EC2 subnet IDs for the cache subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html#cfn-elasticache-subnetgroup-subnetids
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "subnetIds"))

    @subnet_ids.setter
    def subnet_ids(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "subnetIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cacheSubnetGroupName")
    def cache_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''The name for the cache subnet group. This value is stored as a lowercase string.

        Constraints: Must contain no more than 255 alphanumeric characters or hyphens.

        Example: ``mysubnetgroup``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html#cfn-elasticache-subnetgroup-cachesubnetgroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cacheSubnetGroupName"))

    @cache_subnet_group_name.setter
    def cache_subnet_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cacheSubnetGroupName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnSubnetGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "subnet_ids": "subnetIds",
        "cache_subnet_group_name": "cacheSubnetGroupName",
        "tags": "tags",
    },
)
class CfnSubnetGroupProps:
    def __init__(
        self,
        *,
        description: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        cache_subnet_group_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSubnetGroup``.

        :param description: The description for the cache subnet group.
        :param subnet_ids: The EC2 subnet IDs for the cache subnet group.
        :param cache_subnet_group_name: The name for the cache subnet group. This value is stored as a lowercase string. Constraints: Must contain no more than 255 alphanumeric characters or hyphens. Example: ``mysubnetgroup``
        :param tags: A tag that can be added to an ElastiCache subnet group. Tags are composed of a Key/Value pair. You can use tags to categorize and track all your subnet groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_subnet_group_props = elasticache.CfnSubnetGroupProps(
                description="description",
                subnet_ids=["subnetIds"],
            
                # the properties below are optional
                cache_subnet_group_name="cacheSubnetGroupName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "description": description,
            "subnet_ids": subnet_ids,
        }
        if cache_subnet_group_name is not None:
            self._values["cache_subnet_group_name"] = cache_subnet_group_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def description(self) -> builtins.str:
        '''The description for the cache subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html#cfn-elasticache-subnetgroup-description
        '''
        result = self._values.get("description")
        assert result is not None, "Required property 'description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''The EC2 subnet IDs for the cache subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html#cfn-elasticache-subnetgroup-subnetids
        '''
        result = self._values.get("subnet_ids")
        assert result is not None, "Required property 'subnet_ids' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def cache_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''The name for the cache subnet group. This value is stored as a lowercase string.

        Constraints: Must contain no more than 255 alphanumeric characters or hyphens.

        Example: ``mysubnetgroup``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html#cfn-elasticache-subnetgroup-cachesubnetgroupname
        '''
        result = self._values.get("cache_subnet_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A tag that can be added to an ElastiCache subnet group.

        Tags are composed of a Key/Value pair. You can use tags to categorize and track all your subnet groups. A tag with a null Value is permitted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-subnetgroup.html#cfn-elasticache-subnetgroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSubnetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUser(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnUser",
):
    '''A CloudFormation ``AWS::ElastiCache::User``.

    For Redis engine version 6.0 onwards: Creates a Redis user. For more information, see `Using Role Based Access Control (RBAC) <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Clusters.RBAC.html>`_ .

    :cloudformationResource: AWS::ElastiCache::User
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_user = elasticache.CfnUser(self, "MyCfnUser",
            engine="engine",
            user_id="userId",
            user_name="userName",
        
            # the properties below are optional
            access_string="accessString",
            no_password_required=False,
            passwords=["passwords"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        engine: builtins.str,
        user_id: builtins.str,
        user_name: builtins.str,
        access_string: typing.Optional[builtins.str] = None,
        no_password_required: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        passwords: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::User``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param engine: The current supported value is redis.
        :param user_id: The ID of the user.
        :param user_name: The username of the user.
        :param access_string: Access permissions string used for this user.
        :param no_password_required: Indicates a password is not required for this user.
        :param passwords: Passwords used for this user. You can create up to two passwords for each user.
        '''
        props = CfnUserProps(
            engine=engine,
            user_id=user_id,
            user_name=user_name,
            access_string=access_string,
            no_password_required=no_password_required,
            passwords=passwords,
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
        '''The Amazon Resource Name (ARN) of the user.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''Indicates the user status.

        Can be "active", "modifying" or "deleting".

        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engine")
    def engine(self) -> builtins.str:
        '''The current supported value is redis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-engine
        '''
        return typing.cast(builtins.str, jsii.get(self, "engine"))

    @engine.setter
    def engine(self, value: builtins.str) -> None:
        jsii.set(self, "engine", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userId")
    def user_id(self) -> builtins.str:
        '''The ID of the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-userid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userId"))

    @user_id.setter
    def user_id(self, value: builtins.str) -> None:
        jsii.set(self, "userId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> builtins.str:
        '''The username of the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-username
        '''
        return typing.cast(builtins.str, jsii.get(self, "userName"))

    @user_name.setter
    def user_name(self, value: builtins.str) -> None:
        jsii.set(self, "userName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessString")
    def access_string(self) -> typing.Optional[builtins.str]:
        '''Access permissions string used for this user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-accessstring
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "accessString"))

    @access_string.setter
    def access_string(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "accessString", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="noPasswordRequired")
    def no_password_required(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates a password is not required for this user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-nopasswordrequired
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "noPasswordRequired"))

    @no_password_required.setter
    def no_password_required(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "noPasswordRequired", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="passwords")
    def passwords(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Passwords used for this user.

        You can create up to two passwords for each user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-passwords
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "passwords"))

    @passwords.setter
    def passwords(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "passwords", value)


@jsii.implements(_IInspectable_c2943556)
class CfnUserGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticache.CfnUserGroup",
):
    '''A CloudFormation ``AWS::ElastiCache::UserGroup``.

    For Redis engine version 6.0 onwards: Creates a Redis user group. For more information, see `Using Role Based Access Control (RBAC) <https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Clusters.RBAC.html>`_

    :cloudformationResource: AWS::ElastiCache::UserGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-usergroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticache as elasticache
        
        cfn_user_group = elasticache.CfnUserGroup(self, "MyCfnUserGroup",
            engine="engine",
            user_group_id="userGroupId",
        
            # the properties below are optional
            user_ids=["userIds"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        engine: builtins.str,
        user_group_id: builtins.str,
        user_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::ElastiCache::UserGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param engine: The current supported value is redis.
        :param user_group_id: The ID of the user group.
        :param user_ids: The list of user IDs that belong to the user group. A user named ``default`` must be included.
        '''
        props = CfnUserGroupProps(
            engine=engine, user_group_id=user_group_id, user_ids=user_ids
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
        '''The Amazon Resource Name (ARN) of the user group.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''Indicates user group status.

        Can be "creating", "active", "modifying", "deleting".

        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engine")
    def engine(self) -> builtins.str:
        '''The current supported value is redis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-usergroup.html#cfn-elasticache-usergroup-engine
        '''
        return typing.cast(builtins.str, jsii.get(self, "engine"))

    @engine.setter
    def engine(self, value: builtins.str) -> None:
        jsii.set(self, "engine", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userGroupId")
    def user_group_id(self) -> builtins.str:
        '''The ID of the user group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-usergroup.html#cfn-elasticache-usergroup-usergroupid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userGroupId"))

    @user_group_id.setter
    def user_group_id(self, value: builtins.str) -> None:
        jsii.set(self, "userGroupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userIds")
    def user_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of user IDs that belong to the user group.

        A user named ``default`` must be included.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-usergroup.html#cfn-elasticache-usergroup-userids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "userIds"))

    @user_ids.setter
    def user_ids(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "userIds", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnUserGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "engine": "engine",
        "user_group_id": "userGroupId",
        "user_ids": "userIds",
    },
)
class CfnUserGroupProps:
    def __init__(
        self,
        *,
        engine: builtins.str,
        user_group_id: builtins.str,
        user_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserGroup``.

        :param engine: The current supported value is redis.
        :param user_group_id: The ID of the user group.
        :param user_ids: The list of user IDs that belong to the user group. A user named ``default`` must be included.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-usergroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_user_group_props = elasticache.CfnUserGroupProps(
                engine="engine",
                user_group_id="userGroupId",
            
                # the properties below are optional
                user_ids=["userIds"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "engine": engine,
            "user_group_id": user_group_id,
        }
        if user_ids is not None:
            self._values["user_ids"] = user_ids

    @builtins.property
    def engine(self) -> builtins.str:
        '''The current supported value is redis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-usergroup.html#cfn-elasticache-usergroup-engine
        '''
        result = self._values.get("engine")
        assert result is not None, "Required property 'engine' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_group_id(self) -> builtins.str:
        '''The ID of the user group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-usergroup.html#cfn-elasticache-usergroup-usergroupid
        '''
        result = self._values.get("user_group_id")
        assert result is not None, "Required property 'user_group_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of user IDs that belong to the user group.

        A user named ``default`` must be included.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-usergroup.html#cfn-elasticache-usergroup-userids
        '''
        result = self._values.get("user_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticache.CfnUserProps",
    jsii_struct_bases=[],
    name_mapping={
        "engine": "engine",
        "user_id": "userId",
        "user_name": "userName",
        "access_string": "accessString",
        "no_password_required": "noPasswordRequired",
        "passwords": "passwords",
    },
)
class CfnUserProps:
    def __init__(
        self,
        *,
        engine: builtins.str,
        user_id: builtins.str,
        user_name: builtins.str,
        access_string: typing.Optional[builtins.str] = None,
        no_password_required: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        passwords: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUser``.

        :param engine: The current supported value is redis.
        :param user_id: The ID of the user.
        :param user_name: The username of the user.
        :param access_string: Access permissions string used for this user.
        :param no_password_required: Indicates a password is not required for this user.
        :param passwords: Passwords used for this user. You can create up to two passwords for each user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticache as elasticache
            
            cfn_user_props = elasticache.CfnUserProps(
                engine="engine",
                user_id="userId",
                user_name="userName",
            
                # the properties below are optional
                access_string="accessString",
                no_password_required=False,
                passwords=["passwords"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "engine": engine,
            "user_id": user_id,
            "user_name": user_name,
        }
        if access_string is not None:
            self._values["access_string"] = access_string
        if no_password_required is not None:
            self._values["no_password_required"] = no_password_required
        if passwords is not None:
            self._values["passwords"] = passwords

    @builtins.property
    def engine(self) -> builtins.str:
        '''The current supported value is redis.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-engine
        '''
        result = self._values.get("engine")
        assert result is not None, "Required property 'engine' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_id(self) -> builtins.str:
        '''The ID of the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-userid
        '''
        result = self._values.get("user_id")
        assert result is not None, "Required property 'user_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_name(self) -> builtins.str:
        '''The username of the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-username
        '''
        result = self._values.get("user_name")
        assert result is not None, "Required property 'user_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def access_string(self) -> typing.Optional[builtins.str]:
        '''Access permissions string used for this user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-accessstring
        '''
        result = self._values.get("access_string")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def no_password_required(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates a password is not required for this user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-nopasswordrequired
        '''
        result = self._values.get("no_password_required")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def passwords(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Passwords used for this user.

        You can create up to two passwords for each user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-user.html#cfn-elasticache-user-passwords
        '''
        result = self._values.get("passwords")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnCacheCluster",
    "CfnCacheClusterProps",
    "CfnGlobalReplicationGroup",
    "CfnGlobalReplicationGroupProps",
    "CfnParameterGroup",
    "CfnParameterGroupProps",
    "CfnReplicationGroup",
    "CfnReplicationGroupProps",
    "CfnSecurityGroup",
    "CfnSecurityGroupIngress",
    "CfnSecurityGroupIngressProps",
    "CfnSecurityGroupProps",
    "CfnSubnetGroup",
    "CfnSubnetGroupProps",
    "CfnUser",
    "CfnUserGroup",
    "CfnUserGroupProps",
    "CfnUserProps",
]

publication.publish()
