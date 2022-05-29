'''
# Amazon Managed Streaming for Apache Kafka Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_msk as msk
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-msk-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::MSK](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_MSK.html).

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
class CfnCluster(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_msk.CfnCluster",
):
    '''A CloudFormation ``AWS::MSK::Cluster``.

    The ``AWS::MSK::Cluster`` resource creates an Amazon MSK cluster . For more information, see `What Is Amazon MSK? <https://docs.aws.amazon.com/msk/latest/developerguide/what-is-msk.html>`_ in the *Amazon MSK Developer Guide* .

    :cloudformationResource: AWS::MSK::Cluster
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_msk as msk
        
        # tags: Any
        
        cfn_cluster = msk.CfnCluster(self, "MyCfnCluster",
            broker_node_group_info=msk.CfnCluster.BrokerNodeGroupInfoProperty(
                client_subnets=["clientSubnets"],
                instance_type="instanceType",
        
                # the properties below are optional
                broker_az_distribution="brokerAzDistribution",
                connectivity_info=msk.CfnCluster.ConnectivityInfoProperty(
                    public_access=msk.CfnCluster.PublicAccessProperty(
                        type="type"
                    )
                ),
                security_groups=["securityGroups"],
                storage_info=msk.CfnCluster.StorageInfoProperty(
                    ebs_storage_info=msk.CfnCluster.EBSStorageInfoProperty(
                        provisioned_throughput=msk.CfnCluster.ProvisionedThroughputProperty(
                            enabled=False,
                            volume_throughput=123
                        ),
                        volume_size=123
                    )
                )
            ),
            cluster_name="clusterName",
            kafka_version="kafkaVersion",
            number_of_broker_nodes=123,
        
            # the properties below are optional
            client_authentication=msk.CfnCluster.ClientAuthenticationProperty(
                sasl=msk.CfnCluster.SaslProperty(
                    iam=msk.CfnCluster.IamProperty(
                        enabled=False
                    ),
                    scram=msk.CfnCluster.ScramProperty(
                        enabled=False
                    )
                ),
                tls=msk.CfnCluster.TlsProperty(
                    certificate_authority_arn_list=["certificateAuthorityArnList"],
                    enabled=False
                ),
                unauthenticated=msk.CfnCluster.UnauthenticatedProperty(
                    enabled=False
                )
            ),
            configuration_info=msk.CfnCluster.ConfigurationInfoProperty(
                arn="arn",
                revision=123
            ),
            encryption_info=msk.CfnCluster.EncryptionInfoProperty(
                encryption_at_rest=msk.CfnCluster.EncryptionAtRestProperty(
                    data_volume_kms_key_id="dataVolumeKmsKeyId"
                ),
                encryption_in_transit=msk.CfnCluster.EncryptionInTransitProperty(
                    client_broker="clientBroker",
                    in_cluster=False
                )
            ),
            enhanced_monitoring="enhancedMonitoring",
            logging_info=msk.CfnCluster.LoggingInfoProperty(
                broker_logs=msk.CfnCluster.BrokerLogsProperty(
                    cloud_watch_logs=msk.CfnCluster.CloudWatchLogsProperty(
                        enabled=False,
        
                        # the properties below are optional
                        log_group="logGroup"
                    ),
                    firehose=msk.CfnCluster.FirehoseProperty(
                        enabled=False,
        
                        # the properties below are optional
                        delivery_stream="deliveryStream"
                    ),
                    s3=msk.CfnCluster.S3Property(
                        enabled=False,
        
                        # the properties below are optional
                        bucket="bucket",
                        prefix="prefix"
                    )
                )
            ),
            open_monitoring=msk.CfnCluster.OpenMonitoringProperty(
                prometheus=msk.CfnCluster.PrometheusProperty(
                    jmx_exporter=msk.CfnCluster.JmxExporterProperty(
                        enabled_in_broker=False
                    ),
                    node_exporter=msk.CfnCluster.NodeExporterProperty(
                        enabled_in_broker=False
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
        broker_node_group_info: typing.Union["CfnCluster.BrokerNodeGroupInfoProperty", _IResolvable_da3f097b],
        cluster_name: builtins.str,
        kafka_version: builtins.str,
        number_of_broker_nodes: jsii.Number,
        client_authentication: typing.Optional[typing.Union["CfnCluster.ClientAuthenticationProperty", _IResolvable_da3f097b]] = None,
        configuration_info: typing.Optional[typing.Union["CfnCluster.ConfigurationInfoProperty", _IResolvable_da3f097b]] = None,
        encryption_info: typing.Optional[typing.Union["CfnCluster.EncryptionInfoProperty", _IResolvable_da3f097b]] = None,
        enhanced_monitoring: typing.Optional[builtins.str] = None,
        logging_info: typing.Optional[typing.Union["CfnCluster.LoggingInfoProperty", _IResolvable_da3f097b]] = None,
        open_monitoring: typing.Optional[typing.Union["CfnCluster.OpenMonitoringProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::MSK::Cluster``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param broker_node_group_info: The setup to be used for brokers in the cluster.
        :param cluster_name: The name of the cluster.
        :param kafka_version: The version of Apache Kafka. For more information, see `Supported Apache Kafka versions <https://docs.aws.amazon.com/msk/latest/developerguide/supported-kafka-versions.html>`_ in the Amazon MSK Developer Guide.
        :param number_of_broker_nodes: The number of broker nodes you want in the Amazon MSK cluster. You can submit an update to increase the number of broker nodes in a cluster.
        :param client_authentication: Includes information related to client authentication.
        :param configuration_info: The Amazon MSK configuration to use for the cluster.
        :param encryption_info: Includes all encryption-related information.
        :param enhanced_monitoring: Specifies the level of monitoring for the MSK cluster. The possible values are ``DEFAULT`` , ``PER_BROKER`` , and ``PER_TOPIC_PER_BROKER`` .
        :param logging_info: You can configure your Amazon MSK cluster to send broker logs to different destination types. This is a container for the configuration details related to broker logs.
        :param open_monitoring: The settings for open monitoring.
        :param tags: A map of key:value pairs to apply to this resource. Both key and value are of type String.
        '''
        props = CfnClusterProps(
            broker_node_group_info=broker_node_group_info,
            cluster_name=cluster_name,
            kafka_version=kafka_version,
            number_of_broker_nodes=number_of_broker_nodes,
            client_authentication=client_authentication,
            configuration_info=configuration_info,
            encryption_info=encryption_info,
            enhanced_monitoring=enhanced_monitoring,
            logging_info=logging_info,
            open_monitoring=open_monitoring,
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
        '''A map of key:value pairs to apply to this resource.

        Both key and value are of type String.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="brokerNodeGroupInfo")
    def broker_node_group_info(
        self,
    ) -> typing.Union["CfnCluster.BrokerNodeGroupInfoProperty", _IResolvable_da3f097b]:
        '''The setup to be used for brokers in the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-brokernodegroupinfo
        '''
        return typing.cast(typing.Union["CfnCluster.BrokerNodeGroupInfoProperty", _IResolvable_da3f097b], jsii.get(self, "brokerNodeGroupInfo"))

    @broker_node_group_info.setter
    def broker_node_group_info(
        self,
        value: typing.Union["CfnCluster.BrokerNodeGroupInfoProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "brokerNodeGroupInfo", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterName")
    def cluster_name(self) -> builtins.str:
        '''The name of the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-clustername
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterName"))

    @cluster_name.setter
    def cluster_name(self, value: builtins.str) -> None:
        jsii.set(self, "clusterName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kafkaVersion")
    def kafka_version(self) -> builtins.str:
        '''The version of Apache Kafka.

        For more information, see `Supported Apache Kafka versions <https://docs.aws.amazon.com/msk/latest/developerguide/supported-kafka-versions.html>`_ in the Amazon MSK Developer Guide.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-kafkaversion
        '''
        return typing.cast(builtins.str, jsii.get(self, "kafkaVersion"))

    @kafka_version.setter
    def kafka_version(self, value: builtins.str) -> None:
        jsii.set(self, "kafkaVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="numberOfBrokerNodes")
    def number_of_broker_nodes(self) -> jsii.Number:
        '''The number of broker nodes you want in the Amazon MSK cluster.

        You can submit an update to increase the number of broker nodes in a cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-numberofbrokernodes
        '''
        return typing.cast(jsii.Number, jsii.get(self, "numberOfBrokerNodes"))

    @number_of_broker_nodes.setter
    def number_of_broker_nodes(self, value: jsii.Number) -> None:
        jsii.set(self, "numberOfBrokerNodes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clientAuthentication")
    def client_authentication(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.ClientAuthenticationProperty", _IResolvable_da3f097b]]:
        '''Includes information related to client authentication.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-clientauthentication
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.ClientAuthenticationProperty", _IResolvable_da3f097b]], jsii.get(self, "clientAuthentication"))

    @client_authentication.setter
    def client_authentication(
        self,
        value: typing.Optional[typing.Union["CfnCluster.ClientAuthenticationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "clientAuthentication", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="configurationInfo")
    def configuration_info(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.ConfigurationInfoProperty", _IResolvable_da3f097b]]:
        '''The Amazon MSK configuration to use for the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-configurationinfo
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.ConfigurationInfoProperty", _IResolvable_da3f097b]], jsii.get(self, "configurationInfo"))

    @configuration_info.setter
    def configuration_info(
        self,
        value: typing.Optional[typing.Union["CfnCluster.ConfigurationInfoProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "configurationInfo", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionInfo")
    def encryption_info(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.EncryptionInfoProperty", _IResolvable_da3f097b]]:
        '''Includes all encryption-related information.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.EncryptionInfoProperty", _IResolvable_da3f097b]], jsii.get(self, "encryptionInfo"))

    @encryption_info.setter
    def encryption_info(
        self,
        value: typing.Optional[typing.Union["CfnCluster.EncryptionInfoProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "encryptionInfo", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enhancedMonitoring")
    def enhanced_monitoring(self) -> typing.Optional[builtins.str]:
        '''Specifies the level of monitoring for the MSK cluster.

        The possible values are ``DEFAULT`` , ``PER_BROKER`` , and ``PER_TOPIC_PER_BROKER`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-enhancedmonitoring
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "enhancedMonitoring"))

    @enhanced_monitoring.setter
    def enhanced_monitoring(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "enhancedMonitoring", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loggingInfo")
    def logging_info(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.LoggingInfoProperty", _IResolvable_da3f097b]]:
        '''You can configure your Amazon MSK cluster to send broker logs to different destination types.

        This is a container for the configuration details related to broker logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-logginginfo
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.LoggingInfoProperty", _IResolvable_da3f097b]], jsii.get(self, "loggingInfo"))

    @logging_info.setter
    def logging_info(
        self,
        value: typing.Optional[typing.Union["CfnCluster.LoggingInfoProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "loggingInfo", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openMonitoring")
    def open_monitoring(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.OpenMonitoringProperty", _IResolvable_da3f097b]]:
        '''The settings for open monitoring.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-openmonitoring
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.OpenMonitoringProperty", _IResolvable_da3f097b]], jsii.get(self, "openMonitoring"))

    @open_monitoring.setter
    def open_monitoring(
        self,
        value: typing.Optional[typing.Union["CfnCluster.OpenMonitoringProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "openMonitoring", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.BrokerLogsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_logs": "cloudWatchLogs",
            "firehose": "firehose",
            "s3": "s3",
        },
    )
    class BrokerLogsProperty:
        def __init__(
            self,
            *,
            cloud_watch_logs: typing.Optional[typing.Union["CfnCluster.CloudWatchLogsProperty", _IResolvable_da3f097b]] = None,
            firehose: typing.Optional[typing.Union["CfnCluster.FirehoseProperty", _IResolvable_da3f097b]] = None,
            s3: typing.Optional[typing.Union["CfnCluster.S3Property", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''You can configure your Amazon MSK cluster to send broker logs to different destination types.

            This configuration specifies the details of these destinations.

            :param cloud_watch_logs: Details of the CloudWatch Logs destination for broker logs.
            :param firehose: Details of the Kinesis Data Firehose delivery stream that is the destination for broker logs.
            :param s3: Details of the Amazon MSK destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                broker_logs_property = msk.CfnCluster.BrokerLogsProperty(
                    cloud_watch_logs=msk.CfnCluster.CloudWatchLogsProperty(
                        enabled=False,
                
                        # the properties below are optional
                        log_group="logGroup"
                    ),
                    firehose=msk.CfnCluster.FirehoseProperty(
                        enabled=False,
                
                        # the properties below are optional
                        delivery_stream="deliveryStream"
                    ),
                    s3=msk.CfnCluster.S3Property(
                        enabled=False,
                
                        # the properties below are optional
                        bucket="bucket",
                        prefix="prefix"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cloud_watch_logs is not None:
                self._values["cloud_watch_logs"] = cloud_watch_logs
            if firehose is not None:
                self._values["firehose"] = firehose
            if s3 is not None:
                self._values["s3"] = s3

        @builtins.property
        def cloud_watch_logs(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.CloudWatchLogsProperty", _IResolvable_da3f097b]]:
            '''Details of the CloudWatch Logs destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html#cfn-msk-cluster-brokerlogs-cloudwatchlogs
            '''
            result = self._values.get("cloud_watch_logs")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.CloudWatchLogsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def firehose(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.FirehoseProperty", _IResolvable_da3f097b]]:
            '''Details of the Kinesis Data Firehose delivery stream that is the destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html#cfn-msk-cluster-brokerlogs-firehose
            '''
            result = self._values.get("firehose")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.FirehoseProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.S3Property", _IResolvable_da3f097b]]:
            '''Details of the Amazon MSK destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html#cfn-msk-cluster-brokerlogs-s3
            '''
            result = self._values.get("s3")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.S3Property", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BrokerLogsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.BrokerNodeGroupInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "client_subnets": "clientSubnets",
            "instance_type": "instanceType",
            "broker_az_distribution": "brokerAzDistribution",
            "connectivity_info": "connectivityInfo",
            "security_groups": "securityGroups",
            "storage_info": "storageInfo",
        },
    )
    class BrokerNodeGroupInfoProperty:
        def __init__(
            self,
            *,
            client_subnets: typing.Sequence[builtins.str],
            instance_type: builtins.str,
            broker_az_distribution: typing.Optional[builtins.str] = None,
            connectivity_info: typing.Optional[typing.Union["CfnCluster.ConnectivityInfoProperty", _IResolvable_da3f097b]] = None,
            security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
            storage_info: typing.Optional[typing.Union["CfnCluster.StorageInfoProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The setup to be used for brokers in the cluster.

            :param client_subnets: The list of subnets to connect to in the client virtual private cloud (VPC). Amazon creates elastic network interfaces inside these subnets. Client applications use elastic network interfaces to produce and consume data. Specify exactly two subnets if you are using the US West (N. California) Region. For other Regions where Amazon MSK is available, you can specify either two or three subnets. The subnets that you specify must be in distinct Availability Zones. When you create a cluster, Amazon MSK distributes the broker nodes evenly across the subnets that you specify. Client subnets can't be in Availability Zone us-east-1e.
            :param instance_type: The type of Amazon EC2 instances to use for brokers. The following instance types are allowed: kafka.m5.large, kafka.m5.xlarge, kafka.m5.2xlarge, kafka.m5.4xlarge, kafka.m5.8xlarge, kafka.m5.12xlarge, kafka.m5.16xlarge, and kafka.m5.24xlarge.
            :param broker_az_distribution: This parameter is currently not in use.
            :param connectivity_info: Information about the cluster's connectivity setting.
            :param security_groups: The security groups to associate with the elastic network interfaces in order to specify who can connect to and communicate with the Amazon MSK cluster. If you don't specify a security group, Amazon MSK uses the default security group associated with the VPC. If you specify security groups that were shared with you, you must ensure that you have permissions to them. Specifically, you need the ``ec2:DescribeSecurityGroups`` permission.
            :param storage_info: Contains information about storage volumes attached to MSK broker nodes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                broker_node_group_info_property = msk.CfnCluster.BrokerNodeGroupInfoProperty(
                    client_subnets=["clientSubnets"],
                    instance_type="instanceType",
                
                    # the properties below are optional
                    broker_az_distribution="brokerAzDistribution",
                    connectivity_info=msk.CfnCluster.ConnectivityInfoProperty(
                        public_access=msk.CfnCluster.PublicAccessProperty(
                            type="type"
                        )
                    ),
                    security_groups=["securityGroups"],
                    storage_info=msk.CfnCluster.StorageInfoProperty(
                        ebs_storage_info=msk.CfnCluster.EBSStorageInfoProperty(
                            provisioned_throughput=msk.CfnCluster.ProvisionedThroughputProperty(
                                enabled=False,
                                volume_throughput=123
                            ),
                            volume_size=123
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "client_subnets": client_subnets,
                "instance_type": instance_type,
            }
            if broker_az_distribution is not None:
                self._values["broker_az_distribution"] = broker_az_distribution
            if connectivity_info is not None:
                self._values["connectivity_info"] = connectivity_info
            if security_groups is not None:
                self._values["security_groups"] = security_groups
            if storage_info is not None:
                self._values["storage_info"] = storage_info

        @builtins.property
        def client_subnets(self) -> typing.List[builtins.str]:
            '''The list of subnets to connect to in the client virtual private cloud (VPC).

            Amazon creates elastic network interfaces inside these subnets. Client applications use elastic network interfaces to produce and consume data.

            Specify exactly two subnets if you are using the US West (N. California) Region. For other Regions where Amazon MSK is available, you can specify either two or three subnets. The subnets that you specify must be in distinct Availability Zones. When you create a cluster, Amazon MSK distributes the broker nodes evenly across the subnets that you specify.

            Client subnets can't be in Availability Zone us-east-1e.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html#cfn-msk-cluster-brokernodegroupinfo-clientsubnets
            '''
            result = self._values.get("client_subnets")
            assert result is not None, "Required property 'client_subnets' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def instance_type(self) -> builtins.str:
            '''The type of Amazon EC2 instances to use for brokers.

            The following instance types are allowed: kafka.m5.large, kafka.m5.xlarge, kafka.m5.2xlarge, kafka.m5.4xlarge, kafka.m5.8xlarge, kafka.m5.12xlarge, kafka.m5.16xlarge, and kafka.m5.24xlarge.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html#cfn-msk-cluster-brokernodegroupinfo-instancetype
            '''
            result = self._values.get("instance_type")
            assert result is not None, "Required property 'instance_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def broker_az_distribution(self) -> typing.Optional[builtins.str]:
            '''This parameter is currently not in use.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html#cfn-msk-cluster-brokernodegroupinfo-brokerazdistribution
            '''
            result = self._values.get("broker_az_distribution")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def connectivity_info(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.ConnectivityInfoProperty", _IResolvable_da3f097b]]:
            '''Information about the cluster's connectivity setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html#cfn-msk-cluster-brokernodegroupinfo-connectivityinfo
            '''
            result = self._values.get("connectivity_info")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.ConnectivityInfoProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The security groups to associate with the elastic network interfaces in order to specify who can connect to and communicate with the Amazon MSK cluster.

            If you don't specify a security group, Amazon MSK uses the default security group associated with the VPC. If you specify security groups that were shared with you, you must ensure that you have permissions to them. Specifically, you need the ``ec2:DescribeSecurityGroups`` permission.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html#cfn-msk-cluster-brokernodegroupinfo-securitygroups
            '''
            result = self._values.get("security_groups")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def storage_info(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.StorageInfoProperty", _IResolvable_da3f097b]]:
            '''Contains information about storage volumes attached to MSK broker nodes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html#cfn-msk-cluster-brokernodegroupinfo-storageinfo
            '''
            result = self._values.get("storage_info")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.StorageInfoProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BrokerNodeGroupInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.ClientAuthenticationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "sasl": "sasl",
            "tls": "tls",
            "unauthenticated": "unauthenticated",
        },
    )
    class ClientAuthenticationProperty:
        def __init__(
            self,
            *,
            sasl: typing.Optional[typing.Union["CfnCluster.SaslProperty", _IResolvable_da3f097b]] = None,
            tls: typing.Optional[typing.Union["CfnCluster.TlsProperty", _IResolvable_da3f097b]] = None,
            unauthenticated: typing.Optional[typing.Union["CfnCluster.UnauthenticatedProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Includes information related to client authentication.

            :param sasl: Details for ClientAuthentication using SASL.
            :param tls: Details for client authentication using TLS.
            :param unauthenticated: Details for ClientAuthentication using no authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-clientauthentication.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                client_authentication_property = msk.CfnCluster.ClientAuthenticationProperty(
                    sasl=msk.CfnCluster.SaslProperty(
                        iam=msk.CfnCluster.IamProperty(
                            enabled=False
                        ),
                        scram=msk.CfnCluster.ScramProperty(
                            enabled=False
                        )
                    ),
                    tls=msk.CfnCluster.TlsProperty(
                        certificate_authority_arn_list=["certificateAuthorityArnList"],
                        enabled=False
                    ),
                    unauthenticated=msk.CfnCluster.UnauthenticatedProperty(
                        enabled=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if sasl is not None:
                self._values["sasl"] = sasl
            if tls is not None:
                self._values["tls"] = tls
            if unauthenticated is not None:
                self._values["unauthenticated"] = unauthenticated

        @builtins.property
        def sasl(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.SaslProperty", _IResolvable_da3f097b]]:
            '''Details for ClientAuthentication using SASL.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-clientauthentication.html#cfn-msk-cluster-clientauthentication-sasl
            '''
            result = self._values.get("sasl")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.SaslProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def tls(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.TlsProperty", _IResolvable_da3f097b]]:
            '''Details for client authentication using TLS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-clientauthentication.html#cfn-msk-cluster-clientauthentication-tls
            '''
            result = self._values.get("tls")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.TlsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def unauthenticated(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.UnauthenticatedProperty", _IResolvable_da3f097b]]:
            '''Details for ClientAuthentication using no authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-clientauthentication.html#cfn-msk-cluster-clientauthentication-unauthenticated
            '''
            result = self._values.get("unauthenticated")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.UnauthenticatedProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ClientAuthenticationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.CloudWatchLogsProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled", "log_group": "logGroup"},
    )
    class CloudWatchLogsProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            log_group: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Details of the CloudWatch Logs destination for broker logs.

            :param enabled: Specifies whether broker logs get sent to the specified CloudWatch Logs destination.
            :param log_group: The CloudWatch Logs group that is the destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-cloudwatchlogs.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                cloud_watch_logs_property = msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=False,
                
                    # the properties below are optional
                    log_group="logGroup"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }
            if log_group is not None:
                self._values["log_group"] = log_group

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Specifies whether broker logs get sent to the specified CloudWatch Logs destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-cloudwatchlogs.html#cfn-msk-cluster-cloudwatchlogs-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def log_group(self) -> typing.Optional[builtins.str]:
            '''The CloudWatch Logs group that is the destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-cloudwatchlogs.html#cfn-msk-cluster-cloudwatchlogs-loggroup
            '''
            result = self._values.get("log_group")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CloudWatchLogsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.ConfigurationInfoProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn", "revision": "revision"},
    )
    class ConfigurationInfoProperty:
        def __init__(self, *, arn: builtins.str, revision: jsii.Number) -> None:
            '''Specifies the Amazon MSK configuration to use for the brokers.

            :param arn: The Amazon Resource Name (ARN) of the MSK configuration to use. For example, ``arn:aws:kafka:us-east-1:123456789012:configuration/example-configuration-name/abcdabcd-1234-abcd-1234-abcd123e8e8e-1`` .
            :param revision: The revision of the Amazon MSK configuration to use.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-configurationinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                configuration_info_property = msk.CfnCluster.ConfigurationInfoProperty(
                    arn="arn",
                    revision=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
                "revision": revision,
            }

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the MSK configuration to use.

            For example, ``arn:aws:kafka:us-east-1:123456789012:configuration/example-configuration-name/abcdabcd-1234-abcd-1234-abcd123e8e8e-1`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-configurationinfo.html#cfn-msk-cluster-configurationinfo-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def revision(self) -> jsii.Number:
            '''The revision of the Amazon MSK configuration to use.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-configurationinfo.html#cfn-msk-cluster-configurationinfo-revision
            '''
            result = self._values.get("revision")
            assert result is not None, "Required property 'revision' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConfigurationInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.ConnectivityInfoProperty",
        jsii_struct_bases=[],
        name_mapping={"public_access": "publicAccess"},
    )
    class ConnectivityInfoProperty:
        def __init__(
            self,
            *,
            public_access: typing.Optional[typing.Union["CfnCluster.PublicAccessProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies whether the cluster's brokers are publicly accessible.

            By default, they are not.

            :param public_access: Specifies whether the cluster's brokers are accessible from the internet. Public access is off by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-connectivityinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                connectivity_info_property = msk.CfnCluster.ConnectivityInfoProperty(
                    public_access=msk.CfnCluster.PublicAccessProperty(
                        type="type"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if public_access is not None:
                self._values["public_access"] = public_access

        @builtins.property
        def public_access(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.PublicAccessProperty", _IResolvable_da3f097b]]:
            '''Specifies whether the cluster's brokers are accessible from the internet.

            Public access is off by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-connectivityinfo.html#cfn-msk-cluster-connectivityinfo-publicaccess
            '''
            result = self._values.get("public_access")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.PublicAccessProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectivityInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.EBSStorageInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "provisioned_throughput": "provisionedThroughput",
            "volume_size": "volumeSize",
        },
    )
    class EBSStorageInfoProperty:
        def __init__(
            self,
            *,
            provisioned_throughput: typing.Optional[typing.Union["CfnCluster.ProvisionedThroughputProperty", _IResolvable_da3f097b]] = None,
            volume_size: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Contains information about the EBS storage volumes attached to brokers.

            :param provisioned_throughput: Specifies whether provisioned throughput is turned on and the volume throughput target.
            :param volume_size: The size in GiB of the EBS volume for the data drive on each broker node.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-ebsstorageinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                e_bSStorage_info_property = msk.CfnCluster.EBSStorageInfoProperty(
                    provisioned_throughput=msk.CfnCluster.ProvisionedThroughputProperty(
                        enabled=False,
                        volume_throughput=123
                    ),
                    volume_size=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if provisioned_throughput is not None:
                self._values["provisioned_throughput"] = provisioned_throughput
            if volume_size is not None:
                self._values["volume_size"] = volume_size

        @builtins.property
        def provisioned_throughput(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.ProvisionedThroughputProperty", _IResolvable_da3f097b]]:
            '''Specifies whether provisioned throughput is turned on and the volume throughput target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-ebsstorageinfo.html#cfn-msk-cluster-ebsstorageinfo-provisionedthroughput
            '''
            result = self._values.get("provisioned_throughput")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.ProvisionedThroughputProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def volume_size(self) -> typing.Optional[jsii.Number]:
            '''The size in GiB of the EBS volume for the data drive on each broker node.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-ebsstorageinfo.html#cfn-msk-cluster-ebsstorageinfo-volumesize
            '''
            result = self._values.get("volume_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EBSStorageInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.EncryptionAtRestProperty",
        jsii_struct_bases=[],
        name_mapping={"data_volume_kms_key_id": "dataVolumeKmsKeyId"},
    )
    class EncryptionAtRestProperty:
        def __init__(self, *, data_volume_kms_key_id: builtins.str) -> None:
            '''The data volume encryption details.

            :param data_volume_kms_key_id: The ARN of the Amazon KMS key for encrypting data at rest. If you don't specify a KMS key, MSK creates one for you and uses it on your behalf.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-encryptionatrest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                encryption_at_rest_property = msk.CfnCluster.EncryptionAtRestProperty(
                    data_volume_kms_key_id="dataVolumeKmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "data_volume_kms_key_id": data_volume_kms_key_id,
            }

        @builtins.property
        def data_volume_kms_key_id(self) -> builtins.str:
            '''The ARN of the Amazon KMS key for encrypting data at rest.

            If you don't specify a KMS key, MSK creates one for you and uses it on your behalf.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-encryptionatrest.html#cfn-msk-cluster-encryptionatrest-datavolumekmskeyid
            '''
            result = self._values.get("data_volume_kms_key_id")
            assert result is not None, "Required property 'data_volume_kms_key_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionAtRestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.EncryptionInTransitProperty",
        jsii_struct_bases=[],
        name_mapping={"client_broker": "clientBroker", "in_cluster": "inCluster"},
    )
    class EncryptionInTransitProperty:
        def __init__(
            self,
            *,
            client_broker: typing.Optional[builtins.str] = None,
            in_cluster: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The settings for encrypting data in transit.

            :param client_broker: Indicates the encryption setting for data in transit between clients and brokers. The following are the possible values. - ``TLS`` means that client-broker communication is enabled with TLS only. - ``TLS_PLAINTEXT`` means that client-broker communication is enabled for both TLS-encrypted, as well as plain text data. - ``PLAINTEXT`` means that client-broker communication is enabled in plain text only. The default value is ``TLS`` .
            :param in_cluster: When set to true, it indicates that data communication among the broker nodes of the cluster is encrypted. When set to false, the communication happens in plain text. The default value is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-encryptionintransit.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                encryption_in_transit_property = msk.CfnCluster.EncryptionInTransitProperty(
                    client_broker="clientBroker",
                    in_cluster=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if client_broker is not None:
                self._values["client_broker"] = client_broker
            if in_cluster is not None:
                self._values["in_cluster"] = in_cluster

        @builtins.property
        def client_broker(self) -> typing.Optional[builtins.str]:
            '''Indicates the encryption setting for data in transit between clients and brokers. The following are the possible values.

            - ``TLS`` means that client-broker communication is enabled with TLS only.
            - ``TLS_PLAINTEXT`` means that client-broker communication is enabled for both TLS-encrypted, as well as plain text data.
            - ``PLAINTEXT`` means that client-broker communication is enabled in plain text only.

            The default value is ``TLS`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-encryptionintransit.html#cfn-msk-cluster-encryptionintransit-clientbroker
            '''
            result = self._values.get("client_broker")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def in_cluster(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When set to true, it indicates that data communication among the broker nodes of the cluster is encrypted.

            When set to false, the communication happens in plain text. The default value is true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-encryptionintransit.html#cfn-msk-cluster-encryptionintransit-incluster
            '''
            result = self._values.get("in_cluster")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionInTransitProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.EncryptionInfoProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encryption_at_rest": "encryptionAtRest",
            "encryption_in_transit": "encryptionInTransit",
        },
    )
    class EncryptionInfoProperty:
        def __init__(
            self,
            *,
            encryption_at_rest: typing.Optional[typing.Union["CfnCluster.EncryptionAtRestProperty", _IResolvable_da3f097b]] = None,
            encryption_in_transit: typing.Optional[typing.Union["CfnCluster.EncryptionInTransitProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Includes encryption-related information, such as the Amazon KMS key used for encrypting data at rest and whether you want MSK to encrypt your data in transit.

            :param encryption_at_rest: The data-volume encryption details.
            :param encryption_in_transit: The details for encryption in transit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-encryptioninfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                encryption_info_property = msk.CfnCluster.EncryptionInfoProperty(
                    encryption_at_rest=msk.CfnCluster.EncryptionAtRestProperty(
                        data_volume_kms_key_id="dataVolumeKmsKeyId"
                    ),
                    encryption_in_transit=msk.CfnCluster.EncryptionInTransitProperty(
                        client_broker="clientBroker",
                        in_cluster=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if encryption_at_rest is not None:
                self._values["encryption_at_rest"] = encryption_at_rest
            if encryption_in_transit is not None:
                self._values["encryption_in_transit"] = encryption_in_transit

        @builtins.property
        def encryption_at_rest(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.EncryptionAtRestProperty", _IResolvable_da3f097b]]:
            '''The data-volume encryption details.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-encryptioninfo.html#cfn-msk-cluster-encryptioninfo-encryptionatrest
            '''
            result = self._values.get("encryption_at_rest")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.EncryptionAtRestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def encryption_in_transit(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.EncryptionInTransitProperty", _IResolvable_da3f097b]]:
            '''The details for encryption in transit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-encryptioninfo.html#cfn-msk-cluster-encryptioninfo-encryptionintransit
            '''
            result = self._values.get("encryption_in_transit")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.EncryptionInTransitProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.FirehoseProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled", "delivery_stream": "deliveryStream"},
    )
    class FirehoseProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            delivery_stream: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Details of the Kinesis Data Firehose delivery stream that is the destination for broker logs.

            :param enabled: Specifies whether broker logs get sent to the specified Kinesis Data Firehose delivery stream.
            :param delivery_stream: The Kinesis Data Firehose delivery stream that is the destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-firehose.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                firehose_property = msk.CfnCluster.FirehoseProperty(
                    enabled=False,
                
                    # the properties below are optional
                    delivery_stream="deliveryStream"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }
            if delivery_stream is not None:
                self._values["delivery_stream"] = delivery_stream

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Specifies whether broker logs get sent to the specified Kinesis Data Firehose delivery stream.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-firehose.html#cfn-msk-cluster-firehose-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def delivery_stream(self) -> typing.Optional[builtins.str]:
            '''The Kinesis Data Firehose delivery stream that is the destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-firehose.html#cfn-msk-cluster-firehose-deliverystream
            '''
            result = self._values.get("delivery_stream")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FirehoseProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.IamProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled"},
    )
    class IamProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Details for IAM access control.

            :param enabled: Whether IAM access control is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-iam.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                iam_property = msk.CfnCluster.IamProperty(
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Whether IAM access control is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-iam.html#cfn-msk-cluster-iam-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IamProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.JmxExporterProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled_in_broker": "enabledInBroker"},
    )
    class JmxExporterProperty:
        def __init__(
            self,
            *,
            enabled_in_broker: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Indicates whether you want to enable or disable the JMX Exporter.

            :param enabled_in_broker: Indicates whether you want to enable or disable the JMX Exporter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-jmxexporter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                jmx_exporter_property = msk.CfnCluster.JmxExporterProperty(
                    enabled_in_broker=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled_in_broker": enabled_in_broker,
            }

        @builtins.property
        def enabled_in_broker(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Indicates whether you want to enable or disable the JMX Exporter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-jmxexporter.html#cfn-msk-cluster-jmxexporter-enabledinbroker
            '''
            result = self._values.get("enabled_in_broker")
            assert result is not None, "Required property 'enabled_in_broker' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JmxExporterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.LoggingInfoProperty",
        jsii_struct_bases=[],
        name_mapping={"broker_logs": "brokerLogs"},
    )
    class LoggingInfoProperty:
        def __init__(
            self,
            *,
            broker_logs: typing.Union["CfnCluster.BrokerLogsProperty", _IResolvable_da3f097b],
        ) -> None:
            '''You can configure your Amazon MSK cluster to send broker logs to different destination types.

            This is a container for the configuration details related to broker logs.

            :param broker_logs: You can configure your Amazon MSK cluster to send broker logs to different destination types. This configuration specifies the details of these destinations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-logginginfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                logging_info_property = msk.CfnCluster.LoggingInfoProperty(
                    broker_logs=msk.CfnCluster.BrokerLogsProperty(
                        cloud_watch_logs=msk.CfnCluster.CloudWatchLogsProperty(
                            enabled=False,
                
                            # the properties below are optional
                            log_group="logGroup"
                        ),
                        firehose=msk.CfnCluster.FirehoseProperty(
                            enabled=False,
                
                            # the properties below are optional
                            delivery_stream="deliveryStream"
                        ),
                        s3=msk.CfnCluster.S3Property(
                            enabled=False,
                
                            # the properties below are optional
                            bucket="bucket",
                            prefix="prefix"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "broker_logs": broker_logs,
            }

        @builtins.property
        def broker_logs(
            self,
        ) -> typing.Union["CfnCluster.BrokerLogsProperty", _IResolvable_da3f097b]:
            '''You can configure your Amazon MSK cluster to send broker logs to different destination types.

            This configuration specifies the details of these destinations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-logginginfo.html#cfn-msk-cluster-logginginfo-brokerlogs
            '''
            result = self._values.get("broker_logs")
            assert result is not None, "Required property 'broker_logs' is missing"
            return typing.cast(typing.Union["CfnCluster.BrokerLogsProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggingInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.NodeExporterProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled_in_broker": "enabledInBroker"},
    )
    class NodeExporterProperty:
        def __init__(
            self,
            *,
            enabled_in_broker: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Indicates whether you want to enable or disable the Node Exporter.

            :param enabled_in_broker: Indicates whether you want to enable or disable the Node Exporter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-nodeexporter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                node_exporter_property = msk.CfnCluster.NodeExporterProperty(
                    enabled_in_broker=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled_in_broker": enabled_in_broker,
            }

        @builtins.property
        def enabled_in_broker(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Indicates whether you want to enable or disable the Node Exporter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-nodeexporter.html#cfn-msk-cluster-nodeexporter-enabledinbroker
            '''
            result = self._values.get("enabled_in_broker")
            assert result is not None, "Required property 'enabled_in_broker' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NodeExporterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.OpenMonitoringProperty",
        jsii_struct_bases=[],
        name_mapping={"prometheus": "prometheus"},
    )
    class OpenMonitoringProperty:
        def __init__(
            self,
            *,
            prometheus: typing.Union["CfnCluster.PrometheusProperty", _IResolvable_da3f097b],
        ) -> None:
            '''JMX and Node monitoring for the MSK cluster.

            :param prometheus: Prometheus exporter settings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-openmonitoring.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                open_monitoring_property = msk.CfnCluster.OpenMonitoringProperty(
                    prometheus=msk.CfnCluster.PrometheusProperty(
                        jmx_exporter=msk.CfnCluster.JmxExporterProperty(
                            enabled_in_broker=False
                        ),
                        node_exporter=msk.CfnCluster.NodeExporterProperty(
                            enabled_in_broker=False
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "prometheus": prometheus,
            }

        @builtins.property
        def prometheus(
            self,
        ) -> typing.Union["CfnCluster.PrometheusProperty", _IResolvable_da3f097b]:
            '''Prometheus exporter settings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-openmonitoring.html#cfn-msk-cluster-openmonitoring-prometheus
            '''
            result = self._values.get("prometheus")
            assert result is not None, "Required property 'prometheus' is missing"
            return typing.cast(typing.Union["CfnCluster.PrometheusProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OpenMonitoringProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.PrometheusProperty",
        jsii_struct_bases=[],
        name_mapping={"jmx_exporter": "jmxExporter", "node_exporter": "nodeExporter"},
    )
    class PrometheusProperty:
        def __init__(
            self,
            *,
            jmx_exporter: typing.Optional[typing.Union["CfnCluster.JmxExporterProperty", _IResolvable_da3f097b]] = None,
            node_exporter: typing.Optional[typing.Union["CfnCluster.NodeExporterProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Prometheus settings for open monitoring.

            :param jmx_exporter: Indicates whether you want to enable or disable the JMX Exporter.
            :param node_exporter: Indicates whether you want to enable or disable the Node Exporter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-prometheus.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                prometheus_property = msk.CfnCluster.PrometheusProperty(
                    jmx_exporter=msk.CfnCluster.JmxExporterProperty(
                        enabled_in_broker=False
                    ),
                    node_exporter=msk.CfnCluster.NodeExporterProperty(
                        enabled_in_broker=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if jmx_exporter is not None:
                self._values["jmx_exporter"] = jmx_exporter
            if node_exporter is not None:
                self._values["node_exporter"] = node_exporter

        @builtins.property
        def jmx_exporter(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.JmxExporterProperty", _IResolvable_da3f097b]]:
            '''Indicates whether you want to enable or disable the JMX Exporter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-prometheus.html#cfn-msk-cluster-prometheus-jmxexporter
            '''
            result = self._values.get("jmx_exporter")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.JmxExporterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def node_exporter(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.NodeExporterProperty", _IResolvable_da3f097b]]:
            '''Indicates whether you want to enable or disable the Node Exporter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-prometheus.html#cfn-msk-cluster-prometheus-nodeexporter
            '''
            result = self._values.get("node_exporter")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.NodeExporterProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PrometheusProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.ProvisionedThroughputProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled", "volume_throughput": "volumeThroughput"},
    )
    class ProvisionedThroughputProperty:
        def __init__(
            self,
            *,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            volume_throughput: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies whether provisioned throughput is turned on and the volume throughput target.

            :param enabled: Specifies whether provisioned throughput is turned on for the cluster.
            :param volume_throughput: The provisioned throughput rate in MiB per second.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-provisionedthroughput.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                provisioned_throughput_property = msk.CfnCluster.ProvisionedThroughputProperty(
                    enabled=False,
                    volume_throughput=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if enabled is not None:
                self._values["enabled"] = enabled
            if volume_throughput is not None:
                self._values["volume_throughput"] = volume_throughput

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether provisioned throughput is turned on for the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-provisionedthroughput.html#cfn-msk-cluster-provisionedthroughput-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def volume_throughput(self) -> typing.Optional[jsii.Number]:
            '''The provisioned throughput rate in MiB per second.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-provisionedthroughput.html#cfn-msk-cluster-provisionedthroughput-volumethroughput
            '''
            result = self._values.get("volume_throughput")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ProvisionedThroughputProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.PublicAccessProperty",
        jsii_struct_bases=[],
        name_mapping={"type": "type"},
    )
    class PublicAccessProperty:
        def __init__(self, *, type: typing.Optional[builtins.str] = None) -> None:
            '''Specifies whether the cluster's brokers are accessible from the internet.

            Public access is off by default.

            :param type: Set to ``DISABLED`` to turn off public access or to ``SERVICE_PROVIDED_EIPS`` to turn it on. Public access if off by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-publicaccess.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                public_access_property = msk.CfnCluster.PublicAccessProperty(
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''Set to ``DISABLED`` to turn off public access or to ``SERVICE_PROVIDED_EIPS`` to turn it on.

            Public access if off by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-publicaccess.html#cfn-msk-cluster-publicaccess-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PublicAccessProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.S3Property",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled", "bucket": "bucket", "prefix": "prefix"},
    )
    class S3Property:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            bucket: typing.Optional[builtins.str] = None,
            prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The details of the Amazon S3 destination for broker logs.

            :param enabled: Specifies whether broker logs get sent to the specified Amazon S3 destination.
            :param bucket: The name of the S3 bucket that is the destination for broker logs.
            :param prefix: The S3 prefix that is the destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-s3.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                s3_property = msk.CfnCluster.S3Property(
                    enabled=False,
                
                    # the properties below are optional
                    bucket="bucket",
                    prefix="prefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }
            if bucket is not None:
                self._values["bucket"] = bucket
            if prefix is not None:
                self._values["prefix"] = prefix

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Specifies whether broker logs get sent to the specified Amazon S3 destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-s3.html#cfn-msk-cluster-s3-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def bucket(self) -> typing.Optional[builtins.str]:
            '''The name of the S3 bucket that is the destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-s3.html#cfn-msk-cluster-s3-bucket
            '''
            result = self._values.get("bucket")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''The S3 prefix that is the destination for broker logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-s3.html#cfn-msk-cluster-s3-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3Property(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.SaslProperty",
        jsii_struct_bases=[],
        name_mapping={"iam": "iam", "scram": "scram"},
    )
    class SaslProperty:
        def __init__(
            self,
            *,
            iam: typing.Optional[typing.Union["CfnCluster.IamProperty", _IResolvable_da3f097b]] = None,
            scram: typing.Optional[typing.Union["CfnCluster.ScramProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Details for client authentication using SASL.

            To turn on SASL, you must also turn on ``EncryptionInTransit`` by setting ``inCluster`` to true. You must set ``clientBroker`` to either ``TLS`` or ``TLS_PLAINTEXT`` . If you choose ``TLS_PLAINTEXT`` , then you must also set ``unauthenticated`` to true.

            :param iam: Details for IAM access control.
            :param scram: Details for SASL/SCRAM client authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-sasl.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                sasl_property = msk.CfnCluster.SaslProperty(
                    iam=msk.CfnCluster.IamProperty(
                        enabled=False
                    ),
                    scram=msk.CfnCluster.ScramProperty(
                        enabled=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if iam is not None:
                self._values["iam"] = iam
            if scram is not None:
                self._values["scram"] = scram

        @builtins.property
        def iam(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.IamProperty", _IResolvable_da3f097b]]:
            '''Details for IAM access control.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-sasl.html#cfn-msk-cluster-sasl-iam
            '''
            result = self._values.get("iam")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.IamProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def scram(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.ScramProperty", _IResolvable_da3f097b]]:
            '''Details for SASL/SCRAM client authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-sasl.html#cfn-msk-cluster-sasl-scram
            '''
            result = self._values.get("scram")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.ScramProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SaslProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.ScramProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled"},
    )
    class ScramProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Details for SASL/SCRAM client authentication.

            :param enabled: SASL/SCRAM authentication is enabled or not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-scram.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                scram_property = msk.CfnCluster.ScramProperty(
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''SASL/SCRAM authentication is enabled or not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-scram.html#cfn-msk-cluster-scram-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScramProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.StorageInfoProperty",
        jsii_struct_bases=[],
        name_mapping={"ebs_storage_info": "ebsStorageInfo"},
    )
    class StorageInfoProperty:
        def __init__(
            self,
            *,
            ebs_storage_info: typing.Optional[typing.Union["CfnCluster.EBSStorageInfoProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Contains information about storage volumes attached to MSK broker nodes.

            :param ebs_storage_info: EBS volume information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-storageinfo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                storage_info_property = msk.CfnCluster.StorageInfoProperty(
                    ebs_storage_info=msk.CfnCluster.EBSStorageInfoProperty(
                        provisioned_throughput=msk.CfnCluster.ProvisionedThroughputProperty(
                            enabled=False,
                            volume_throughput=123
                        ),
                        volume_size=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ebs_storage_info is not None:
                self._values["ebs_storage_info"] = ebs_storage_info

        @builtins.property
        def ebs_storage_info(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.EBSStorageInfoProperty", _IResolvable_da3f097b]]:
            '''EBS volume information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-storageinfo.html#cfn-msk-cluster-storageinfo-ebsstorageinfo
            '''
            result = self._values.get("ebs_storage_info")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.EBSStorageInfoProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StorageInfoProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.TlsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "certificate_authority_arn_list": "certificateAuthorityArnList",
            "enabled": "enabled",
        },
    )
    class TlsProperty:
        def __init__(
            self,
            *,
            certificate_authority_arn_list: typing.Optional[typing.Sequence[builtins.str]] = None,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Details for client authentication using TLS.

            :param certificate_authority_arn_list: List of ACM Certificate Authority ARNs.
            :param enabled: TLS authentication is enabled or not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-tls.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                tls_property = msk.CfnCluster.TlsProperty(
                    certificate_authority_arn_list=["certificateAuthorityArnList"],
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if certificate_authority_arn_list is not None:
                self._values["certificate_authority_arn_list"] = certificate_authority_arn_list
            if enabled is not None:
                self._values["enabled"] = enabled

        @builtins.property
        def certificate_authority_arn_list(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''List of ACM Certificate Authority ARNs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-tls.html#cfn-msk-cluster-tls-certificateauthorityarnlist
            '''
            result = self._values.get("certificate_authority_arn_list")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''TLS authentication is enabled or not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-tls.html#cfn-msk-cluster-tls-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TlsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_msk.CfnCluster.UnauthenticatedProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled"},
    )
    class UnauthenticatedProperty:
        def __init__(
            self,
            *,
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Details for allowing no client authentication.

            :param enabled: Unauthenticated is enabled or not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-unauthenticated.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_msk as msk
                
                unauthenticated_property = msk.CfnCluster.UnauthenticatedProperty(
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "enabled": enabled,
            }

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Unauthenticated is enabled or not.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-unauthenticated.html#cfn-msk-cluster-unauthenticated-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UnauthenticatedProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_msk.CfnClusterProps",
    jsii_struct_bases=[],
    name_mapping={
        "broker_node_group_info": "brokerNodeGroupInfo",
        "cluster_name": "clusterName",
        "kafka_version": "kafkaVersion",
        "number_of_broker_nodes": "numberOfBrokerNodes",
        "client_authentication": "clientAuthentication",
        "configuration_info": "configurationInfo",
        "encryption_info": "encryptionInfo",
        "enhanced_monitoring": "enhancedMonitoring",
        "logging_info": "loggingInfo",
        "open_monitoring": "openMonitoring",
        "tags": "tags",
    },
)
class CfnClusterProps:
    def __init__(
        self,
        *,
        broker_node_group_info: typing.Union[CfnCluster.BrokerNodeGroupInfoProperty, _IResolvable_da3f097b],
        cluster_name: builtins.str,
        kafka_version: builtins.str,
        number_of_broker_nodes: jsii.Number,
        client_authentication: typing.Optional[typing.Union[CfnCluster.ClientAuthenticationProperty, _IResolvable_da3f097b]] = None,
        configuration_info: typing.Optional[typing.Union[CfnCluster.ConfigurationInfoProperty, _IResolvable_da3f097b]] = None,
        encryption_info: typing.Optional[typing.Union[CfnCluster.EncryptionInfoProperty, _IResolvable_da3f097b]] = None,
        enhanced_monitoring: typing.Optional[builtins.str] = None,
        logging_info: typing.Optional[typing.Union[CfnCluster.LoggingInfoProperty, _IResolvable_da3f097b]] = None,
        open_monitoring: typing.Optional[typing.Union[CfnCluster.OpenMonitoringProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnCluster``.

        :param broker_node_group_info: The setup to be used for brokers in the cluster.
        :param cluster_name: The name of the cluster.
        :param kafka_version: The version of Apache Kafka. For more information, see `Supported Apache Kafka versions <https://docs.aws.amazon.com/msk/latest/developerguide/supported-kafka-versions.html>`_ in the Amazon MSK Developer Guide.
        :param number_of_broker_nodes: The number of broker nodes you want in the Amazon MSK cluster. You can submit an update to increase the number of broker nodes in a cluster.
        :param client_authentication: Includes information related to client authentication.
        :param configuration_info: The Amazon MSK configuration to use for the cluster.
        :param encryption_info: Includes all encryption-related information.
        :param enhanced_monitoring: Specifies the level of monitoring for the MSK cluster. The possible values are ``DEFAULT`` , ``PER_BROKER`` , and ``PER_TOPIC_PER_BROKER`` .
        :param logging_info: You can configure your Amazon MSK cluster to send broker logs to different destination types. This is a container for the configuration details related to broker logs.
        :param open_monitoring: The settings for open monitoring.
        :param tags: A map of key:value pairs to apply to this resource. Both key and value are of type String.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_msk as msk
            
            # tags: Any
            
            cfn_cluster_props = msk.CfnClusterProps(
                broker_node_group_info=msk.CfnCluster.BrokerNodeGroupInfoProperty(
                    client_subnets=["clientSubnets"],
                    instance_type="instanceType",
            
                    # the properties below are optional
                    broker_az_distribution="brokerAzDistribution",
                    connectivity_info=msk.CfnCluster.ConnectivityInfoProperty(
                        public_access=msk.CfnCluster.PublicAccessProperty(
                            type="type"
                        )
                    ),
                    security_groups=["securityGroups"],
                    storage_info=msk.CfnCluster.StorageInfoProperty(
                        ebs_storage_info=msk.CfnCluster.EBSStorageInfoProperty(
                            provisioned_throughput=msk.CfnCluster.ProvisionedThroughputProperty(
                                enabled=False,
                                volume_throughput=123
                            ),
                            volume_size=123
                        )
                    )
                ),
                cluster_name="clusterName",
                kafka_version="kafkaVersion",
                number_of_broker_nodes=123,
            
                # the properties below are optional
                client_authentication=msk.CfnCluster.ClientAuthenticationProperty(
                    sasl=msk.CfnCluster.SaslProperty(
                        iam=msk.CfnCluster.IamProperty(
                            enabled=False
                        ),
                        scram=msk.CfnCluster.ScramProperty(
                            enabled=False
                        )
                    ),
                    tls=msk.CfnCluster.TlsProperty(
                        certificate_authority_arn_list=["certificateAuthorityArnList"],
                        enabled=False
                    ),
                    unauthenticated=msk.CfnCluster.UnauthenticatedProperty(
                        enabled=False
                    )
                ),
                configuration_info=msk.CfnCluster.ConfigurationInfoProperty(
                    arn="arn",
                    revision=123
                ),
                encryption_info=msk.CfnCluster.EncryptionInfoProperty(
                    encryption_at_rest=msk.CfnCluster.EncryptionAtRestProperty(
                        data_volume_kms_key_id="dataVolumeKmsKeyId"
                    ),
                    encryption_in_transit=msk.CfnCluster.EncryptionInTransitProperty(
                        client_broker="clientBroker",
                        in_cluster=False
                    )
                ),
                enhanced_monitoring="enhancedMonitoring",
                logging_info=msk.CfnCluster.LoggingInfoProperty(
                    broker_logs=msk.CfnCluster.BrokerLogsProperty(
                        cloud_watch_logs=msk.CfnCluster.CloudWatchLogsProperty(
                            enabled=False,
            
                            # the properties below are optional
                            log_group="logGroup"
                        ),
                        firehose=msk.CfnCluster.FirehoseProperty(
                            enabled=False,
            
                            # the properties below are optional
                            delivery_stream="deliveryStream"
                        ),
                        s3=msk.CfnCluster.S3Property(
                            enabled=False,
            
                            # the properties below are optional
                            bucket="bucket",
                            prefix="prefix"
                        )
                    )
                ),
                open_monitoring=msk.CfnCluster.OpenMonitoringProperty(
                    prometheus=msk.CfnCluster.PrometheusProperty(
                        jmx_exporter=msk.CfnCluster.JmxExporterProperty(
                            enabled_in_broker=False
                        ),
                        node_exporter=msk.CfnCluster.NodeExporterProperty(
                            enabled_in_broker=False
                        )
                    )
                ),
                tags=tags
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "broker_node_group_info": broker_node_group_info,
            "cluster_name": cluster_name,
            "kafka_version": kafka_version,
            "number_of_broker_nodes": number_of_broker_nodes,
        }
        if client_authentication is not None:
            self._values["client_authentication"] = client_authentication
        if configuration_info is not None:
            self._values["configuration_info"] = configuration_info
        if encryption_info is not None:
            self._values["encryption_info"] = encryption_info
        if enhanced_monitoring is not None:
            self._values["enhanced_monitoring"] = enhanced_monitoring
        if logging_info is not None:
            self._values["logging_info"] = logging_info
        if open_monitoring is not None:
            self._values["open_monitoring"] = open_monitoring
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def broker_node_group_info(
        self,
    ) -> typing.Union[CfnCluster.BrokerNodeGroupInfoProperty, _IResolvable_da3f097b]:
        '''The setup to be used for brokers in the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-brokernodegroupinfo
        '''
        result = self._values.get("broker_node_group_info")
        assert result is not None, "Required property 'broker_node_group_info' is missing"
        return typing.cast(typing.Union[CfnCluster.BrokerNodeGroupInfoProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def cluster_name(self) -> builtins.str:
        '''The name of the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-clustername
        '''
        result = self._values.get("cluster_name")
        assert result is not None, "Required property 'cluster_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def kafka_version(self) -> builtins.str:
        '''The version of Apache Kafka.

        For more information, see `Supported Apache Kafka versions <https://docs.aws.amazon.com/msk/latest/developerguide/supported-kafka-versions.html>`_ in the Amazon MSK Developer Guide.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-kafkaversion
        '''
        result = self._values.get("kafka_version")
        assert result is not None, "Required property 'kafka_version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def number_of_broker_nodes(self) -> jsii.Number:
        '''The number of broker nodes you want in the Amazon MSK cluster.

        You can submit an update to increase the number of broker nodes in a cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-numberofbrokernodes
        '''
        result = self._values.get("number_of_broker_nodes")
        assert result is not None, "Required property 'number_of_broker_nodes' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def client_authentication(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.ClientAuthenticationProperty, _IResolvable_da3f097b]]:
        '''Includes information related to client authentication.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-clientauthentication
        '''
        result = self._values.get("client_authentication")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.ClientAuthenticationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def configuration_info(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.ConfigurationInfoProperty, _IResolvable_da3f097b]]:
        '''The Amazon MSK configuration to use for the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-configurationinfo
        '''
        result = self._values.get("configuration_info")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.ConfigurationInfoProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def encryption_info(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.EncryptionInfoProperty, _IResolvable_da3f097b]]:
        '''Includes all encryption-related information.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo
        '''
        result = self._values.get("encryption_info")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.EncryptionInfoProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def enhanced_monitoring(self) -> typing.Optional[builtins.str]:
        '''Specifies the level of monitoring for the MSK cluster.

        The possible values are ``DEFAULT`` , ``PER_BROKER`` , and ``PER_TOPIC_PER_BROKER`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-enhancedmonitoring
        '''
        result = self._values.get("enhanced_monitoring")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def logging_info(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.LoggingInfoProperty, _IResolvable_da3f097b]]:
        '''You can configure your Amazon MSK cluster to send broker logs to different destination types.

        This is a container for the configuration details related to broker logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-logginginfo
        '''
        result = self._values.get("logging_info")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.LoggingInfoProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def open_monitoring(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.OpenMonitoringProperty, _IResolvable_da3f097b]]:
        '''The settings for open monitoring.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-openmonitoring
        '''
        result = self._values.get("open_monitoring")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.OpenMonitoringProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''A map of key:value pairs to apply to this resource.

        Both key and value are of type String.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnClusterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnCluster",
    "CfnClusterProps",
]

publication.publish()
