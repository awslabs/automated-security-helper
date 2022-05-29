'''
# Amazon MQ Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_amazonmq as amazonmq
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-amazonmq-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::AmazonMQ](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_AmazonMQ.html).

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
class CfnBroker(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_amazonmq.CfnBroker",
):
    '''A CloudFormation ``AWS::AmazonMQ::Broker``.

    A *broker* is a message broker environment running on Amazon MQ . It is the basic building block of Amazon MQ .

    The ``AWS::AmazonMQ::Broker`` resource lets you create Amazon MQ for ActiveMQ and Amazon MQ for RabbitMQ brokers, add configuration changes or modify users for a speified ActiveMQ broker, return information about the specified broker, and delete the broker. For more information, see `How Amazon MQ works <https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/amazon-mq-how-it-works.html>`_ in the *Amazon MQ Developer Guide* .

    - ``ec2:CreateNetworkInterface``

    This permission is required to allow Amazon MQ to create an elastic network interface (ENI) on behalf of your account.

    - ``ec2:CreateNetworkInterfacePermission``

    This permission is required to attach the ENI to the broker instance.

    - ``ec2:DeleteNetworkInterface``
    - ``ec2:DeleteNetworkInterfacePermission``
    - ``ec2:DetachNetworkInterface``
    - ``ec2:DescribeInternetGateways``
    - ``ec2:DescribeNetworkInterfaces``
    - ``ec2:DescribeNetworkInterfacePermissions``
    - ``ec2:DescribeRouteTables``
    - ``ec2:DescribeSecurityGroups``
    - ``ec2:DescribeSubnets``
    - ``ec2:DescribeVpcs``

    :cloudformationResource: AWS::AmazonMQ::Broker
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_amazonmq as amazonmq
        
        cfn_broker = amazonmq.CfnBroker(self, "MyCfnBroker",
            auto_minor_version_upgrade=False,
            broker_name="brokerName",
            deployment_mode="deploymentMode",
            engine_type="engineType",
            engine_version="engineVersion",
            host_instance_type="hostInstanceType",
            publicly_accessible=False,
            users=[amazonmq.CfnBroker.UserProperty(
                password="password",
                username="username",
        
                # the properties below are optional
                console_access=False,
                groups=["groups"]
            )],
        
            # the properties below are optional
            authentication_strategy="authenticationStrategy",
            configuration=amazonmq.CfnBroker.ConfigurationIdProperty(
                id="id",
                revision=123
            ),
            encryption_options=amazonmq.CfnBroker.EncryptionOptionsProperty(
                use_aws_owned_key=False,
        
                # the properties below are optional
                kms_key_id="kmsKeyId"
            ),
            ldap_server_metadata=amazonmq.CfnBroker.LdapServerMetadataProperty(
                hosts=["hosts"],
                role_base="roleBase",
                role_search_matching="roleSearchMatching",
                service_account_password="serviceAccountPassword",
                service_account_username="serviceAccountUsername",
                user_base="userBase",
                user_search_matching="userSearchMatching",
        
                # the properties below are optional
                role_name="roleName",
                role_search_subtree=False,
                user_role_name="userRoleName",
                user_search_subtree=False
            ),
            logs=amazonmq.CfnBroker.LogListProperty(
                audit=False,
                general=False
            ),
            maintenance_window_start_time=amazonmq.CfnBroker.MaintenanceWindowProperty(
                day_of_week="dayOfWeek",
                time_of_day="timeOfDay",
                time_zone="timeZone"
            ),
            security_groups=["securityGroups"],
            storage_type="storageType",
            subnet_ids=["subnetIds"],
            tags=[amazonmq.CfnBroker.TagsEntryProperty(
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
        auto_minor_version_upgrade: typing.Union[builtins.bool, _IResolvable_da3f097b],
        broker_name: builtins.str,
        deployment_mode: builtins.str,
        engine_type: builtins.str,
        engine_version: builtins.str,
        host_instance_type: builtins.str,
        publicly_accessible: typing.Union[builtins.bool, _IResolvable_da3f097b],
        users: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBroker.UserProperty", _IResolvable_da3f097b]]],
        authentication_strategy: typing.Optional[builtins.str] = None,
        configuration: typing.Optional[typing.Union["CfnBroker.ConfigurationIdProperty", _IResolvable_da3f097b]] = None,
        encryption_options: typing.Optional[typing.Union["CfnBroker.EncryptionOptionsProperty", _IResolvable_da3f097b]] = None,
        ldap_server_metadata: typing.Optional[typing.Union["CfnBroker.LdapServerMetadataProperty", _IResolvable_da3f097b]] = None,
        logs: typing.Optional[typing.Union["CfnBroker.LogListProperty", _IResolvable_da3f097b]] = None,
        maintenance_window_start_time: typing.Optional[typing.Union["CfnBroker.MaintenanceWindowProperty", _IResolvable_da3f097b]] = None,
        security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        storage_type: typing.Optional[builtins.str] = None,
        subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence["CfnBroker.TagsEntryProperty"]] = None,
    ) -> None:
        '''Create a new ``AWS::AmazonMQ::Broker``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param auto_minor_version_upgrade: Enables automatic upgrades to new minor versions for brokers, as new broker engine versions are released and supported by Amazon MQ. Automatic upgrades occur during the scheduled maintenance window of the broker or after a manual broker reboot.
        :param broker_name: The name of the broker. This value must be unique in your AWS account , 1-50 characters long, must contain only letters, numbers, dashes, and underscores, and must not contain white spaces, brackets, wildcard characters, or special characters. .. epigraph:: Do not add personally identifiable information (PII) or other confidential or sensitive information in broker names. Broker names are accessible to other AWS services, including C CloudWatch Logs . Broker names are not intended to be used for private or sensitive data.
        :param deployment_mode: The deployment mode of the broker. Available values:. - ``SINGLE_INSTANCE`` - ``ACTIVE_STANDBY_MULTI_AZ`` - ``CLUSTER_MULTI_AZ``
        :param engine_type: The type of broker engine. Currently, Amazon MQ supports ``ACTIVEMQ`` and ``RABBITMQ`` .
        :param engine_version: The version of the broker engine. For a list of supported engine versions, see `Engine <https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html>`_ in the *Amazon MQ Developer Guide* .
        :param host_instance_type: The broker's instance type.
        :param publicly_accessible: Enables connections from applications outside of the VPC that hosts the broker's subnets.
        :param users: The list of broker users (persons or applications) who can access queues and topics. For Amazon MQ for RabbitMQ brokers, one and only one administrative user is accepted and created when a broker is first provisioned. All subsequent RabbitMQ users are created by via the RabbitMQ web console or by using the RabbitMQ management API.
        :param authentication_strategy: Optional. The authentication strategy used to secure the broker. The default is ``SIMPLE`` .
        :param configuration: A list of information about the configuration. Does not apply to RabbitMQ brokers.
        :param encryption_options: Encryption options for the broker. Does not apply to RabbitMQ brokers.
        :param ldap_server_metadata: Optional. The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.
        :param logs: Enables Amazon CloudWatch logging for brokers.
        :param maintenance_window_start_time: The scheduled time period relative to UTC during which Amazon MQ begins to apply pending updates or patches to the broker.
        :param security_groups: The list of rules (1 minimum, 125 maximum) that authorize connections to brokers.
        :param storage_type: The broker's storage type.
        :param subnet_ids: The list of groups that define which subnets and IP ranges the broker can use from different Availability Zones. If you specify more than one subnet, the subnets must be in different Availability Zones. Amazon MQ will not be able to create VPC endpoints for your broker with multiple subnets in the same Availability Zone. A SINGLE_INSTANCE deployment requires one subnet (for example, the default subnet). An ACTIVE_STANDBY_MULTI_AZ deployment (ACTIVEMQ) requires two subnets. A CLUSTER_MULTI_AZ deployment (RABBITMQ) has no subnet requirements when deployed with public accessibility, deployment without public accessibility requires at least one subnet. .. epigraph:: If you specify subnets in a shared VPC for a RabbitMQ broker, the associated VPC to which the specified subnets belong must be owned by your AWS account . Amazon MQ will not be able to create VPC enpoints in VPCs that are not owned by your AWS account .
        :param tags: An array of key-value pairs. For more information, see `Using Cost Allocation Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`_ in the *Billing and Cost Management User Guide* .
        '''
        props = CfnBrokerProps(
            auto_minor_version_upgrade=auto_minor_version_upgrade,
            broker_name=broker_name,
            deployment_mode=deployment_mode,
            engine_type=engine_type,
            engine_version=engine_version,
            host_instance_type=host_instance_type,
            publicly_accessible=publicly_accessible,
            users=users,
            authentication_strategy=authentication_strategy,
            configuration=configuration,
            encryption_options=encryption_options,
            ldap_server_metadata=ldap_server_metadata,
            logs=logs,
            maintenance_window_start_time=maintenance_window_start_time,
            security_groups=security_groups,
            storage_type=storage_type,
            subnet_ids=subnet_ids,
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
    @jsii.member(jsii_name="attrAmqpEndpoints")
    def attr_amqp_endpoints(self) -> typing.List[builtins.str]:
        '''The AMQP endpoints of each broker instance as a list of strings.

        ``amqp+ssl://b-4aada85d-a80c-4be0-9d30-e344a01b921e-1.mq.eu-central-amazonaws.com:5671``

        :cloudformationAttribute: AmqpEndpoints
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrAmqpEndpoints"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the Amazon MQ broker.

        ``arn:aws:mq:us-east-2:123456789012:broker:MyBroker:b-1234a5b6-78cd-901e-2fgh-3i45j6k178l9``

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrConfigurationId")
    def attr_configuration_id(self) -> builtins.str:
        '''The unique ID that Amazon MQ generates for the configuration.

        ``c-1234a5b6-78cd-901e-2fgh-3i45j6k178l9``

        :cloudformationAttribute: ConfigurationId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrConfigurationId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrConfigurationRevision")
    def attr_configuration_revision(self) -> jsii.Number:
        '''The revision number of the configuration.

        ``1``

        :cloudformationAttribute: ConfigurationRevision
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrConfigurationRevision"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrIpAddresses")
    def attr_ip_addresses(self) -> typing.List[builtins.str]:
        '''The IP addresses of each broker instance as a list of strings. Does not apply to RabbitMQ brokers.

        ``['198.51.100.2', '203.0.113.9']``

        :cloudformationAttribute: IpAddresses
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrIpAddresses"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrMqttEndpoints")
    def attr_mqtt_endpoints(self) -> typing.List[builtins.str]:
        '''The MQTT endpoints of each broker instance as a list of strings.

        ``mqtt+ssl://b-4aada85d-a80c-4be0-9d30-e344a01b921e-1.mq.eu-central-amazonaws.com:8883``

        :cloudformationAttribute: MqttEndpoints
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrMqttEndpoints"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrOpenWireEndpoints")
    def attr_open_wire_endpoints(self) -> typing.List[builtins.str]:
        '''The OpenWire endpoints of each broker instance as a list of strings.

        ``ssl://b-4aada85d-a80c-4be0-9d30-e344a01b921e-1.mq.eu-central-amazonaws.com:61617``

        :cloudformationAttribute: OpenWireEndpoints
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrOpenWireEndpoints"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStompEndpoints")
    def attr_stomp_endpoints(self) -> typing.List[builtins.str]:
        '''The STOMP endpoints of each broker instance as a list of strings.

        ``stomp+ssl://b-4aada85d-a80c-4be0-9d30-e344a01b921e-1.mq.eu-central-amazonaws.com:61614``

        :cloudformationAttribute: StompEndpoints
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrStompEndpoints"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrWssEndpoints")
    def attr_wss_endpoints(self) -> typing.List[builtins.str]:
        '''The WSS endpoints of each broker instance as a list of strings.

        ``wss://b-4aada85d-a80c-4be0-9d30-e344a01b921e-1.mq.eu-central-amazonaws.com:61619``

        :cloudformationAttribute: WssEndpoints
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrWssEndpoints"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs.

        For more information, see `Using Cost Allocation Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`_ in the *Billing and Cost Management User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoMinorVersionUpgrade")
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Enables automatic upgrades to new minor versions for brokers, as new broker engine versions are released and supported by Amazon MQ.

        Automatic upgrades occur during the scheduled maintenance window of the broker or after a manual broker reboot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-autominorversionupgrade
        '''
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], jsii.get(self, "autoMinorVersionUpgrade"))

    @auto_minor_version_upgrade.setter
    def auto_minor_version_upgrade(
        self,
        value: typing.Union[builtins.bool, _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "autoMinorVersionUpgrade", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="brokerName")
    def broker_name(self) -> builtins.str:
        '''The name of the broker.

        This value must be unique in your AWS account , 1-50 characters long, must contain only letters, numbers, dashes, and underscores, and must not contain white spaces, brackets, wildcard characters, or special characters.
        .. epigraph::

           Do not add personally identifiable information (PII) or other confidential or sensitive information in broker names. Broker names are accessible to other AWS services, including C CloudWatch Logs . Broker names are not intended to be used for private or sensitive data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-brokername
        '''
        return typing.cast(builtins.str, jsii.get(self, "brokerName"))

    @broker_name.setter
    def broker_name(self, value: builtins.str) -> None:
        jsii.set(self, "brokerName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deploymentMode")
    def deployment_mode(self) -> builtins.str:
        '''The deployment mode of the broker. Available values:.

        - ``SINGLE_INSTANCE``
        - ``ACTIVE_STANDBY_MULTI_AZ``
        - ``CLUSTER_MULTI_AZ``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-deploymentmode
        '''
        return typing.cast(builtins.str, jsii.get(self, "deploymentMode"))

    @deployment_mode.setter
    def deployment_mode(self, value: builtins.str) -> None:
        jsii.set(self, "deploymentMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineType")
    def engine_type(self) -> builtins.str:
        '''The type of broker engine.

        Currently, Amazon MQ supports ``ACTIVEMQ`` and ``RABBITMQ`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-enginetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "engineType"))

    @engine_type.setter
    def engine_type(self, value: builtins.str) -> None:
        jsii.set(self, "engineType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineVersion")
    def engine_version(self) -> builtins.str:
        '''The version of the broker engine.

        For a list of supported engine versions, see `Engine <https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html>`_ in the *Amazon MQ Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-engineversion
        '''
        return typing.cast(builtins.str, jsii.get(self, "engineVersion"))

    @engine_version.setter
    def engine_version(self, value: builtins.str) -> None:
        jsii.set(self, "engineVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostInstanceType")
    def host_instance_type(self) -> builtins.str:
        '''The broker's instance type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-hostinstancetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "hostInstanceType"))

    @host_instance_type.setter
    def host_instance_type(self, value: builtins.str) -> None:
        jsii.set(self, "hostInstanceType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publiclyAccessible")
    def publicly_accessible(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Enables connections from applications outside of the VPC that hosts the broker's subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-publiclyaccessible
        '''
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], jsii.get(self, "publiclyAccessible"))

    @publicly_accessible.setter
    def publicly_accessible(
        self,
        value: typing.Union[builtins.bool, _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "publiclyAccessible", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="users")
    def users(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBroker.UserProperty", _IResolvable_da3f097b]]]:
        '''The list of broker users (persons or applications) who can access queues and topics.

        For Amazon MQ for RabbitMQ brokers, one and only one administrative user is accepted and created when a broker is first provisioned. All subsequent RabbitMQ users are created by via the RabbitMQ web console or by using the RabbitMQ management API.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-users
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBroker.UserProperty", _IResolvable_da3f097b]]], jsii.get(self, "users"))

    @users.setter
    def users(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBroker.UserProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "users", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="authenticationStrategy")
    def authentication_strategy(self) -> typing.Optional[builtins.str]:
        '''Optional.

        The authentication strategy used to secure the broker. The default is ``SIMPLE`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-authenticationstrategy
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "authenticationStrategy"))

    @authentication_strategy.setter
    def authentication_strategy(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "authenticationStrategy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="configuration")
    def configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBroker.ConfigurationIdProperty", _IResolvable_da3f097b]]:
        '''A list of information about the configuration.

        Does not apply to RabbitMQ brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-configuration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBroker.ConfigurationIdProperty", _IResolvable_da3f097b]], jsii.get(self, "configuration"))

    @configuration.setter
    def configuration(
        self,
        value: typing.Optional[typing.Union["CfnBroker.ConfigurationIdProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "configuration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionOptions")
    def encryption_options(
        self,
    ) -> typing.Optional[typing.Union["CfnBroker.EncryptionOptionsProperty", _IResolvable_da3f097b]]:
        '''Encryption options for the broker.

        Does not apply to RabbitMQ brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-encryptionoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBroker.EncryptionOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "encryptionOptions"))

    @encryption_options.setter
    def encryption_options(
        self,
        value: typing.Optional[typing.Union["CfnBroker.EncryptionOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "encryptionOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ldapServerMetadata")
    def ldap_server_metadata(
        self,
    ) -> typing.Optional[typing.Union["CfnBroker.LdapServerMetadataProperty", _IResolvable_da3f097b]]:
        '''Optional.

        The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-ldapservermetadata
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBroker.LdapServerMetadataProperty", _IResolvable_da3f097b]], jsii.get(self, "ldapServerMetadata"))

    @ldap_server_metadata.setter
    def ldap_server_metadata(
        self,
        value: typing.Optional[typing.Union["CfnBroker.LdapServerMetadataProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ldapServerMetadata", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logs")
    def logs(
        self,
    ) -> typing.Optional[typing.Union["CfnBroker.LogListProperty", _IResolvable_da3f097b]]:
        '''Enables Amazon CloudWatch logging for brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-logs
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBroker.LogListProperty", _IResolvable_da3f097b]], jsii.get(self, "logs"))

    @logs.setter
    def logs(
        self,
        value: typing.Optional[typing.Union["CfnBroker.LogListProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "logs", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maintenanceWindowStartTime")
    def maintenance_window_start_time(
        self,
    ) -> typing.Optional[typing.Union["CfnBroker.MaintenanceWindowProperty", _IResolvable_da3f097b]]:
        '''The scheduled time period relative to UTC during which Amazon MQ begins to apply pending updates or patches to the broker.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-maintenancewindowstarttime
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBroker.MaintenanceWindowProperty", _IResolvable_da3f097b]], jsii.get(self, "maintenanceWindowStartTime"))

    @maintenance_window_start_time.setter
    def maintenance_window_start_time(
        self,
        value: typing.Optional[typing.Union["CfnBroker.MaintenanceWindowProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "maintenanceWindowStartTime", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroups")
    def security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of rules (1 minimum, 125 maximum) that authorize connections to brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-securitygroups
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "securityGroups"))

    @security_groups.setter
    def security_groups(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "securityGroups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="storageType")
    def storage_type(self) -> typing.Optional[builtins.str]:
        '''The broker's storage type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-storagetype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "storageType"))

    @storage_type.setter
    def storage_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "storageType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetIds")
    def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of groups that define which subnets and IP ranges the broker can use from different Availability Zones.

        If you specify more than one subnet, the subnets must be in different Availability Zones. Amazon MQ will not be able to create VPC endpoints for your broker with multiple subnets in the same Availability Zone. A SINGLE_INSTANCE deployment requires one subnet (for example, the default subnet). An ACTIVE_STANDBY_MULTI_AZ deployment (ACTIVEMQ) requires two subnets. A CLUSTER_MULTI_AZ deployment (RABBITMQ) has no subnet requirements when deployed with public accessibility, deployment without public accessibility requires at least one subnet.
        .. epigraph::

           If you specify subnets in a shared VPC for a RabbitMQ broker, the associated VPC to which the specified subnets belong must be owned by your AWS account . Amazon MQ will not be able to create VPC enpoints in VPCs that are not owned by your AWS account .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-subnetids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "subnetIds"))

    @subnet_ids.setter
    def subnet_ids(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "subnetIds", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnBroker.ConfigurationIdProperty",
        jsii_struct_bases=[],
        name_mapping={"id": "id", "revision": "revision"},
    )
    class ConfigurationIdProperty:
        def __init__(self, *, id: builtins.str, revision: jsii.Number) -> None:
            '''A list of information about the configuration.

            .. epigraph::

               Does not apply to RabbitMQ brokers.

            :param id: The unique ID that Amazon MQ generates for the configuration.
            :param revision: The revision number of the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-configurationid.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                configuration_id_property = amazonmq.CfnBroker.ConfigurationIdProperty(
                    id="id",
                    revision=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
                "revision": revision,
            }

        @builtins.property
        def id(self) -> builtins.str:
            '''The unique ID that Amazon MQ generates for the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-configurationid.html#cfn-amazonmq-broker-configurationid-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def revision(self) -> jsii.Number:
            '''The revision number of the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-configurationid.html#cfn-amazonmq-broker-configurationid-revision
            '''
            result = self._values.get("revision")
            assert result is not None, "Required property 'revision' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConfigurationIdProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnBroker.EncryptionOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={"use_aws_owned_key": "useAwsOwnedKey", "kms_key_id": "kmsKeyId"},
    )
    class EncryptionOptionsProperty:
        def __init__(
            self,
            *,
            use_aws_owned_key: typing.Union[builtins.bool, _IResolvable_da3f097b],
            kms_key_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Encryption options for the broker.

            .. epigraph::

               Does not apply to RabbitMQ brokers.

            :param use_aws_owned_key: Enables the use of an AWS owned CMK using AWS KMS (KMS). Set to ``true`` by default, if no value is provided, for example, for RabbitMQ brokers.
            :param kms_key_id: The customer master key (CMK) to use for the A AWS KMS (KMS). This key is used to encrypt your data at rest. If not provided, Amazon MQ will use a default CMK to encrypt your data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-encryptionoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                encryption_options_property = amazonmq.CfnBroker.EncryptionOptionsProperty(
                    use_aws_owned_key=False,
                
                    # the properties below are optional
                    kms_key_id="kmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "use_aws_owned_key": use_aws_owned_key,
            }
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id

        @builtins.property
        def use_aws_owned_key(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Enables the use of an AWS owned CMK using AWS KMS (KMS).

            Set to ``true`` by default, if no value is provided, for example, for RabbitMQ brokers.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-encryptionoptions.html#cfn-amazonmq-broker-encryptionoptions-useawsownedkey
            '''
            result = self._values.get("use_aws_owned_key")
            assert result is not None, "Required property 'use_aws_owned_key' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''The customer master key (CMK) to use for the A AWS KMS (KMS).

            This key is used to encrypt your data at rest. If not provided, Amazon MQ will use a default CMK to encrypt your data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-encryptionoptions.html#cfn-amazonmq-broker-encryptionoptions-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnBroker.LdapServerMetadataProperty",
        jsii_struct_bases=[],
        name_mapping={
            "hosts": "hosts",
            "role_base": "roleBase",
            "role_search_matching": "roleSearchMatching",
            "service_account_password": "serviceAccountPassword",
            "service_account_username": "serviceAccountUsername",
            "user_base": "userBase",
            "user_search_matching": "userSearchMatching",
            "role_name": "roleName",
            "role_search_subtree": "roleSearchSubtree",
            "user_role_name": "userRoleName",
            "user_search_subtree": "userSearchSubtree",
        },
    )
    class LdapServerMetadataProperty:
        def __init__(
            self,
            *,
            hosts: typing.Sequence[builtins.str],
            role_base: builtins.str,
            role_search_matching: builtins.str,
            service_account_password: builtins.str,
            service_account_username: builtins.str,
            user_base: builtins.str,
            user_search_matching: builtins.str,
            role_name: typing.Optional[builtins.str] = None,
            role_search_subtree: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            user_role_name: typing.Optional[builtins.str] = None,
            user_search_subtree: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Optional. The metadata of the LDAP server used to authenticate and authorize connections to the broker.

            .. epigraph::

               Does not apply to RabbitMQ brokers.

            :param hosts: Specifies the location of the LDAP server such as AWS Directory Service for Microsoft Active Directory . Optional failover server.
            :param role_base: The distinguished name of the node in the directory information tree (DIT) to search for roles or groups. For example, ``ou=group`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .
            :param role_search_matching: The LDAP search filter used to find roles within the roleBase. The distinguished name of the user matched by userSearchMatching is substituted into the ``{0}`` placeholder in the search filter. The client's username is substituted into the ``{1}`` placeholder. For example, if you set this option to ``(member=uid={1})`` for the user janedoe, the search filter becomes ``(member=uid=janedoe)`` after string substitution. It matches all role entries that have a member attribute equal to ``uid=janedoe`` under the subtree selected by the ``RoleBases`` .
            :param service_account_password: Service account password. A service account is an account in your LDAP server that has access to initiate a connection. For example, ``cn=admin`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .
            :param service_account_username: Service account username. A service account is an account in your LDAP server that has access to initiate a connection. For example, ``cn=admin`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .
            :param user_base: Select a particular subtree of the directory information tree (DIT) to search for user entries. The subtree is specified by a DN, which specifies the base node of the subtree. For example, by setting this option to ``ou=Users`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` , the search for user entries is restricted to the subtree beneath ``ou=Users`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .
            :param user_search_matching: The LDAP search filter used to find users within the ``userBase`` . The client's username is substituted into the ``{0}`` placeholder in the search filter. For example, if this option is set to ``(uid={0})`` and the received username is ``janedoe`` , the search filter becomes ``(uid=janedoe)`` after string substitution. It will result in matching an entry like ``uid=janedoe`` , ``ou=Users`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .
            :param role_name: The group name attribute in a role entry whose value is the name of that role. For example, you can specify ``cn`` for a group entry's common name. If authentication succeeds, then the user is assigned the the value of the ``cn`` attribute for each role entry that they are a member of.
            :param role_search_subtree: The directory search scope for the role. If set to true, scope is to search the entire subtree.
            :param user_role_name: The name of the LDAP attribute in the user's directory entry for the user's group membership. In some cases, user roles may be identified by the value of an attribute in the user's directory entry. The ``UserRoleName`` option allows you to provide the name of this attribute.
            :param user_search_subtree: The directory search scope for the user. If set to true, scope is to search the entire subtree.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                ldap_server_metadata_property = amazonmq.CfnBroker.LdapServerMetadataProperty(
                    hosts=["hosts"],
                    role_base="roleBase",
                    role_search_matching="roleSearchMatching",
                    service_account_password="serviceAccountPassword",
                    service_account_username="serviceAccountUsername",
                    user_base="userBase",
                    user_search_matching="userSearchMatching",
                
                    # the properties below are optional
                    role_name="roleName",
                    role_search_subtree=False,
                    user_role_name="userRoleName",
                    user_search_subtree=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "hosts": hosts,
                "role_base": role_base,
                "role_search_matching": role_search_matching,
                "service_account_password": service_account_password,
                "service_account_username": service_account_username,
                "user_base": user_base,
                "user_search_matching": user_search_matching,
            }
            if role_name is not None:
                self._values["role_name"] = role_name
            if role_search_subtree is not None:
                self._values["role_search_subtree"] = role_search_subtree
            if user_role_name is not None:
                self._values["user_role_name"] = user_role_name
            if user_search_subtree is not None:
                self._values["user_search_subtree"] = user_search_subtree

        @builtins.property
        def hosts(self) -> typing.List[builtins.str]:
            '''Specifies the location of the LDAP server such as AWS Directory Service for Microsoft Active Directory .

            Optional failover server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-hosts
            '''
            result = self._values.get("hosts")
            assert result is not None, "Required property 'hosts' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def role_base(self) -> builtins.str:
            '''The distinguished name of the node in the directory information tree (DIT) to search for roles or groups.

            For example, ``ou=group`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-rolebase
            '''
            result = self._values.get("role_base")
            assert result is not None, "Required property 'role_base' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_search_matching(self) -> builtins.str:
            '''The LDAP search filter used to find roles within the roleBase.

            The distinguished name of the user matched by userSearchMatching is substituted into the ``{0}`` placeholder in the search filter. The client's username is substituted into the ``{1}`` placeholder. For example, if you set this option to ``(member=uid={1})`` for the user janedoe, the search filter becomes ``(member=uid=janedoe)`` after string substitution. It matches all role entries that have a member attribute equal to ``uid=janedoe`` under the subtree selected by the ``RoleBases`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-rolesearchmatching
            '''
            result = self._values.get("role_search_matching")
            assert result is not None, "Required property 'role_search_matching' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def service_account_password(self) -> builtins.str:
            '''Service account password.

            A service account is an account in your LDAP server that has access to initiate a connection. For example, ``cn=admin`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-serviceaccountpassword
            '''
            result = self._values.get("service_account_password")
            assert result is not None, "Required property 'service_account_password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def service_account_username(self) -> builtins.str:
            '''Service account username.

            A service account is an account in your LDAP server that has access to initiate a connection. For example, ``cn=admin`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-serviceaccountusername
            '''
            result = self._values.get("service_account_username")
            assert result is not None, "Required property 'service_account_username' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_base(self) -> builtins.str:
            '''Select a particular subtree of the directory information tree (DIT) to search for user entries.

            The subtree is specified by a DN, which specifies the base node of the subtree. For example, by setting this option to ``ou=Users`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` , the search for user entries is restricted to the subtree beneath ``ou=Users`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-userbase
            '''
            result = self._values.get("user_base")
            assert result is not None, "Required property 'user_base' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_search_matching(self) -> builtins.str:
            '''The LDAP search filter used to find users within the ``userBase`` .

            The client's username is substituted into the ``{0}`` placeholder in the search filter. For example, if this option is set to ``(uid={0})`` and the received username is ``janedoe`` , the search filter becomes ``(uid=janedoe)`` after string substitution. It will result in matching an entry like ``uid=janedoe`` , ``ou=Users`` , ``ou=corp`` , ``dc=corp`` , ``dc=example`` , ``dc=com`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-usersearchmatching
            '''
            result = self._values.get("user_search_matching")
            assert result is not None, "Required property 'user_search_matching' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_name(self) -> typing.Optional[builtins.str]:
            '''The group name attribute in a role entry whose value is the name of that role.

            For example, you can specify ``cn`` for a group entry's common name. If authentication succeeds, then the user is assigned the the value of the ``cn`` attribute for each role entry that they are a member of.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-rolename
            '''
            result = self._values.get("role_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def role_search_subtree(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The directory search scope for the role.

            If set to true, scope is to search the entire subtree.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-rolesearchsubtree
            '''
            result = self._values.get("role_search_subtree")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def user_role_name(self) -> typing.Optional[builtins.str]:
            '''The name of the LDAP attribute in the user's directory entry for the user's group membership.

            In some cases, user roles may be identified by the value of an attribute in the user's directory entry. The ``UserRoleName`` option allows you to provide the name of this attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-userrolename
            '''
            result = self._values.get("user_role_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def user_search_subtree(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The directory search scope for the user.

            If set to true, scope is to search the entire subtree.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-ldapservermetadata.html#cfn-amazonmq-broker-ldapservermetadata-usersearchsubtree
            '''
            result = self._values.get("user_search_subtree")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LdapServerMetadataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnBroker.LogListProperty",
        jsii_struct_bases=[],
        name_mapping={"audit": "audit", "general": "general"},
    )
    class LogListProperty:
        def __init__(
            self,
            *,
            audit: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            general: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The list of information about logs to be enabled for the specified broker.

            :param audit: Enables audit logging. Every user management action made using JMX or the ActiveMQ Web Console is logged. Does not apply to RabbitMQ brokers.
            :param general: Enables general logging.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-loglist.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                log_list_property = amazonmq.CfnBroker.LogListProperty(
                    audit=False,
                    general=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if audit is not None:
                self._values["audit"] = audit
            if general is not None:
                self._values["general"] = general

        @builtins.property
        def audit(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables audit logging.

            Every user management action made using JMX or the ActiveMQ Web Console is logged. Does not apply to RabbitMQ brokers.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-loglist.html#cfn-amazonmq-broker-loglist-audit
            '''
            result = self._values.get("audit")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def general(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables general logging.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-loglist.html#cfn-amazonmq-broker-loglist-general
            '''
            result = self._values.get("general")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogListProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnBroker.MaintenanceWindowProperty",
        jsii_struct_bases=[],
        name_mapping={
            "day_of_week": "dayOfWeek",
            "time_of_day": "timeOfDay",
            "time_zone": "timeZone",
        },
    )
    class MaintenanceWindowProperty:
        def __init__(
            self,
            *,
            day_of_week: builtins.str,
            time_of_day: builtins.str,
            time_zone: builtins.str,
        ) -> None:
            '''The parameters that determine the ``WeeklyStartTime`` to apply pending updates or patches to the broker.

            :param day_of_week: The day of the week.
            :param time_of_day: The time, in 24-hour format.
            :param time_zone: The time zone, UTC by default, in either the Country/City format, or the UTC offset format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-maintenancewindow.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                maintenance_window_property = amazonmq.CfnBroker.MaintenanceWindowProperty(
                    day_of_week="dayOfWeek",
                    time_of_day="timeOfDay",
                    time_zone="timeZone"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "day_of_week": day_of_week,
                "time_of_day": time_of_day,
                "time_zone": time_zone,
            }

        @builtins.property
        def day_of_week(self) -> builtins.str:
            '''The day of the week.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-maintenancewindow.html#cfn-amazonmq-broker-maintenancewindow-dayofweek
            '''
            result = self._values.get("day_of_week")
            assert result is not None, "Required property 'day_of_week' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def time_of_day(self) -> builtins.str:
            '''The time, in 24-hour format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-maintenancewindow.html#cfn-amazonmq-broker-maintenancewindow-timeofday
            '''
            result = self._values.get("time_of_day")
            assert result is not None, "Required property 'time_of_day' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def time_zone(self) -> builtins.str:
            '''The time zone, UTC by default, in either the Country/City format, or the UTC offset format.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-maintenancewindow.html#cfn-amazonmq-broker-maintenancewindow-timezone
            '''
            result = self._values.get("time_zone")
            assert result is not None, "Required property 'time_zone' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MaintenanceWindowProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnBroker.TagsEntryProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class TagsEntryProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''A key-value pair to associate with the broker.

            :param key: The key in a key-value pair.
            :param value: The value in a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-tagsentry.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                tags_entry_property = amazonmq.CfnBroker.TagsEntryProperty(
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
            '''The key in a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-tagsentry.html#cfn-amazonmq-broker-tagsentry-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value in a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-tagsentry.html#cfn-amazonmq-broker-tagsentry-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TagsEntryProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnBroker.UserProperty",
        jsii_struct_bases=[],
        name_mapping={
            "password": "password",
            "username": "username",
            "console_access": "consoleAccess",
            "groups": "groups",
        },
    )
    class UserProperty:
        def __init__(
            self,
            *,
            password: builtins.str,
            username: builtins.str,
            console_access: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The list of broker users (persons or applications) who can access queues and topics.

            For Amazon MQ for RabbitMQ brokers, one and only one administrative user is accepted and created when a broker is first provisioned. All subsequent broker users are created via the RabbitMQ web console or by using the RabbitMQ management API.

            :param password: The password of the user. This value must be at least 12 characters long, must contain at least 4 unique characters, and must not contain commas, colons, or equal signs (,:=).
            :param username: The username of the broker user. For Amazon MQ for ActiveMQ brokers, this value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). For Amazon MQ for RabbitMQ brokers, this value can contain only alphanumeric characters, dashes, periods, underscores (- . _). This value must not contain a tilde (~) character. Amazon MQ prohibts using guest as a valid usename. This value must be 2-100 characters long. .. epigraph:: Do not add personally identifiable information (PII) or other confidential or sensitive information in broker usernames. Broker usernames are accessible to other AWS services, including CloudWatch Logs . Broker usernames are not intended to be used for private or sensitive data.
            :param console_access: Enables access to the ActiveMQ web console for the ActiveMQ user. Does not apply to RabbitMQ brokers.
            :param groups: The list of groups (20 maximum) to which the ActiveMQ user belongs. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long. Does not apply to RabbitMQ brokers.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-user.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                user_property = amazonmq.CfnBroker.UserProperty(
                    password="password",
                    username="username",
                
                    # the properties below are optional
                    console_access=False,
                    groups=["groups"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
                "username": username,
            }
            if console_access is not None:
                self._values["console_access"] = console_access
            if groups is not None:
                self._values["groups"] = groups

        @builtins.property
        def password(self) -> builtins.str:
            '''The password of the user.

            This value must be at least 12 characters long, must contain at least 4 unique characters, and must not contain commas, colons, or equal signs (,:=).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-user.html#cfn-amazonmq-broker-user-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def username(self) -> builtins.str:
            '''The username of the broker user.

            For Amazon MQ for ActiveMQ brokers, this value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). For Amazon MQ for RabbitMQ brokers, this value can contain only alphanumeric characters, dashes, periods, underscores (- . _). This value must not contain a tilde (~) character. Amazon MQ prohibts using guest as a valid usename. This value must be 2-100 characters long.
            .. epigraph::

               Do not add personally identifiable information (PII) or other confidential or sensitive information in broker usernames. Broker usernames are accessible to other AWS services, including CloudWatch Logs . Broker usernames are not intended to be used for private or sensitive data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-user.html#cfn-amazonmq-broker-user-username
            '''
            result = self._values.get("username")
            assert result is not None, "Required property 'username' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def console_access(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables access to the ActiveMQ web console for the ActiveMQ user.

            Does not apply to RabbitMQ brokers.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-user.html#cfn-amazonmq-broker-user-consoleaccess
            '''
            result = self._values.get("console_access")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def groups(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The list of groups (20 maximum) to which the ActiveMQ user belongs.

            This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 2-100 characters long. Does not apply to RabbitMQ brokers.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-broker-user.html#cfn-amazonmq-broker-user-groups
            '''
            result = self._values.get("groups")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UserProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_amazonmq.CfnBrokerProps",
    jsii_struct_bases=[],
    name_mapping={
        "auto_minor_version_upgrade": "autoMinorVersionUpgrade",
        "broker_name": "brokerName",
        "deployment_mode": "deploymentMode",
        "engine_type": "engineType",
        "engine_version": "engineVersion",
        "host_instance_type": "hostInstanceType",
        "publicly_accessible": "publiclyAccessible",
        "users": "users",
        "authentication_strategy": "authenticationStrategy",
        "configuration": "configuration",
        "encryption_options": "encryptionOptions",
        "ldap_server_metadata": "ldapServerMetadata",
        "logs": "logs",
        "maintenance_window_start_time": "maintenanceWindowStartTime",
        "security_groups": "securityGroups",
        "storage_type": "storageType",
        "subnet_ids": "subnetIds",
        "tags": "tags",
    },
)
class CfnBrokerProps:
    def __init__(
        self,
        *,
        auto_minor_version_upgrade: typing.Union[builtins.bool, _IResolvable_da3f097b],
        broker_name: builtins.str,
        deployment_mode: builtins.str,
        engine_type: builtins.str,
        engine_version: builtins.str,
        host_instance_type: builtins.str,
        publicly_accessible: typing.Union[builtins.bool, _IResolvable_da3f097b],
        users: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBroker.UserProperty, _IResolvable_da3f097b]]],
        authentication_strategy: typing.Optional[builtins.str] = None,
        configuration: typing.Optional[typing.Union[CfnBroker.ConfigurationIdProperty, _IResolvable_da3f097b]] = None,
        encryption_options: typing.Optional[typing.Union[CfnBroker.EncryptionOptionsProperty, _IResolvable_da3f097b]] = None,
        ldap_server_metadata: typing.Optional[typing.Union[CfnBroker.LdapServerMetadataProperty, _IResolvable_da3f097b]] = None,
        logs: typing.Optional[typing.Union[CfnBroker.LogListProperty, _IResolvable_da3f097b]] = None,
        maintenance_window_start_time: typing.Optional[typing.Union[CfnBroker.MaintenanceWindowProperty, _IResolvable_da3f097b]] = None,
        security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        storage_type: typing.Optional[builtins.str] = None,
        subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[CfnBroker.TagsEntryProperty]] = None,
    ) -> None:
        '''Properties for defining a ``CfnBroker``.

        :param auto_minor_version_upgrade: Enables automatic upgrades to new minor versions for brokers, as new broker engine versions are released and supported by Amazon MQ. Automatic upgrades occur during the scheduled maintenance window of the broker or after a manual broker reboot.
        :param broker_name: The name of the broker. This value must be unique in your AWS account , 1-50 characters long, must contain only letters, numbers, dashes, and underscores, and must not contain white spaces, brackets, wildcard characters, or special characters. .. epigraph:: Do not add personally identifiable information (PII) or other confidential or sensitive information in broker names. Broker names are accessible to other AWS services, including C CloudWatch Logs . Broker names are not intended to be used for private or sensitive data.
        :param deployment_mode: The deployment mode of the broker. Available values:. - ``SINGLE_INSTANCE`` - ``ACTIVE_STANDBY_MULTI_AZ`` - ``CLUSTER_MULTI_AZ``
        :param engine_type: The type of broker engine. Currently, Amazon MQ supports ``ACTIVEMQ`` and ``RABBITMQ`` .
        :param engine_version: The version of the broker engine. For a list of supported engine versions, see `Engine <https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html>`_ in the *Amazon MQ Developer Guide* .
        :param host_instance_type: The broker's instance type.
        :param publicly_accessible: Enables connections from applications outside of the VPC that hosts the broker's subnets.
        :param users: The list of broker users (persons or applications) who can access queues and topics. For Amazon MQ for RabbitMQ brokers, one and only one administrative user is accepted and created when a broker is first provisioned. All subsequent RabbitMQ users are created by via the RabbitMQ web console or by using the RabbitMQ management API.
        :param authentication_strategy: Optional. The authentication strategy used to secure the broker. The default is ``SIMPLE`` .
        :param configuration: A list of information about the configuration. Does not apply to RabbitMQ brokers.
        :param encryption_options: Encryption options for the broker. Does not apply to RabbitMQ brokers.
        :param ldap_server_metadata: Optional. The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.
        :param logs: Enables Amazon CloudWatch logging for brokers.
        :param maintenance_window_start_time: The scheduled time period relative to UTC during which Amazon MQ begins to apply pending updates or patches to the broker.
        :param security_groups: The list of rules (1 minimum, 125 maximum) that authorize connections to brokers.
        :param storage_type: The broker's storage type.
        :param subnet_ids: The list of groups that define which subnets and IP ranges the broker can use from different Availability Zones. If you specify more than one subnet, the subnets must be in different Availability Zones. Amazon MQ will not be able to create VPC endpoints for your broker with multiple subnets in the same Availability Zone. A SINGLE_INSTANCE deployment requires one subnet (for example, the default subnet). An ACTIVE_STANDBY_MULTI_AZ deployment (ACTIVEMQ) requires two subnets. A CLUSTER_MULTI_AZ deployment (RABBITMQ) has no subnet requirements when deployed with public accessibility, deployment without public accessibility requires at least one subnet. .. epigraph:: If you specify subnets in a shared VPC for a RabbitMQ broker, the associated VPC to which the specified subnets belong must be owned by your AWS account . Amazon MQ will not be able to create VPC enpoints in VPCs that are not owned by your AWS account .
        :param tags: An array of key-value pairs. For more information, see `Using Cost Allocation Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`_ in the *Billing and Cost Management User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_amazonmq as amazonmq
            
            cfn_broker_props = amazonmq.CfnBrokerProps(
                auto_minor_version_upgrade=False,
                broker_name="brokerName",
                deployment_mode="deploymentMode",
                engine_type="engineType",
                engine_version="engineVersion",
                host_instance_type="hostInstanceType",
                publicly_accessible=False,
                users=[amazonmq.CfnBroker.UserProperty(
                    password="password",
                    username="username",
            
                    # the properties below are optional
                    console_access=False,
                    groups=["groups"]
                )],
            
                # the properties below are optional
                authentication_strategy="authenticationStrategy",
                configuration=amazonmq.CfnBroker.ConfigurationIdProperty(
                    id="id",
                    revision=123
                ),
                encryption_options=amazonmq.CfnBroker.EncryptionOptionsProperty(
                    use_aws_owned_key=False,
            
                    # the properties below are optional
                    kms_key_id="kmsKeyId"
                ),
                ldap_server_metadata=amazonmq.CfnBroker.LdapServerMetadataProperty(
                    hosts=["hosts"],
                    role_base="roleBase",
                    role_search_matching="roleSearchMatching",
                    service_account_password="serviceAccountPassword",
                    service_account_username="serviceAccountUsername",
                    user_base="userBase",
                    user_search_matching="userSearchMatching",
            
                    # the properties below are optional
                    role_name="roleName",
                    role_search_subtree=False,
                    user_role_name="userRoleName",
                    user_search_subtree=False
                ),
                logs=amazonmq.CfnBroker.LogListProperty(
                    audit=False,
                    general=False
                ),
                maintenance_window_start_time=amazonmq.CfnBroker.MaintenanceWindowProperty(
                    day_of_week="dayOfWeek",
                    time_of_day="timeOfDay",
                    time_zone="timeZone"
                ),
                security_groups=["securityGroups"],
                storage_type="storageType",
                subnet_ids=["subnetIds"],
                tags=[amazonmq.CfnBroker.TagsEntryProperty(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "auto_minor_version_upgrade": auto_minor_version_upgrade,
            "broker_name": broker_name,
            "deployment_mode": deployment_mode,
            "engine_type": engine_type,
            "engine_version": engine_version,
            "host_instance_type": host_instance_type,
            "publicly_accessible": publicly_accessible,
            "users": users,
        }
        if authentication_strategy is not None:
            self._values["authentication_strategy"] = authentication_strategy
        if configuration is not None:
            self._values["configuration"] = configuration
        if encryption_options is not None:
            self._values["encryption_options"] = encryption_options
        if ldap_server_metadata is not None:
            self._values["ldap_server_metadata"] = ldap_server_metadata
        if logs is not None:
            self._values["logs"] = logs
        if maintenance_window_start_time is not None:
            self._values["maintenance_window_start_time"] = maintenance_window_start_time
        if security_groups is not None:
            self._values["security_groups"] = security_groups
        if storage_type is not None:
            self._values["storage_type"] = storage_type
        if subnet_ids is not None:
            self._values["subnet_ids"] = subnet_ids
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Enables automatic upgrades to new minor versions for brokers, as new broker engine versions are released and supported by Amazon MQ.

        Automatic upgrades occur during the scheduled maintenance window of the broker or after a manual broker reboot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-autominorversionupgrade
        '''
        result = self._values.get("auto_minor_version_upgrade")
        assert result is not None, "Required property 'auto_minor_version_upgrade' is missing"
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

    @builtins.property
    def broker_name(self) -> builtins.str:
        '''The name of the broker.

        This value must be unique in your AWS account , 1-50 characters long, must contain only letters, numbers, dashes, and underscores, and must not contain white spaces, brackets, wildcard characters, or special characters.
        .. epigraph::

           Do not add personally identifiable information (PII) or other confidential or sensitive information in broker names. Broker names are accessible to other AWS services, including C CloudWatch Logs . Broker names are not intended to be used for private or sensitive data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-brokername
        '''
        result = self._values.get("broker_name")
        assert result is not None, "Required property 'broker_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def deployment_mode(self) -> builtins.str:
        '''The deployment mode of the broker. Available values:.

        - ``SINGLE_INSTANCE``
        - ``ACTIVE_STANDBY_MULTI_AZ``
        - ``CLUSTER_MULTI_AZ``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-deploymentmode
        '''
        result = self._values.get("deployment_mode")
        assert result is not None, "Required property 'deployment_mode' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def engine_type(self) -> builtins.str:
        '''The type of broker engine.

        Currently, Amazon MQ supports ``ACTIVEMQ`` and ``RABBITMQ`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-enginetype
        '''
        result = self._values.get("engine_type")
        assert result is not None, "Required property 'engine_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def engine_version(self) -> builtins.str:
        '''The version of the broker engine.

        For a list of supported engine versions, see `Engine <https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html>`_ in the *Amazon MQ Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-engineversion
        '''
        result = self._values.get("engine_version")
        assert result is not None, "Required property 'engine_version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def host_instance_type(self) -> builtins.str:
        '''The broker's instance type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-hostinstancetype
        '''
        result = self._values.get("host_instance_type")
        assert result is not None, "Required property 'host_instance_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def publicly_accessible(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Enables connections from applications outside of the VPC that hosts the broker's subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-publiclyaccessible
        '''
        result = self._values.get("publicly_accessible")
        assert result is not None, "Required property 'publicly_accessible' is missing"
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

    @builtins.property
    def users(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBroker.UserProperty, _IResolvable_da3f097b]]]:
        '''The list of broker users (persons or applications) who can access queues and topics.

        For Amazon MQ for RabbitMQ brokers, one and only one administrative user is accepted and created when a broker is first provisioned. All subsequent RabbitMQ users are created by via the RabbitMQ web console or by using the RabbitMQ management API.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-users
        '''
        result = self._values.get("users")
        assert result is not None, "Required property 'users' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBroker.UserProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def authentication_strategy(self) -> typing.Optional[builtins.str]:
        '''Optional.

        The authentication strategy used to secure the broker. The default is ``SIMPLE`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-authenticationstrategy
        '''
        result = self._values.get("authentication_strategy")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBroker.ConfigurationIdProperty, _IResolvable_da3f097b]]:
        '''A list of information about the configuration.

        Does not apply to RabbitMQ brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-configuration
        '''
        result = self._values.get("configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBroker.ConfigurationIdProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def encryption_options(
        self,
    ) -> typing.Optional[typing.Union[CfnBroker.EncryptionOptionsProperty, _IResolvable_da3f097b]]:
        '''Encryption options for the broker.

        Does not apply to RabbitMQ brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-encryptionoptions
        '''
        result = self._values.get("encryption_options")
        return typing.cast(typing.Optional[typing.Union[CfnBroker.EncryptionOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def ldap_server_metadata(
        self,
    ) -> typing.Optional[typing.Union[CfnBroker.LdapServerMetadataProperty, _IResolvable_da3f097b]]:
        '''Optional.

        The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-ldapservermetadata
        '''
        result = self._values.get("ldap_server_metadata")
        return typing.cast(typing.Optional[typing.Union[CfnBroker.LdapServerMetadataProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def logs(
        self,
    ) -> typing.Optional[typing.Union[CfnBroker.LogListProperty, _IResolvable_da3f097b]]:
        '''Enables Amazon CloudWatch logging for brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-logs
        '''
        result = self._values.get("logs")
        return typing.cast(typing.Optional[typing.Union[CfnBroker.LogListProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def maintenance_window_start_time(
        self,
    ) -> typing.Optional[typing.Union[CfnBroker.MaintenanceWindowProperty, _IResolvable_da3f097b]]:
        '''The scheduled time period relative to UTC during which Amazon MQ begins to apply pending updates or patches to the broker.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-maintenancewindowstarttime
        '''
        result = self._values.get("maintenance_window_start_time")
        return typing.cast(typing.Optional[typing.Union[CfnBroker.MaintenanceWindowProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of rules (1 minimum, 125 maximum) that authorize connections to brokers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-securitygroups
        '''
        result = self._values.get("security_groups")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def storage_type(self) -> typing.Optional[builtins.str]:
        '''The broker's storage type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-storagetype
        '''
        result = self._values.get("storage_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of groups that define which subnets and IP ranges the broker can use from different Availability Zones.

        If you specify more than one subnet, the subnets must be in different Availability Zones. Amazon MQ will not be able to create VPC endpoints for your broker with multiple subnets in the same Availability Zone. A SINGLE_INSTANCE deployment requires one subnet (for example, the default subnet). An ACTIVE_STANDBY_MULTI_AZ deployment (ACTIVEMQ) requires two subnets. A CLUSTER_MULTI_AZ deployment (RABBITMQ) has no subnet requirements when deployed with public accessibility, deployment without public accessibility requires at least one subnet.
        .. epigraph::

           If you specify subnets in a shared VPC for a RabbitMQ broker, the associated VPC to which the specified subnets belong must be owned by your AWS account . Amazon MQ will not be able to create VPC enpoints in VPCs that are not owned by your AWS account .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-subnetids
        '''
        result = self._values.get("subnet_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[CfnBroker.TagsEntryProperty]]:
        '''An array of key-value pairs.

        For more information, see `Using Cost Allocation Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`_ in the *Billing and Cost Management User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[CfnBroker.TagsEntryProperty]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBrokerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_amazonmq.CfnConfiguration",
):
    '''A CloudFormation ``AWS::AmazonMQ::Configuration``.

    Creates a new configuration for the specified configuration name. Amazon MQ uses the default configuration (the engine type and version).
    .. epigraph::

       Does not apply to RabbitMQ brokers.

    :cloudformationResource: AWS::AmazonMQ::Configuration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_amazonmq as amazonmq
        
        cfn_configuration = amazonmq.CfnConfiguration(self, "MyCfnConfiguration",
            data="data",
            engine_type="engineType",
            engine_version="engineVersion",
            name="name",
        
            # the properties below are optional
            authentication_strategy="authenticationStrategy",
            description="description",
            tags=[amazonmq.CfnConfiguration.TagsEntryProperty(
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
        data: builtins.str,
        engine_type: builtins.str,
        engine_version: builtins.str,
        name: builtins.str,
        authentication_strategy: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence["CfnConfiguration.TagsEntryProperty"]] = None,
    ) -> None:
        '''Create a new ``AWS::AmazonMQ::Configuration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param data: The base64-encoded XML configuration.
        :param engine_type: The type of broker engine. Note: Currently, Amazon MQ only supports ACTIVEMQ for creating and editing broker configurations.
        :param engine_version: The version of the broker engine. For a list of supported engine versions, see ` <https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html>`_
        :param name: The name of the configuration. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.
        :param authentication_strategy: Optional. The authentication strategy associated with the configuration. The default is ``SIMPLE`` .
        :param description: The description of the configuration.
        :param tags: Create tags when creating the configuration.
        '''
        props = CfnConfigurationProps(
            data=data,
            engine_type=engine_type,
            engine_version=engine_version,
            name=name,
            authentication_strategy=authentication_strategy,
            description=description,
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
        '''The Amazon Resource Name (ARN) of the Amazon MQ configuration.

        ``arn:aws:mq:us-east-2:123456789012:configuration:MyConfigurationDevelopment:c-1234a5b6-78cd-901e-2fgh-3i45j6k178l9``

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the Amazon MQ configuration.

        ``c-1234a5b6-78cd-901e-2fgh-3i45j6k178l9``

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRevision")
    def attr_revision(self) -> jsii.Number:
        '''The revision number of the configuration.

        ``1``

        :cloudformationAttribute: Revision
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrRevision"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Create tags when creating the configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="data")
    def data(self) -> builtins.str:
        '''The base64-encoded XML configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-data
        '''
        return typing.cast(builtins.str, jsii.get(self, "data"))

    @data.setter
    def data(self, value: builtins.str) -> None:
        jsii.set(self, "data", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineType")
    def engine_type(self) -> builtins.str:
        '''The type of broker engine.

        Note: Currently, Amazon MQ only supports ACTIVEMQ for creating and editing broker configurations.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-enginetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "engineType"))

    @engine_type.setter
    def engine_type(self, value: builtins.str) -> None:
        jsii.set(self, "engineType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineVersion")
    def engine_version(self) -> builtins.str:
        '''The version of the broker engine.

        For a list of supported engine versions, see ` <https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-engineversion
        '''
        return typing.cast(builtins.str, jsii.get(self, "engineVersion"))

    @engine_version.setter
    def engine_version(self, value: builtins.str) -> None:
        jsii.set(self, "engineVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the configuration.

        This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="authenticationStrategy")
    def authentication_strategy(self) -> typing.Optional[builtins.str]:
        '''Optional.

        The authentication strategy associated with the configuration. The default is ``SIMPLE`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-authenticationstrategy
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "authenticationStrategy"))

    @authentication_strategy.setter
    def authentication_strategy(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "authenticationStrategy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnConfiguration.TagsEntryProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class TagsEntryProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''A key-value pair to associate with the configuration.

            :param key: The key in a key-value pair.
            :param value: The value in a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-configuration-tagsentry.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                tags_entry_property = amazonmq.CfnConfiguration.TagsEntryProperty(
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
            '''The key in a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-configuration-tagsentry.html#cfn-amazonmq-configuration-tagsentry-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value in a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-configuration-tagsentry.html#cfn-amazonmq-configuration-tagsentry-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TagsEntryProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnConfigurationAssociation(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_amazonmq.CfnConfigurationAssociation",
):
    '''A CloudFormation ``AWS::AmazonMQ::ConfigurationAssociation``.

    Use the AWS CloudFormation ``AWS::AmazonMQ::ConfigurationAssociation`` resource to associate a configuration with a broker, or return information about the specified ConfigurationAssociation. Only use one per broker, and don't use a configuration on the broker resource if you have associated a configuration with that broker.
    .. epigraph::

       Does not apply to RabbitMQ brokers.

    :cloudformationResource: AWS::AmazonMQ::ConfigurationAssociation
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configurationassociation.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_amazonmq as amazonmq
        
        cfn_configuration_association = amazonmq.CfnConfigurationAssociation(self, "MyCfnConfigurationAssociation",
            broker="broker",
            configuration=amazonmq.CfnConfigurationAssociation.ConfigurationIdProperty(
                id="id",
                revision=123
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        broker: builtins.str,
        configuration: typing.Union["CfnConfigurationAssociation.ConfigurationIdProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::AmazonMQ::ConfigurationAssociation``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param broker: The broker to associate with a configuration.
        :param configuration: The configuration to associate with a broker.
        '''
        props = CfnConfigurationAssociationProps(
            broker=broker, configuration=configuration
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
    @jsii.member(jsii_name="broker")
    def broker(self) -> builtins.str:
        '''The broker to associate with a configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configurationassociation.html#cfn-amazonmq-configurationassociation-broker
        '''
        return typing.cast(builtins.str, jsii.get(self, "broker"))

    @broker.setter
    def broker(self, value: builtins.str) -> None:
        jsii.set(self, "broker", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="configuration")
    def configuration(
        self,
    ) -> typing.Union["CfnConfigurationAssociation.ConfigurationIdProperty", _IResolvable_da3f097b]:
        '''The configuration to associate with a broker.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configurationassociation.html#cfn-amazonmq-configurationassociation-configuration
        '''
        return typing.cast(typing.Union["CfnConfigurationAssociation.ConfigurationIdProperty", _IResolvable_da3f097b], jsii.get(self, "configuration"))

    @configuration.setter
    def configuration(
        self,
        value: typing.Union["CfnConfigurationAssociation.ConfigurationIdProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "configuration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amazonmq.CfnConfigurationAssociation.ConfigurationIdProperty",
        jsii_struct_bases=[],
        name_mapping={"id": "id", "revision": "revision"},
    )
    class ConfigurationIdProperty:
        def __init__(self, *, id: builtins.str, revision: jsii.Number) -> None:
            '''The ``ConfigurationId`` property type specifies a configuration Id and the revision of a configuration.

            :param id: The unique ID that Amazon MQ generates for the configuration.
            :param revision: The revision number of the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-configurationassociation-configurationid.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amazonmq as amazonmq
                
                configuration_id_property = amazonmq.CfnConfigurationAssociation.ConfigurationIdProperty(
                    id="id",
                    revision=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
                "revision": revision,
            }

        @builtins.property
        def id(self) -> builtins.str:
            '''The unique ID that Amazon MQ generates for the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-configurationassociation-configurationid.html#cfn-amazonmq-configurationassociation-configurationid-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def revision(self) -> jsii.Number:
            '''The revision number of the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amazonmq-configurationassociation-configurationid.html#cfn-amazonmq-configurationassociation-configurationid-revision
            '''
            result = self._values.get("revision")
            assert result is not None, "Required property 'revision' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConfigurationIdProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_amazonmq.CfnConfigurationAssociationProps",
    jsii_struct_bases=[],
    name_mapping={"broker": "broker", "configuration": "configuration"},
)
class CfnConfigurationAssociationProps:
    def __init__(
        self,
        *,
        broker: builtins.str,
        configuration: typing.Union[CfnConfigurationAssociation.ConfigurationIdProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnConfigurationAssociation``.

        :param broker: The broker to associate with a configuration.
        :param configuration: The configuration to associate with a broker.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configurationassociation.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_amazonmq as amazonmq
            
            cfn_configuration_association_props = amazonmq.CfnConfigurationAssociationProps(
                broker="broker",
                configuration=amazonmq.CfnConfigurationAssociation.ConfigurationIdProperty(
                    id="id",
                    revision=123
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "broker": broker,
            "configuration": configuration,
        }

    @builtins.property
    def broker(self) -> builtins.str:
        '''The broker to associate with a configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configurationassociation.html#cfn-amazonmq-configurationassociation-broker
        '''
        result = self._values.get("broker")
        assert result is not None, "Required property 'broker' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def configuration(
        self,
    ) -> typing.Union[CfnConfigurationAssociation.ConfigurationIdProperty, _IResolvable_da3f097b]:
        '''The configuration to associate with a broker.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configurationassociation.html#cfn-amazonmq-configurationassociation-configuration
        '''
        result = self._values.get("configuration")
        assert result is not None, "Required property 'configuration' is missing"
        return typing.cast(typing.Union[CfnConfigurationAssociation.ConfigurationIdProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnConfigurationAssociationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_amazonmq.CfnConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "data": "data",
        "engine_type": "engineType",
        "engine_version": "engineVersion",
        "name": "name",
        "authentication_strategy": "authenticationStrategy",
        "description": "description",
        "tags": "tags",
    },
)
class CfnConfigurationProps:
    def __init__(
        self,
        *,
        data: builtins.str,
        engine_type: builtins.str,
        engine_version: builtins.str,
        name: builtins.str,
        authentication_strategy: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[CfnConfiguration.TagsEntryProperty]] = None,
    ) -> None:
        '''Properties for defining a ``CfnConfiguration``.

        :param data: The base64-encoded XML configuration.
        :param engine_type: The type of broker engine. Note: Currently, Amazon MQ only supports ACTIVEMQ for creating and editing broker configurations.
        :param engine_version: The version of the broker engine. For a list of supported engine versions, see ` <https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html>`_
        :param name: The name of the configuration. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.
        :param authentication_strategy: Optional. The authentication strategy associated with the configuration. The default is ``SIMPLE`` .
        :param description: The description of the configuration.
        :param tags: Create tags when creating the configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_amazonmq as amazonmq
            
            cfn_configuration_props = amazonmq.CfnConfigurationProps(
                data="data",
                engine_type="engineType",
                engine_version="engineVersion",
                name="name",
            
                # the properties below are optional
                authentication_strategy="authenticationStrategy",
                description="description",
                tags=[amazonmq.CfnConfiguration.TagsEntryProperty(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "data": data,
            "engine_type": engine_type,
            "engine_version": engine_version,
            "name": name,
        }
        if authentication_strategy is not None:
            self._values["authentication_strategy"] = authentication_strategy
        if description is not None:
            self._values["description"] = description
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def data(self) -> builtins.str:
        '''The base64-encoded XML configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-data
        '''
        result = self._values.get("data")
        assert result is not None, "Required property 'data' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def engine_type(self) -> builtins.str:
        '''The type of broker engine.

        Note: Currently, Amazon MQ only supports ACTIVEMQ for creating and editing broker configurations.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-enginetype
        '''
        result = self._values.get("engine_type")
        assert result is not None, "Required property 'engine_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def engine_version(self) -> builtins.str:
        '''The version of the broker engine.

        For a list of supported engine versions, see ` <https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker-engine.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-engineversion
        '''
        result = self._values.get("engine_version")
        assert result is not None, "Required property 'engine_version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the configuration.

        This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def authentication_strategy(self) -> typing.Optional[builtins.str]:
        '''Optional.

        The authentication strategy associated with the configuration. The default is ``SIMPLE`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-authenticationstrategy
        '''
        result = self._values.get("authentication_strategy")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[CfnConfiguration.TagsEntryProperty]]:
        '''Create tags when creating the configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-configuration.html#cfn-amazonmq-configuration-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[CfnConfiguration.TagsEntryProperty]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnBroker",
    "CfnBrokerProps",
    "CfnConfiguration",
    "CfnConfigurationAssociation",
    "CfnConfigurationAssociationProps",
    "CfnConfigurationProps",
]

publication.publish()
