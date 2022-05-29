'''
# Amazon ECS Service Discovery Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

This package contains constructs for working with **AWS Cloud Map**

AWS Cloud Map is a fully managed service that you can use to create and
maintain a map of the backend services and resources that your applications
depend on.

For further information on AWS Cloud Map,
see the [AWS Cloud Map documentation](https://docs.aws.amazon.com/cloud-map)

## HTTP Namespace Example

The following example creates an AWS Cloud Map namespace that
supports API calls, creates a service in that namespace, and
registers an instance to it:

```python
import aws_cdk as cdk
import aws_cdk as servicediscovery

app = cdk.App()
stack = cdk.Stack(app, "aws-servicediscovery-integ")

namespace = servicediscovery.HttpNamespace(stack, "MyNamespace",
    name="covfefe"
)

service1 = namespace.create_service("NonIpService",
    description="service registering non-ip instances"
)

service1.register_non_ip_instance("NonIpInstance",
    custom_attributes={"arn": "arn:aws:s3:::mybucket"}
)

service2 = namespace.create_service("IpService",
    description="service registering ip instances",
    health_check=cdk.aws_servicediscovery.HealthCheckConfig(
        type=servicediscovery.HealthCheckType.HTTP,
        resource_path="/check"
    )
)

service2.register_ip_instance("IpInstance",
    ipv4="54.239.25.192"
)

app.synth()
```

## Private DNS Namespace Example

The following example creates an AWS Cloud Map namespace that
supports both API calls and DNS queries within a vpc, creates a
service in that namespace, and registers a loadbalancer as an
instance:

```python
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
import aws_cdk as cdk
import aws_cdk as servicediscovery

app = cdk.App()
stack = cdk.Stack(app, "aws-servicediscovery-integ")

vpc = ec2.Vpc(stack, "Vpc", max_azs=2)

namespace = servicediscovery.PrivateDnsNamespace(stack, "Namespace",
    name="boobar.com",
    vpc=vpc
)

service = namespace.create_service("Service",
    dns_record_type=servicediscovery.DnsRecordType.A_AAAA,
    dns_ttl=cdk.Duration.seconds(30),
    load_balancer=True
)

loadbalancer = elbv2.ApplicationLoadBalancer(stack, "LB", vpc=vpc, internet_facing=True)

service.register_load_balancer("Loadbalancer", loadbalancer)

app.synth()
```

## Public DNS Namespace Example

The following example creates an AWS Cloud Map namespace that
supports both API calls and public DNS queries, creates a service in
that namespace, and registers an IP instance:

```python
import aws_cdk as cdk
import aws_cdk as servicediscovery

app = cdk.App()
stack = cdk.Stack(app, "aws-servicediscovery-integ")

namespace = servicediscovery.PublicDnsNamespace(stack, "Namespace",
    name="foobar.com"
)

service = namespace.create_service("Service",
    name="foo",
    dns_record_type=servicediscovery.DnsRecordType.A,
    dns_ttl=cdk.Duration.seconds(30),
    health_check=cdk.aws_servicediscovery.HealthCheckConfig(
        type=servicediscovery.HealthCheckType.HTTPS,
        resource_path="/healthcheck",
        failure_threshold=2
    )
)

service.register_ip_instance("IpInstance",
    ipv4="54.239.25.192",
    port=443
)

app.synth()
```

For DNS namespaces, you can also register instances to services with CNAME records:

```python
import aws_cdk as cdk
import aws_cdk as servicediscovery

app = cdk.App()
stack = cdk.Stack(app, "aws-servicediscovery-integ")

namespace = servicediscovery.PublicDnsNamespace(stack, "Namespace",
    name="foobar.com"
)

service = namespace.create_service("Service",
    name="foo",
    dns_record_type=servicediscovery.DnsRecordType.CNAME,
    dns_ttl=cdk.Duration.seconds(30)
)

service.register_cname_instance("CnameInstance",
    instance_cname="service.pizza"
)

app.synth()
```
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
    Duration as _Duration_4839e8c3,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    ResourceProps as _ResourceProps_15a65b4e,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_ec2 import IVpc as _IVpc_f30d5663
from ..aws_elasticloadbalancingv2 import ILoadBalancerV2 as _ILoadBalancerV2_4c5c0fbb


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.BaseInstanceProps",
    jsii_struct_bases=[],
    name_mapping={
        "custom_attributes": "customAttributes",
        "instance_id": "instanceId",
    },
)
class BaseInstanceProps:
    def __init__(
        self,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Used when the resource that's associated with the service instance is accessible using values other than an IP address or a domain name (CNAME), i.e. for non-ip-instances.

        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            base_instance_props = servicediscovery.BaseInstanceProps(
                custom_attributes={
                    "custom_attributes_key": "customAttributes"
                },
                instance_id="instanceId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if instance_id is not None:
            self._values["instance_id"] = instance_id

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom attributes of the instance.

        :default: none
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The id of the instance resource.

        :default: Automatically generated name
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.BaseNamespaceProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "description": "description"},
)
class BaseNamespaceProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param name: A name for the Namespace.
        :param description: A description of the Namespace. Default: none

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            base_namespace_props = servicediscovery.BaseNamespaceProps(
                name="name",
            
                # the properties below are optional
                description="description"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def name(self) -> builtins.str:
        '''A name for the Namespace.'''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the Namespace.

        :default: none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseNamespaceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.BaseServiceProps",
    jsii_struct_bases=[],
    name_mapping={
        "custom_health_check": "customHealthCheck",
        "description": "description",
        "health_check": "healthCheck",
        "name": "name",
    },
)
class BaseServiceProps:
    def __init__(
        self,
        *,
        custom_health_check: typing.Optional["HealthCheckCustomConfig"] = None,
        description: typing.Optional[builtins.str] = None,
        health_check: typing.Optional["HealthCheckConfig"] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Basic props needed to create a service in a given namespace.

        Used by HttpNamespace.createService

        :param custom_health_check: Structure containing failure threshold for a custom health checker. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html Default: none
        :param description: A description of the service. Default: none
        :param health_check: Settings for an optional health check. If you specify health check settings, AWS Cloud Map associates the health check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to this service. Default: none
        :param name: A name for the Service. Default: CloudFormation-generated name

        :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-http-namespace.lit.ts infused

        Example::

            import aws_cdk as cdk
            import aws_cdk as servicediscovery
            
            app = cdk.App()
            stack = cdk.Stack(app, "aws-servicediscovery-integ")
            
            namespace = servicediscovery.HttpNamespace(stack, "MyNamespace",
                name="covfefe"
            )
            
            service1 = namespace.create_service("NonIpService",
                description="service registering non-ip instances"
            )
            
            service1.register_non_ip_instance("NonIpInstance",
                custom_attributes={"arn": "arn:aws:s3:::mybucket"}
            )
            
            service2 = namespace.create_service("IpService",
                description="service registering ip instances",
                health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                    type=servicediscovery.HealthCheckType.HTTP,
                    resource_path="/check"
                )
            )
            
            service2.register_ip_instance("IpInstance",
                ipv4="54.239.25.192"
            )
            
            app.synth()
        '''
        if isinstance(custom_health_check, dict):
            custom_health_check = HealthCheckCustomConfig(**custom_health_check)
        if isinstance(health_check, dict):
            health_check = HealthCheckConfig(**health_check)
        self._values: typing.Dict[str, typing.Any] = {}
        if custom_health_check is not None:
            self._values["custom_health_check"] = custom_health_check
        if description is not None:
            self._values["description"] = description
        if health_check is not None:
            self._values["health_check"] = health_check
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def custom_health_check(self) -> typing.Optional["HealthCheckCustomConfig"]:
        '''Structure containing failure threshold for a custom health checker.

        Only one of healthCheckConfig or healthCheckCustomConfig can be specified.
        See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html

        :default: none
        '''
        result = self._values.get("custom_health_check")
        return typing.cast(typing.Optional["HealthCheckCustomConfig"], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the service.

        :default: none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def health_check(self) -> typing.Optional["HealthCheckConfig"]:
        '''Settings for an optional health check.

        If you specify health check settings, AWS Cloud Map associates the health
        check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can
        be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to
        this service.

        :default: none
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional["HealthCheckConfig"], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A name for the Service.

        :default: CloudFormation-generated name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseServiceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnHttpNamespace(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnHttpNamespace",
):
    '''A CloudFormation ``AWS::ServiceDiscovery::HttpNamespace``.

    The ``HttpNamespace`` resource is an AWS Cloud Map resource type that contains information about an HTTP namespace. Service instances that you register using an HTTP namespace can be discovered using a ``DiscoverInstances`` request but can't be discovered using DNS.

    For the current quota on the number of namespaces that you can create using the same AWS account, see `AWS Cloud Map quotas <https://docs.aws.amazon.com/cloud-map/latest/dg/cloud-map-limits.html>`_ in the ** .

    :cloudformationResource: AWS::ServiceDiscovery::HttpNamespace
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-httpnamespace.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        cfn_http_namespace = servicediscovery.CfnHttpNamespace(self, "MyCfnHttpNamespace",
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
        '''Create a new ``AWS::ServiceDiscovery::HttpNamespace``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name that you want to assign to this namespace.
        :param description: A description for the namespace.
        :param tags: The tags for the namespace. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.
        '''
        props = CfnHttpNamespaceProps(name=name, description=description, tags=tags)

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
        '''The Amazon Resource Name (ARN) of the namespace, such as ``arn:aws:service-discovery:us-east-1:123456789012:http-namespace/http-namespace-a1bzhi`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the namespace.

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
        '''The tags for the namespace.

        Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-httpnamespace.html#cfn-servicediscovery-httpnamespace-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name that you want to assign to this namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-httpnamespace.html#cfn-servicediscovery-httpnamespace-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-httpnamespace.html#cfn-servicediscovery-httpnamespace-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnHttpNamespaceProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "description": "description", "tags": "tags"},
)
class CfnHttpNamespaceProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnHttpNamespace``.

        :param name: The name that you want to assign to this namespace.
        :param description: A description for the namespace.
        :param tags: The tags for the namespace. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-httpnamespace.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            cfn_http_namespace_props = servicediscovery.CfnHttpNamespaceProps(
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
        '''The name that you want to assign to this namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-httpnamespace.html#cfn-servicediscovery-httpnamespace-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-httpnamespace.html#cfn-servicediscovery-httpnamespace-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags for the namespace.

        Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-httpnamespace.html#cfn-servicediscovery-httpnamespace-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnHttpNamespaceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnInstance(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnInstance",
):
    '''A CloudFormation ``AWS::ServiceDiscovery::Instance``.

    A complex type that contains information about an instance that AWS Cloud Map creates when you submit a ``RegisterInstance`` request.

    :cloudformationResource: AWS::ServiceDiscovery::Instance
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        # instance_attributes: Any
        
        cfn_instance = servicediscovery.CfnInstance(self, "MyCfnInstance",
            instance_attributes=instance_attributes,
            service_id="serviceId",
        
            # the properties below are optional
            instance_id="instanceId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instance_attributes: typing.Any,
        service_id: builtins.str,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ServiceDiscovery::Instance``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param instance_attributes: A string map that contains the following information for the service that you specify in ``ServiceId`` :. - The attributes that apply to the records that are defined in the service. - For each attribute, the applicable value. Supported attribute keys include the following: - **AWS_ALIAS_DNS_NAME** - If you want AWS Cloud Map to create a Route 53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that is associated with the load balancer. For information about how to get the DNS name, see `AliasTarget->DNSName <https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName>`_ in the *Route 53 API Reference* . Note the following: - The configuration for the service that is specified by ``ServiceId`` must include settings for an ``A`` record, an ``AAAA`` record, or both. - In the service that is specified by ``ServiceId`` , the value of ``RoutingPolicy`` must be ``WEIGHTED`` . - If the service that is specified by ``ServiceId`` includes ``HealthCheckConfig`` settings, AWS Cloud Map will create the health check, but it won't associate the health check with the alias record. - Auto naming currently doesn't support creating alias records that route traffic to AWS resources other than ELB load balancers. - If you specify a value for ``AWS_ALIAS_DNS_NAME`` , don't specify values for any of the ``AWS_INSTANCE`` attributes. - **AWS_EC2_INSTANCE_ID** - *HTTP namespaces only.* The Amazon EC2 instance ID for the instance. The ``AWS_INSTANCE_IPV4`` attribute contains the primary private IPv4 address. When creating resources with a type of `AWS::ServiceDiscovery::Instance <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html>`_ , if the ``AWS_EC2_INSTANCE_ID`` attribute is specified, the only other attribute that can be specified is ``AWS_INIT_HEALTH_STATUS`` . After the resource has been created, the ``AWS_INSTANCE_IPV4`` attribute contains the primary private IPv4 address. - **AWS_INIT_HEALTH_STATUS** - If the service configuration includes ``HealthCheckCustomConfig`` , when creating resources with a type of `AWS::ServiceDiscovery::Instance <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html>`_ you can optionally use ``AWS_INIT_HEALTH_STATUS`` to specify the initial status of the custom health check, ``HEALTHY`` or ``UNHEALTHY`` . If you don't specify a value for ``AWS_INIT_HEALTH_STATUS`` , the initial status is ``HEALTHY`` . This attribute can only be used when creating resources and will not be seen on existing resources. - **AWS_INSTANCE_CNAME** - If the service configuration includes a ``CNAME`` record, the domain name that you want Route 53 to return in response to DNS queries, for example, ``example.com`` . This value is required if the service specified by ``ServiceId`` includes settings for an ``CNAME`` record. - **AWS_INSTANCE_IPV4** - If the service configuration includes an ``A`` record, the IPv4 address that you want Route 53 to return in response to DNS queries, for example, ``192.0.2.44`` . This value is required if the service specified by ``ServiceId`` includes settings for an ``A`` record. If the service includes settings for an ``SRV`` record, you must specify a value for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both. - **AWS_INSTANCE_IPV6** - If the service configuration includes an ``AAAA`` record, the IPv6 address that you want Route 53 to return in response to DNS queries, for example, ``2001:0db8:85a3:0000:0000:abcd:0001:2345`` . This value is required if the service specified by ``ServiceId`` includes settings for an ``AAAA`` record. If the service includes settings for an ``SRV`` record, you must specify a value for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both. - **AWS_INSTANCE_PORT** - If the service includes an ``SRV`` record, the value that you want Route 53 to return for the port. If the service includes ``HealthCheckConfig`` , the port on the endpoint that you want Route 53 to send requests to. This value is required if you specified settings for an ``SRV`` record or a Route 53 health check when you created the service.
        :param service_id: The ID of the service that you want to use for settings for the instance.
        :param instance_id: An identifier that you want to associate with the instance. Note the following:. - If the service that's specified by ``ServiceId`` includes settings for an ``SRV`` record, the value of ``InstanceId`` is automatically included as part of the value for the ``SRV`` record. For more information, see `DnsRecord > Type <https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type>`_ . - You can use this value to update an existing instance. - To register a new instance, you must specify a value that's unique among instances that you register by using the same service. - If you specify an existing ``InstanceId`` and ``ServiceId`` , AWS Cloud Map updates the existing DNS records, if any. If there's also an existing health check, AWS Cloud Map deletes the old health check and creates a new one. .. epigraph:: The health check isn't deleted immediately, so it will still appear for a while if you submit a ``ListHealthChecks`` request, for example.
        '''
        props = CfnInstanceProps(
            instance_attributes=instance_attributes,
            service_id=service_id,
            instance_id=instance_id,
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
    @jsii.member(jsii_name="instanceAttributes")
    def instance_attributes(self) -> typing.Any:
        '''A string map that contains the following information for the service that you specify in ``ServiceId`` :.

        - The attributes that apply to the records that are defined in the service.
        - For each attribute, the applicable value.

        Supported attribute keys include the following:

        - **AWS_ALIAS_DNS_NAME** - If you want AWS Cloud Map to create a Route 53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that is associated with the load balancer. For information about how to get the DNS name, see `AliasTarget->DNSName <https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName>`_ in the *Route 53 API Reference* .

        Note the following:

        - The configuration for the service that is specified by ``ServiceId`` must include settings for an ``A`` record, an ``AAAA`` record, or both.
        - In the service that is specified by ``ServiceId`` , the value of ``RoutingPolicy`` must be ``WEIGHTED`` .
        - If the service that is specified by ``ServiceId`` includes ``HealthCheckConfig`` settings, AWS Cloud Map will create the health check, but it won't associate the health check with the alias record.
        - Auto naming currently doesn't support creating alias records that route traffic to AWS resources other than ELB load balancers.
        - If you specify a value for ``AWS_ALIAS_DNS_NAME`` , don't specify values for any of the ``AWS_INSTANCE`` attributes.
        - **AWS_EC2_INSTANCE_ID** - *HTTP namespaces only.* The Amazon EC2 instance ID for the instance. The ``AWS_INSTANCE_IPV4`` attribute contains the primary private IPv4 address. When creating resources with a type of `AWS::ServiceDiscovery::Instance <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html>`_ , if the ``AWS_EC2_INSTANCE_ID`` attribute is specified, the only other attribute that can be specified is ``AWS_INIT_HEALTH_STATUS`` . After the resource has been created, the ``AWS_INSTANCE_IPV4`` attribute contains the primary private IPv4 address.
        - **AWS_INIT_HEALTH_STATUS** - If the service configuration includes ``HealthCheckCustomConfig`` , when creating resources with a type of `AWS::ServiceDiscovery::Instance <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html>`_ you can optionally use ``AWS_INIT_HEALTH_STATUS`` to specify the initial status of the custom health check, ``HEALTHY`` or ``UNHEALTHY`` . If you don't specify a value for ``AWS_INIT_HEALTH_STATUS`` , the initial status is ``HEALTHY`` . This attribute can only be used when creating resources and will not be seen on existing resources.
        - **AWS_INSTANCE_CNAME** - If the service configuration includes a ``CNAME`` record, the domain name that you want Route 53 to return in response to DNS queries, for example, ``example.com`` .

        This value is required if the service specified by ``ServiceId`` includes settings for an ``CNAME`` record.

        - **AWS_INSTANCE_IPV4** - If the service configuration includes an ``A`` record, the IPv4 address that you want Route 53 to return in response to DNS queries, for example, ``192.0.2.44`` .

        This value is required if the service specified by ``ServiceId`` includes settings for an ``A`` record. If the service includes settings for an ``SRV`` record, you must specify a value for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both.

        - **AWS_INSTANCE_IPV6** - If the service configuration includes an ``AAAA`` record, the IPv6 address that you want Route 53 to return in response to DNS queries, for example, ``2001:0db8:85a3:0000:0000:abcd:0001:2345`` .

        This value is required if the service specified by ``ServiceId`` includes settings for an ``AAAA`` record. If the service includes settings for an ``SRV`` record, you must specify a value for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both.

        - **AWS_INSTANCE_PORT** - If the service includes an ``SRV`` record, the value that you want Route 53 to return for the port.

        If the service includes ``HealthCheckConfig`` , the port on the endpoint that you want Route 53 to send requests to.

        This value is required if you specified settings for an ``SRV`` record or a Route 53 health check when you created the service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html#cfn-servicediscovery-instance-instanceattributes
        '''
        return typing.cast(typing.Any, jsii.get(self, "instanceAttributes"))

    @instance_attributes.setter
    def instance_attributes(self, value: typing.Any) -> None:
        jsii.set(self, "instanceAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceId")
    def service_id(self) -> builtins.str:
        '''The ID of the service that you want to use for settings for the instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html#cfn-servicediscovery-instance-serviceid
        '''
        return typing.cast(builtins.str, jsii.get(self, "serviceId"))

    @service_id.setter
    def service_id(self, value: builtins.str) -> None:
        jsii.set(self, "serviceId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''An identifier that you want to associate with the instance. Note the following:.

        - If the service that's specified by ``ServiceId`` includes settings for an ``SRV`` record, the value of ``InstanceId`` is automatically included as part of the value for the ``SRV`` record. For more information, see `DnsRecord > Type <https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type>`_ .
        - You can use this value to update an existing instance.
        - To register a new instance, you must specify a value that's unique among instances that you register by using the same service.
        - If you specify an existing ``InstanceId`` and ``ServiceId`` , AWS Cloud Map updates the existing DNS records, if any. If there's also an existing health check, AWS Cloud Map deletes the old health check and creates a new one.

        .. epigraph::

           The health check isn't deleted immediately, so it will still appear for a while if you submit a ``ListHealthChecks`` request, for example.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html#cfn-servicediscovery-instance-instanceid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "instanceId"))

    @instance_id.setter
    def instance_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "instanceId", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnInstanceProps",
    jsii_struct_bases=[],
    name_mapping={
        "instance_attributes": "instanceAttributes",
        "service_id": "serviceId",
        "instance_id": "instanceId",
    },
)
class CfnInstanceProps:
    def __init__(
        self,
        *,
        instance_attributes: typing.Any,
        service_id: builtins.str,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnInstance``.

        :param instance_attributes: A string map that contains the following information for the service that you specify in ``ServiceId`` :. - The attributes that apply to the records that are defined in the service. - For each attribute, the applicable value. Supported attribute keys include the following: - **AWS_ALIAS_DNS_NAME** - If you want AWS Cloud Map to create a Route 53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that is associated with the load balancer. For information about how to get the DNS name, see `AliasTarget->DNSName <https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName>`_ in the *Route 53 API Reference* . Note the following: - The configuration for the service that is specified by ``ServiceId`` must include settings for an ``A`` record, an ``AAAA`` record, or both. - In the service that is specified by ``ServiceId`` , the value of ``RoutingPolicy`` must be ``WEIGHTED`` . - If the service that is specified by ``ServiceId`` includes ``HealthCheckConfig`` settings, AWS Cloud Map will create the health check, but it won't associate the health check with the alias record. - Auto naming currently doesn't support creating alias records that route traffic to AWS resources other than ELB load balancers. - If you specify a value for ``AWS_ALIAS_DNS_NAME`` , don't specify values for any of the ``AWS_INSTANCE`` attributes. - **AWS_EC2_INSTANCE_ID** - *HTTP namespaces only.* The Amazon EC2 instance ID for the instance. The ``AWS_INSTANCE_IPV4`` attribute contains the primary private IPv4 address. When creating resources with a type of `AWS::ServiceDiscovery::Instance <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html>`_ , if the ``AWS_EC2_INSTANCE_ID`` attribute is specified, the only other attribute that can be specified is ``AWS_INIT_HEALTH_STATUS`` . After the resource has been created, the ``AWS_INSTANCE_IPV4`` attribute contains the primary private IPv4 address. - **AWS_INIT_HEALTH_STATUS** - If the service configuration includes ``HealthCheckCustomConfig`` , when creating resources with a type of `AWS::ServiceDiscovery::Instance <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html>`_ you can optionally use ``AWS_INIT_HEALTH_STATUS`` to specify the initial status of the custom health check, ``HEALTHY`` or ``UNHEALTHY`` . If you don't specify a value for ``AWS_INIT_HEALTH_STATUS`` , the initial status is ``HEALTHY`` . This attribute can only be used when creating resources and will not be seen on existing resources. - **AWS_INSTANCE_CNAME** - If the service configuration includes a ``CNAME`` record, the domain name that you want Route 53 to return in response to DNS queries, for example, ``example.com`` . This value is required if the service specified by ``ServiceId`` includes settings for an ``CNAME`` record. - **AWS_INSTANCE_IPV4** - If the service configuration includes an ``A`` record, the IPv4 address that you want Route 53 to return in response to DNS queries, for example, ``192.0.2.44`` . This value is required if the service specified by ``ServiceId`` includes settings for an ``A`` record. If the service includes settings for an ``SRV`` record, you must specify a value for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both. - **AWS_INSTANCE_IPV6** - If the service configuration includes an ``AAAA`` record, the IPv6 address that you want Route 53 to return in response to DNS queries, for example, ``2001:0db8:85a3:0000:0000:abcd:0001:2345`` . This value is required if the service specified by ``ServiceId`` includes settings for an ``AAAA`` record. If the service includes settings for an ``SRV`` record, you must specify a value for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both. - **AWS_INSTANCE_PORT** - If the service includes an ``SRV`` record, the value that you want Route 53 to return for the port. If the service includes ``HealthCheckConfig`` , the port on the endpoint that you want Route 53 to send requests to. This value is required if you specified settings for an ``SRV`` record or a Route 53 health check when you created the service.
        :param service_id: The ID of the service that you want to use for settings for the instance.
        :param instance_id: An identifier that you want to associate with the instance. Note the following:. - If the service that's specified by ``ServiceId`` includes settings for an ``SRV`` record, the value of ``InstanceId`` is automatically included as part of the value for the ``SRV`` record. For more information, see `DnsRecord > Type <https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type>`_ . - You can use this value to update an existing instance. - To register a new instance, you must specify a value that's unique among instances that you register by using the same service. - If you specify an existing ``InstanceId`` and ``ServiceId`` , AWS Cloud Map updates the existing DNS records, if any. If there's also an existing health check, AWS Cloud Map deletes the old health check and creates a new one. .. epigraph:: The health check isn't deleted immediately, so it will still appear for a while if you submit a ``ListHealthChecks`` request, for example.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            # instance_attributes: Any
            
            cfn_instance_props = servicediscovery.CfnInstanceProps(
                instance_attributes=instance_attributes,
                service_id="serviceId",
            
                # the properties below are optional
                instance_id="instanceId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instance_attributes": instance_attributes,
            "service_id": service_id,
        }
        if instance_id is not None:
            self._values["instance_id"] = instance_id

    @builtins.property
    def instance_attributes(self) -> typing.Any:
        '''A string map that contains the following information for the service that you specify in ``ServiceId`` :.

        - The attributes that apply to the records that are defined in the service.
        - For each attribute, the applicable value.

        Supported attribute keys include the following:

        - **AWS_ALIAS_DNS_NAME** - If you want AWS Cloud Map to create a Route 53 alias record that routes traffic to an Elastic Load Balancing load balancer, specify the DNS name that is associated with the load balancer. For information about how to get the DNS name, see `AliasTarget->DNSName <https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-DNSName>`_ in the *Route 53 API Reference* .

        Note the following:

        - The configuration for the service that is specified by ``ServiceId`` must include settings for an ``A`` record, an ``AAAA`` record, or both.
        - In the service that is specified by ``ServiceId`` , the value of ``RoutingPolicy`` must be ``WEIGHTED`` .
        - If the service that is specified by ``ServiceId`` includes ``HealthCheckConfig`` settings, AWS Cloud Map will create the health check, but it won't associate the health check with the alias record.
        - Auto naming currently doesn't support creating alias records that route traffic to AWS resources other than ELB load balancers.
        - If you specify a value for ``AWS_ALIAS_DNS_NAME`` , don't specify values for any of the ``AWS_INSTANCE`` attributes.
        - **AWS_EC2_INSTANCE_ID** - *HTTP namespaces only.* The Amazon EC2 instance ID for the instance. The ``AWS_INSTANCE_IPV4`` attribute contains the primary private IPv4 address. When creating resources with a type of `AWS::ServiceDiscovery::Instance <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html>`_ , if the ``AWS_EC2_INSTANCE_ID`` attribute is specified, the only other attribute that can be specified is ``AWS_INIT_HEALTH_STATUS`` . After the resource has been created, the ``AWS_INSTANCE_IPV4`` attribute contains the primary private IPv4 address.
        - **AWS_INIT_HEALTH_STATUS** - If the service configuration includes ``HealthCheckCustomConfig`` , when creating resources with a type of `AWS::ServiceDiscovery::Instance <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html>`_ you can optionally use ``AWS_INIT_HEALTH_STATUS`` to specify the initial status of the custom health check, ``HEALTHY`` or ``UNHEALTHY`` . If you don't specify a value for ``AWS_INIT_HEALTH_STATUS`` , the initial status is ``HEALTHY`` . This attribute can only be used when creating resources and will not be seen on existing resources.
        - **AWS_INSTANCE_CNAME** - If the service configuration includes a ``CNAME`` record, the domain name that you want Route 53 to return in response to DNS queries, for example, ``example.com`` .

        This value is required if the service specified by ``ServiceId`` includes settings for an ``CNAME`` record.

        - **AWS_INSTANCE_IPV4** - If the service configuration includes an ``A`` record, the IPv4 address that you want Route 53 to return in response to DNS queries, for example, ``192.0.2.44`` .

        This value is required if the service specified by ``ServiceId`` includes settings for an ``A`` record. If the service includes settings for an ``SRV`` record, you must specify a value for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both.

        - **AWS_INSTANCE_IPV6** - If the service configuration includes an ``AAAA`` record, the IPv6 address that you want Route 53 to return in response to DNS queries, for example, ``2001:0db8:85a3:0000:0000:abcd:0001:2345`` .

        This value is required if the service specified by ``ServiceId`` includes settings for an ``AAAA`` record. If the service includes settings for an ``SRV`` record, you must specify a value for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both.

        - **AWS_INSTANCE_PORT** - If the service includes an ``SRV`` record, the value that you want Route 53 to return for the port.

        If the service includes ``HealthCheckConfig`` , the port on the endpoint that you want Route 53 to send requests to.

        This value is required if you specified settings for an ``SRV`` record or a Route 53 health check when you created the service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html#cfn-servicediscovery-instance-instanceattributes
        '''
        result = self._values.get("instance_attributes")
        assert result is not None, "Required property 'instance_attributes' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def service_id(self) -> builtins.str:
        '''The ID of the service that you want to use for settings for the instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html#cfn-servicediscovery-instance-serviceid
        '''
        result = self._values.get("service_id")
        assert result is not None, "Required property 'service_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''An identifier that you want to associate with the instance. Note the following:.

        - If the service that's specified by ``ServiceId`` includes settings for an ``SRV`` record, the value of ``InstanceId`` is automatically included as part of the value for the ``SRV`` record. For more information, see `DnsRecord > Type <https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsRecord.html#cloudmap-Type-DnsRecord-Type>`_ .
        - You can use this value to update an existing instance.
        - To register a new instance, you must specify a value that's unique among instances that you register by using the same service.
        - If you specify an existing ``InstanceId`` and ``ServiceId`` , AWS Cloud Map updates the existing DNS records, if any. If there's also an existing health check, AWS Cloud Map deletes the old health check and creates a new one.

        .. epigraph::

           The health check isn't deleted immediately, so it will still appear for a while if you submit a ``ListHealthChecks`` request, for example.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html#cfn-servicediscovery-instance-instanceid
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPrivateDnsNamespace(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPrivateDnsNamespace",
):
    '''A CloudFormation ``AWS::ServiceDiscovery::PrivateDnsNamespace``.

    Creates a private namespace based on DNS, which is visible only inside a specified Amazon VPC. The namespace defines your service naming scheme. For example, if you name your namespace ``example.com`` and name your service ``backend`` , the resulting DNS name for the service is ``backend.example.com`` . Service instances that are registered using a private DNS namespace can be discovered using either a ``DiscoverInstances`` request or using DNS. For the current quota on the number of namespaces that you can create using the same AWS account , see `AWS Cloud Map quotas <https://docs.aws.amazon.com/cloud-map/latest/dg/cloud-map-limits.html>`_ in the *AWS Cloud Map Developer Guide* .

    :cloudformationResource: AWS::ServiceDiscovery::PrivateDnsNamespace
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        cfn_private_dns_namespace = servicediscovery.CfnPrivateDnsNamespace(self, "MyCfnPrivateDnsNamespace",
            name="name",
            vpc="vpc",
        
            # the properties below are optional
            description="description",
            properties=servicediscovery.CfnPrivateDnsNamespace.PropertiesProperty(
                dns_properties=servicediscovery.CfnPrivateDnsNamespace.PrivateDnsPropertiesMutableProperty(
                    soa=servicediscovery.CfnPrivateDnsNamespace.SOAProperty(
                        ttl=123
                    )
                )
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
        name: builtins.str,
        vpc: builtins.str,
        description: typing.Optional[builtins.str] = None,
        properties: typing.Optional[typing.Union["CfnPrivateDnsNamespace.PropertiesProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::ServiceDiscovery::PrivateDnsNamespace``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name that you want to assign to this namespace. When you create a private DNS namespace, AWS Cloud Map automatically creates an Amazon Route 53 private hosted zone that has the same name as the namespace.
        :param vpc: The ID of the Amazon VPC that you want to associate the namespace with.
        :param description: A description for the namespace.
        :param properties: Properties for the private DNS namespace.
        :param tags: The tags for the namespace. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.
        '''
        props = CfnPrivateDnsNamespaceProps(
            name=name,
            vpc=vpc,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the private namespace.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrHostedZoneId")
    def attr_hosted_zone_id(self) -> builtins.str:
        '''The ID for the Route 53 hosted zone that AWS Cloud Map creates when you create a namespace.

        :cloudformationAttribute: HostedZoneId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrHostedZoneId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the private namespace.

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
        '''The tags for the namespace.

        Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name that you want to assign to this namespace.

        When you create a private DNS namespace, AWS Cloud Map automatically creates an Amazon Route 53 private hosted zone that has the same name as the namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> builtins.str:
        '''The ID of the Amazon VPC that you want to associate the namespace with.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-vpc
        '''
        return typing.cast(builtins.str, jsii.get(self, "vpc"))

    @vpc.setter
    def vpc(self, value: builtins.str) -> None:
        jsii.set(self, "vpc", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="properties")
    def properties(
        self,
    ) -> typing.Optional[typing.Union["CfnPrivateDnsNamespace.PropertiesProperty", _IResolvable_da3f097b]]:
        '''Properties for the private DNS namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-properties
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPrivateDnsNamespace.PropertiesProperty", _IResolvable_da3f097b]], jsii.get(self, "properties"))

    @properties.setter
    def properties(
        self,
        value: typing.Optional[typing.Union["CfnPrivateDnsNamespace.PropertiesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "properties", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPrivateDnsNamespace.PrivateDnsPropertiesMutableProperty",
        jsii_struct_bases=[],
        name_mapping={"soa": "soa"},
    )
    class PrivateDnsPropertiesMutableProperty:
        def __init__(
            self,
            *,
            soa: typing.Optional[typing.Union["CfnPrivateDnsNamespace.SOAProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''DNS properties for the private DNS namespace.

            :param soa: Fields for the Start of Authority (SOA) record for the hosted zone for the private DNS namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-privatednsnamespace-privatednspropertiesmutable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                private_dns_properties_mutable_property = servicediscovery.CfnPrivateDnsNamespace.PrivateDnsPropertiesMutableProperty(
                    soa=servicediscovery.CfnPrivateDnsNamespace.SOAProperty(
                        ttl=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if soa is not None:
                self._values["soa"] = soa

        @builtins.property
        def soa(
            self,
        ) -> typing.Optional[typing.Union["CfnPrivateDnsNamespace.SOAProperty", _IResolvable_da3f097b]]:
            '''Fields for the Start of Authority (SOA) record for the hosted zone for the private DNS namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-privatednsnamespace-privatednspropertiesmutable.html#cfn-servicediscovery-privatednsnamespace-privatednspropertiesmutable-soa
            '''
            result = self._values.get("soa")
            return typing.cast(typing.Optional[typing.Union["CfnPrivateDnsNamespace.SOAProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PrivateDnsPropertiesMutableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPrivateDnsNamespace.PropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"dns_properties": "dnsProperties"},
    )
    class PropertiesProperty:
        def __init__(
            self,
            *,
            dns_properties: typing.Optional[typing.Union["CfnPrivateDnsNamespace.PrivateDnsPropertiesMutableProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Properties for the private DNS namespace.

            :param dns_properties: DNS properties for the private DNS namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-privatednsnamespace-properties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                properties_property = servicediscovery.CfnPrivateDnsNamespace.PropertiesProperty(
                    dns_properties=servicediscovery.CfnPrivateDnsNamespace.PrivateDnsPropertiesMutableProperty(
                        soa=servicediscovery.CfnPrivateDnsNamespace.SOAProperty(
                            ttl=123
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if dns_properties is not None:
                self._values["dns_properties"] = dns_properties

        @builtins.property
        def dns_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnPrivateDnsNamespace.PrivateDnsPropertiesMutableProperty", _IResolvable_da3f097b]]:
            '''DNS properties for the private DNS namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-privatednsnamespace-properties.html#cfn-servicediscovery-privatednsnamespace-properties-dnsproperties
            '''
            result = self._values.get("dns_properties")
            return typing.cast(typing.Optional[typing.Union["CfnPrivateDnsNamespace.PrivateDnsPropertiesMutableProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPrivateDnsNamespace.SOAProperty",
        jsii_struct_bases=[],
        name_mapping={"ttl": "ttl"},
    )
    class SOAProperty:
        def __init__(self, *, ttl: typing.Optional[jsii.Number] = None) -> None:
            '''Start of Authority (SOA) properties for a public or private DNS namespace.

            :param ttl: The time to live (TTL) for purposes of negative caching.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-privatednsnamespace-soa.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                s_oAProperty = servicediscovery.CfnPrivateDnsNamespace.SOAProperty(
                    ttl=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ttl is not None:
                self._values["ttl"] = ttl

        @builtins.property
        def ttl(self) -> typing.Optional[jsii.Number]:
            '''The time to live (TTL) for purposes of negative caching.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-privatednsnamespace-soa.html#cfn-servicediscovery-privatednsnamespace-soa-ttl
            '''
            result = self._values.get("ttl")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SOAProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPrivateDnsNamespaceProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "vpc": "vpc",
        "description": "description",
        "properties": "properties",
        "tags": "tags",
    },
)
class CfnPrivateDnsNamespaceProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        vpc: builtins.str,
        description: typing.Optional[builtins.str] = None,
        properties: typing.Optional[typing.Union[CfnPrivateDnsNamespace.PropertiesProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPrivateDnsNamespace``.

        :param name: The name that you want to assign to this namespace. When you create a private DNS namespace, AWS Cloud Map automatically creates an Amazon Route 53 private hosted zone that has the same name as the namespace.
        :param vpc: The ID of the Amazon VPC that you want to associate the namespace with.
        :param description: A description for the namespace.
        :param properties: Properties for the private DNS namespace.
        :param tags: The tags for the namespace. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            cfn_private_dns_namespace_props = servicediscovery.CfnPrivateDnsNamespaceProps(
                name="name",
                vpc="vpc",
            
                # the properties below are optional
                description="description",
                properties=servicediscovery.CfnPrivateDnsNamespace.PropertiesProperty(
                    dns_properties=servicediscovery.CfnPrivateDnsNamespace.PrivateDnsPropertiesMutableProperty(
                        soa=servicediscovery.CfnPrivateDnsNamespace.SOAProperty(
                            ttl=123
                        )
                    )
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "vpc": vpc,
        }
        if description is not None:
            self._values["description"] = description
        if properties is not None:
            self._values["properties"] = properties
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name that you want to assign to this namespace.

        When you create a private DNS namespace, AWS Cloud Map automatically creates an Amazon Route 53 private hosted zone that has the same name as the namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def vpc(self) -> builtins.str:
        '''The ID of the Amazon VPC that you want to associate the namespace with.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-vpc
        '''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def properties(
        self,
    ) -> typing.Optional[typing.Union[CfnPrivateDnsNamespace.PropertiesProperty, _IResolvable_da3f097b]]:
        '''Properties for the private DNS namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-properties
        '''
        result = self._values.get("properties")
        return typing.cast(typing.Optional[typing.Union[CfnPrivateDnsNamespace.PropertiesProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags for the namespace.

        Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-privatednsnamespace.html#cfn-servicediscovery-privatednsnamespace-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPrivateDnsNamespaceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPublicDnsNamespace(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPublicDnsNamespace",
):
    '''A CloudFormation ``AWS::ServiceDiscovery::PublicDnsNamespace``.

    Creates a public namespace based on DNS, which is visible on the internet. The namespace defines your service naming scheme. For example, if you name your namespace ``example.com`` and name your service ``backend`` , the resulting DNS name for the service is ``backend.example.com`` . You can discover instances that were registered with a public DNS namespace by using either a ``DiscoverInstances`` request or using DNS. For the current quota on the number of namespaces that you can create using the same AWS account , see `AWS Cloud Map quotas <https://docs.aws.amazon.com/cloud-map/latest/dg/cloud-map-limits.html>`_ in the *AWS Cloud Map Developer Guide* .
    .. epigraph::

       The ``CreatePublicDnsNamespace`` API operation is not supported in the AWS GovCloud (US) Regions.

    :cloudformationResource: AWS::ServiceDiscovery::PublicDnsNamespace
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        cfn_public_dns_namespace = servicediscovery.CfnPublicDnsNamespace(self, "MyCfnPublicDnsNamespace",
            name="name",
        
            # the properties below are optional
            description="description",
            properties=servicediscovery.CfnPublicDnsNamespace.PropertiesProperty(
                dns_properties=servicediscovery.CfnPublicDnsNamespace.PublicDnsPropertiesMutableProperty(
                    soa=servicediscovery.CfnPublicDnsNamespace.SOAProperty(
                        ttl=123
                    )
                )
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
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        properties: typing.Optional[typing.Union["CfnPublicDnsNamespace.PropertiesProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::ServiceDiscovery::PublicDnsNamespace``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name that you want to assign to this namespace.
        :param description: A description for the namespace.
        :param properties: Properties for the public DNS namespace.
        :param tags: The tags for the namespace. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.
        '''
        props = CfnPublicDnsNamespaceProps(
            name=name, description=description, properties=properties, tags=tags
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
        '''The Amazon Resource Name (ARN) of the public namespace.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrHostedZoneId")
    def attr_hosted_zone_id(self) -> builtins.str:
        '''The ID for the Route 53 hosted zone that AWS Cloud Map creates when you create a namespace.

        :cloudformationAttribute: HostedZoneId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrHostedZoneId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the public namespace.

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
        '''The tags for the namespace.

        Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html#cfn-servicediscovery-publicdnsnamespace-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name that you want to assign to this namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html#cfn-servicediscovery-publicdnsnamespace-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html#cfn-servicediscovery-publicdnsnamespace-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="properties")
    def properties(
        self,
    ) -> typing.Optional[typing.Union["CfnPublicDnsNamespace.PropertiesProperty", _IResolvable_da3f097b]]:
        '''Properties for the public DNS namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html#cfn-servicediscovery-publicdnsnamespace-properties
        '''
        return typing.cast(typing.Optional[typing.Union["CfnPublicDnsNamespace.PropertiesProperty", _IResolvable_da3f097b]], jsii.get(self, "properties"))

    @properties.setter
    def properties(
        self,
        value: typing.Optional[typing.Union["CfnPublicDnsNamespace.PropertiesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "properties", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPublicDnsNamespace.PropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"dns_properties": "dnsProperties"},
    )
    class PropertiesProperty:
        def __init__(
            self,
            *,
            dns_properties: typing.Optional[typing.Union["CfnPublicDnsNamespace.PublicDnsPropertiesMutableProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Properties for the public DNS namespace.

            :param dns_properties: DNS properties for the public DNS namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-publicdnsnamespace-properties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                properties_property = servicediscovery.CfnPublicDnsNamespace.PropertiesProperty(
                    dns_properties=servicediscovery.CfnPublicDnsNamespace.PublicDnsPropertiesMutableProperty(
                        soa=servicediscovery.CfnPublicDnsNamespace.SOAProperty(
                            ttl=123
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if dns_properties is not None:
                self._values["dns_properties"] = dns_properties

        @builtins.property
        def dns_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnPublicDnsNamespace.PublicDnsPropertiesMutableProperty", _IResolvable_da3f097b]]:
            '''DNS properties for the public DNS namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-publicdnsnamespace-properties.html#cfn-servicediscovery-publicdnsnamespace-properties-dnsproperties
            '''
            result = self._values.get("dns_properties")
            return typing.cast(typing.Optional[typing.Union["CfnPublicDnsNamespace.PublicDnsPropertiesMutableProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPublicDnsNamespace.PublicDnsPropertiesMutableProperty",
        jsii_struct_bases=[],
        name_mapping={"soa": "soa"},
    )
    class PublicDnsPropertiesMutableProperty:
        def __init__(
            self,
            *,
            soa: typing.Optional[typing.Union["CfnPublicDnsNamespace.SOAProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''DNS properties for the public DNS namespace.

            :param soa: Start of Authority (SOA) record for the hosted zone for the public DNS namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-publicdnsnamespace-publicdnspropertiesmutable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                public_dns_properties_mutable_property = servicediscovery.CfnPublicDnsNamespace.PublicDnsPropertiesMutableProperty(
                    soa=servicediscovery.CfnPublicDnsNamespace.SOAProperty(
                        ttl=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if soa is not None:
                self._values["soa"] = soa

        @builtins.property
        def soa(
            self,
        ) -> typing.Optional[typing.Union["CfnPublicDnsNamespace.SOAProperty", _IResolvable_da3f097b]]:
            '''Start of Authority (SOA) record for the hosted zone for the public DNS namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-publicdnsnamespace-publicdnspropertiesmutable.html#cfn-servicediscovery-publicdnsnamespace-publicdnspropertiesmutable-soa
            '''
            result = self._values.get("soa")
            return typing.cast(typing.Optional[typing.Union["CfnPublicDnsNamespace.SOAProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PublicDnsPropertiesMutableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPublicDnsNamespace.SOAProperty",
        jsii_struct_bases=[],
        name_mapping={"ttl": "ttl"},
    )
    class SOAProperty:
        def __init__(self, *, ttl: typing.Optional[jsii.Number] = None) -> None:
            '''Start of Authority (SOA) properties for a public or private DNS namespace.

            :param ttl: The time to live (TTL) for purposes of negative caching.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-publicdnsnamespace-soa.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                s_oAProperty = servicediscovery.CfnPublicDnsNamespace.SOAProperty(
                    ttl=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ttl is not None:
                self._values["ttl"] = ttl

        @builtins.property
        def ttl(self) -> typing.Optional[jsii.Number]:
            '''The time to live (TTL) for purposes of negative caching.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-publicdnsnamespace-soa.html#cfn-servicediscovery-publicdnsnamespace-soa-ttl
            '''
            result = self._values.get("ttl")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SOAProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnPublicDnsNamespaceProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "description": "description",
        "properties": "properties",
        "tags": "tags",
    },
)
class CfnPublicDnsNamespaceProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        properties: typing.Optional[typing.Union[CfnPublicDnsNamespace.PropertiesProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPublicDnsNamespace``.

        :param name: The name that you want to assign to this namespace.
        :param description: A description for the namespace.
        :param properties: Properties for the public DNS namespace.
        :param tags: The tags for the namespace. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            cfn_public_dns_namespace_props = servicediscovery.CfnPublicDnsNamespaceProps(
                name="name",
            
                # the properties below are optional
                description="description",
                properties=servicediscovery.CfnPublicDnsNamespace.PropertiesProperty(
                    dns_properties=servicediscovery.CfnPublicDnsNamespace.PublicDnsPropertiesMutableProperty(
                        soa=servicediscovery.CfnPublicDnsNamespace.SOAProperty(
                            ttl=123
                        )
                    )
                ),
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
        if properties is not None:
            self._values["properties"] = properties
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name that you want to assign to this namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html#cfn-servicediscovery-publicdnsnamespace-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html#cfn-servicediscovery-publicdnsnamespace-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def properties(
        self,
    ) -> typing.Optional[typing.Union[CfnPublicDnsNamespace.PropertiesProperty, _IResolvable_da3f097b]]:
        '''Properties for the public DNS namespace.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html#cfn-servicediscovery-publicdnsnamespace-properties
        '''
        result = self._values.get("properties")
        return typing.cast(typing.Optional[typing.Union[CfnPublicDnsNamespace.PropertiesProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags for the namespace.

        Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html#cfn-servicediscovery-publicdnsnamespace-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPublicDnsNamespaceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnService(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnService",
):
    '''A CloudFormation ``AWS::ServiceDiscovery::Service``.

    A complex type that contains information about a service, which defines the configuration of the following entities:

    - For public and private DNS namespaces, one of the following combinations of DNS records in Amazon Route 53:
    - A
    - AAAA
    - A and AAAA
    - SRV
    - CNAME
    - Optionally, a health check

    :cloudformationResource: AWS::ServiceDiscovery::Service
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        cfn_service = servicediscovery.CfnService(self, "MyCfnService",
            description="description",
            dns_config=servicediscovery.CfnService.DnsConfigProperty(
                dns_records=[servicediscovery.CfnService.DnsRecordProperty(
                    ttl=123,
                    type="type"
                )],
        
                # the properties below are optional
                namespace_id="namespaceId",
                routing_policy="routingPolicy"
            ),
            health_check_config=servicediscovery.CfnService.HealthCheckConfigProperty(
                type="type",
        
                # the properties below are optional
                failure_threshold=123,
                resource_path="resourcePath"
            ),
            health_check_custom_config=servicediscovery.CfnService.HealthCheckCustomConfigProperty(
                failure_threshold=123
            ),
            name="name",
            namespace_id="namespaceId",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            type="type"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        dns_config: typing.Optional[typing.Union["CfnService.DnsConfigProperty", _IResolvable_da3f097b]] = None,
        health_check_config: typing.Optional[typing.Union["CfnService.HealthCheckConfigProperty", _IResolvable_da3f097b]] = None,
        health_check_custom_config: typing.Optional[typing.Union["CfnService.HealthCheckCustomConfigProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        namespace_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ServiceDiscovery::Service``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: The description of the service.
        :param dns_config: A complex type that contains information about the Route 53 DNS records that you want AWS Cloud Map to create when you register an instance.
        :param health_check_config: *Public DNS and HTTP namespaces only.* A complex type that contains settings for an optional health check. If you specify settings for a health check, AWS Cloud Map associates the health check with the records that you specify in ``DnsConfig`` . For information about the charges for health checks, see `Amazon Route 53 Pricing <https://docs.aws.amazon.com/route53/pricing/>`_ .
        :param health_check_custom_config: A complex type that contains information about an optional custom health check. .. epigraph:: If you specify a health check configuration, you can specify either ``HealthCheckCustomConfig`` or ``HealthCheckConfig`` but not both.
        :param name: The name of the service.
        :param namespace_id: The ID of the namespace that was used to create the service. .. epigraph:: You must specify a value for ``NamespaceId`` either for the service properties or for `DnsConfig <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsconfig.html>`_ . Don't specify a value in both places.
        :param tags: The tags for the service. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.
        :param type: If present, specifies that the service instances are only discoverable using the ``DiscoverInstances`` API operation. No DNS records is registered for the service instances. The only valid value is ``HTTP`` .
        '''
        props = CfnServiceProps(
            description=description,
            dns_config=dns_config,
            health_check_config=health_check_config,
            health_check_custom_config=health_check_custom_config,
            name=name,
            namespace_id=namespace_id,
            tags=tags,
            type=type,
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
        '''The Amazon Resource Name (ARN) of the service.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the service.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name that you assigned to the service.

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags for the service.

        Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dnsConfig")
    def dns_config(
        self,
    ) -> typing.Optional[typing.Union["CfnService.DnsConfigProperty", _IResolvable_da3f097b]]:
        '''A complex type that contains information about the Route 53 DNS records that you want AWS Cloud Map to create when you register an instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-dnsconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnService.DnsConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "dnsConfig"))

    @dns_config.setter
    def dns_config(
        self,
        value: typing.Optional[typing.Union["CfnService.DnsConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "dnsConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckConfig")
    def health_check_config(
        self,
    ) -> typing.Optional[typing.Union["CfnService.HealthCheckConfigProperty", _IResolvable_da3f097b]]:
        '''*Public DNS and HTTP namespaces only.* A complex type that contains settings for an optional health check. If you specify settings for a health check, AWS Cloud Map associates the health check with the records that you specify in ``DnsConfig`` .

        For information about the charges for health checks, see `Amazon Route 53 Pricing <https://docs.aws.amazon.com/route53/pricing/>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-healthcheckconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnService.HealthCheckConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "healthCheckConfig"))

    @health_check_config.setter
    def health_check_config(
        self,
        value: typing.Optional[typing.Union["CfnService.HealthCheckConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "healthCheckConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckCustomConfig")
    def health_check_custom_config(
        self,
    ) -> typing.Optional[typing.Union["CfnService.HealthCheckCustomConfigProperty", _IResolvable_da3f097b]]:
        '''A complex type that contains information about an optional custom health check.

        .. epigraph::

           If you specify a health check configuration, you can specify either ``HealthCheckCustomConfig`` or ``HealthCheckConfig`` but not both.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-healthcheckcustomconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnService.HealthCheckCustomConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "healthCheckCustomConfig"))

    @health_check_custom_config.setter
    def health_check_custom_config(
        self,
        value: typing.Optional[typing.Union["CfnService.HealthCheckCustomConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "healthCheckCustomConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceId")
    def namespace_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the namespace that was used to create the service.

        .. epigraph::

           You must specify a value for ``NamespaceId`` either for the service properties or for `DnsConfig <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsconfig.html>`_ . Don't specify a value in both places.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-namespaceid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "namespaceId"))

    @namespace_id.setter
    def namespace_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "namespaceId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> typing.Optional[builtins.str]:
        '''If present, specifies that the service instances are only discoverable using the ``DiscoverInstances`` API operation.

        No DNS records is registered for the service instances. The only valid value is ``HTTP`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-type
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "type"))

    @type.setter
    def type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "type", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnService.DnsConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "dns_records": "dnsRecords",
            "namespace_id": "namespaceId",
            "routing_policy": "routingPolicy",
        },
    )
    class DnsConfigProperty:
        def __init__(
            self,
            *,
            dns_records: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnService.DnsRecordProperty", _IResolvable_da3f097b]]],
            namespace_id: typing.Optional[builtins.str] = None,
            routing_policy: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A complex type that contains information about the Amazon Route 53 DNS records that you want AWS Cloud Map to create when you register an instance.

            :param dns_records: An array that contains one ``DnsRecord`` object for each Route 53 DNS record that you want AWS Cloud Map to create when you register an instance.
            :param namespace_id: The ID of the namespace to use for DNS configuration. .. epigraph:: You must specify a value for ``NamespaceId`` either for ``DnsConfig`` or for the `service properties <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html>`_ . Don't specify a value in both places.
            :param routing_policy: The routing policy that you want to apply to all Route 53 DNS records that AWS Cloud Map creates when you register an instance and specify this service. .. epigraph:: If you want to use this service to register instances that create alias records, specify ``WEIGHTED`` for the routing policy. You can specify the following values: - **MULTIVALUE** - If you define a health check for the service and the health check is healthy, Route 53 returns the applicable value for up to eight instances. For example, suppose that the service includes configurations for one ``A`` record and a health check. You use the service to register 10 instances. Route 53 responds to DNS queries with IP addresses for up to eight healthy instances. If fewer than eight instances are healthy, Route 53 responds to every DNS query with the IP addresses for all of the healthy instances. If you don't define a health check for the service, Route 53 assumes that all instances are healthy and returns the values for up to eight instances. For more information about the multivalue routing policy, see `Multivalue Answer Routing <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html#routing-policy-multivalue>`_ in the *Route 53 Developer Guide* . - **WEIGHTED** - Route 53 returns the applicable value from one randomly selected instance from among the instances that you registered using the same service. Currently, all records have the same weight, so you can't route more or less traffic to any instances. For example, suppose that the service includes configurations for one ``A`` record and a health check. You use the service to register 10 instances. Route 53 responds to DNS queries with the IP address for one randomly selected instance from among the healthy instances. If no instances are healthy, Route 53 responds to DNS queries as if all of the instances were healthy. If you don't define a health check for the service, Route 53 assumes that all instances are healthy and returns the applicable value for one randomly selected instance. For more information about the weighted routing policy, see `Weighted Routing <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html#routing-policy-weighted>`_ in the *Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                dns_config_property = servicediscovery.CfnService.DnsConfigProperty(
                    dns_records=[servicediscovery.CfnService.DnsRecordProperty(
                        ttl=123,
                        type="type"
                    )],
                
                    # the properties below are optional
                    namespace_id="namespaceId",
                    routing_policy="routingPolicy"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dns_records": dns_records,
            }
            if namespace_id is not None:
                self._values["namespace_id"] = namespace_id
            if routing_policy is not None:
                self._values["routing_policy"] = routing_policy

        @builtins.property
        def dns_records(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnService.DnsRecordProperty", _IResolvable_da3f097b]]]:
            '''An array that contains one ``DnsRecord`` object for each Route 53 DNS record that you want AWS Cloud Map to create when you register an instance.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsconfig.html#cfn-servicediscovery-service-dnsconfig-dnsrecords
            '''
            result = self._values.get("dns_records")
            assert result is not None, "Required property 'dns_records' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnService.DnsRecordProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def namespace_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the namespace to use for DNS configuration.

            .. epigraph::

               You must specify a value for ``NamespaceId`` either for ``DnsConfig`` or for the `service properties <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html>`_ . Don't specify a value in both places.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsconfig.html#cfn-servicediscovery-service-dnsconfig-namespaceid
            '''
            result = self._values.get("namespace_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def routing_policy(self) -> typing.Optional[builtins.str]:
            '''The routing policy that you want to apply to all Route 53 DNS records that AWS Cloud Map creates when you register an instance and specify this service.

            .. epigraph::

               If you want to use this service to register instances that create alias records, specify ``WEIGHTED`` for the routing policy.

            You can specify the following values:

            - **MULTIVALUE** - If you define a health check for the service and the health check is healthy, Route 53 returns the applicable value for up to eight instances.

            For example, suppose that the service includes configurations for one ``A`` record and a health check. You use the service to register 10 instances. Route 53 responds to DNS queries with IP addresses for up to eight healthy instances. If fewer than eight instances are healthy, Route 53 responds to every DNS query with the IP addresses for all of the healthy instances.

            If you don't define a health check for the service, Route 53 assumes that all instances are healthy and returns the values for up to eight instances.

            For more information about the multivalue routing policy, see `Multivalue Answer Routing <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html#routing-policy-multivalue>`_ in the *Route 53 Developer Guide* .

            - **WEIGHTED** - Route 53 returns the applicable value from one randomly selected instance from among the instances that you registered using the same service. Currently, all records have the same weight, so you can't route more or less traffic to any instances.

            For example, suppose that the service includes configurations for one ``A`` record and a health check. You use the service to register 10 instances. Route 53 responds to DNS queries with the IP address for one randomly selected instance from among the healthy instances. If no instances are healthy, Route 53 responds to DNS queries as if all of the instances were healthy.

            If you don't define a health check for the service, Route 53 assumes that all instances are healthy and returns the applicable value for one randomly selected instance.

            For more information about the weighted routing policy, see `Weighted Routing <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html#routing-policy-weighted>`_ in the *Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsconfig.html#cfn-servicediscovery-service-dnsconfig-routingpolicy
            '''
            result = self._values.get("routing_policy")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DnsConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnService.DnsRecordProperty",
        jsii_struct_bases=[],
        name_mapping={"ttl": "ttl", "type": "type"},
    )
    class DnsRecordProperty:
        def __init__(self, *, ttl: jsii.Number, type: builtins.str) -> None:
            '''A complex type that contains information about the Route 53 DNS records that you want AWS Cloud Map to create when you register an instance.

            :param ttl: The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record. .. epigraph:: Alias records don't include a TTL because Route 53 uses the TTL for the AWS resource that an alias record routes traffic to. If you include the ``AWS_ALIAS_DNS_NAME`` attribute when you submit a `RegisterInstance <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html>`_ request, the ``TTL`` value is ignored. Always specify a TTL for the service; you can use a service to register instances that create either alias or non-alias records.
            :param type: The type of the resource, which indicates the type of value that Route 53 returns in response to DNS queries. You can specify values for ``Type`` in the following combinations: - ``A`` - ``AAAA`` - ``A`` and ``AAAA`` - ``SRV`` - ``CNAME`` If you want AWS Cloud Map to create a Route 53 alias record when you register an instance, specify ``A`` or ``AAAA`` for ``Type`` . You specify other settings, such as the IP address for ``A`` and ``AAAA`` records, when you register an instance. For more information, see `RegisterInstance <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html>`_ . The following values are supported: - **A** - Route 53 returns the IP address of the resource in IPv4 format, such as 192.0.2.44. - **AAAA** - Route 53 returns the IP address of the resource in IPv6 format, such as 2001:0db8:85a3:0000:0000:abcd:0001:2345. - **CNAME** - Route 53 returns the domain name of the resource, such as www.example.com. Note the following: - You specify the domain name that you want to route traffic to when you register an instance. For more information, see `Attributes <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html#cloudmap-RegisterInstance-request-Attributes>`_ in the topic `RegisterInstance <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html>`_ . - You must specify ``WEIGHTED`` for the value of ``RoutingPolicy`` . - You can't specify both ``CNAME`` for ``Type`` and settings for ``HealthCheckConfig`` . If you do, the request will fail with an ``InvalidInput`` error. - **SRV** - Route 53 returns the value for an ``SRV`` record. The value for an ``SRV`` record uses the following values: ``priority weight port service-hostname`` Note the following about the values: - The values of ``priority`` and ``weight`` are both set to ``1`` and can't be changed. - The value of ``port`` comes from the value that you specify for the ``AWS_INSTANCE_PORT`` attribute when you submit a `RegisterInstance <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html>`_ request. - The value of ``service-hostname`` is a concatenation of the following values: - The value that you specify for ``InstanceId`` when you register an instance. - The name of the service. - The name of the namespace. For example, if the value of ``InstanceId`` is ``test`` , the name of the service is ``backend`` , and the name of the namespace is ``example.com`` , the value of ``service-hostname`` is: ``test.backend.example.com`` If you specify settings for an ``SRV`` record and if you specify values for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both in the ``RegisterInstance`` request, AWS Cloud Map automatically creates ``A`` and/or ``AAAA`` records that have the same name as the value of ``service-hostname`` in the ``SRV`` record. You can ignore these records.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsrecord.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                dns_record_property = servicediscovery.CfnService.DnsRecordProperty(
                    ttl=123,
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "ttl": ttl,
                "type": type,
            }

        @builtins.property
        def ttl(self) -> jsii.Number:
            '''The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record.

            .. epigraph::

               Alias records don't include a TTL because Route 53 uses the TTL for the AWS resource that an alias record routes traffic to. If you include the ``AWS_ALIAS_DNS_NAME`` attribute when you submit a `RegisterInstance <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html>`_ request, the ``TTL`` value is ignored. Always specify a TTL for the service; you can use a service to register instances that create either alias or non-alias records.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsrecord.html#cfn-servicediscovery-service-dnsrecord-ttl
            '''
            result = self._values.get("ttl")
            assert result is not None, "Required property 'ttl' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The type of the resource, which indicates the type of value that Route 53 returns in response to DNS queries.

            You can specify values for ``Type`` in the following combinations:

            - ``A``
            - ``AAAA``
            - ``A`` and ``AAAA``
            - ``SRV``
            - ``CNAME``

            If you want AWS Cloud Map to create a Route 53 alias record when you register an instance, specify ``A`` or ``AAAA`` for ``Type`` .

            You specify other settings, such as the IP address for ``A`` and ``AAAA`` records, when you register an instance. For more information, see `RegisterInstance <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html>`_ .

            The following values are supported:

            - **A** - Route 53 returns the IP address of the resource in IPv4 format, such as 192.0.2.44.
            - **AAAA** - Route 53 returns the IP address of the resource in IPv6 format, such as 2001:0db8:85a3:0000:0000:abcd:0001:2345.
            - **CNAME** - Route 53 returns the domain name of the resource, such as www.example.com. Note the following:
            - You specify the domain name that you want to route traffic to when you register an instance. For more information, see `Attributes <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html#cloudmap-RegisterInstance-request-Attributes>`_ in the topic `RegisterInstance <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html>`_ .
            - You must specify ``WEIGHTED`` for the value of ``RoutingPolicy`` .
            - You can't specify both ``CNAME`` for ``Type`` and settings for ``HealthCheckConfig`` . If you do, the request will fail with an ``InvalidInput`` error.
            - **SRV** - Route 53 returns the value for an ``SRV`` record. The value for an ``SRV`` record uses the following values:

            ``priority weight port service-hostname``

            Note the following about the values:

            - The values of ``priority`` and ``weight`` are both set to ``1`` and can't be changed.
            - The value of ``port`` comes from the value that you specify for the ``AWS_INSTANCE_PORT`` attribute when you submit a `RegisterInstance <https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html>`_ request.
            - The value of ``service-hostname`` is a concatenation of the following values:
            - The value that you specify for ``InstanceId`` when you register an instance.
            - The name of the service.
            - The name of the namespace.

            For example, if the value of ``InstanceId`` is ``test`` , the name of the service is ``backend`` , and the name of the namespace is ``example.com`` , the value of ``service-hostname`` is:

            ``test.backend.example.com``

            If you specify settings for an ``SRV`` record and if you specify values for ``AWS_INSTANCE_IPV4`` , ``AWS_INSTANCE_IPV6`` , or both in the ``RegisterInstance`` request, AWS Cloud Map automatically creates ``A`` and/or ``AAAA`` records that have the same name as the value of ``service-hostname`` in the ``SRV`` record. You can ignore these records.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsrecord.html#cfn-servicediscovery-service-dnsrecord-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DnsRecordProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnService.HealthCheckConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "type": "type",
            "failure_threshold": "failureThreshold",
            "resource_path": "resourcePath",
        },
    )
    class HealthCheckConfigProperty:
        def __init__(
            self,
            *,
            type: builtins.str,
            failure_threshold: typing.Optional[jsii.Number] = None,
            resource_path: typing.Optional[builtins.str] = None,
        ) -> None:
            '''*Public DNS and HTTP namespaces only.* A complex type that contains settings for an optional health check. If you specify settings for a health check, AWS Cloud Map associates the health check with the records that you specify in ``DnsConfig`` .

            .. epigraph::

               If you specify a health check configuration, you can specify either ``HealthCheckCustomConfig`` or ``HealthCheckConfig`` but not both.

            Health checks are basic Route 53 health checks that monitor an AWS endpoint. For information about pricing for health checks, see `Amazon Route 53 Pricing <https://docs.aws.amazon.com/route53/pricing/>`_ .

            Note the following about configuring health checks.

            - **A and AAAA records** - If ``DnsConfig`` includes configurations for both ``A`` and ``AAAA`` records, AWS Cloud Map creates a health check that uses the IPv4 address to check the health of the resource. If the endpoint tthat's specified by the IPv4 address is unhealthy, Route 53 considers both the ``A`` and ``AAAA`` records to be unhealthy.
            - **CNAME records** - You can't specify settings for ``HealthCheckConfig`` when the ``DNSConfig`` includes ``CNAME`` for the value of ``Type`` . If you do, the ``CreateService`` request will fail with an ``InvalidInput`` error.
            - **Request interval** - A Route 53 health checker in each health-checking AWS Region sends a health check request to an endpoint every 30 seconds. On average, your endpoint receives a health check request about every two seconds. However, health checkers don't coordinate with one another. Therefore, you might sometimes see several requests in one second that's followed by a few seconds with no health checks at all.
            - **Health checking regions** - Health checkers perform checks from all Route 53 health-checking Regions. For a list of the current Regions, see `Regions <https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html#Route53-Type-HealthCheckConfig-Regions>`_ .
            - **Alias records** - When you register an instance, if you include the ``AWS_ALIAS_DNS_NAME`` attribute, AWS Cloud Map creates a Route 53 alias record. Note the following:
            - Route 53 automatically sets ``EvaluateTargetHealth`` to true for alias records. When ``EvaluateTargetHealth`` is true, the alias record inherits the health of the referenced AWS resource. such as an ELB load balancer. For more information, see `EvaluateTargetHealth <https://docs.aws.amazon.com/Route53/latest/APIReference/API_AliasTarget.html#Route53-Type-AliasTarget-EvaluateTargetHealth>`_ .
            - If you include ``HealthCheckConfig`` and then use the service to register an instance that creates an alias record, Route 53 doesn't create the health check.
            - **Charges for health checks** - Health checks are basic Route 53 health checks that monitor an AWS endpoint. For information about pricing for health checks, see `Amazon Route 53 Pricing <https://docs.aws.amazon.com/route53/pricing/>`_ .

            :param type: The type of health check that you want to create, which indicates how Route 53 determines whether an endpoint is healthy. .. epigraph:: You can't change the value of ``Type`` after you create a health check. You can create the following types of health checks: - *HTTP* : Route 53 tries to establish a TCP connection. If successful, Route 53 submits an HTTP request and waits for an HTTP status code of 200 or greater and less than 400. - *HTTPS* : Route 53 tries to establish a TCP connection. If successful, Route 53 submits an HTTPS request and waits for an HTTP status code of 200 or greater and less than 400. .. epigraph:: If you specify HTTPS for the value of ``Type`` , the endpoint must support TLS v1.0 or later. - *TCP* : Route 53 tries to establish a TCP connection. If you specify ``TCP`` for ``Type`` , don't specify a value for ``ResourcePath`` . For more information, see `How Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_ in the *Route 53 Developer Guide* .
            :param failure_threshold: The number of consecutive health checks that an endpoint must pass or fail for Route 53 to change the current status of the endpoint from unhealthy to healthy or the other way around. For more information, see `How Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_ in the *Route 53 Developer Guide* .
            :param resource_path: The path that you want Route 53 to request when performing health checks. The path can be any value that your endpoint returns an HTTP status code of a 2xx or 3xx format for when the endpoint is healthy. An example file is ``/docs/route53-health-check.html`` . Route 53 automatically adds the DNS name for the service. If you don't specify a value for ``ResourcePath`` , the default value is ``/`` . If you specify ``TCP`` for ``Type`` , you must *not* specify a value for ``ResourcePath`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-healthcheckconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                health_check_config_property = servicediscovery.CfnService.HealthCheckConfigProperty(
                    type="type",
                
                    # the properties below are optional
                    failure_threshold=123,
                    resource_path="resourcePath"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "type": type,
            }
            if failure_threshold is not None:
                self._values["failure_threshold"] = failure_threshold
            if resource_path is not None:
                self._values["resource_path"] = resource_path

        @builtins.property
        def type(self) -> builtins.str:
            '''The type of health check that you want to create, which indicates how Route 53 determines whether an endpoint is healthy.

            .. epigraph::

               You can't change the value of ``Type`` after you create a health check.

            You can create the following types of health checks:

            - *HTTP* : Route 53 tries to establish a TCP connection. If successful, Route 53 submits an HTTP request and waits for an HTTP status code of 200 or greater and less than 400.
            - *HTTPS* : Route 53 tries to establish a TCP connection. If successful, Route 53 submits an HTTPS request and waits for an HTTP status code of 200 or greater and less than 400.

            .. epigraph::

               If you specify HTTPS for the value of ``Type`` , the endpoint must support TLS v1.0 or later.

            - *TCP* : Route 53 tries to establish a TCP connection.

            If you specify ``TCP`` for ``Type`` , don't specify a value for ``ResourcePath`` .

            For more information, see `How Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_ in the *Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-healthcheckconfig.html#cfn-servicediscovery-service-healthcheckconfig-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def failure_threshold(self) -> typing.Optional[jsii.Number]:
            '''The number of consecutive health checks that an endpoint must pass or fail for Route 53 to change the current status of the endpoint from unhealthy to healthy or the other way around.

            For more information, see `How Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_ in the *Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-healthcheckconfig.html#cfn-servicediscovery-service-healthcheckconfig-failurethreshold
            '''
            result = self._values.get("failure_threshold")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def resource_path(self) -> typing.Optional[builtins.str]:
            '''The path that you want Route 53 to request when performing health checks.

            The path can be any value that your endpoint returns an HTTP status code of a 2xx or 3xx format for when the endpoint is healthy. An example file is ``/docs/route53-health-check.html`` . Route 53 automatically adds the DNS name for the service. If you don't specify a value for ``ResourcePath`` , the default value is ``/`` .

            If you specify ``TCP`` for ``Type`` , you must *not* specify a value for ``ResourcePath`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-healthcheckconfig.html#cfn-servicediscovery-service-healthcheckconfig-resourcepath
            '''
            result = self._values.get("resource_path")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HealthCheckConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_servicediscovery.CfnService.HealthCheckCustomConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"failure_threshold": "failureThreshold"},
    )
    class HealthCheckCustomConfigProperty:
        def __init__(
            self,
            *,
            failure_threshold: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''A complex type that contains information about an optional custom health check.

            A custom health check, which requires that you use a third-party health checker to evaluate the health of your resources, is useful in the following circumstances:

            - You can't use a health check that's defined by ``HealthCheckConfig`` because the resource isn't available over the internet. For example, you can use a custom health check when the instance is in an Amazon VPC. (To check the health of resources in a VPC, the health checker must also be in the VPC.)
            - You want to use a third-party health checker regardless of where your resources are located.

            .. epigraph::

               If you specify a health check configuration, you can specify either ``HealthCheckCustomConfig`` or ``HealthCheckConfig`` but not both.

            To change the status of a custom health check, submit an ``UpdateInstanceCustomHealthStatus`` request. AWS Cloud Map doesn't monitor the status of the resource, it just keeps a record of the status specified in the most recent ``UpdateInstanceCustomHealthStatus`` request.

            Here's how custom health checks work:

            - You create a service.
            - You register an instance.
            - You configure a third-party health checker to monitor the resource that's associated with the new instance.

            .. epigraph::

               AWS Cloud Map doesn't check the health of the resource directly.

            - The third-party health-checker determines that the resource is unhealthy and notifies your application.
            - Your application submits an ``UpdateInstanceCustomHealthStatus`` request.
            - AWS Cloud Map waits for 30 seconds.
            - If another ``UpdateInstanceCustomHealthStatus`` request doesn't arrive during that time to change the status back to healthy, AWS Cloud Map stops routing traffic to the resource.

            :param failure_threshold: .. epigraph:: This parameter is no longer supported and is always set to 1. AWS Cloud Map waits for approximately 30 seconds after receiving an ``UpdateInstanceCustomHealthStatus`` request before changing the status of the service instance. The number of 30-second intervals that you want AWS Cloud Map to wait after receiving an ``UpdateInstanceCustomHealthStatus`` request before it changes the health status of a service instance. Sending a second or subsequent ``UpdateInstanceCustomHealthStatus`` request with the same value before 30 seconds has passed doesn't accelerate the change. AWS Cloud Map still waits ``30`` seconds after the first request to make the change.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-healthcheckcustomconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_servicediscovery as servicediscovery
                
                health_check_custom_config_property = servicediscovery.CfnService.HealthCheckCustomConfigProperty(
                    failure_threshold=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if failure_threshold is not None:
                self._values["failure_threshold"] = failure_threshold

        @builtins.property
        def failure_threshold(self) -> typing.Optional[jsii.Number]:
            '''.. epigraph::

   This parameter is no longer supported and is always set to 1.

            AWS Cloud Map waits for approximately 30 seconds after receiving an ``UpdateInstanceCustomHealthStatus`` request before changing the status of the service instance.

            The number of 30-second intervals that you want AWS Cloud Map to wait after receiving an ``UpdateInstanceCustomHealthStatus`` request before it changes the health status of a service instance.

            Sending a second or subsequent ``UpdateInstanceCustomHealthStatus`` request with the same value before 30 seconds has passed doesn't accelerate the change. AWS Cloud Map still waits ``30`` seconds after the first request to make the change.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-healthcheckcustomconfig.html#cfn-servicediscovery-service-healthcheckcustomconfig-failurethreshold
            '''
            result = self._values.get("failure_threshold")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HealthCheckCustomConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.CfnServiceProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "dns_config": "dnsConfig",
        "health_check_config": "healthCheckConfig",
        "health_check_custom_config": "healthCheckCustomConfig",
        "name": "name",
        "namespace_id": "namespaceId",
        "tags": "tags",
        "type": "type",
    },
)
class CfnServiceProps:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        dns_config: typing.Optional[typing.Union[CfnService.DnsConfigProperty, _IResolvable_da3f097b]] = None,
        health_check_config: typing.Optional[typing.Union[CfnService.HealthCheckConfigProperty, _IResolvable_da3f097b]] = None,
        health_check_custom_config: typing.Optional[typing.Union[CfnService.HealthCheckCustomConfigProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        namespace_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnService``.

        :param description: The description of the service.
        :param dns_config: A complex type that contains information about the Route 53 DNS records that you want AWS Cloud Map to create when you register an instance.
        :param health_check_config: *Public DNS and HTTP namespaces only.* A complex type that contains settings for an optional health check. If you specify settings for a health check, AWS Cloud Map associates the health check with the records that you specify in ``DnsConfig`` . For information about the charges for health checks, see `Amazon Route 53 Pricing <https://docs.aws.amazon.com/route53/pricing/>`_ .
        :param health_check_custom_config: A complex type that contains information about an optional custom health check. .. epigraph:: If you specify a health check configuration, you can specify either ``HealthCheckCustomConfig`` or ``HealthCheckConfig`` but not both.
        :param name: The name of the service.
        :param namespace_id: The ID of the namespace that was used to create the service. .. epigraph:: You must specify a value for ``NamespaceId`` either for the service properties or for `DnsConfig <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsconfig.html>`_ . Don't specify a value in both places.
        :param tags: The tags for the service. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.
        :param type: If present, specifies that the service instances are only discoverable using the ``DiscoverInstances`` API operation. No DNS records is registered for the service instances. The only valid value is ``HTTP`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            cfn_service_props = servicediscovery.CfnServiceProps(
                description="description",
                dns_config=servicediscovery.CfnService.DnsConfigProperty(
                    dns_records=[servicediscovery.CfnService.DnsRecordProperty(
                        ttl=123,
                        type="type"
                    )],
            
                    # the properties below are optional
                    namespace_id="namespaceId",
                    routing_policy="routingPolicy"
                ),
                health_check_config=servicediscovery.CfnService.HealthCheckConfigProperty(
                    type="type",
            
                    # the properties below are optional
                    failure_threshold=123,
                    resource_path="resourcePath"
                ),
                health_check_custom_config=servicediscovery.CfnService.HealthCheckCustomConfigProperty(
                    failure_threshold=123
                ),
                name="name",
                namespace_id="namespaceId",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                type="type"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if dns_config is not None:
            self._values["dns_config"] = dns_config
        if health_check_config is not None:
            self._values["health_check_config"] = health_check_config
        if health_check_custom_config is not None:
            self._values["health_check_custom_config"] = health_check_custom_config
        if name is not None:
            self._values["name"] = name
        if namespace_id is not None:
            self._values["namespace_id"] = namespace_id
        if tags is not None:
            self._values["tags"] = tags
        if type is not None:
            self._values["type"] = type

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def dns_config(
        self,
    ) -> typing.Optional[typing.Union[CfnService.DnsConfigProperty, _IResolvable_da3f097b]]:
        '''A complex type that contains information about the Route 53 DNS records that you want AWS Cloud Map to create when you register an instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-dnsconfig
        '''
        result = self._values.get("dns_config")
        return typing.cast(typing.Optional[typing.Union[CfnService.DnsConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def health_check_config(
        self,
    ) -> typing.Optional[typing.Union[CfnService.HealthCheckConfigProperty, _IResolvable_da3f097b]]:
        '''*Public DNS and HTTP namespaces only.* A complex type that contains settings for an optional health check. If you specify settings for a health check, AWS Cloud Map associates the health check with the records that you specify in ``DnsConfig`` .

        For information about the charges for health checks, see `Amazon Route 53 Pricing <https://docs.aws.amazon.com/route53/pricing/>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-healthcheckconfig
        '''
        result = self._values.get("health_check_config")
        return typing.cast(typing.Optional[typing.Union[CfnService.HealthCheckConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def health_check_custom_config(
        self,
    ) -> typing.Optional[typing.Union[CfnService.HealthCheckCustomConfigProperty, _IResolvable_da3f097b]]:
        '''A complex type that contains information about an optional custom health check.

        .. epigraph::

           If you specify a health check configuration, you can specify either ``HealthCheckCustomConfig`` or ``HealthCheckConfig`` but not both.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-healthcheckcustomconfig
        '''
        result = self._values.get("health_check_custom_config")
        return typing.cast(typing.Optional[typing.Union[CfnService.HealthCheckCustomConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the namespace that was used to create the service.

        .. epigraph::

           You must specify a value for ``NamespaceId`` either for the service properties or for `DnsConfig <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-dnsconfig.html>`_ . Don't specify a value in both places.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-namespaceid
        '''
        result = self._values.get("namespace_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags for the service.

        Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def type(self) -> typing.Optional[builtins.str]:
        '''If present, specifies that the service instances are only discoverable using the ``DiscoverInstances`` API operation.

        No DNS records is registered for the service instances. The only valid value is ``HTTP`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-service.html#cfn-servicediscovery-service-type
        '''
        result = self._values.get("type")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnServiceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.CnameInstanceBaseProps",
    jsii_struct_bases=[BaseInstanceProps],
    name_mapping={
        "custom_attributes": "customAttributes",
        "instance_id": "instanceId",
        "instance_cname": "instanceCname",
    },
)
class CnameInstanceBaseProps(BaseInstanceProps):
    def __init__(
        self,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
        instance_cname: builtins.str,
    ) -> None:
        '''
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        :param instance_cname: If the service configuration includes a CNAME record, the domain name that you want Route 53 to return in response to DNS queries, for example, example.com. This value is required if the service specified by ServiceId includes settings for an CNAME record.

        :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-cname-record.lit.ts infused

        Example::

            import aws_cdk as cdk
            import aws_cdk as servicediscovery
            
            app = cdk.App()
            stack = cdk.Stack(app, "aws-servicediscovery-integ")
            
            namespace = servicediscovery.PublicDnsNamespace(stack, "Namespace",
                name="foobar.com"
            )
            
            service = namespace.create_service("Service",
                name="foo",
                dns_record_type=servicediscovery.DnsRecordType.CNAME,
                dns_ttl=cdk.Duration.seconds(30)
            )
            
            service.register_cname_instance("CnameInstance",
                instance_cname="service.pizza"
            )
            
            app.synth()
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instance_cname": instance_cname,
        }
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if instance_id is not None:
            self._values["instance_id"] = instance_id

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom attributes of the instance.

        :default: none
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The id of the instance resource.

        :default: Automatically generated name
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def instance_cname(self) -> builtins.str:
        '''If the service configuration includes a CNAME record, the domain name that you want Route 53 to return in response to DNS queries, for example, example.com. This value is required if the service specified by ServiceId includes settings for an CNAME record.'''
        result = self._values.get("instance_cname")
        assert result is not None, "Required property 'instance_cname' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CnameInstanceBaseProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.CnameInstanceProps",
    jsii_struct_bases=[CnameInstanceBaseProps],
    name_mapping={
        "custom_attributes": "customAttributes",
        "instance_id": "instanceId",
        "instance_cname": "instanceCname",
        "service": "service",
    },
)
class CnameInstanceProps(CnameInstanceBaseProps):
    def __init__(
        self,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
        instance_cname: builtins.str,
        service: "IService",
    ) -> None:
        '''
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        :param instance_cname: If the service configuration includes a CNAME record, the domain name that you want Route 53 to return in response to DNS queries, for example, example.com. This value is required if the service specified by ServiceId includes settings for an CNAME record.
        :param service: The Cloudmap service this resource is registered to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            # service: servicediscovery.Service
            
            cname_instance_props = servicediscovery.CnameInstanceProps(
                instance_cname="instanceCname",
                service=service,
            
                # the properties below are optional
                custom_attributes={
                    "custom_attributes_key": "customAttributes"
                },
                instance_id="instanceId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instance_cname": instance_cname,
            "service": service,
        }
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if instance_id is not None:
            self._values["instance_id"] = instance_id

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom attributes of the instance.

        :default: none
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The id of the instance resource.

        :default: Automatically generated name
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def instance_cname(self) -> builtins.str:
        '''If the service configuration includes a CNAME record, the domain name that you want Route 53 to return in response to DNS queries, for example, example.com. This value is required if the service specified by ServiceId includes settings for an CNAME record.'''
        result = self._values.get("instance_cname")
        assert result is not None, "Required property 'instance_cname' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service(self) -> "IService":
        '''The Cloudmap service this resource is registered to.'''
        result = self._values.get("service")
        assert result is not None, "Required property 'service' is missing"
        return typing.cast("IService", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CnameInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_servicediscovery.DnsRecordType")
class DnsRecordType(enum.Enum):
    '''
    :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-cname-record.lit.ts infused

    Example::

        import aws_cdk as cdk
        import aws_cdk as servicediscovery
        
        app = cdk.App()
        stack = cdk.Stack(app, "aws-servicediscovery-integ")
        
        namespace = servicediscovery.PublicDnsNamespace(stack, "Namespace",
            name="foobar.com"
        )
        
        service = namespace.create_service("Service",
            name="foo",
            dns_record_type=servicediscovery.DnsRecordType.CNAME,
            dns_ttl=cdk.Duration.seconds(30)
        )
        
        service.register_cname_instance("CnameInstance",
            instance_cname="service.pizza"
        )
        
        app.synth()
    '''

    A = "A"
    '''An A record.'''
    AAAA = "AAAA"
    '''An AAAA record.'''
    A_AAAA = "A_AAAA"
    '''Both an A and AAAA record.'''
    SRV = "SRV"
    '''A Srv record.'''
    CNAME = "CNAME"
    '''A CNAME record.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.DnsServiceProps",
    jsii_struct_bases=[BaseServiceProps],
    name_mapping={
        "custom_health_check": "customHealthCheck",
        "description": "description",
        "health_check": "healthCheck",
        "name": "name",
        "dns_record_type": "dnsRecordType",
        "dns_ttl": "dnsTtl",
        "load_balancer": "loadBalancer",
        "routing_policy": "routingPolicy",
    },
)
class DnsServiceProps(BaseServiceProps):
    def __init__(
        self,
        *,
        custom_health_check: typing.Optional["HealthCheckCustomConfig"] = None,
        description: typing.Optional[builtins.str] = None,
        health_check: typing.Optional["HealthCheckConfig"] = None,
        name: typing.Optional[builtins.str] = None,
        dns_record_type: typing.Optional[DnsRecordType] = None,
        dns_ttl: typing.Optional[_Duration_4839e8c3] = None,
        load_balancer: typing.Optional[builtins.bool] = None,
        routing_policy: typing.Optional["RoutingPolicy"] = None,
    ) -> None:
        '''Service props needed to create a service in a given namespace.

        Used by createService() for PrivateDnsNamespace and
        PublicDnsNamespace

        :param custom_health_check: Structure containing failure threshold for a custom health checker. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html Default: none
        :param description: A description of the service. Default: none
        :param health_check: Settings for an optional health check. If you specify health check settings, AWS Cloud Map associates the health check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to this service. Default: none
        :param name: A name for the Service. Default: CloudFormation-generated name
        :param dns_record_type: The DNS type of the record that you want AWS Cloud Map to create. Supported record types include A, AAAA, A and AAAA (A_AAAA), CNAME, and SRV. Default: A
        :param dns_ttl: The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record. Default: Duration.minutes(1)
        :param load_balancer: Whether or not this service will have an Elastic LoadBalancer registered to it as an AliasTargetInstance. Setting this to ``true`` correctly configures the ``routingPolicy`` and performs some additional validation. Default: false
        :param routing_policy: The routing policy that you want to apply to all DNS records that AWS Cloud Map creates when you register an instance and specify this service. Default: WEIGHTED for CNAME records and when loadBalancer is true, MULTIVALUE otherwise

        :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-public-dns-namespace.lit.ts infused

        Example::

            import aws_cdk as cdk
            import aws_cdk as servicediscovery
            
            app = cdk.App()
            stack = cdk.Stack(app, "aws-servicediscovery-integ")
            
            namespace = servicediscovery.PublicDnsNamespace(stack, "Namespace",
                name="foobar.com"
            )
            
            service = namespace.create_service("Service",
                name="foo",
                dns_record_type=servicediscovery.DnsRecordType.A,
                dns_ttl=cdk.Duration.seconds(30),
                health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                    type=servicediscovery.HealthCheckType.HTTPS,
                    resource_path="/healthcheck",
                    failure_threshold=2
                )
            )
            
            service.register_ip_instance("IpInstance",
                ipv4="54.239.25.192",
                port=443
            )
            
            app.synth()
        '''
        if isinstance(custom_health_check, dict):
            custom_health_check = HealthCheckCustomConfig(**custom_health_check)
        if isinstance(health_check, dict):
            health_check = HealthCheckConfig(**health_check)
        self._values: typing.Dict[str, typing.Any] = {}
        if custom_health_check is not None:
            self._values["custom_health_check"] = custom_health_check
        if description is not None:
            self._values["description"] = description
        if health_check is not None:
            self._values["health_check"] = health_check
        if name is not None:
            self._values["name"] = name
        if dns_record_type is not None:
            self._values["dns_record_type"] = dns_record_type
        if dns_ttl is not None:
            self._values["dns_ttl"] = dns_ttl
        if load_balancer is not None:
            self._values["load_balancer"] = load_balancer
        if routing_policy is not None:
            self._values["routing_policy"] = routing_policy

    @builtins.property
    def custom_health_check(self) -> typing.Optional["HealthCheckCustomConfig"]:
        '''Structure containing failure threshold for a custom health checker.

        Only one of healthCheckConfig or healthCheckCustomConfig can be specified.
        See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html

        :default: none
        '''
        result = self._values.get("custom_health_check")
        return typing.cast(typing.Optional["HealthCheckCustomConfig"], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the service.

        :default: none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def health_check(self) -> typing.Optional["HealthCheckConfig"]:
        '''Settings for an optional health check.

        If you specify health check settings, AWS Cloud Map associates the health
        check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can
        be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to
        this service.

        :default: none
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional["HealthCheckConfig"], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A name for the Service.

        :default: CloudFormation-generated name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def dns_record_type(self) -> typing.Optional[DnsRecordType]:
        '''The DNS type of the record that you want AWS Cloud Map to create.

        Supported record types
        include A, AAAA, A and AAAA (A_AAAA), CNAME, and SRV.

        :default: A
        '''
        result = self._values.get("dns_record_type")
        return typing.cast(typing.Optional[DnsRecordType], result)

    @builtins.property
    def dns_ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record.

        :default: Duration.minutes(1)
        '''
        result = self._values.get("dns_ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def load_balancer(self) -> typing.Optional[builtins.bool]:
        '''Whether or not this service will have an Elastic LoadBalancer registered to it as an AliasTargetInstance.

        Setting this to ``true`` correctly configures the ``routingPolicy``
        and performs some additional validation.

        :default: false
        '''
        result = self._values.get("load_balancer")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def routing_policy(self) -> typing.Optional["RoutingPolicy"]:
        '''The routing policy that you want to apply to all DNS records that AWS Cloud Map creates when you register an instance and specify this service.

        :default: WEIGHTED for CNAME records and when loadBalancer is true, MULTIVALUE otherwise
        '''
        result = self._values.get("routing_policy")
        return typing.cast(typing.Optional["RoutingPolicy"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DnsServiceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.HealthCheckConfig",
    jsii_struct_bases=[],
    name_mapping={
        "failure_threshold": "failureThreshold",
        "resource_path": "resourcePath",
        "type": "type",
    },
)
class HealthCheckConfig:
    def __init__(
        self,
        *,
        failure_threshold: typing.Optional[jsii.Number] = None,
        resource_path: typing.Optional[builtins.str] = None,
        type: typing.Optional["HealthCheckType"] = None,
    ) -> None:
        '''Settings for an optional Amazon Route 53 health check.

        If you specify settings for a health check, AWS Cloud Map
        associates the health check with all the records that you specify in DnsConfig. Only valid with a PublicDnsNamespace.

        :param failure_threshold: The number of consecutive health checks that an endpoint must pass or fail for Route 53 to change the current status of the endpoint from unhealthy to healthy or vice versa. Default: 1
        :param resource_path: The path that you want Route 53 to request when performing health checks. Do not use when health check type is TCP. Default: '/'
        :param type: The type of health check that you want to create, which indicates how Route 53 determines whether an endpoint is healthy. Cannot be modified once created. Supported values are HTTP, HTTPS, and TCP. Default: HTTP

        :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-http-namespace.lit.ts infused

        Example::

            import aws_cdk as cdk
            import aws_cdk as servicediscovery
            
            app = cdk.App()
            stack = cdk.Stack(app, "aws-servicediscovery-integ")
            
            namespace = servicediscovery.HttpNamespace(stack, "MyNamespace",
                name="covfefe"
            )
            
            service1 = namespace.create_service("NonIpService",
                description="service registering non-ip instances"
            )
            
            service1.register_non_ip_instance("NonIpInstance",
                custom_attributes={"arn": "arn:aws:s3:::mybucket"}
            )
            
            service2 = namespace.create_service("IpService",
                description="service registering ip instances",
                health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                    type=servicediscovery.HealthCheckType.HTTP,
                    resource_path="/check"
                )
            )
            
            service2.register_ip_instance("IpInstance",
                ipv4="54.239.25.192"
            )
            
            app.synth()
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if failure_threshold is not None:
            self._values["failure_threshold"] = failure_threshold
        if resource_path is not None:
            self._values["resource_path"] = resource_path
        if type is not None:
            self._values["type"] = type

    @builtins.property
    def failure_threshold(self) -> typing.Optional[jsii.Number]:
        '''The number of consecutive health checks that an endpoint must pass or fail for Route 53 to change the current status of the endpoint from unhealthy to healthy or vice versa.

        :default: 1
        '''
        result = self._values.get("failure_threshold")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def resource_path(self) -> typing.Optional[builtins.str]:
        '''The path that you want Route 53 to request when performing health checks.

        Do not use when health check type is TCP.

        :default: '/'
        '''
        result = self._values.get("resource_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def type(self) -> typing.Optional["HealthCheckType"]:
        '''The type of health check that you want to create, which indicates how Route 53 determines whether an endpoint is healthy.

        Cannot be modified once created. Supported values are HTTP, HTTPS, and TCP.

        :default: HTTP
        '''
        result = self._values.get("type")
        return typing.cast(typing.Optional["HealthCheckType"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HealthCheckConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.HealthCheckCustomConfig",
    jsii_struct_bases=[],
    name_mapping={"failure_threshold": "failureThreshold"},
)
class HealthCheckCustomConfig:
    def __init__(
        self,
        *,
        failure_threshold: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Specifies information about an optional custom health check.

        :param failure_threshold: The number of 30-second intervals that you want Cloud Map to wait after receiving an UpdateInstanceCustomHealthStatus request before it changes the health status of a service instance. Default: 1

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            health_check_custom_config = servicediscovery.HealthCheckCustomConfig(
                failure_threshold=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if failure_threshold is not None:
            self._values["failure_threshold"] = failure_threshold

    @builtins.property
    def failure_threshold(self) -> typing.Optional[jsii.Number]:
        '''The number of 30-second intervals that you want Cloud Map to wait after receiving an UpdateInstanceCustomHealthStatus request before it changes the health status of a service instance.

        :default: 1
        '''
        result = self._values.get("failure_threshold")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HealthCheckCustomConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_servicediscovery.HealthCheckType")
class HealthCheckType(enum.Enum):
    '''
    :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-http-namespace.lit.ts infused

    Example::

        import aws_cdk as cdk
        import aws_cdk as servicediscovery
        
        app = cdk.App()
        stack = cdk.Stack(app, "aws-servicediscovery-integ")
        
        namespace = servicediscovery.HttpNamespace(stack, "MyNamespace",
            name="covfefe"
        )
        
        service1 = namespace.create_service("NonIpService",
            description="service registering non-ip instances"
        )
        
        service1.register_non_ip_instance("NonIpInstance",
            custom_attributes={"arn": "arn:aws:s3:::mybucket"}
        )
        
        service2 = namespace.create_service("IpService",
            description="service registering ip instances",
            health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                type=servicediscovery.HealthCheckType.HTTP,
                resource_path="/check"
            )
        )
        
        service2.register_ip_instance("IpInstance",
            ipv4="54.239.25.192"
        )
        
        app.synth()
    '''

    HTTP = "HTTP"
    '''Route 53 tries to establish a TCP connection.

    If successful, Route 53 submits an HTTP request and waits for an HTTP
    status code of 200 or greater and less than 400.
    '''
    HTTPS = "HTTPS"
    '''Route 53 tries to establish a TCP connection.

    If successful, Route 53 submits an HTTPS request and waits for an
    HTTP status code of 200 or greater and less than 400.  If you specify HTTPS for the value of Type, the endpoint
    must support TLS v1.0 or later.
    '''
    TCP = "TCP"
    '''Route 53 tries to establish a TCP connection.

    If you specify TCP for Type, don't specify a value for ResourcePath.
    '''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.HttpNamespaceAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "namespace_arn": "namespaceArn",
        "namespace_id": "namespaceId",
        "namespace_name": "namespaceName",
    },
)
class HttpNamespaceAttributes:
    def __init__(
        self,
        *,
        namespace_arn: builtins.str,
        namespace_id: builtins.str,
        namespace_name: builtins.str,
    ) -> None:
        '''
        :param namespace_arn: Namespace ARN for the Namespace.
        :param namespace_id: Namespace Id for the Namespace.
        :param namespace_name: A name for the Namespace.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            http_namespace_attributes = servicediscovery.HttpNamespaceAttributes(
                namespace_arn="namespaceArn",
                namespace_id="namespaceId",
                namespace_name="namespaceName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "namespace_arn": namespace_arn,
            "namespace_id": namespace_id,
            "namespace_name": namespace_name,
        }

    @builtins.property
    def namespace_arn(self) -> builtins.str:
        '''Namespace ARN for the Namespace.'''
        result = self._values.get("namespace_arn")
        assert result is not None, "Required property 'namespace_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def namespace_id(self) -> builtins.str:
        '''Namespace Id for the Namespace.'''
        result = self._values.get("namespace_id")
        assert result is not None, "Required property 'namespace_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def namespace_name(self) -> builtins.str:
        '''A name for the Namespace.'''
        result = self._values.get("namespace_name")
        assert result is not None, "Required property 'namespace_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HttpNamespaceAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.HttpNamespaceProps",
    jsii_struct_bases=[BaseNamespaceProps],
    name_mapping={"name": "name", "description": "description"},
)
class HttpNamespaceProps(BaseNamespaceProps):
    def __init__(
        self,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param name: A name for the Namespace.
        :param description: A description of the Namespace. Default: none

        :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-http-namespace.lit.ts infused

        Example::

            import aws_cdk as cdk
            import aws_cdk as servicediscovery
            
            app = cdk.App()
            stack = cdk.Stack(app, "aws-servicediscovery-integ")
            
            namespace = servicediscovery.HttpNamespace(stack, "MyNamespace",
                name="covfefe"
            )
            
            service1 = namespace.create_service("NonIpService",
                description="service registering non-ip instances"
            )
            
            service1.register_non_ip_instance("NonIpInstance",
                custom_attributes={"arn": "arn:aws:s3:::mybucket"}
            )
            
            service2 = namespace.create_service("IpService",
                description="service registering ip instances",
                health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                    type=servicediscovery.HealthCheckType.HTTP,
                    resource_path="/check"
                )
            )
            
            service2.register_ip_instance("IpInstance",
                ipv4="54.239.25.192"
            )
            
            app.synth()
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def name(self) -> builtins.str:
        '''A name for the Namespace.'''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the Namespace.

        :default: none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HttpNamespaceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_servicediscovery.IInstance")
class IInstance(_IResource_c80c4260, typing_extensions.Protocol):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> builtins.str:
        '''The id of the instance resource.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    def service(self) -> "IService":
        '''The Cloudmap service this resource is registered to.'''
        ...


class _IInstanceProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_servicediscovery.IInstance"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> builtins.str:
        '''The id of the instance resource.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    def service(self) -> "IService":
        '''The Cloudmap service this resource is registered to.'''
        return typing.cast("IService", jsii.get(self, "service"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IInstance).__jsii_proxy_class__ = lambda : _IInstanceProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_servicediscovery.INamespace")
class INamespace(_IResource_c80c4260, typing_extensions.Protocol):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceArn")
    def namespace_arn(self) -> builtins.str:
        '''Namespace ARN for the Namespace.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceId")
    def namespace_id(self) -> builtins.str:
        '''Namespace Id for the Namespace.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceName")
    def namespace_name(self) -> builtins.str:
        '''A name for the Namespace.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> "NamespaceType":
        '''Type of Namespace.'''
        ...


class _INamespaceProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_servicediscovery.INamespace"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceArn")
    def namespace_arn(self) -> builtins.str:
        '''Namespace ARN for the Namespace.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "namespaceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceId")
    def namespace_id(self) -> builtins.str:
        '''Namespace Id for the Namespace.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "namespaceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceName")
    def namespace_name(self) -> builtins.str:
        '''A name for the Namespace.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "namespaceName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> "NamespaceType":
        '''Type of Namespace.'''
        return typing.cast("NamespaceType", jsii.get(self, "type"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INamespace).__jsii_proxy_class__ = lambda : _INamespaceProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_servicediscovery.IPrivateDnsNamespace")
class IPrivateDnsNamespace(INamespace, typing_extensions.Protocol):
    pass


class _IPrivateDnsNamespaceProxy(
    jsii.proxy_for(INamespace) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_servicediscovery.IPrivateDnsNamespace"
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IPrivateDnsNamespace).__jsii_proxy_class__ = lambda : _IPrivateDnsNamespaceProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_servicediscovery.IPublicDnsNamespace")
class IPublicDnsNamespace(INamespace, typing_extensions.Protocol):
    pass


class _IPublicDnsNamespaceProxy(
    jsii.proxy_for(INamespace) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_servicediscovery.IPublicDnsNamespace"
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IPublicDnsNamespace).__jsii_proxy_class__ = lambda : _IPublicDnsNamespaceProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_servicediscovery.IService")
class IService(_IResource_c80c4260, typing_extensions.Protocol):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dnsRecordType")
    def dns_record_type(self) -> DnsRecordType:
        '''The DnsRecordType used by the service.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespace")
    def namespace(self) -> INamespace:
        '''The namespace for the Cloudmap Service.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="routingPolicy")
    def routing_policy(self) -> "RoutingPolicy":
        '''The Routing Policy used by the service.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceArn")
    def service_arn(self) -> builtins.str:
        '''The Arn of the namespace that you want to use for DNS configuration.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceId")
    def service_id(self) -> builtins.str:
        '''The ID of the namespace that you want to use for DNS configuration.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceName")
    def service_name(self) -> builtins.str:
        '''A name for the Cloudmap Service.

        :attribute: true
        '''
        ...


class _IServiceProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_servicediscovery.IService"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dnsRecordType")
    def dns_record_type(self) -> DnsRecordType:
        '''The DnsRecordType used by the service.'''
        return typing.cast(DnsRecordType, jsii.get(self, "dnsRecordType"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespace")
    def namespace(self) -> INamespace:
        '''The namespace for the Cloudmap Service.'''
        return typing.cast(INamespace, jsii.get(self, "namespace"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="routingPolicy")
    def routing_policy(self) -> "RoutingPolicy":
        '''The Routing Policy used by the service.'''
        return typing.cast("RoutingPolicy", jsii.get(self, "routingPolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceArn")
    def service_arn(self) -> builtins.str:
        '''The Arn of the namespace that you want to use for DNS configuration.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "serviceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceId")
    def service_id(self) -> builtins.str:
        '''The ID of the namespace that you want to use for DNS configuration.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "serviceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceName")
    def service_name(self) -> builtins.str:
        '''A name for the Cloudmap Service.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "serviceName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IService).__jsii_proxy_class__ = lambda : _IServiceProxy


@jsii.implements(IInstance)
class InstanceBase(
    _Resource_45bc6135,
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_servicediscovery.InstanceBase",
):
    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        environment_from_arn: typing.Optional[builtins.str] = None,
        physical_name: typing.Optional[builtins.str] = None,
        region: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param account: The AWS account ID this resource belongs to. Default: - the resource is in the same account as the stack it belongs to
        :param environment_from_arn: ARN to deduce region and account from. The ARN is parsed and the account and region are taken from the ARN. This should be used for imported resources. Cannot be supplied together with either ``account`` or ``region``. Default: - take environment from ``account``, ``region`` parameters, or use Stack environment.
        :param physical_name: The value passed in by users to the physical name prop of the resource. - ``undefined`` implies that a physical name will be allocated by CloudFormation during deployment. - a concrete value implies a specific physical name - ``PhysicalName.GENERATE_IF_NEEDED`` is a marker that indicates that a physical will only be generated by the CDK if it is needed for cross-environment references. Otherwise, it will be allocated by CloudFormation. Default: - The physical name will be allocated by CloudFormation at deployment time
        :param region: The AWS region this resource belongs to. Default: - the resource is in the same region as the stack it belongs to
        '''
        props = _ResourceProps_15a65b4e(
            account=account,
            environment_from_arn=environment_from_arn,
            physical_name=physical_name,
            region=region,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="uniqueInstanceId")
    def _unique_instance_id(self) -> builtins.str:
        '''Generate a unique instance Id that is safe to pass to CloudMap.'''
        return typing.cast(builtins.str, jsii.invoke(self, "uniqueInstanceId", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    @abc.abstractmethod
    def instance_id(self) -> builtins.str:
        '''The Id of the instance.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    @abc.abstractmethod
    def service(self) -> IService:
        '''The Cloudmap service to which the instance is registered.'''
        ...


class _InstanceBaseProxy(
    InstanceBase, jsii.proxy_for(_Resource_45bc6135) # type: ignore[misc]
):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> builtins.str:
        '''The Id of the instance.'''
        return typing.cast(builtins.str, jsii.get(self, "instanceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    def service(self) -> IService:
        '''The Cloudmap service to which the instance is registered.'''
        return typing.cast(IService, jsii.get(self, "service"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, InstanceBase).__jsii_proxy_class__ = lambda : _InstanceBaseProxy


class IpInstance(
    InstanceBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.IpInstance",
):
    '''Instance that is accessible using an IP address.

    :resource: AWS::ServiceDiscovery::Instance
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        # service: servicediscovery.Service
        
        ip_instance = servicediscovery.IpInstance(self, "MyIpInstance",
            service=service,
        
            # the properties below are optional
            custom_attributes={
                "custom_attributes_key": "customAttributes"
            },
            instance_id="instanceId",
            ipv4="ipv4",
            ipv6="ipv6",
            port=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        service: IService,
        ipv4: typing.Optional[builtins.str] = None,
        ipv6: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param service: The Cloudmap service this resource is registered to.
        :param ipv4: If the service that you specify contains a template for an A record, the IPv4 address that you want AWS Cloud Map to use for the value of the A record. Default: none
        :param ipv6: If the service that you specify contains a template for an AAAA record, the IPv6 address that you want AWS Cloud Map to use for the value of the AAAA record. Default: none
        :param port: The port on the endpoint that you want AWS Cloud Map to perform health checks on. This value is also used for the port value in an SRV record if the service that you specify includes an SRV record. You can also specify a default port that is applied to all instances in the Service configuration. Default: 80
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        '''
        props = IpInstanceProps(
            service=service,
            ipv4=ipv4,
            ipv6=ipv6,
            port=port,
            custom_attributes=custom_attributes,
            instance_id=instance_id,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> builtins.str:
        '''The Id of the instance.'''
        return typing.cast(builtins.str, jsii.get(self, "instanceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ipv4")
    def ipv4(self) -> builtins.str:
        '''The Ipv4 address of the instance, or blank string if none available.'''
        return typing.cast(builtins.str, jsii.get(self, "ipv4"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ipv6")
    def ipv6(self) -> builtins.str:
        '''The Ipv6 address of the instance, or blank string if none available.'''
        return typing.cast(builtins.str, jsii.get(self, "ipv6"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="port")
    def port(self) -> jsii.Number:
        '''The exposed port of the instance.'''
        return typing.cast(jsii.Number, jsii.get(self, "port"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    def service(self) -> IService:
        '''The Cloudmap service to which the instance is registered.'''
        return typing.cast(IService, jsii.get(self, "service"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.IpInstanceBaseProps",
    jsii_struct_bases=[BaseInstanceProps],
    name_mapping={
        "custom_attributes": "customAttributes",
        "instance_id": "instanceId",
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "port": "port",
    },
)
class IpInstanceBaseProps(BaseInstanceProps):
    def __init__(
        self,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
        ipv4: typing.Optional[builtins.str] = None,
        ipv6: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        :param ipv4: If the service that you specify contains a template for an A record, the IPv4 address that you want AWS Cloud Map to use for the value of the A record. Default: none
        :param ipv6: If the service that you specify contains a template for an AAAA record, the IPv6 address that you want AWS Cloud Map to use for the value of the AAAA record. Default: none
        :param port: The port on the endpoint that you want AWS Cloud Map to perform health checks on. This value is also used for the port value in an SRV record if the service that you specify includes an SRV record. You can also specify a default port that is applied to all instances in the Service configuration. Default: 80

        :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-http-namespace.lit.ts infused

        Example::

            import aws_cdk as cdk
            import aws_cdk as servicediscovery
            
            app = cdk.App()
            stack = cdk.Stack(app, "aws-servicediscovery-integ")
            
            namespace = servicediscovery.HttpNamespace(stack, "MyNamespace",
                name="covfefe"
            )
            
            service1 = namespace.create_service("NonIpService",
                description="service registering non-ip instances"
            )
            
            service1.register_non_ip_instance("NonIpInstance",
                custom_attributes={"arn": "arn:aws:s3:::mybucket"}
            )
            
            service2 = namespace.create_service("IpService",
                description="service registering ip instances",
                health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                    type=servicediscovery.HealthCheckType.HTTP,
                    resource_path="/check"
                )
            )
            
            service2.register_ip_instance("IpInstance",
                ipv4="54.239.25.192"
            )
            
            app.synth()
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if instance_id is not None:
            self._values["instance_id"] = instance_id
        if ipv4 is not None:
            self._values["ipv4"] = ipv4
        if ipv6 is not None:
            self._values["ipv6"] = ipv6
        if port is not None:
            self._values["port"] = port

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom attributes of the instance.

        :default: none
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The id of the instance resource.

        :default: Automatically generated name
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ipv4(self) -> typing.Optional[builtins.str]:
        '''If the service that you specify contains a template for an A record, the IPv4 address that you want AWS Cloud Map to use for the value of the A record.

        :default: none
        '''
        result = self._values.get("ipv4")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ipv6(self) -> typing.Optional[builtins.str]:
        '''If the service that you specify contains a template for an AAAA record, the IPv6 address that you want AWS Cloud Map to use for the value of the AAAA record.

        :default: none
        '''
        result = self._values.get("ipv6")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on the endpoint that you want AWS Cloud Map to perform health checks on.

        This value is also used for
        the port value in an SRV record if the service that you specify includes an SRV record. You can also specify a
        default port that is applied to all instances in the Service configuration.

        :default: 80
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "IpInstanceBaseProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.IpInstanceProps",
    jsii_struct_bases=[IpInstanceBaseProps],
    name_mapping={
        "custom_attributes": "customAttributes",
        "instance_id": "instanceId",
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "port": "port",
        "service": "service",
    },
)
class IpInstanceProps(IpInstanceBaseProps):
    def __init__(
        self,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
        ipv4: typing.Optional[builtins.str] = None,
        ipv6: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        service: IService,
    ) -> None:
        '''
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        :param ipv4: If the service that you specify contains a template for an A record, the IPv4 address that you want AWS Cloud Map to use for the value of the A record. Default: none
        :param ipv6: If the service that you specify contains a template for an AAAA record, the IPv6 address that you want AWS Cloud Map to use for the value of the AAAA record. Default: none
        :param port: The port on the endpoint that you want AWS Cloud Map to perform health checks on. This value is also used for the port value in an SRV record if the service that you specify includes an SRV record. You can also specify a default port that is applied to all instances in the Service configuration. Default: 80
        :param service: The Cloudmap service this resource is registered to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            # service: servicediscovery.Service
            
            ip_instance_props = servicediscovery.IpInstanceProps(
                service=service,
            
                # the properties below are optional
                custom_attributes={
                    "custom_attributes_key": "customAttributes"
                },
                instance_id="instanceId",
                ipv4="ipv4",
                ipv6="ipv6",
                port=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "service": service,
        }
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if instance_id is not None:
            self._values["instance_id"] = instance_id
        if ipv4 is not None:
            self._values["ipv4"] = ipv4
        if ipv6 is not None:
            self._values["ipv6"] = ipv6
        if port is not None:
            self._values["port"] = port

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom attributes of the instance.

        :default: none
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The id of the instance resource.

        :default: Automatically generated name
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ipv4(self) -> typing.Optional[builtins.str]:
        '''If the service that you specify contains a template for an A record, the IPv4 address that you want AWS Cloud Map to use for the value of the A record.

        :default: none
        '''
        result = self._values.get("ipv4")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ipv6(self) -> typing.Optional[builtins.str]:
        '''If the service that you specify contains a template for an AAAA record, the IPv6 address that you want AWS Cloud Map to use for the value of the AAAA record.

        :default: none
        '''
        result = self._values.get("ipv6")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on the endpoint that you want AWS Cloud Map to perform health checks on.

        This value is also used for
        the port value in an SRV record if the service that you specify includes an SRV record. You can also specify a
        default port that is applied to all instances in the Service configuration.

        :default: 80
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def service(self) -> IService:
        '''The Cloudmap service this resource is registered to.'''
        result = self._values.get("service")
        assert result is not None, "Required property 'service' is missing"
        return typing.cast(IService, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "IpInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_servicediscovery.NamespaceType")
class NamespaceType(enum.Enum):
    HTTP = "HTTP"
    '''Choose this option if you want your application to use only API calls to discover registered instances.'''
    DNS_PRIVATE = "DNS_PRIVATE"
    '''Choose this option if you want your application to be able to discover instances using either API calls or using DNS queries in a VPC.'''
    DNS_PUBLIC = "DNS_PUBLIC"
    '''Choose this option if you want your application to be able to discover instances using either API calls or using public DNS queries.

    You aren't required to use both methods.
    '''


class NonIpInstance(
    InstanceBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.NonIpInstance",
):
    '''Instance accessible using values other than an IP address or a domain name (CNAME).

    Specify the other values in Custom attributes.

    :resource: AWS::ServiceDiscovery::Instance
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        # service: servicediscovery.Service
        
        non_ip_instance = servicediscovery.NonIpInstance(self, "MyNonIpInstance",
            service=service,
        
            # the properties below are optional
            custom_attributes={
                "custom_attributes_key": "customAttributes"
            },
            instance_id="instanceId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        service: IService,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param service: The Cloudmap service this resource is registered to.
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        '''
        props = NonIpInstanceProps(
            service=service,
            custom_attributes=custom_attributes,
            instance_id=instance_id,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> builtins.str:
        '''The Id of the instance.'''
        return typing.cast(builtins.str, jsii.get(self, "instanceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    def service(self) -> IService:
        '''The Cloudmap service to which the instance is registered.'''
        return typing.cast(IService, jsii.get(self, "service"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.NonIpInstanceBaseProps",
    jsii_struct_bases=[BaseInstanceProps],
    name_mapping={
        "custom_attributes": "customAttributes",
        "instance_id": "instanceId",
    },
)
class NonIpInstanceBaseProps(BaseInstanceProps):
    def __init__(
        self,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name

        :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-http-namespace.lit.ts infused

        Example::

            import aws_cdk as cdk
            import aws_cdk as servicediscovery
            
            app = cdk.App()
            stack = cdk.Stack(app, "aws-servicediscovery-integ")
            
            namespace = servicediscovery.HttpNamespace(stack, "MyNamespace",
                name="covfefe"
            )
            
            service1 = namespace.create_service("NonIpService",
                description="service registering non-ip instances"
            )
            
            service1.register_non_ip_instance("NonIpInstance",
                custom_attributes={"arn": "arn:aws:s3:::mybucket"}
            )
            
            service2 = namespace.create_service("IpService",
                description="service registering ip instances",
                health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                    type=servicediscovery.HealthCheckType.HTTP,
                    resource_path="/check"
                )
            )
            
            service2.register_ip_instance("IpInstance",
                ipv4="54.239.25.192"
            )
            
            app.synth()
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if instance_id is not None:
            self._values["instance_id"] = instance_id

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom attributes of the instance.

        :default: none
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The id of the instance resource.

        :default: Automatically generated name
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NonIpInstanceBaseProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.NonIpInstanceProps",
    jsii_struct_bases=[NonIpInstanceBaseProps],
    name_mapping={
        "custom_attributes": "customAttributes",
        "instance_id": "instanceId",
        "service": "service",
    },
)
class NonIpInstanceProps(NonIpInstanceBaseProps):
    def __init__(
        self,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
        service: IService,
    ) -> None:
        '''
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        :param service: The Cloudmap service this resource is registered to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            # service: servicediscovery.Service
            
            non_ip_instance_props = servicediscovery.NonIpInstanceProps(
                service=service,
            
                # the properties below are optional
                custom_attributes={
                    "custom_attributes_key": "customAttributes"
                },
                instance_id="instanceId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "service": service,
        }
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if instance_id is not None:
            self._values["instance_id"] = instance_id

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom attributes of the instance.

        :default: none
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The id of the instance resource.

        :default: Automatically generated name
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def service(self) -> IService:
        '''The Cloudmap service this resource is registered to.'''
        result = self._values.get("service")
        assert result is not None, "Required property 'service' is missing"
        return typing.cast(IService, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NonIpInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IPrivateDnsNamespace)
class PrivateDnsNamespace(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.PrivateDnsNamespace",
):
    '''Define a Service Discovery HTTP Namespace.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        # mesh: appmesh.Mesh
        # Cloud Map service discovery is currently required for host ejection by outlier detection
        vpc = ec2.Vpc(self, "vpc")
        namespace = cloudmap.PrivateDnsNamespace(self, "test-namespace",
            vpc=vpc,
            name="domain.local"
        )
        service = namespace.create_service("Svc")
        node = mesh.add_virtual_node("virtual-node",
            service_discovery=appmesh.ServiceDiscovery.cloud_map(service),
            listeners=[appmesh.VirtualNodeListener.http(
                outlier_detection=appmesh.OutlierDetection(
                    base_ejection_duration=cdk.Duration.seconds(10),
                    interval=cdk.Duration.seconds(30),
                    max_ejection_percent=50,
                    max_server_errors=5
                )
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        vpc: _IVpc_f30d5663,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param vpc: The Amazon VPC that you want to associate the namespace with.
        :param name: A name for the Namespace.
        :param description: A description of the Namespace. Default: none
        '''
        props = PrivateDnsNamespaceProps(vpc=vpc, name=name, description=description)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromPrivateDnsNamespaceAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_private_dns_namespace_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        namespace_arn: builtins.str,
        namespace_id: builtins.str,
        namespace_name: builtins.str,
    ) -> IPrivateDnsNamespace:
        '''
        :param scope: -
        :param id: -
        :param namespace_arn: Namespace ARN for the Namespace.
        :param namespace_id: Namespace Id for the Namespace.
        :param namespace_name: A name for the Namespace.
        '''
        attrs = PrivateDnsNamespaceAttributes(
            namespace_arn=namespace_arn,
            namespace_id=namespace_id,
            namespace_name=namespace_name,
        )

        return typing.cast(IPrivateDnsNamespace, jsii.sinvoke(cls, "fromPrivateDnsNamespaceAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="createService")
    def create_service(
        self,
        id: builtins.str,
        *,
        dns_record_type: typing.Optional[DnsRecordType] = None,
        dns_ttl: typing.Optional[_Duration_4839e8c3] = None,
        load_balancer: typing.Optional[builtins.bool] = None,
        routing_policy: typing.Optional["RoutingPolicy"] = None,
        custom_health_check: typing.Optional[HealthCheckCustomConfig] = None,
        description: typing.Optional[builtins.str] = None,
        health_check: typing.Optional[HealthCheckConfig] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> "Service":
        '''Creates a service within the namespace.

        :param id: -
        :param dns_record_type: The DNS type of the record that you want AWS Cloud Map to create. Supported record types include A, AAAA, A and AAAA (A_AAAA), CNAME, and SRV. Default: A
        :param dns_ttl: The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record. Default: Duration.minutes(1)
        :param load_balancer: Whether or not this service will have an Elastic LoadBalancer registered to it as an AliasTargetInstance. Setting this to ``true`` correctly configures the ``routingPolicy`` and performs some additional validation. Default: false
        :param routing_policy: The routing policy that you want to apply to all DNS records that AWS Cloud Map creates when you register an instance and specify this service. Default: WEIGHTED for CNAME records and when loadBalancer is true, MULTIVALUE otherwise
        :param custom_health_check: Structure containing failure threshold for a custom health checker. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html Default: none
        :param description: A description of the service. Default: none
        :param health_check: Settings for an optional health check. If you specify health check settings, AWS Cloud Map associates the health check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to this service. Default: none
        :param name: A name for the Service. Default: CloudFormation-generated name
        '''
        props = DnsServiceProps(
            dns_record_type=dns_record_type,
            dns_ttl=dns_ttl,
            load_balancer=load_balancer,
            routing_policy=routing_policy,
            custom_health_check=custom_health_check,
            description=description,
            health_check=health_check,
            name=name,
        )

        return typing.cast("Service", jsii.invoke(self, "createService", [id, props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceArn")
    def namespace_arn(self) -> builtins.str:
        '''Namespace Arn of the namespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceId")
    def namespace_id(self) -> builtins.str:
        '''Namespace Id of the PrivateDnsNamespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceName")
    def namespace_name(self) -> builtins.str:
        '''The name of the PrivateDnsNamespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="privateDnsNamespaceArn")
    def private_dns_namespace_arn(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "privateDnsNamespaceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="privateDnsNamespaceId")
    def private_dns_namespace_id(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "privateDnsNamespaceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="privateDnsNamespaceName")
    def private_dns_namespace_name(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "privateDnsNamespaceName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> NamespaceType:
        '''Type of the namespace.'''
        return typing.cast(NamespaceType, jsii.get(self, "type"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.PrivateDnsNamespaceAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "namespace_arn": "namespaceArn",
        "namespace_id": "namespaceId",
        "namespace_name": "namespaceName",
    },
)
class PrivateDnsNamespaceAttributes:
    def __init__(
        self,
        *,
        namespace_arn: builtins.str,
        namespace_id: builtins.str,
        namespace_name: builtins.str,
    ) -> None:
        '''
        :param namespace_arn: Namespace ARN for the Namespace.
        :param namespace_id: Namespace Id for the Namespace.
        :param namespace_name: A name for the Namespace.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            private_dns_namespace_attributes = servicediscovery.PrivateDnsNamespaceAttributes(
                namespace_arn="namespaceArn",
                namespace_id="namespaceId",
                namespace_name="namespaceName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "namespace_arn": namespace_arn,
            "namespace_id": namespace_id,
            "namespace_name": namespace_name,
        }

    @builtins.property
    def namespace_arn(self) -> builtins.str:
        '''Namespace ARN for the Namespace.'''
        result = self._values.get("namespace_arn")
        assert result is not None, "Required property 'namespace_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def namespace_id(self) -> builtins.str:
        '''Namespace Id for the Namespace.'''
        result = self._values.get("namespace_id")
        assert result is not None, "Required property 'namespace_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def namespace_name(self) -> builtins.str:
        '''A name for the Namespace.'''
        result = self._values.get("namespace_name")
        assert result is not None, "Required property 'namespace_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PrivateDnsNamespaceAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.PrivateDnsNamespaceProps",
    jsii_struct_bases=[BaseNamespaceProps],
    name_mapping={"name": "name", "description": "description", "vpc": "vpc"},
)
class PrivateDnsNamespaceProps(BaseNamespaceProps):
    def __init__(
        self,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        vpc: _IVpc_f30d5663,
    ) -> None:
        '''
        :param name: A name for the Namespace.
        :param description: A description of the Namespace. Default: none
        :param vpc: The Amazon VPC that you want to associate the namespace with.

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            # mesh: appmesh.Mesh
            # Cloud Map service discovery is currently required for host ejection by outlier detection
            vpc = ec2.Vpc(self, "vpc")
            namespace = cloudmap.PrivateDnsNamespace(self, "test-namespace",
                vpc=vpc,
                name="domain.local"
            )
            service = namespace.create_service("Svc")
            node = mesh.add_virtual_node("virtual-node",
                service_discovery=appmesh.ServiceDiscovery.cloud_map(service),
                listeners=[appmesh.VirtualNodeListener.http(
                    outlier_detection=appmesh.OutlierDetection(
                        base_ejection_duration=cdk.Duration.seconds(10),
                        interval=cdk.Duration.seconds(30),
                        max_ejection_percent=50,
                        max_server_errors=5
                    )
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "vpc": vpc,
        }
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def name(self) -> builtins.str:
        '''A name for the Namespace.'''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the Namespace.

        :default: none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''The Amazon VPC that you want to associate the namespace with.'''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PrivateDnsNamespaceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IPublicDnsNamespace)
class PublicDnsNamespace(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.PublicDnsNamespace",
):
    '''Define a Public DNS Namespace.

    :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-public-dns-namespace.lit.ts infused

    Example::

        import aws_cdk as cdk
        import aws_cdk as servicediscovery
        
        app = cdk.App()
        stack = cdk.Stack(app, "aws-servicediscovery-integ")
        
        namespace = servicediscovery.PublicDnsNamespace(stack, "Namespace",
            name="foobar.com"
        )
        
        service = namespace.create_service("Service",
            name="foo",
            dns_record_type=servicediscovery.DnsRecordType.A,
            dns_ttl=cdk.Duration.seconds(30),
            health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                type=servicediscovery.HealthCheckType.HTTPS,
                resource_path="/healthcheck",
                failure_threshold=2
            )
        )
        
        service.register_ip_instance("IpInstance",
            ipv4="54.239.25.192",
            port=443
        )
        
        app.synth()
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param name: A name for the Namespace.
        :param description: A description of the Namespace. Default: none
        '''
        props = PublicDnsNamespaceProps(name=name, description=description)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromPublicDnsNamespaceAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_public_dns_namespace_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        namespace_arn: builtins.str,
        namespace_id: builtins.str,
        namespace_name: builtins.str,
    ) -> IPublicDnsNamespace:
        '''
        :param scope: -
        :param id: -
        :param namespace_arn: Namespace ARN for the Namespace.
        :param namespace_id: Namespace Id for the Namespace.
        :param namespace_name: A name for the Namespace.
        '''
        attrs = PublicDnsNamespaceAttributes(
            namespace_arn=namespace_arn,
            namespace_id=namespace_id,
            namespace_name=namespace_name,
        )

        return typing.cast(IPublicDnsNamespace, jsii.sinvoke(cls, "fromPublicDnsNamespaceAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="createService")
    def create_service(
        self,
        id: builtins.str,
        *,
        dns_record_type: typing.Optional[DnsRecordType] = None,
        dns_ttl: typing.Optional[_Duration_4839e8c3] = None,
        load_balancer: typing.Optional[builtins.bool] = None,
        routing_policy: typing.Optional["RoutingPolicy"] = None,
        custom_health_check: typing.Optional[HealthCheckCustomConfig] = None,
        description: typing.Optional[builtins.str] = None,
        health_check: typing.Optional[HealthCheckConfig] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> "Service":
        '''Creates a service within the namespace.

        :param id: -
        :param dns_record_type: The DNS type of the record that you want AWS Cloud Map to create. Supported record types include A, AAAA, A and AAAA (A_AAAA), CNAME, and SRV. Default: A
        :param dns_ttl: The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record. Default: Duration.minutes(1)
        :param load_balancer: Whether or not this service will have an Elastic LoadBalancer registered to it as an AliasTargetInstance. Setting this to ``true`` correctly configures the ``routingPolicy`` and performs some additional validation. Default: false
        :param routing_policy: The routing policy that you want to apply to all DNS records that AWS Cloud Map creates when you register an instance and specify this service. Default: WEIGHTED for CNAME records and when loadBalancer is true, MULTIVALUE otherwise
        :param custom_health_check: Structure containing failure threshold for a custom health checker. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html Default: none
        :param description: A description of the service. Default: none
        :param health_check: Settings for an optional health check. If you specify health check settings, AWS Cloud Map associates the health check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to this service. Default: none
        :param name: A name for the Service. Default: CloudFormation-generated name
        '''
        props = DnsServiceProps(
            dns_record_type=dns_record_type,
            dns_ttl=dns_ttl,
            load_balancer=load_balancer,
            routing_policy=routing_policy,
            custom_health_check=custom_health_check,
            description=description,
            health_check=health_check,
            name=name,
        )

        return typing.cast("Service", jsii.invoke(self, "createService", [id, props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceArn")
    def namespace_arn(self) -> builtins.str:
        '''Namespace Arn for the namespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceId")
    def namespace_id(self) -> builtins.str:
        '''Namespace Id for the namespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceName")
    def namespace_name(self) -> builtins.str:
        '''A name for the namespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publicDnsNamespaceArn")
    def public_dns_namespace_arn(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "publicDnsNamespaceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publicDnsNamespaceId")
    def public_dns_namespace_id(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "publicDnsNamespaceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publicDnsNamespaceName")
    def public_dns_namespace_name(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "publicDnsNamespaceName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> NamespaceType:
        '''Type of the namespace.'''
        return typing.cast(NamespaceType, jsii.get(self, "type"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.PublicDnsNamespaceAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "namespace_arn": "namespaceArn",
        "namespace_id": "namespaceId",
        "namespace_name": "namespaceName",
    },
)
class PublicDnsNamespaceAttributes:
    def __init__(
        self,
        *,
        namespace_arn: builtins.str,
        namespace_id: builtins.str,
        namespace_name: builtins.str,
    ) -> None:
        '''
        :param namespace_arn: Namespace ARN for the Namespace.
        :param namespace_id: Namespace Id for the Namespace.
        :param namespace_name: A name for the Namespace.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            public_dns_namespace_attributes = servicediscovery.PublicDnsNamespaceAttributes(
                namespace_arn="namespaceArn",
                namespace_id="namespaceId",
                namespace_name="namespaceName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "namespace_arn": namespace_arn,
            "namespace_id": namespace_id,
            "namespace_name": namespace_name,
        }

    @builtins.property
    def namespace_arn(self) -> builtins.str:
        '''Namespace ARN for the Namespace.'''
        result = self._values.get("namespace_arn")
        assert result is not None, "Required property 'namespace_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def namespace_id(self) -> builtins.str:
        '''Namespace Id for the Namespace.'''
        result = self._values.get("namespace_id")
        assert result is not None, "Required property 'namespace_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def namespace_name(self) -> builtins.str:
        '''A name for the Namespace.'''
        result = self._values.get("namespace_name")
        assert result is not None, "Required property 'namespace_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PublicDnsNamespaceAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.PublicDnsNamespaceProps",
    jsii_struct_bases=[BaseNamespaceProps],
    name_mapping={"name": "name", "description": "description"},
)
class PublicDnsNamespaceProps(BaseNamespaceProps):
    def __init__(
        self,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param name: A name for the Namespace.
        :param description: A description of the Namespace. Default: none

        :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-public-dns-namespace.lit.ts infused

        Example::

            import aws_cdk as cdk
            import aws_cdk as servicediscovery
            
            app = cdk.App()
            stack = cdk.Stack(app, "aws-servicediscovery-integ")
            
            namespace = servicediscovery.PublicDnsNamespace(stack, "Namespace",
                name="foobar.com"
            )
            
            service = namespace.create_service("Service",
                name="foo",
                dns_record_type=servicediscovery.DnsRecordType.A,
                dns_ttl=cdk.Duration.seconds(30),
                health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                    type=servicediscovery.HealthCheckType.HTTPS,
                    resource_path="/healthcheck",
                    failure_threshold=2
                )
            )
            
            service.register_ip_instance("IpInstance",
                ipv4="54.239.25.192",
                port=443
            )
            
            app.synth()
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def name(self) -> builtins.str:
        '''A name for the Namespace.'''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the Namespace.

        :default: none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PublicDnsNamespaceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_servicediscovery.RoutingPolicy")
class RoutingPolicy(enum.Enum):
    WEIGHTED = "WEIGHTED"
    '''Route 53 returns the applicable value from one randomly selected instance from among the instances that you registered using the same service.'''
    MULTIVALUE = "MULTIVALUE"
    '''If you define a health check for the service and the health check is healthy, Route 53 returns the applicable value for up to eight instances.'''


@jsii.implements(IService)
class Service(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.Service",
):
    '''Define a CloudMap Service.

    :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-public-dns-namespace.lit.ts infused

    Example::

        import aws_cdk as cdk
        import aws_cdk as servicediscovery
        
        app = cdk.App()
        stack = cdk.Stack(app, "aws-servicediscovery-integ")
        
        namespace = servicediscovery.PublicDnsNamespace(stack, "Namespace",
            name="foobar.com"
        )
        
        service = namespace.create_service("Service",
            name="foo",
            dns_record_type=servicediscovery.DnsRecordType.A,
            dns_ttl=cdk.Duration.seconds(30),
            health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                type=servicediscovery.HealthCheckType.HTTPS,
                resource_path="/healthcheck",
                failure_threshold=2
            )
        )
        
        service.register_ip_instance("IpInstance",
            ipv4="54.239.25.192",
            port=443
        )
        
        app.synth()
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        namespace: INamespace,
        dns_record_type: typing.Optional[DnsRecordType] = None,
        dns_ttl: typing.Optional[_Duration_4839e8c3] = None,
        load_balancer: typing.Optional[builtins.bool] = None,
        routing_policy: typing.Optional[RoutingPolicy] = None,
        custom_health_check: typing.Optional[HealthCheckCustomConfig] = None,
        description: typing.Optional[builtins.str] = None,
        health_check: typing.Optional[HealthCheckConfig] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param namespace: The namespace that you want to use for DNS configuration.
        :param dns_record_type: The DNS type of the record that you want AWS Cloud Map to create. Supported record types include A, AAAA, A and AAAA (A_AAAA), CNAME, and SRV. Default: A
        :param dns_ttl: The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record. Default: Duration.minutes(1)
        :param load_balancer: Whether or not this service will have an Elastic LoadBalancer registered to it as an AliasTargetInstance. Setting this to ``true`` correctly configures the ``routingPolicy`` and performs some additional validation. Default: false
        :param routing_policy: The routing policy that you want to apply to all DNS records that AWS Cloud Map creates when you register an instance and specify this service. Default: WEIGHTED for CNAME records and when loadBalancer is true, MULTIVALUE otherwise
        :param custom_health_check: Structure containing failure threshold for a custom health checker. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html Default: none
        :param description: A description of the service. Default: none
        :param health_check: Settings for an optional health check. If you specify health check settings, AWS Cloud Map associates the health check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to this service. Default: none
        :param name: A name for the Service. Default: CloudFormation-generated name
        '''
        props = ServiceProps(
            namespace=namespace,
            dns_record_type=dns_record_type,
            dns_ttl=dns_ttl,
            load_balancer=load_balancer,
            routing_policy=routing_policy,
            custom_health_check=custom_health_check,
            description=description,
            health_check=health_check,
            name=name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromServiceAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_service_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        dns_record_type: DnsRecordType,
        namespace: INamespace,
        routing_policy: RoutingPolicy,
        service_arn: builtins.str,
        service_id: builtins.str,
        service_name: builtins.str,
    ) -> IService:
        '''
        :param scope: -
        :param id: -
        :param dns_record_type: 
        :param namespace: 
        :param routing_policy: 
        :param service_arn: 
        :param service_id: 
        :param service_name: 
        '''
        attrs = ServiceAttributes(
            dns_record_type=dns_record_type,
            namespace=namespace,
            routing_policy=routing_policy,
            service_arn=service_arn,
            service_id=service_id,
            service_name=service_name,
        )

        return typing.cast(IService, jsii.sinvoke(cls, "fromServiceAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="registerCnameInstance")
    def register_cname_instance(
        self,
        id: builtins.str,
        *,
        instance_cname: builtins.str,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> IInstance:
        '''Registers a resource that is accessible using a CNAME.

        :param id: -
        :param instance_cname: If the service configuration includes a CNAME record, the domain name that you want Route 53 to return in response to DNS queries, for example, example.com. This value is required if the service specified by ServiceId includes settings for an CNAME record.
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        '''
        props = CnameInstanceBaseProps(
            instance_cname=instance_cname,
            custom_attributes=custom_attributes,
            instance_id=instance_id,
        )

        return typing.cast(IInstance, jsii.invoke(self, "registerCnameInstance", [id, props]))

    @jsii.member(jsii_name="registerIpInstance")
    def register_ip_instance(
        self,
        id: builtins.str,
        *,
        ipv4: typing.Optional[builtins.str] = None,
        ipv6: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> IInstance:
        '''Registers a resource that is accessible using an IP address.

        :param id: -
        :param ipv4: If the service that you specify contains a template for an A record, the IPv4 address that you want AWS Cloud Map to use for the value of the A record. Default: none
        :param ipv6: If the service that you specify contains a template for an AAAA record, the IPv6 address that you want AWS Cloud Map to use for the value of the AAAA record. Default: none
        :param port: The port on the endpoint that you want AWS Cloud Map to perform health checks on. This value is also used for the port value in an SRV record if the service that you specify includes an SRV record. You can also specify a default port that is applied to all instances in the Service configuration. Default: 80
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        '''
        props = IpInstanceBaseProps(
            ipv4=ipv4,
            ipv6=ipv6,
            port=port,
            custom_attributes=custom_attributes,
            instance_id=instance_id,
        )

        return typing.cast(IInstance, jsii.invoke(self, "registerIpInstance", [id, props]))

    @jsii.member(jsii_name="registerLoadBalancer")
    def register_load_balancer(
        self,
        id: builtins.str,
        load_balancer: _ILoadBalancerV2_4c5c0fbb,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> IInstance:
        '''Registers an ELB as a new instance with unique name instanceId in this service.

        :param id: -
        :param load_balancer: -
        :param custom_attributes: -
        '''
        return typing.cast(IInstance, jsii.invoke(self, "registerLoadBalancer", [id, load_balancer, custom_attributes]))

    @jsii.member(jsii_name="registerNonIpInstance")
    def register_non_ip_instance(
        self,
        id: builtins.str,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> IInstance:
        '''Registers a resource that is accessible using values other than an IP address or a domain name (CNAME).

        :param id: -
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        '''
        props = NonIpInstanceBaseProps(
            custom_attributes=custom_attributes, instance_id=instance_id
        )

        return typing.cast(IInstance, jsii.invoke(self, "registerNonIpInstance", [id, props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dnsRecordType")
    def dns_record_type(self) -> DnsRecordType:
        '''The DnsRecordType used by the service.'''
        return typing.cast(DnsRecordType, jsii.get(self, "dnsRecordType"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespace")
    def namespace(self) -> INamespace:
        '''The namespace for the Cloudmap Service.'''
        return typing.cast(INamespace, jsii.get(self, "namespace"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="routingPolicy")
    def routing_policy(self) -> RoutingPolicy:
        '''The Routing Policy used by the service.'''
        return typing.cast(RoutingPolicy, jsii.get(self, "routingPolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceArn")
    def service_arn(self) -> builtins.str:
        '''The Arn of the namespace that you want to use for DNS configuration.'''
        return typing.cast(builtins.str, jsii.get(self, "serviceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceId")
    def service_id(self) -> builtins.str:
        '''The ID of the namespace that you want to use for DNS configuration.'''
        return typing.cast(builtins.str, jsii.get(self, "serviceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceName")
    def service_name(self) -> builtins.str:
        '''A name for the Cloudmap Service.'''
        return typing.cast(builtins.str, jsii.get(self, "serviceName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.ServiceAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "dns_record_type": "dnsRecordType",
        "namespace": "namespace",
        "routing_policy": "routingPolicy",
        "service_arn": "serviceArn",
        "service_id": "serviceId",
        "service_name": "serviceName",
    },
)
class ServiceAttributes:
    def __init__(
        self,
        *,
        dns_record_type: DnsRecordType,
        namespace: INamespace,
        routing_policy: RoutingPolicy,
        service_arn: builtins.str,
        service_id: builtins.str,
        service_name: builtins.str,
    ) -> None:
        '''
        :param dns_record_type: 
        :param namespace: 
        :param routing_policy: 
        :param service_arn: 
        :param service_id: 
        :param service_name: 

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            # namespace: servicediscovery.INamespace
            
            service_attributes = servicediscovery.ServiceAttributes(
                dns_record_type=servicediscovery.DnsRecordType.A,
                namespace=namespace,
                routing_policy=servicediscovery.RoutingPolicy.WEIGHTED,
                service_arn="serviceArn",
                service_id="serviceId",
                service_name="serviceName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "dns_record_type": dns_record_type,
            "namespace": namespace,
            "routing_policy": routing_policy,
            "service_arn": service_arn,
            "service_id": service_id,
            "service_name": service_name,
        }

    @builtins.property
    def dns_record_type(self) -> DnsRecordType:
        result = self._values.get("dns_record_type")
        assert result is not None, "Required property 'dns_record_type' is missing"
        return typing.cast(DnsRecordType, result)

    @builtins.property
    def namespace(self) -> INamespace:
        result = self._values.get("namespace")
        assert result is not None, "Required property 'namespace' is missing"
        return typing.cast(INamespace, result)

    @builtins.property
    def routing_policy(self) -> RoutingPolicy:
        result = self._values.get("routing_policy")
        assert result is not None, "Required property 'routing_policy' is missing"
        return typing.cast(RoutingPolicy, result)

    @builtins.property
    def service_arn(self) -> builtins.str:
        result = self._values.get("service_arn")
        assert result is not None, "Required property 'service_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service_id(self) -> builtins.str:
        result = self._values.get("service_id")
        assert result is not None, "Required property 'service_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service_name(self) -> builtins.str:
        result = self._values.get("service_name")
        assert result is not None, "Required property 'service_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ServiceAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.ServiceProps",
    jsii_struct_bases=[DnsServiceProps],
    name_mapping={
        "custom_health_check": "customHealthCheck",
        "description": "description",
        "health_check": "healthCheck",
        "name": "name",
        "dns_record_type": "dnsRecordType",
        "dns_ttl": "dnsTtl",
        "load_balancer": "loadBalancer",
        "routing_policy": "routingPolicy",
        "namespace": "namespace",
    },
)
class ServiceProps(DnsServiceProps):
    def __init__(
        self,
        *,
        custom_health_check: typing.Optional[HealthCheckCustomConfig] = None,
        description: typing.Optional[builtins.str] = None,
        health_check: typing.Optional[HealthCheckConfig] = None,
        name: typing.Optional[builtins.str] = None,
        dns_record_type: typing.Optional[DnsRecordType] = None,
        dns_ttl: typing.Optional[_Duration_4839e8c3] = None,
        load_balancer: typing.Optional[builtins.bool] = None,
        routing_policy: typing.Optional[RoutingPolicy] = None,
        namespace: INamespace,
    ) -> None:
        '''
        :param custom_health_check: Structure containing failure threshold for a custom health checker. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html Default: none
        :param description: A description of the service. Default: none
        :param health_check: Settings for an optional health check. If you specify health check settings, AWS Cloud Map associates the health check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to this service. Default: none
        :param name: A name for the Service. Default: CloudFormation-generated name
        :param dns_record_type: The DNS type of the record that you want AWS Cloud Map to create. Supported record types include A, AAAA, A and AAAA (A_AAAA), CNAME, and SRV. Default: A
        :param dns_ttl: The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record. Default: Duration.minutes(1)
        :param load_balancer: Whether or not this service will have an Elastic LoadBalancer registered to it as an AliasTargetInstance. Setting this to ``true`` correctly configures the ``routingPolicy`` and performs some additional validation. Default: false
        :param routing_policy: The routing policy that you want to apply to all DNS records that AWS Cloud Map creates when you register an instance and specify this service. Default: WEIGHTED for CNAME records and when loadBalancer is true, MULTIVALUE otherwise
        :param namespace: The namespace that you want to use for DNS configuration.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            # namespace: servicediscovery.INamespace
            
            service_props = servicediscovery.ServiceProps(
                namespace=namespace,
            
                # the properties below are optional
                custom_health_check=servicediscovery.HealthCheckCustomConfig(
                    failure_threshold=123
                ),
                description="description",
                dns_record_type=servicediscovery.DnsRecordType.A,
                dns_ttl=cdk.Duration.minutes(30),
                health_check=servicediscovery.HealthCheckConfig(
                    failure_threshold=123,
                    resource_path="resourcePath",
                    type=servicediscovery.HealthCheckType.HTTP
                ),
                load_balancer=False,
                name="name",
                routing_policy=servicediscovery.RoutingPolicy.WEIGHTED
            )
        '''
        if isinstance(custom_health_check, dict):
            custom_health_check = HealthCheckCustomConfig(**custom_health_check)
        if isinstance(health_check, dict):
            health_check = HealthCheckConfig(**health_check)
        self._values: typing.Dict[str, typing.Any] = {
            "namespace": namespace,
        }
        if custom_health_check is not None:
            self._values["custom_health_check"] = custom_health_check
        if description is not None:
            self._values["description"] = description
        if health_check is not None:
            self._values["health_check"] = health_check
        if name is not None:
            self._values["name"] = name
        if dns_record_type is not None:
            self._values["dns_record_type"] = dns_record_type
        if dns_ttl is not None:
            self._values["dns_ttl"] = dns_ttl
        if load_balancer is not None:
            self._values["load_balancer"] = load_balancer
        if routing_policy is not None:
            self._values["routing_policy"] = routing_policy

    @builtins.property
    def custom_health_check(self) -> typing.Optional[HealthCheckCustomConfig]:
        '''Structure containing failure threshold for a custom health checker.

        Only one of healthCheckConfig or healthCheckCustomConfig can be specified.
        See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html

        :default: none
        '''
        result = self._values.get("custom_health_check")
        return typing.cast(typing.Optional[HealthCheckCustomConfig], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the service.

        :default: none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def health_check(self) -> typing.Optional[HealthCheckConfig]:
        '''Settings for an optional health check.

        If you specify health check settings, AWS Cloud Map associates the health
        check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can
        be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to
        this service.

        :default: none
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional[HealthCheckConfig], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A name for the Service.

        :default: CloudFormation-generated name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def dns_record_type(self) -> typing.Optional[DnsRecordType]:
        '''The DNS type of the record that you want AWS Cloud Map to create.

        Supported record types
        include A, AAAA, A and AAAA (A_AAAA), CNAME, and SRV.

        :default: A
        '''
        result = self._values.get("dns_record_type")
        return typing.cast(typing.Optional[DnsRecordType], result)

    @builtins.property
    def dns_ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The amount of time, in seconds, that you want DNS resolvers to cache the settings for this record.

        :default: Duration.minutes(1)
        '''
        result = self._values.get("dns_ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def load_balancer(self) -> typing.Optional[builtins.bool]:
        '''Whether or not this service will have an Elastic LoadBalancer registered to it as an AliasTargetInstance.

        Setting this to ``true`` correctly configures the ``routingPolicy``
        and performs some additional validation.

        :default: false
        '''
        result = self._values.get("load_balancer")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def routing_policy(self) -> typing.Optional[RoutingPolicy]:
        '''The routing policy that you want to apply to all DNS records that AWS Cloud Map creates when you register an instance and specify this service.

        :default: WEIGHTED for CNAME records and when loadBalancer is true, MULTIVALUE otherwise
        '''
        result = self._values.get("routing_policy")
        return typing.cast(typing.Optional[RoutingPolicy], result)

    @builtins.property
    def namespace(self) -> INamespace:
        '''The namespace that you want to use for DNS configuration.'''
        result = self._values.get("namespace")
        assert result is not None, "Required property 'namespace' is missing"
        return typing.cast(INamespace, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ServiceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class AliasTargetInstance(
    InstanceBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.AliasTargetInstance",
):
    '''Instance that uses Route 53 Alias record type.

    Currently, the only resource types supported are Elastic Load
    Balancers.

    :resource: AWS::ServiceDiscovery::Instance
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        # service: servicediscovery.Service
        
        alias_target_instance = servicediscovery.AliasTargetInstance(self, "MyAliasTargetInstance",
            dns_name="dnsName",
            service=service,
        
            # the properties below are optional
            custom_attributes={
                "custom_attributes_key": "customAttributes"
            },
            instance_id="instanceId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        dns_name: builtins.str,
        service: IService,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param dns_name: DNS name of the target.
        :param service: The Cloudmap service this resource is registered to.
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        '''
        props = AliasTargetInstanceProps(
            dns_name=dns_name,
            service=service,
            custom_attributes=custom_attributes,
            instance_id=instance_id,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dnsName")
    def dns_name(self) -> builtins.str:
        '''The Route53 DNS name of the alias target.'''
        return typing.cast(builtins.str, jsii.get(self, "dnsName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> builtins.str:
        '''The Id of the instance.'''
        return typing.cast(builtins.str, jsii.get(self, "instanceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    def service(self) -> IService:
        '''The Cloudmap service to which the instance is registered.'''
        return typing.cast(IService, jsii.get(self, "service"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_servicediscovery.AliasTargetInstanceProps",
    jsii_struct_bases=[BaseInstanceProps],
    name_mapping={
        "custom_attributes": "customAttributes",
        "instance_id": "instanceId",
        "dns_name": "dnsName",
        "service": "service",
    },
)
class AliasTargetInstanceProps(BaseInstanceProps):
    def __init__(
        self,
        *,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
        dns_name: builtins.str,
        service: IService,
    ) -> None:
        '''
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        :param dns_name: DNS name of the target.
        :param service: The Cloudmap service this resource is registered to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_servicediscovery as servicediscovery
            
            # service: servicediscovery.Service
            
            alias_target_instance_props = servicediscovery.AliasTargetInstanceProps(
                dns_name="dnsName",
                service=service,
            
                # the properties below are optional
                custom_attributes={
                    "custom_attributes_key": "customAttributes"
                },
                instance_id="instanceId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "dns_name": dns_name,
            "service": service,
        }
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if instance_id is not None:
            self._values["instance_id"] = instance_id

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom attributes of the instance.

        :default: none
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The id of the instance resource.

        :default: Automatically generated name
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def dns_name(self) -> builtins.str:
        '''DNS name of the target.'''
        result = self._values.get("dns_name")
        assert result is not None, "Required property 'dns_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service(self) -> IService:
        '''The Cloudmap service this resource is registered to.'''
        result = self._values.get("service")
        assert result is not None, "Required property 'service' is missing"
        return typing.cast(IService, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AliasTargetInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class CnameInstance(
    InstanceBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.CnameInstance",
):
    '''Instance that is accessible using a domain name (CNAME).

    :resource: AWS::ServiceDiscovery::Instance
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_servicediscovery as servicediscovery
        
        # service: servicediscovery.Service
        
        cname_instance = servicediscovery.CnameInstance(self, "MyCnameInstance",
            instance_cname="instanceCname",
            service=service,
        
            # the properties below are optional
            custom_attributes={
                "custom_attributes_key": "customAttributes"
            },
            instance_id="instanceId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        service: IService,
        instance_cname: builtins.str,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        instance_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param service: The Cloudmap service this resource is registered to.
        :param instance_cname: If the service configuration includes a CNAME record, the domain name that you want Route 53 to return in response to DNS queries, for example, example.com. This value is required if the service specified by ServiceId includes settings for an CNAME record.
        :param custom_attributes: Custom attributes of the instance. Default: none
        :param instance_id: The id of the instance resource. Default: Automatically generated name
        '''
        props = CnameInstanceProps(
            service=service,
            instance_cname=instance_cname,
            custom_attributes=custom_attributes,
            instance_id=instance_id,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cname")
    def cname(self) -> builtins.str:
        '''The domain name returned by DNS queries for the instance.'''
        return typing.cast(builtins.str, jsii.get(self, "cname"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> builtins.str:
        '''The Id of the instance.'''
        return typing.cast(builtins.str, jsii.get(self, "instanceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    def service(self) -> IService:
        '''The Cloudmap service to which the instance is registered.'''
        return typing.cast(IService, jsii.get(self, "service"))


@jsii.interface(jsii_type="aws-cdk-lib.aws_servicediscovery.IHttpNamespace")
class IHttpNamespace(INamespace, typing_extensions.Protocol):
    pass


class _IHttpNamespaceProxy(
    jsii.proxy_for(INamespace) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_servicediscovery.IHttpNamespace"
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IHttpNamespace).__jsii_proxy_class__ = lambda : _IHttpNamespaceProxy


@jsii.implements(IHttpNamespace)
class HttpNamespace(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_servicediscovery.HttpNamespace",
):
    '''Define an HTTP Namespace.

    :exampleMetadata: lit=aws-servicediscovery/test/integ.service-with-http-namespace.lit.ts infused

    Example::

        import aws_cdk as cdk
        import aws_cdk as servicediscovery
        
        app = cdk.App()
        stack = cdk.Stack(app, "aws-servicediscovery-integ")
        
        namespace = servicediscovery.HttpNamespace(stack, "MyNamespace",
            name="covfefe"
        )
        
        service1 = namespace.create_service("NonIpService",
            description="service registering non-ip instances"
        )
        
        service1.register_non_ip_instance("NonIpInstance",
            custom_attributes={"arn": "arn:aws:s3:::mybucket"}
        )
        
        service2 = namespace.create_service("IpService",
            description="service registering ip instances",
            health_check=cdk.aws_servicediscovery.HealthCheckConfig(
                type=servicediscovery.HealthCheckType.HTTP,
                resource_path="/check"
            )
        )
        
        service2.register_ip_instance("IpInstance",
            ipv4="54.239.25.192"
        )
        
        app.synth()
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param name: A name for the Namespace.
        :param description: A description of the Namespace. Default: none
        '''
        props = HttpNamespaceProps(name=name, description=description)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromHttpNamespaceAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_http_namespace_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        namespace_arn: builtins.str,
        namespace_id: builtins.str,
        namespace_name: builtins.str,
    ) -> IHttpNamespace:
        '''
        :param scope: -
        :param id: -
        :param namespace_arn: Namespace ARN for the Namespace.
        :param namespace_id: Namespace Id for the Namespace.
        :param namespace_name: A name for the Namespace.
        '''
        attrs = HttpNamespaceAttributes(
            namespace_arn=namespace_arn,
            namespace_id=namespace_id,
            namespace_name=namespace_name,
        )

        return typing.cast(IHttpNamespace, jsii.sinvoke(cls, "fromHttpNamespaceAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="createService")
    def create_service(
        self,
        id: builtins.str,
        *,
        custom_health_check: typing.Optional[HealthCheckCustomConfig] = None,
        description: typing.Optional[builtins.str] = None,
        health_check: typing.Optional[HealthCheckConfig] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> Service:
        '''Creates a service within the namespace.

        :param id: -
        :param custom_health_check: Structure containing failure threshold for a custom health checker. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. See: https://docs.aws.amazon.com/cloud-map/latest/api/API_HealthCheckCustomConfig.html Default: none
        :param description: A description of the service. Default: none
        :param health_check: Settings for an optional health check. If you specify health check settings, AWS Cloud Map associates the health check with the records that you specify in DnsConfig. Only one of healthCheckConfig or healthCheckCustomConfig can be specified. Not valid for PrivateDnsNamespaces. If you use healthCheck, you can only register IP instances to this service. Default: none
        :param name: A name for the Service. Default: CloudFormation-generated name
        '''
        props = BaseServiceProps(
            custom_health_check=custom_health_check,
            description=description,
            health_check=health_check,
            name=name,
        )

        return typing.cast(Service, jsii.invoke(self, "createService", [id, props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="httpNamespaceArn")
    def http_namespace_arn(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "httpNamespaceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="httpNamespaceId")
    def http_namespace_id(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "httpNamespaceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="httpNamespaceName")
    def http_namespace_name(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "httpNamespaceName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceArn")
    def namespace_arn(self) -> builtins.str:
        '''Namespace Arn for the namespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceId")
    def namespace_id(self) -> builtins.str:
        '''Namespace Id for the namespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="namespaceName")
    def namespace_name(self) -> builtins.str:
        '''A name for the namespace.'''
        return typing.cast(builtins.str, jsii.get(self, "namespaceName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> NamespaceType:
        '''Type of the namespace.'''
        return typing.cast(NamespaceType, jsii.get(self, "type"))


__all__ = [
    "AliasTargetInstance",
    "AliasTargetInstanceProps",
    "BaseInstanceProps",
    "BaseNamespaceProps",
    "BaseServiceProps",
    "CfnHttpNamespace",
    "CfnHttpNamespaceProps",
    "CfnInstance",
    "CfnInstanceProps",
    "CfnPrivateDnsNamespace",
    "CfnPrivateDnsNamespaceProps",
    "CfnPublicDnsNamespace",
    "CfnPublicDnsNamespaceProps",
    "CfnService",
    "CfnServiceProps",
    "CnameInstance",
    "CnameInstanceBaseProps",
    "CnameInstanceProps",
    "DnsRecordType",
    "DnsServiceProps",
    "HealthCheckConfig",
    "HealthCheckCustomConfig",
    "HealthCheckType",
    "HttpNamespace",
    "HttpNamespaceAttributes",
    "HttpNamespaceProps",
    "IHttpNamespace",
    "IInstance",
    "INamespace",
    "IPrivateDnsNamespace",
    "IPublicDnsNamespace",
    "IService",
    "InstanceBase",
    "IpInstance",
    "IpInstanceBaseProps",
    "IpInstanceProps",
    "NamespaceType",
    "NonIpInstance",
    "NonIpInstanceBaseProps",
    "NonIpInstanceProps",
    "PrivateDnsNamespace",
    "PrivateDnsNamespaceAttributes",
    "PrivateDnsNamespaceProps",
    "PublicDnsNamespace",
    "PublicDnsNamespaceAttributes",
    "PublicDnsNamespaceProps",
    "RoutingPolicy",
    "Service",
    "ServiceAttributes",
    "ServiceProps",
]

publication.publish()
