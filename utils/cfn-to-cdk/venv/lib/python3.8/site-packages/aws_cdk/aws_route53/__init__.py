'''
# Amazon Route53 Construct Library

To add a public hosted zone:

```python
route53.PublicHostedZone(self, "HostedZone",
    zone_name="fully.qualified.domain.com"
)
```

To add a private hosted zone, use `PrivateHostedZone`. Note that
`enableDnsHostnames` and `enableDnsSupport` must have been enabled for the
VPC you're configuring for private hosted zones.

```python
# vpc: ec2.Vpc


zone = route53.PrivateHostedZone(self, "HostedZone",
    zone_name="fully.qualified.domain.com",
    vpc=vpc
)
```

Additional VPCs can be added with `zone.addVpc()`.

## Adding Records

To add a TXT record to your zone:

```python
# my_zone: route53.HostedZone


route53.TxtRecord(self, "TXTRecord",
    zone=my_zone,
    record_name="_foo",  # If the name ends with a ".", it will be used as-is;
    # if it ends with a "." followed by the zone name, a trailing "." will be added automatically;
    # otherwise, a ".", the zone name, and a trailing "." will be added automatically.
    # Defaults to zone root if not specified.
    values=["Bar!", "Baz?"],
    ttl=Duration.minutes(90)
)
```

To add a NS record to your zone:

```python
# my_zone: route53.HostedZone


route53.NsRecord(self, "NSRecord",
    zone=my_zone,
    record_name="foo",
    values=["ns-1.awsdns.co.uk.", "ns-2.awsdns.com."
    ],
    ttl=Duration.minutes(90)
)
```

To add a DS record to your zone:

```python
# my_zone: route53.HostedZone


route53.DsRecord(self, "DSRecord",
    zone=my_zone,
    record_name="foo",
    values=["12345 3 1 123456789abcdef67890123456789abcdef67890"
    ],
    ttl=Duration.minutes(90)
)
```

To add an A record to your zone:

```python
# my_zone: route53.HostedZone


route53.ARecord(self, "ARecord",
    zone=my_zone,
    target=route53.RecordTarget.from_ip_addresses("1.2.3.4", "5.6.7.8")
)
```

To add an A record for an EC2 instance with an Elastic IP (EIP) to your zone:

```python
# instance: ec2.Instance

# my_zone: route53.HostedZone


elastic_ip = ec2.CfnEIP(self, "EIP",
    domain="vpc",
    instance_id=instance.instance_id
)
route53.ARecord(self, "ARecord",
    zone=my_zone,
    target=route53.RecordTarget.from_ip_addresses(elastic_ip.ref)
)
```

To add an AAAA record pointing to a CloudFront distribution:

```python
import aws_cdk.aws_cloudfront as cloudfront

# my_zone: route53.HostedZone
# distribution: cloudfront.CloudFrontWebDistribution

route53.AaaaRecord(self, "Alias",
    zone=my_zone,
    target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(distribution))
)
```

Constructs are available for A, AAAA, CAA, CNAME, MX, NS, SRV and TXT records.

Use the `CaaAmazonRecord` construct to easily restrict certificate authorities
allowed to issue certificates for a domain to Amazon only.

To add a NS record to a HostedZone in different account you can do the following:

In the account containing the parent hosted zone:

```python
parent_zone = route53.PublicHostedZone(self, "HostedZone",
    zone_name="someexample.com",
    cross_account_zone_delegation_principal=iam.AccountPrincipal("12345678901"),
    cross_account_zone_delegation_role_name="MyDelegationRole"
)
```

In the account containing the child zone to be delegated:

```python
sub_zone = route53.PublicHostedZone(self, "SubZone",
    zone_name="sub.someexample.com"
)

# import the delegation role by constructing the roleArn
delegation_role_arn = Stack.of(self).format_arn(
    region="",  # IAM is global in each partition
    service="iam",
    account="parent-account-id",
    resource="role",
    resource_name="MyDelegationRole"
)
delegation_role = iam.Role.from_role_arn(self, "DelegationRole", delegation_role_arn)

# create the record
route53.CrossAccountZoneDelegationRecord(self, "delegate",
    delegated_zone=sub_zone,
    parent_hosted_zone_name="someexample.com",  # or you can use parentHostedZoneId
    delegation_role=delegation_role
)
```

## Imports

If you don't know the ID of the Hosted Zone to import, you can use the
`HostedZone.fromLookup`:

```python
route53.HostedZone.from_lookup(self, "MyZone",
    domain_name="example.com"
)
```

`HostedZone.fromLookup` requires an environment to be configured. Check
out the [documentation](https://docs.aws.amazon.com/cdk/latest/guide/environments.html) for more documentation and examples. CDK
automatically looks into your `~/.aws/config` file for the `[default]` profile.
If you want to specify a different account run `cdk deploy --profile [profile]`.

```text
new MyDevStack(app, 'dev', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});
```

If you know the ID and Name of a Hosted Zone, you can import it directly:

```python
zone = route53.HostedZone.from_hosted_zone_attributes(self, "MyZone",
    zone_name="example.com",
    hosted_zone_id="ZOJJZC49E0EPZ"
)
```

Alternatively, use the `HostedZone.fromHostedZoneId` to import hosted zones if
you know the ID and the retrieval for the `zoneName` is undesirable.

```python
zone = route53.HostedZone.from_hosted_zone_id(self, "MyZone", "ZOJJZC49E0EPZ")
```

## VPC Endpoint Service Private DNS

When you create a VPC endpoint service, AWS generates endpoint-specific DNS hostnames that consumers use to communicate with the service.
For example, vpce-1234-abcdev-us-east-1.vpce-svc-123345.us-east-1.vpce.amazonaws.com.
By default, your consumers access the service with that DNS name.
This can cause problems with HTTPS traffic because the DNS will not match the backend certificate:

```console
curl: (60) SSL: no alternative certificate subject name matches target host name 'vpce-abcdefghijklmnopq-rstuvwx.vpce-svc-abcdefghijklmnopq.us-east-1.vpce.amazonaws.com'
```

Effectively, the endpoint appears untrustworthy. To mitigate this, clients have to create an alias for this DNS name in Route53.

Private DNS for an endpoint service lets you configure a private DNS name so consumers can
access the service using an existing DNS name without creating this Route53 DNS alias
This DNS name can also be guaranteed to match up with the backend certificate.

Before consumers can use the private DNS name, you must verify that you have control of the domain/subdomain.

Assuming your account has ownership of the particular domain/subdomain,
this construct sets up the private DNS configuration on the endpoint service,
creates all the necessary Route53 entries, and verifies domain ownership.

```python
from aws_cdk import Stack
from aws_cdk.aws_ec2 import Vpc, VpcEndpointService
from aws_cdk.aws_elasticloadbalancingv2 import NetworkLoadBalancer
from aws_cdk.aws_route53 import PublicHostedZone, VpcEndpointServiceDomainName

stack = Stack()
vpc = Vpc(stack, "VPC")
nlb = NetworkLoadBalancer(stack, "NLB",
    vpc=vpc
)
vpces = VpcEndpointService(stack, "VPCES",
    vpc_endpoint_service_load_balancers=[nlb]
)
# You must use a public hosted zone so domain ownership can be verified
zone = PublicHostedZone(stack, "PHZ",
    zone_name="aws-cdk.dev"
)
VpcEndpointServiceDomainName(stack, "EndpointDomain",
    endpoint_service=vpces,
    domain_name="my-stuff.aws-cdk.dev",
    public_hosted_zone=zone
)
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
    Duration as _Duration_4839e8c3,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    IResource as _IResource_c80c4260,
    RemovalPolicy as _RemovalPolicy_9f93c814,
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_ec2 import (
    IVpc as _IVpc_f30d5663, IVpcEndpointService as _IVpcEndpointService_4ddddab0
)
from ..aws_iam import (
    IPrincipal as _IPrincipal_539bb2fd,
    IRole as _IRole_235f5d8e,
    Role as _Role_e8c6e11f,
)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.AliasRecordTargetConfig",
    jsii_struct_bases=[],
    name_mapping={"dns_name": "dnsName", "hosted_zone_id": "hostedZoneId"},
)
class AliasRecordTargetConfig:
    def __init__(self, *, dns_name: builtins.str, hosted_zone_id: builtins.str) -> None:
        '''Represents the properties of an alias target destination.

        :param dns_name: DNS name of the target.
        :param hosted_zone_id: Hosted zone ID of the target.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            alias_record_target_config = route53.AliasRecordTargetConfig(
                dns_name="dnsName",
                hosted_zone_id="hostedZoneId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "dns_name": dns_name,
            "hosted_zone_id": hosted_zone_id,
        }

    @builtins.property
    def dns_name(self) -> builtins.str:
        '''DNS name of the target.'''
        result = self._values.get("dns_name")
        assert result is not None, "Required property 'dns_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def hosted_zone_id(self) -> builtins.str:
        '''Hosted zone ID of the target.'''
        result = self._values.get("hosted_zone_id")
        assert result is not None, "Required property 'hosted_zone_id' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AliasRecordTargetConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CaaRecordValue",
    jsii_struct_bases=[],
    name_mapping={"flag": "flag", "tag": "tag", "value": "value"},
)
class CaaRecordValue:
    def __init__(
        self,
        *,
        flag: jsii.Number,
        tag: "CaaTag",
        value: builtins.str,
    ) -> None:
        '''Properties for a CAA record value.

        :param flag: The flag.
        :param tag: The tag.
        :param value: The value associated with the tag.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            caa_record_value = route53.CaaRecordValue(
                flag=123,
                tag=route53.CaaTag.ISSUE,
                value="value"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "flag": flag,
            "tag": tag,
            "value": value,
        }

    @builtins.property
    def flag(self) -> jsii.Number:
        '''The flag.'''
        result = self._values.get("flag")
        assert result is not None, "Required property 'flag' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def tag(self) -> "CaaTag":
        '''The tag.'''
        result = self._values.get("tag")
        assert result is not None, "Required property 'tag' is missing"
        return typing.cast("CaaTag", result)

    @builtins.property
    def value(self) -> builtins.str:
        '''The value associated with the tag.'''
        result = self._values.get("value")
        assert result is not None, "Required property 'value' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CaaRecordValue(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_route53.CaaTag")
class CaaTag(enum.Enum):
    '''The CAA tag.'''

    ISSUE = "ISSUE"
    '''Explicity authorizes a single certificate authority to issue a certificate (any type) for the hostname.'''
    ISSUEWILD = "ISSUEWILD"
    '''Explicity authorizes a single certificate authority to issue a wildcard certificate (and only wildcard) for the hostname.'''
    IODEF = "IODEF"
    '''Specifies a URL to which a certificate authority may report policy violations.'''


@jsii.implements(_IInspectable_c2943556)
class CfnDNSSEC(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CfnDNSSEC",
):
    '''A CloudFormation ``AWS::Route53::DNSSEC``.

    The ``AWS::Route53::DNSSEC`` resource is used to enable DNSSEC signing in a hosted zone.

    :cloudformationResource: AWS::Route53::DNSSEC
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-dnssec.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53 as route53
        
        cfn_dNSSEC = route53.CfnDNSSEC(self, "MyCfnDNSSEC",
            hosted_zone_id="hostedZoneId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        hosted_zone_id: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Route53::DNSSEC``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param hosted_zone_id: A unique string (ID) that is used to identify a hosted zone. For example: ``Z00001111A1ABCaaABC11`` .
        '''
        props = CfnDNSSECProps(hosted_zone_id=hosted_zone_id)

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
    @jsii.member(jsii_name="hostedZoneId")
    def hosted_zone_id(self) -> builtins.str:
        '''A unique string (ID) that is used to identify a hosted zone.

        For example: ``Z00001111A1ABCaaABC11`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-dnssec.html#cfn-route53-dnssec-hostedzoneid
        '''
        return typing.cast(builtins.str, jsii.get(self, "hostedZoneId"))

    @hosted_zone_id.setter
    def hosted_zone_id(self, value: builtins.str) -> None:
        jsii.set(self, "hostedZoneId", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CfnDNSSECProps",
    jsii_struct_bases=[],
    name_mapping={"hosted_zone_id": "hostedZoneId"},
)
class CfnDNSSECProps:
    def __init__(self, *, hosted_zone_id: builtins.str) -> None:
        '''Properties for defining a ``CfnDNSSEC``.

        :param hosted_zone_id: A unique string (ID) that is used to identify a hosted zone. For example: ``Z00001111A1ABCaaABC11`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-dnssec.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            cfn_dNSSECProps = route53.CfnDNSSECProps(
                hosted_zone_id="hostedZoneId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "hosted_zone_id": hosted_zone_id,
        }

    @builtins.property
    def hosted_zone_id(self) -> builtins.str:
        '''A unique string (ID) that is used to identify a hosted zone.

        For example: ``Z00001111A1ABCaaABC11`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-dnssec.html#cfn-route53-dnssec-hostedzoneid
        '''
        result = self._values.get("hosted_zone_id")
        assert result is not None, "Required property 'hosted_zone_id' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDNSSECProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnHealthCheck(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CfnHealthCheck",
):
    '''A CloudFormation ``AWS::Route53::HealthCheck``.

    The ``AWS::Route53::HealthCheck`` resource is a Route 53 resource type that contains settings for a Route 53 health check.

    For information about associating health checks with records, see `HealthCheckId <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ResourceRecordSet.html#Route53-Type-ResourceRecordSet-HealthCheckId>`_ in `ChangeResourceRecordSets <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html>`_ .
    .. epigraph::

       You can't create a health check with simple routing.

    *ELB Load Balancers*

    If you're registering EC2 instances with an Elastic Load Balancing (ELB) load balancer, do not create Amazon Route 53 health checks for the EC2 instances. When you register an EC2 instance with a load balancer, you configure settings for an ELB health check, which performs a similar function to a Route 53 health check.

    *Private Hosted Zones*

    You can associate health checks with failover records in a private hosted zone. Note the following:

    - Route 53 health checkers are outside the VPC. To check the health of an endpoint within a VPC by IP address, you must assign a public IP address to the instance in the VPC.
    - You can configure a health checker to check the health of an external resource that the instance relies on, such as a database server.
    - You can create a CloudWatch metric, associate an alarm with the metric, and then create a health check that is based on the state of the alarm. For example, you might create a CloudWatch metric that checks the status of the Amazon EC2 ``StatusCheckFailed`` metric, add an alarm to the metric, and then create a health check that is based on the state of the alarm. For information about creating CloudWatch metrics and alarms by using the CloudWatch console, see the `Amazon CloudWatch User Guide <https://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/WhatIsCloudWatch.html>`_ .

    :cloudformationResource: AWS::Route53::HealthCheck
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-healthcheck.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53 as route53
        
        cfn_health_check = route53.CfnHealthCheck(self, "MyCfnHealthCheck",
            health_check_config=route53.CfnHealthCheck.HealthCheckConfigProperty(
                type="type",
        
                # the properties below are optional
                alarm_identifier=route53.CfnHealthCheck.AlarmIdentifierProperty(
                    name="name",
                    region="region"
                ),
                child_health_checks=["childHealthChecks"],
                enable_sni=False,
                failure_threshold=123,
                fully_qualified_domain_name="fullyQualifiedDomainName",
                health_threshold=123,
                insufficient_data_health_status="insufficientDataHealthStatus",
                inverted=False,
                ip_address="ipAddress",
                measure_latency=False,
                port=123,
                regions=["regions"],
                request_interval=123,
                resource_path="resourcePath",
                routing_control_arn="routingControlArn",
                search_string="searchString"
            ),
        
            # the properties below are optional
            health_check_tags=[route53.CfnHealthCheck.HealthCheckTagProperty(
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
        health_check_config: typing.Union["CfnHealthCheck.HealthCheckConfigProperty", _IResolvable_da3f097b],
        health_check_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnHealthCheck.HealthCheckTagProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Route53::HealthCheck``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param health_check_config: A complex type that contains detailed information about one health check. For the values to enter for ``HealthCheckConfig`` , see `HealthCheckConfig <https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html>`_
        :param health_check_tags: The ``HealthCheckTags`` property describes key-value pairs that are associated with an ``AWS::Route53::HealthCheck`` resource.
        '''
        props = CfnHealthCheckProps(
            health_check_config=health_check_config,
            health_check_tags=health_check_tags,
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
    @jsii.member(jsii_name="attrHealthCheckId")
    def attr_health_check_id(self) -> builtins.str:
        '''The identifier that Amazon Route 53 assigned to the health check when you created it.

        When you add or update a resource record set, you use this value to specify which health check to use. The value can be up to 64 characters long.

        :cloudformationAttribute: HealthCheckId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrHealthCheckId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckConfig")
    def health_check_config(
        self,
    ) -> typing.Union["CfnHealthCheck.HealthCheckConfigProperty", _IResolvable_da3f097b]:
        '''A complex type that contains detailed information about one health check.

        For the values to enter for ``HealthCheckConfig`` , see `HealthCheckConfig <https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-healthcheck.html#cfn-route53-healthcheck-healthcheckconfig
        '''
        return typing.cast(typing.Union["CfnHealthCheck.HealthCheckConfigProperty", _IResolvable_da3f097b], jsii.get(self, "healthCheckConfig"))

    @health_check_config.setter
    def health_check_config(
        self,
        value: typing.Union["CfnHealthCheck.HealthCheckConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "healthCheckConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckTags")
    def health_check_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnHealthCheck.HealthCheckTagProperty", _IResolvable_da3f097b]]]]:
        '''The ``HealthCheckTags`` property describes key-value pairs that are associated with an ``AWS::Route53::HealthCheck`` resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-healthcheck.html#cfn-route53-healthcheck-healthchecktags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnHealthCheck.HealthCheckTagProperty", _IResolvable_da3f097b]]]], jsii.get(self, "healthCheckTags"))

    @health_check_tags.setter
    def health_check_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnHealthCheck.HealthCheckTagProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "healthCheckTags", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnHealthCheck.AlarmIdentifierProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "region": "region"},
    )
    class AlarmIdentifierProperty:
        def __init__(self, *, name: builtins.str, region: builtins.str) -> None:
            '''
            :param name: ``CfnHealthCheck.AlarmIdentifierProperty.Name``.
            :param region: ``CfnHealthCheck.AlarmIdentifierProperty.Region``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-alarmidentifier.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                alarm_identifier_property = route53.CfnHealthCheck.AlarmIdentifierProperty(
                    name="name",
                    region="region"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "region": region,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''``CfnHealthCheck.AlarmIdentifierProperty.Name``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-alarmidentifier.html#cfn-route53-healthcheck-alarmidentifier-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def region(self) -> builtins.str:
            '''``CfnHealthCheck.AlarmIdentifierProperty.Region``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-alarmidentifier.html#cfn-route53-healthcheck-alarmidentifier-region
            '''
            result = self._values.get("region")
            assert result is not None, "Required property 'region' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AlarmIdentifierProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnHealthCheck.HealthCheckConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "type": "type",
            "alarm_identifier": "alarmIdentifier",
            "child_health_checks": "childHealthChecks",
            "enable_sni": "enableSni",
            "failure_threshold": "failureThreshold",
            "fully_qualified_domain_name": "fullyQualifiedDomainName",
            "health_threshold": "healthThreshold",
            "insufficient_data_health_status": "insufficientDataHealthStatus",
            "inverted": "inverted",
            "ip_address": "ipAddress",
            "measure_latency": "measureLatency",
            "port": "port",
            "regions": "regions",
            "request_interval": "requestInterval",
            "resource_path": "resourcePath",
            "routing_control_arn": "routingControlArn",
            "search_string": "searchString",
        },
    )
    class HealthCheckConfigProperty:
        def __init__(
            self,
            *,
            type: builtins.str,
            alarm_identifier: typing.Optional[typing.Union["CfnHealthCheck.AlarmIdentifierProperty", _IResolvable_da3f097b]] = None,
            child_health_checks: typing.Optional[typing.Sequence[builtins.str]] = None,
            enable_sni: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            failure_threshold: typing.Optional[jsii.Number] = None,
            fully_qualified_domain_name: typing.Optional[builtins.str] = None,
            health_threshold: typing.Optional[jsii.Number] = None,
            insufficient_data_health_status: typing.Optional[builtins.str] = None,
            inverted: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            ip_address: typing.Optional[builtins.str] = None,
            measure_latency: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            port: typing.Optional[jsii.Number] = None,
            regions: typing.Optional[typing.Sequence[builtins.str]] = None,
            request_interval: typing.Optional[jsii.Number] = None,
            resource_path: typing.Optional[builtins.str] = None,
            routing_control_arn: typing.Optional[builtins.str] = None,
            search_string: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param type: ``CfnHealthCheck.HealthCheckConfigProperty.Type``.
            :param alarm_identifier: ``CfnHealthCheck.HealthCheckConfigProperty.AlarmIdentifier``.
            :param child_health_checks: ``CfnHealthCheck.HealthCheckConfigProperty.ChildHealthChecks``.
            :param enable_sni: ``CfnHealthCheck.HealthCheckConfigProperty.EnableSNI``.
            :param failure_threshold: ``CfnHealthCheck.HealthCheckConfigProperty.FailureThreshold``.
            :param fully_qualified_domain_name: ``CfnHealthCheck.HealthCheckConfigProperty.FullyQualifiedDomainName``.
            :param health_threshold: ``CfnHealthCheck.HealthCheckConfigProperty.HealthThreshold``.
            :param insufficient_data_health_status: ``CfnHealthCheck.HealthCheckConfigProperty.InsufficientDataHealthStatus``.
            :param inverted: ``CfnHealthCheck.HealthCheckConfigProperty.Inverted``.
            :param ip_address: ``CfnHealthCheck.HealthCheckConfigProperty.IPAddress``.
            :param measure_latency: ``CfnHealthCheck.HealthCheckConfigProperty.MeasureLatency``.
            :param port: ``CfnHealthCheck.HealthCheckConfigProperty.Port``.
            :param regions: ``CfnHealthCheck.HealthCheckConfigProperty.Regions``.
            :param request_interval: ``CfnHealthCheck.HealthCheckConfigProperty.RequestInterval``.
            :param resource_path: ``CfnHealthCheck.HealthCheckConfigProperty.ResourcePath``.
            :param routing_control_arn: ``CfnHealthCheck.HealthCheckConfigProperty.RoutingControlArn``.
            :param search_string: ``CfnHealthCheck.HealthCheckConfigProperty.SearchString``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                health_check_config_property = route53.CfnHealthCheck.HealthCheckConfigProperty(
                    type="type",
                
                    # the properties below are optional
                    alarm_identifier=route53.CfnHealthCheck.AlarmIdentifierProperty(
                        name="name",
                        region="region"
                    ),
                    child_health_checks=["childHealthChecks"],
                    enable_sni=False,
                    failure_threshold=123,
                    fully_qualified_domain_name="fullyQualifiedDomainName",
                    health_threshold=123,
                    insufficient_data_health_status="insufficientDataHealthStatus",
                    inverted=False,
                    ip_address="ipAddress",
                    measure_latency=False,
                    port=123,
                    regions=["regions"],
                    request_interval=123,
                    resource_path="resourcePath",
                    routing_control_arn="routingControlArn",
                    search_string="searchString"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "type": type,
            }
            if alarm_identifier is not None:
                self._values["alarm_identifier"] = alarm_identifier
            if child_health_checks is not None:
                self._values["child_health_checks"] = child_health_checks
            if enable_sni is not None:
                self._values["enable_sni"] = enable_sni
            if failure_threshold is not None:
                self._values["failure_threshold"] = failure_threshold
            if fully_qualified_domain_name is not None:
                self._values["fully_qualified_domain_name"] = fully_qualified_domain_name
            if health_threshold is not None:
                self._values["health_threshold"] = health_threshold
            if insufficient_data_health_status is not None:
                self._values["insufficient_data_health_status"] = insufficient_data_health_status
            if inverted is not None:
                self._values["inverted"] = inverted
            if ip_address is not None:
                self._values["ip_address"] = ip_address
            if measure_latency is not None:
                self._values["measure_latency"] = measure_latency
            if port is not None:
                self._values["port"] = port
            if regions is not None:
                self._values["regions"] = regions
            if request_interval is not None:
                self._values["request_interval"] = request_interval
            if resource_path is not None:
                self._values["resource_path"] = resource_path
            if routing_control_arn is not None:
                self._values["routing_control_arn"] = routing_control_arn
            if search_string is not None:
                self._values["search_string"] = search_string

        @builtins.property
        def type(self) -> builtins.str:
            '''``CfnHealthCheck.HealthCheckConfigProperty.Type``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def alarm_identifier(
            self,
        ) -> typing.Optional[typing.Union["CfnHealthCheck.AlarmIdentifierProperty", _IResolvable_da3f097b]]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.AlarmIdentifier``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-alarmidentifier
            '''
            result = self._values.get("alarm_identifier")
            return typing.cast(typing.Optional[typing.Union["CfnHealthCheck.AlarmIdentifierProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def child_health_checks(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.ChildHealthChecks``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-childhealthchecks
            '''
            result = self._values.get("child_health_checks")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def enable_sni(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.EnableSNI``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-enablesni
            '''
            result = self._values.get("enable_sni")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def failure_threshold(self) -> typing.Optional[jsii.Number]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.FailureThreshold``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-failurethreshold
            '''
            result = self._values.get("failure_threshold")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def fully_qualified_domain_name(self) -> typing.Optional[builtins.str]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.FullyQualifiedDomainName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-fullyqualifieddomainname
            '''
            result = self._values.get("fully_qualified_domain_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def health_threshold(self) -> typing.Optional[jsii.Number]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.HealthThreshold``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-healththreshold
            '''
            result = self._values.get("health_threshold")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def insufficient_data_health_status(self) -> typing.Optional[builtins.str]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.InsufficientDataHealthStatus``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-insufficientdatahealthstatus
            '''
            result = self._values.get("insufficient_data_health_status")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def inverted(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.Inverted``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-inverted
            '''
            result = self._values.get("inverted")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def ip_address(self) -> typing.Optional[builtins.str]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.IPAddress``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-ipaddress
            '''
            result = self._values.get("ip_address")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def measure_latency(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.MeasureLatency``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-measurelatency
            '''
            result = self._values.get("measure_latency")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def port(self) -> typing.Optional[jsii.Number]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.Port``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-port
            '''
            result = self._values.get("port")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def regions(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.Regions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-regions
            '''
            result = self._values.get("regions")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def request_interval(self) -> typing.Optional[jsii.Number]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.RequestInterval``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-requestinterval
            '''
            result = self._values.get("request_interval")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def resource_path(self) -> typing.Optional[builtins.str]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.ResourcePath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-resourcepath
            '''
            result = self._values.get("resource_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def routing_control_arn(self) -> typing.Optional[builtins.str]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.RoutingControlArn``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-routingcontrolarn
            '''
            result = self._values.get("routing_control_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def search_string(self) -> typing.Optional[builtins.str]:
            '''``CfnHealthCheck.HealthCheckConfigProperty.SearchString``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthcheckconfig.html#cfn-route53-healthcheck-healthcheckconfig-searchstring
            '''
            result = self._values.get("search_string")
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
        jsii_type="aws-cdk-lib.aws_route53.CfnHealthCheck.HealthCheckTagProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class HealthCheckTagProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''The ``HealthCheckTag`` property describes one key-value pair that is associated with an ``AWS::Route53::HealthCheck`` resource.

            :param key: The value of ``Key`` depends on the operation that you want to perform:. - *Add a tag to a health check or hosted zone* : ``Key`` is the name that you want to give the new tag. - *Edit a tag* : ``Key`` is the name of the tag that you want to change the ``Value`` for. - *Delete a key* : ``Key`` is the name of the tag you want to remove. - *Give a name to a health check* : Edit the default ``Name`` tag. In the Amazon Route 53 console, the list of your health checks includes a *Name* column that lets you see the name that you've given to each health check.
            :param value: The value of ``Value`` depends on the operation that you want to perform:. - *Add a tag to a health check or hosted zone* : ``Value`` is the value that you want to give the new tag. - *Edit a tag* : ``Value`` is the new value that you want to assign the tag.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthchecktag.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                health_check_tag_property = route53.CfnHealthCheck.HealthCheckTagProperty(
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
            '''The value of ``Key`` depends on the operation that you want to perform:.

            - *Add a tag to a health check or hosted zone* : ``Key`` is the name that you want to give the new tag.
            - *Edit a tag* : ``Key`` is the name of the tag that you want to change the ``Value`` for.
            - *Delete a key* : ``Key`` is the name of the tag you want to remove.
            - *Give a name to a health check* : Edit the default ``Name`` tag. In the Amazon Route 53 console, the list of your health checks includes a *Name* column that lets you see the name that you've given to each health check.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthchecktag.html#cfn-route53-healthcheck-healthchecktag-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value of ``Value`` depends on the operation that you want to perform:.

            - *Add a tag to a health check or hosted zone* : ``Value`` is the value that you want to give the new tag.
            - *Edit a tag* : ``Value`` is the new value that you want to assign the tag.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-healthcheck-healthchecktag.html#cfn-route53-healthcheck-healthchecktag-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HealthCheckTagProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CfnHealthCheckProps",
    jsii_struct_bases=[],
    name_mapping={
        "health_check_config": "healthCheckConfig",
        "health_check_tags": "healthCheckTags",
    },
)
class CfnHealthCheckProps:
    def __init__(
        self,
        *,
        health_check_config: typing.Union[CfnHealthCheck.HealthCheckConfigProperty, _IResolvable_da3f097b],
        health_check_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnHealthCheck.HealthCheckTagProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnHealthCheck``.

        :param health_check_config: A complex type that contains detailed information about one health check. For the values to enter for ``HealthCheckConfig`` , see `HealthCheckConfig <https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html>`_
        :param health_check_tags: The ``HealthCheckTags`` property describes key-value pairs that are associated with an ``AWS::Route53::HealthCheck`` resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-healthcheck.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            cfn_health_check_props = route53.CfnHealthCheckProps(
                health_check_config=route53.CfnHealthCheck.HealthCheckConfigProperty(
                    type="type",
            
                    # the properties below are optional
                    alarm_identifier=route53.CfnHealthCheck.AlarmIdentifierProperty(
                        name="name",
                        region="region"
                    ),
                    child_health_checks=["childHealthChecks"],
                    enable_sni=False,
                    failure_threshold=123,
                    fully_qualified_domain_name="fullyQualifiedDomainName",
                    health_threshold=123,
                    insufficient_data_health_status="insufficientDataHealthStatus",
                    inverted=False,
                    ip_address="ipAddress",
                    measure_latency=False,
                    port=123,
                    regions=["regions"],
                    request_interval=123,
                    resource_path="resourcePath",
                    routing_control_arn="routingControlArn",
                    search_string="searchString"
                ),
            
                # the properties below are optional
                health_check_tags=[route53.CfnHealthCheck.HealthCheckTagProperty(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "health_check_config": health_check_config,
        }
        if health_check_tags is not None:
            self._values["health_check_tags"] = health_check_tags

    @builtins.property
    def health_check_config(
        self,
    ) -> typing.Union[CfnHealthCheck.HealthCheckConfigProperty, _IResolvable_da3f097b]:
        '''A complex type that contains detailed information about one health check.

        For the values to enter for ``HealthCheckConfig`` , see `HealthCheckConfig <https://docs.aws.amazon.com/Route53/latest/APIReference/API_HealthCheckConfig.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-healthcheck.html#cfn-route53-healthcheck-healthcheckconfig
        '''
        result = self._values.get("health_check_config")
        assert result is not None, "Required property 'health_check_config' is missing"
        return typing.cast(typing.Union[CfnHealthCheck.HealthCheckConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def health_check_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnHealthCheck.HealthCheckTagProperty, _IResolvable_da3f097b]]]]:
        '''The ``HealthCheckTags`` property describes key-value pairs that are associated with an ``AWS::Route53::HealthCheck`` resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-healthcheck.html#cfn-route53-healthcheck-healthchecktags
        '''
        result = self._values.get("health_check_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnHealthCheck.HealthCheckTagProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnHealthCheckProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnHostedZone(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CfnHostedZone",
):
    '''A CloudFormation ``AWS::Route53::HostedZone``.

    Creates a new public or private hosted zone. You create records in a public hosted zone to define how you want to route traffic on the internet for a domain, such as example.com, and its subdomains (apex.example.com, acme.example.com). You create records in a private hosted zone to define how you want to route traffic for a domain and its subdomains within one or more Amazon Virtual Private Clouds (Amazon VPCs).
    .. epigraph::

       You can't convert a public hosted zone to a private hosted zone or vice versa. Instead, you must create a new hosted zone with the same name and create new resource record sets.

    For more information about charges for hosted zones, see `Amazon Route 53 Pricing <https://docs.aws.amazon.com/route53/pricing/>`_ .

    Note the following:

    - You can't create a hosted zone for a top-level domain (TLD) such as .com.
    - For public hosted zones, Route 53 automatically creates a default SOA record and four NS records for the zone. For more information about SOA and NS records, see `NS and SOA Records that Route 53 Creates for a Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/SOA-NSrecords.html>`_ in the *Amazon Route 53 Developer Guide* .

    If you want to use the same name servers for multiple public hosted zones, you can optionally associate a reusable delegation set with the hosted zone. See the ``DelegationSetId`` element.

    - If your domain is registered with a registrar other than Route 53, you must update the name servers with your registrar to make Route 53 the DNS service for the domain. For more information, see `Migrating DNS Service for an Existing Domain to Amazon Route 53 <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/MigratingDNS.html>`_ in the *Amazon Route 53 Developer Guide* .

    When you submit a ``CreateHostedZone`` request, the initial status of the hosted zone is ``PENDING`` . For public hosted zones, this means that the NS and SOA records are not yet available on all Route 53 DNS servers. When the NS and SOA records are available, the status of the zone changes to ``INSYNC`` .

    The ``CreateHostedZone`` request requires the caller to have an ``ec2:DescribeVpcs`` permission.
    .. epigraph::

       When creating private hosted zones, the Amazon VPC must belong to the same partition where the hosted zone is created. A partition is a group of AWS Regions . Each AWS account is scoped to one partition.

       The following are the supported partitions:

       - ``aws`` - AWS Regions
       - ``aws-cn`` - China Regions
       - ``aws-us-gov`` - AWS GovCloud (US) Region

       For more information, see `Access Management <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .

    :cloudformationResource: AWS::Route53::HostedZone
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53 as route53
        
        cfn_hosted_zone = route53.CfnHostedZone(self, "MyCfnHostedZone",
            hosted_zone_config=route53.CfnHostedZone.HostedZoneConfigProperty(
                comment="comment"
            ),
            hosted_zone_tags=[route53.CfnHostedZone.HostedZoneTagProperty(
                key="key",
                value="value"
            )],
            name="name",
            query_logging_config=route53.CfnHostedZone.QueryLoggingConfigProperty(
                cloud_watch_logs_log_group_arn="cloudWatchLogsLogGroupArn"
            ),
            vpcs=[route53.CfnHostedZone.VPCProperty(
                vpc_id="vpcId",
                vpc_region="vpcRegion"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        hosted_zone_config: typing.Optional[typing.Union["CfnHostedZone.HostedZoneConfigProperty", _IResolvable_da3f097b]] = None,
        hosted_zone_tags: typing.Optional[typing.Sequence["CfnHostedZone.HostedZoneTagProperty"]] = None,
        name: typing.Optional[builtins.str] = None,
        query_logging_config: typing.Optional[typing.Union["CfnHostedZone.QueryLoggingConfigProperty", _IResolvable_da3f097b]] = None,
        vpcs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnHostedZone.VPCProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Route53::HostedZone``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param hosted_zone_config: A complex type that contains an optional comment. If you don't want to specify a comment, omit the ``HostedZoneConfig`` and ``Comment`` elements.
        :param hosted_zone_tags: Adds, edits, or deletes tags for a health check or a hosted zone. For information about using tags for cost allocation, see `Using Cost Allocation Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`_ in the *AWS Billing and Cost Management User Guide* .
        :param name: The name of the domain. Specify a fully qualified domain name, for example, *www.example.com* . The trailing dot is optional; Amazon Route 53 assumes that the domain name is fully qualified. This means that Route 53 treats *www.example.com* (without a trailing dot) and *www.example.com.* (with a trailing dot) as identical. If you're creating a public hosted zone, this is the name you have registered with your DNS registrar. If your domain name is registered with a registrar other than Route 53, change the name servers for your domain to the set of ``NameServers`` that are returned by the ``Fn::GetAtt`` intrinsic function.
        :param query_logging_config: Creates a configuration for DNS query logging. After you create a query logging configuration, Amazon Route 53 begins to publish log data to an Amazon CloudWatch Logs log group. DNS query logs contain information about the queries that Route 53 receives for a specified public hosted zone, such as the following: - Route 53 edge location that responded to the DNS query - Domain or subdomain that was requested - DNS record type, such as A or AAAA - DNS response code, such as ``NoError`` or ``ServFail`` - **Log Group and Resource Policy** - Before you create a query logging configuration, perform the following operations. .. epigraph:: If you create a query logging configuration using the Route 53 console, Route 53 performs these operations automatically. - Create a CloudWatch Logs log group, and make note of the ARN, which you specify when you create a query logging configuration. Note the following: - You must create the log group in the us-east-1 region. - You must use the same AWS account to create the log group and the hosted zone that you want to configure query logging for. - When you create log groups for query logging, we recommend that you use a consistent prefix, for example: ``/aws/route53/ *hosted zone name*`` In the next step, you'll create a resource policy, which controls access to one or more log groups and the associated AWS resources, such as Route 53 hosted zones. There's a limit on the number of resource policies that you can create, so we recommend that you use a consistent prefix so you can use the same resource policy for all the log groups that you create for query logging. - Create a CloudWatch Logs resource policy, and give it the permissions that Route 53 needs to create log streams and to send query logs to log streams. For the value of ``Resource`` , specify the ARN for the log group that you created in the previous step. To use the same resource policy for all the CloudWatch Logs log groups that you created for query logging configurations, replace the hosted zone name with ``*`` , for example: ``arn:aws:logs:us-east-1:123412341234:log-group:/aws/route53/*`` To avoid the confused deputy problem, a security issue where an entity without a permission for an action can coerce a more-privileged entity to perform it, you can optionally limit the permissions that a service has to a resource in a resource-based policy by supplying the following values: - For ``aws:SourceArn`` , supply the hosted zone ARN used in creating the query logging configuration. For example, ``aws:SourceArn: arn:aws:route53:::hostedzone/hosted zone ID`` . - For ``aws:SourceAccount`` , supply the account ID for the account that creates the query logging configuration. For example, ``aws:SourceAccount:111111111111`` . For more information, see `The confused deputy problem <https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html>`_ in the *AWS IAM User Guide* . .. epigraph:: You can't use the CloudWatch console to create or edit a resource policy. You must use the CloudWatch API, one of the AWS SDKs, or the AWS CLI . - **Log Streams and Edge Locations** - When Route 53 finishes creating the configuration for DNS query logging, it does the following: - Creates a log stream for an edge location the first time that the edge location responds to DNS queries for the specified hosted zone. That log stream is used to log all queries that Route 53 responds to for that edge location. - Begins to send query logs to the applicable log stream. The name of each log stream is in the following format: ``*hosted zone ID* / *edge location code*`` The edge location code is a three-letter code and an arbitrarily assigned number, for example, DFW3. The three-letter code typically corresponds with the International Air Transport Association airport code for an airport near the edge location. (These abbreviations might change in the future.) For a list of edge locations, see "The Route 53 Global Network" on the `Route 53 Product Details <https://docs.aws.amazon.com/route53/details/>`_ page. - **Queries That Are Logged** - Query logs contain only the queries that DNS resolvers forward to Route 53. If a DNS resolver has already cached the response to a query (such as the IP address for a load balancer for example.com), the resolver will continue to return the cached response. It doesn't forward another query to Route 53 until the TTL for the corresponding resource record set expires. Depending on how many DNS queries are submitted for a resource record set, and depending on the TTL for that resource record set, query logs might contain information about only one query out of every several thousand queries that are submitted to DNS. For more information about how DNS works, see `Routing Internet Traffic to Your Website or Web Application <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/welcome-dns-service.html>`_ in the *Amazon Route 53 Developer Guide* . - **Log File Format** - For a list of the values in each query log and the format of each value, see `Logging DNS Queries <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html>`_ in the *Amazon Route 53 Developer Guide* . - **Pricing** - For information about charges for query logs, see `Amazon CloudWatch Pricing <https://docs.aws.amazon.com/cloudwatch/pricing/>`_ . - **How to Stop Logging** - If you want Route 53 to stop sending query logs to CloudWatch Logs, delete the query logging configuration. For more information, see `DeleteQueryLoggingConfig <https://docs.aws.amazon.com/Route53/latest/APIReference/API_DeleteQueryLoggingConfig.html>`_ .
        :param vpcs: *Private hosted zones:* A complex type that contains information about the VPCs that are associated with the specified hosted zone. .. epigraph:: For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .
        '''
        props = CfnHostedZoneProps(
            hosted_zone_config=hosted_zone_config,
            hosted_zone_tags=hosted_zone_tags,
            name=name,
            query_logging_config=query_logging_config,
            vpcs=vpcs,
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
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID that Amazon Route 53 assigned to the hosted zone when you created it.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrNameServers")
    def attr_name_servers(self) -> typing.List[builtins.str]:
        '''Returns the set of name servers for the specific hosted zone. For example: ``ns1.example.com`` .

        This attribute is not supported for private hosted zones.

        :cloudformationAttribute: NameServers
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrNameServers"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Adds, edits, or deletes tags for a health check or a hosted zone.

        For information about using tags for cost allocation, see `Using Cost Allocation Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`_ in the *AWS Billing and Cost Management User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-hostedzonetags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneConfig")
    def hosted_zone_config(
        self,
    ) -> typing.Optional[typing.Union["CfnHostedZone.HostedZoneConfigProperty", _IResolvable_da3f097b]]:
        '''A complex type that contains an optional comment.

        If you don't want to specify a comment, omit the ``HostedZoneConfig`` and ``Comment`` elements.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-hostedzoneconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnHostedZone.HostedZoneConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "hostedZoneConfig"))

    @hosted_zone_config.setter
    def hosted_zone_config(
        self,
        value: typing.Optional[typing.Union["CfnHostedZone.HostedZoneConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "hostedZoneConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the domain.

        Specify a fully qualified domain name, for example, *www.example.com* . The trailing dot is optional; Amazon Route 53 assumes that the domain name is fully qualified. This means that Route 53 treats *www.example.com* (without a trailing dot) and *www.example.com.* (with a trailing dot) as identical.

        If you're creating a public hosted zone, this is the name you have registered with your DNS registrar. If your domain name is registered with a registrar other than Route 53, change the name servers for your domain to the set of ``NameServers`` that are returned by the ``Fn::GetAtt`` intrinsic function.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queryLoggingConfig")
    def query_logging_config(
        self,
    ) -> typing.Optional[typing.Union["CfnHostedZone.QueryLoggingConfigProperty", _IResolvable_da3f097b]]:
        '''Creates a configuration for DNS query logging.

        After you create a query logging configuration, Amazon Route 53 begins to publish log data to an Amazon CloudWatch Logs log group.

        DNS query logs contain information about the queries that Route 53 receives for a specified public hosted zone, such as the following:

        - Route 53 edge location that responded to the DNS query
        - Domain or subdomain that was requested
        - DNS record type, such as A or AAAA
        - DNS response code, such as ``NoError`` or ``ServFail``
        - **Log Group and Resource Policy** - Before you create a query logging configuration, perform the following operations.

        .. epigraph::

           If you create a query logging configuration using the Route 53 console, Route 53 performs these operations automatically.

        - Create a CloudWatch Logs log group, and make note of the ARN, which you specify when you create a query logging configuration. Note the following:
        - You must create the log group in the us-east-1 region.
        - You must use the same AWS account to create the log group and the hosted zone that you want to configure query logging for.
        - When you create log groups for query logging, we recommend that you use a consistent prefix, for example:

        ``/aws/route53/ *hosted zone name*``

        In the next step, you'll create a resource policy, which controls access to one or more log groups and the associated AWS resources, such as Route 53 hosted zones. There's a limit on the number of resource policies that you can create, so we recommend that you use a consistent prefix so you can use the same resource policy for all the log groups that you create for query logging.

        - Create a CloudWatch Logs resource policy, and give it the permissions that Route 53 needs to create log streams and to send query logs to log streams. For the value of ``Resource`` , specify the ARN for the log group that you created in the previous step. To use the same resource policy for all the CloudWatch Logs log groups that you created for query logging configurations, replace the hosted zone name with ``*`` , for example:

        ``arn:aws:logs:us-east-1:123412341234:log-group:/aws/route53/*``

        To avoid the confused deputy problem, a security issue where an entity without a permission for an action can coerce a more-privileged entity to perform it, you can optionally limit the permissions that a service has to a resource in a resource-based policy by supplying the following values:

        - For ``aws:SourceArn`` , supply the hosted zone ARN used in creating the query logging configuration. For example, ``aws:SourceArn: arn:aws:route53:::hostedzone/hosted zone ID`` .
        - For ``aws:SourceAccount`` , supply the account ID for the account that creates the query logging configuration. For example, ``aws:SourceAccount:111111111111`` .

        For more information, see `The confused deputy problem <https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html>`_ in the *AWS IAM User Guide* .
        .. epigraph::

           You can't use the CloudWatch console to create or edit a resource policy. You must use the CloudWatch API, one of the AWS SDKs, or the AWS CLI .

        - **Log Streams and Edge Locations** - When Route 53 finishes creating the configuration for DNS query logging, it does the following:
        - Creates a log stream for an edge location the first time that the edge location responds to DNS queries for the specified hosted zone. That log stream is used to log all queries that Route 53 responds to for that edge location.
        - Begins to send query logs to the applicable log stream.

        The name of each log stream is in the following format:

        ``*hosted zone ID* / *edge location code*``

        The edge location code is a three-letter code and an arbitrarily assigned number, for example, DFW3. The three-letter code typically corresponds with the International Air Transport Association airport code for an airport near the edge location. (These abbreviations might change in the future.) For a list of edge locations, see "The Route 53 Global Network" on the `Route 53 Product Details <https://docs.aws.amazon.com/route53/details/>`_ page.

        - **Queries That Are Logged** - Query logs contain only the queries that DNS resolvers forward to Route 53. If a DNS resolver has already cached the response to a query (such as the IP address for a load balancer for example.com), the resolver will continue to return the cached response. It doesn't forward another query to Route 53 until the TTL for the corresponding resource record set expires. Depending on how many DNS queries are submitted for a resource record set, and depending on the TTL for that resource record set, query logs might contain information about only one query out of every several thousand queries that are submitted to DNS. For more information about how DNS works, see `Routing Internet Traffic to Your Website or Web Application <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/welcome-dns-service.html>`_ in the *Amazon Route 53 Developer Guide* .
        - **Log File Format** - For a list of the values in each query log and the format of each value, see `Logging DNS Queries <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html>`_ in the *Amazon Route 53 Developer Guide* .
        - **Pricing** - For information about charges for query logs, see `Amazon CloudWatch Pricing <https://docs.aws.amazon.com/cloudwatch/pricing/>`_ .
        - **How to Stop Logging** - If you want Route 53 to stop sending query logs to CloudWatch Logs, delete the query logging configuration. For more information, see `DeleteQueryLoggingConfig <https://docs.aws.amazon.com/Route53/latest/APIReference/API_DeleteQueryLoggingConfig.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-queryloggingconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnHostedZone.QueryLoggingConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "queryLoggingConfig"))

    @query_logging_config.setter
    def query_logging_config(
        self,
        value: typing.Optional[typing.Union["CfnHostedZone.QueryLoggingConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "queryLoggingConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcs")
    def vpcs(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnHostedZone.VPCProperty", _IResolvable_da3f097b]]]]:
        '''*Private hosted zones:* A complex type that contains information about the VPCs that are associated with the specified hosted zone.

        .. epigraph::

           For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-vpcs
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnHostedZone.VPCProperty", _IResolvable_da3f097b]]]], jsii.get(self, "vpcs"))

    @vpcs.setter
    def vpcs(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnHostedZone.VPCProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "vpcs", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnHostedZone.HostedZoneConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"comment": "comment"},
    )
    class HostedZoneConfigProperty:
        def __init__(self, *, comment: typing.Optional[builtins.str] = None) -> None:
            '''A complex type that contains an optional comment about your hosted zone.

            If you don't want to specify a comment, omit both the ``HostedZoneConfig`` and ``Comment`` elements.

            :param comment: Any comments that you want to include about the hosted zone.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-hostedzoneconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                hosted_zone_config_property = route53.CfnHostedZone.HostedZoneConfigProperty(
                    comment="comment"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if comment is not None:
                self._values["comment"] = comment

        @builtins.property
        def comment(self) -> typing.Optional[builtins.str]:
            '''Any comments that you want to include about the hosted zone.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-hostedzoneconfig.html#cfn-route53-hostedzone-hostedzoneconfig-comment
            '''
            result = self._values.get("comment")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HostedZoneConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnHostedZone.HostedZoneTagProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class HostedZoneTagProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''A complex type that contains information about a tag that you want to add or edit for the specified health check or hosted zone.

            :param key: The value of ``Key`` depends on the operation that you want to perform:. - *Add a tag to a health check or hosted zone* : ``Key`` is the name that you want to give the new tag. - *Edit a tag* : ``Key`` is the name of the tag that you want to change the ``Value`` for. - *Delete a key* : ``Key`` is the name of the tag you want to remove. - *Give a name to a health check* : Edit the default ``Name`` tag. In the Amazon Route 53 console, the list of your health checks includes a *Name* column that lets you see the name that you've given to each health check.
            :param value: The value of ``Value`` depends on the operation that you want to perform:. - *Add a tag to a health check or hosted zone* : ``Value`` is the value that you want to give the new tag. - *Edit a tag* : ``Value`` is the new value that you want to assign the tag.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-hostedzonetag.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                hosted_zone_tag_property = route53.CfnHostedZone.HostedZoneTagProperty(
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
            '''The value of ``Key`` depends on the operation that you want to perform:.

            - *Add a tag to a health check or hosted zone* : ``Key`` is the name that you want to give the new tag.
            - *Edit a tag* : ``Key`` is the name of the tag that you want to change the ``Value`` for.
            - *Delete a key* : ``Key`` is the name of the tag you want to remove.
            - *Give a name to a health check* : Edit the default ``Name`` tag. In the Amazon Route 53 console, the list of your health checks includes a *Name* column that lets you see the name that you've given to each health check.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-hostedzonetag.html#cfn-route53-hostedzone-hostedzonetag-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value of ``Value`` depends on the operation that you want to perform:.

            - *Add a tag to a health check or hosted zone* : ``Value`` is the value that you want to give the new tag.
            - *Edit a tag* : ``Value`` is the new value that you want to assign the tag.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-hostedzonetag.html#cfn-route53-hostedzone-hostedzonetag-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HostedZoneTagProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnHostedZone.QueryLoggingConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"cloud_watch_logs_log_group_arn": "cloudWatchLogsLogGroupArn"},
    )
    class QueryLoggingConfigProperty:
        def __init__(self, *, cloud_watch_logs_log_group_arn: builtins.str) -> None:
            '''A complex type that contains information about a configuration for DNS query logging.

            :param cloud_watch_logs_log_group_arn: The Amazon Resource Name (ARN) of the CloudWatch Logs log group that Amazon Route 53 is publishing logs to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-queryloggingconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                query_logging_config_property = route53.CfnHostedZone.QueryLoggingConfigProperty(
                    cloud_watch_logs_log_group_arn="cloudWatchLogsLogGroupArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cloud_watch_logs_log_group_arn": cloud_watch_logs_log_group_arn,
            }

        @builtins.property
        def cloud_watch_logs_log_group_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the CloudWatch Logs log group that Amazon Route 53 is publishing logs to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-queryloggingconfig.html#cfn-route53-hostedzone-queryloggingconfig-cloudwatchlogsloggrouparn
            '''
            result = self._values.get("cloud_watch_logs_log_group_arn")
            assert result is not None, "Required property 'cloud_watch_logs_log_group_arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "QueryLoggingConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnHostedZone.VPCProperty",
        jsii_struct_bases=[],
        name_mapping={"vpc_id": "vpcId", "vpc_region": "vpcRegion"},
    )
    class VPCProperty:
        def __init__(self, *, vpc_id: builtins.str, vpc_region: builtins.str) -> None:
            '''*Private hosted zones only:* A complex type that contains information about an Amazon VPC.

            Route 53 Resolver uses the records in the private hosted zone to route traffic in that VPC.
            .. epigraph::

               For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .

            :param vpc_id: *Private hosted zones only:* The ID of an Amazon VPC. .. epigraph:: For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .
            :param vpc_region: *Private hosted zones only:* The region that an Amazon VPC was created in. .. epigraph:: For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-vpc.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                v_pCProperty = route53.CfnHostedZone.VPCProperty(
                    vpc_id="vpcId",
                    vpc_region="vpcRegion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "vpc_id": vpc_id,
                "vpc_region": vpc_region,
            }

        @builtins.property
        def vpc_id(self) -> builtins.str:
            '''*Private hosted zones only:* The ID of an Amazon VPC.

            .. epigraph::

               For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-vpc.html#cfn-route53-hostedzone-vpc-vpcid
            '''
            result = self._values.get("vpc_id")
            assert result is not None, "Required property 'vpc_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def vpc_region(self) -> builtins.str:
            '''*Private hosted zones only:* The region that an Amazon VPC was created in.

            .. epigraph::

               For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-hostedzone-vpc.html#cfn-route53-hostedzone-vpc-vpcregion
            '''
            result = self._values.get("vpc_region")
            assert result is not None, "Required property 'vpc_region' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VPCProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CfnHostedZoneProps",
    jsii_struct_bases=[],
    name_mapping={
        "hosted_zone_config": "hostedZoneConfig",
        "hosted_zone_tags": "hostedZoneTags",
        "name": "name",
        "query_logging_config": "queryLoggingConfig",
        "vpcs": "vpcs",
    },
)
class CfnHostedZoneProps:
    def __init__(
        self,
        *,
        hosted_zone_config: typing.Optional[typing.Union[CfnHostedZone.HostedZoneConfigProperty, _IResolvable_da3f097b]] = None,
        hosted_zone_tags: typing.Optional[typing.Sequence[CfnHostedZone.HostedZoneTagProperty]] = None,
        name: typing.Optional[builtins.str] = None,
        query_logging_config: typing.Optional[typing.Union[CfnHostedZone.QueryLoggingConfigProperty, _IResolvable_da3f097b]] = None,
        vpcs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnHostedZone.VPCProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnHostedZone``.

        :param hosted_zone_config: A complex type that contains an optional comment. If you don't want to specify a comment, omit the ``HostedZoneConfig`` and ``Comment`` elements.
        :param hosted_zone_tags: Adds, edits, or deletes tags for a health check or a hosted zone. For information about using tags for cost allocation, see `Using Cost Allocation Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`_ in the *AWS Billing and Cost Management User Guide* .
        :param name: The name of the domain. Specify a fully qualified domain name, for example, *www.example.com* . The trailing dot is optional; Amazon Route 53 assumes that the domain name is fully qualified. This means that Route 53 treats *www.example.com* (without a trailing dot) and *www.example.com.* (with a trailing dot) as identical. If you're creating a public hosted zone, this is the name you have registered with your DNS registrar. If your domain name is registered with a registrar other than Route 53, change the name servers for your domain to the set of ``NameServers`` that are returned by the ``Fn::GetAtt`` intrinsic function.
        :param query_logging_config: Creates a configuration for DNS query logging. After you create a query logging configuration, Amazon Route 53 begins to publish log data to an Amazon CloudWatch Logs log group. DNS query logs contain information about the queries that Route 53 receives for a specified public hosted zone, such as the following: - Route 53 edge location that responded to the DNS query - Domain or subdomain that was requested - DNS record type, such as A or AAAA - DNS response code, such as ``NoError`` or ``ServFail`` - **Log Group and Resource Policy** - Before you create a query logging configuration, perform the following operations. .. epigraph:: If you create a query logging configuration using the Route 53 console, Route 53 performs these operations automatically. - Create a CloudWatch Logs log group, and make note of the ARN, which you specify when you create a query logging configuration. Note the following: - You must create the log group in the us-east-1 region. - You must use the same AWS account to create the log group and the hosted zone that you want to configure query logging for. - When you create log groups for query logging, we recommend that you use a consistent prefix, for example: ``/aws/route53/ *hosted zone name*`` In the next step, you'll create a resource policy, which controls access to one or more log groups and the associated AWS resources, such as Route 53 hosted zones. There's a limit on the number of resource policies that you can create, so we recommend that you use a consistent prefix so you can use the same resource policy for all the log groups that you create for query logging. - Create a CloudWatch Logs resource policy, and give it the permissions that Route 53 needs to create log streams and to send query logs to log streams. For the value of ``Resource`` , specify the ARN for the log group that you created in the previous step. To use the same resource policy for all the CloudWatch Logs log groups that you created for query logging configurations, replace the hosted zone name with ``*`` , for example: ``arn:aws:logs:us-east-1:123412341234:log-group:/aws/route53/*`` To avoid the confused deputy problem, a security issue where an entity without a permission for an action can coerce a more-privileged entity to perform it, you can optionally limit the permissions that a service has to a resource in a resource-based policy by supplying the following values: - For ``aws:SourceArn`` , supply the hosted zone ARN used in creating the query logging configuration. For example, ``aws:SourceArn: arn:aws:route53:::hostedzone/hosted zone ID`` . - For ``aws:SourceAccount`` , supply the account ID for the account that creates the query logging configuration. For example, ``aws:SourceAccount:111111111111`` . For more information, see `The confused deputy problem <https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html>`_ in the *AWS IAM User Guide* . .. epigraph:: You can't use the CloudWatch console to create or edit a resource policy. You must use the CloudWatch API, one of the AWS SDKs, or the AWS CLI . - **Log Streams and Edge Locations** - When Route 53 finishes creating the configuration for DNS query logging, it does the following: - Creates a log stream for an edge location the first time that the edge location responds to DNS queries for the specified hosted zone. That log stream is used to log all queries that Route 53 responds to for that edge location. - Begins to send query logs to the applicable log stream. The name of each log stream is in the following format: ``*hosted zone ID* / *edge location code*`` The edge location code is a three-letter code and an arbitrarily assigned number, for example, DFW3. The three-letter code typically corresponds with the International Air Transport Association airport code for an airport near the edge location. (These abbreviations might change in the future.) For a list of edge locations, see "The Route 53 Global Network" on the `Route 53 Product Details <https://docs.aws.amazon.com/route53/details/>`_ page. - **Queries That Are Logged** - Query logs contain only the queries that DNS resolvers forward to Route 53. If a DNS resolver has already cached the response to a query (such as the IP address for a load balancer for example.com), the resolver will continue to return the cached response. It doesn't forward another query to Route 53 until the TTL for the corresponding resource record set expires. Depending on how many DNS queries are submitted for a resource record set, and depending on the TTL for that resource record set, query logs might contain information about only one query out of every several thousand queries that are submitted to DNS. For more information about how DNS works, see `Routing Internet Traffic to Your Website or Web Application <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/welcome-dns-service.html>`_ in the *Amazon Route 53 Developer Guide* . - **Log File Format** - For a list of the values in each query log and the format of each value, see `Logging DNS Queries <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html>`_ in the *Amazon Route 53 Developer Guide* . - **Pricing** - For information about charges for query logs, see `Amazon CloudWatch Pricing <https://docs.aws.amazon.com/cloudwatch/pricing/>`_ . - **How to Stop Logging** - If you want Route 53 to stop sending query logs to CloudWatch Logs, delete the query logging configuration. For more information, see `DeleteQueryLoggingConfig <https://docs.aws.amazon.com/Route53/latest/APIReference/API_DeleteQueryLoggingConfig.html>`_ .
        :param vpcs: *Private hosted zones:* A complex type that contains information about the VPCs that are associated with the specified hosted zone. .. epigraph:: For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            cfn_hosted_zone_props = route53.CfnHostedZoneProps(
                hosted_zone_config=route53.CfnHostedZone.HostedZoneConfigProperty(
                    comment="comment"
                ),
                hosted_zone_tags=[route53.CfnHostedZone.HostedZoneTagProperty(
                    key="key",
                    value="value"
                )],
                name="name",
                query_logging_config=route53.CfnHostedZone.QueryLoggingConfigProperty(
                    cloud_watch_logs_log_group_arn="cloudWatchLogsLogGroupArn"
                ),
                vpcs=[route53.CfnHostedZone.VPCProperty(
                    vpc_id="vpcId",
                    vpc_region="vpcRegion"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if hosted_zone_config is not None:
            self._values["hosted_zone_config"] = hosted_zone_config
        if hosted_zone_tags is not None:
            self._values["hosted_zone_tags"] = hosted_zone_tags
        if name is not None:
            self._values["name"] = name
        if query_logging_config is not None:
            self._values["query_logging_config"] = query_logging_config
        if vpcs is not None:
            self._values["vpcs"] = vpcs

    @builtins.property
    def hosted_zone_config(
        self,
    ) -> typing.Optional[typing.Union[CfnHostedZone.HostedZoneConfigProperty, _IResolvable_da3f097b]]:
        '''A complex type that contains an optional comment.

        If you don't want to specify a comment, omit the ``HostedZoneConfig`` and ``Comment`` elements.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-hostedzoneconfig
        '''
        result = self._values.get("hosted_zone_config")
        return typing.cast(typing.Optional[typing.Union[CfnHostedZone.HostedZoneConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def hosted_zone_tags(
        self,
    ) -> typing.Optional[typing.List[CfnHostedZone.HostedZoneTagProperty]]:
        '''Adds, edits, or deletes tags for a health check or a hosted zone.

        For information about using tags for cost allocation, see `Using Cost Allocation Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`_ in the *AWS Billing and Cost Management User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-hostedzonetags
        '''
        result = self._values.get("hosted_zone_tags")
        return typing.cast(typing.Optional[typing.List[CfnHostedZone.HostedZoneTagProperty]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the domain.

        Specify a fully qualified domain name, for example, *www.example.com* . The trailing dot is optional; Amazon Route 53 assumes that the domain name is fully qualified. This means that Route 53 treats *www.example.com* (without a trailing dot) and *www.example.com.* (with a trailing dot) as identical.

        If you're creating a public hosted zone, this is the name you have registered with your DNS registrar. If your domain name is registered with a registrar other than Route 53, change the name servers for your domain to the set of ``NameServers`` that are returned by the ``Fn::GetAtt`` intrinsic function.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def query_logging_config(
        self,
    ) -> typing.Optional[typing.Union[CfnHostedZone.QueryLoggingConfigProperty, _IResolvable_da3f097b]]:
        '''Creates a configuration for DNS query logging.

        After you create a query logging configuration, Amazon Route 53 begins to publish log data to an Amazon CloudWatch Logs log group.

        DNS query logs contain information about the queries that Route 53 receives for a specified public hosted zone, such as the following:

        - Route 53 edge location that responded to the DNS query
        - Domain or subdomain that was requested
        - DNS record type, such as A or AAAA
        - DNS response code, such as ``NoError`` or ``ServFail``
        - **Log Group and Resource Policy** - Before you create a query logging configuration, perform the following operations.

        .. epigraph::

           If you create a query logging configuration using the Route 53 console, Route 53 performs these operations automatically.

        - Create a CloudWatch Logs log group, and make note of the ARN, which you specify when you create a query logging configuration. Note the following:
        - You must create the log group in the us-east-1 region.
        - You must use the same AWS account to create the log group and the hosted zone that you want to configure query logging for.
        - When you create log groups for query logging, we recommend that you use a consistent prefix, for example:

        ``/aws/route53/ *hosted zone name*``

        In the next step, you'll create a resource policy, which controls access to one or more log groups and the associated AWS resources, such as Route 53 hosted zones. There's a limit on the number of resource policies that you can create, so we recommend that you use a consistent prefix so you can use the same resource policy for all the log groups that you create for query logging.

        - Create a CloudWatch Logs resource policy, and give it the permissions that Route 53 needs to create log streams and to send query logs to log streams. For the value of ``Resource`` , specify the ARN for the log group that you created in the previous step. To use the same resource policy for all the CloudWatch Logs log groups that you created for query logging configurations, replace the hosted zone name with ``*`` , for example:

        ``arn:aws:logs:us-east-1:123412341234:log-group:/aws/route53/*``

        To avoid the confused deputy problem, a security issue where an entity without a permission for an action can coerce a more-privileged entity to perform it, you can optionally limit the permissions that a service has to a resource in a resource-based policy by supplying the following values:

        - For ``aws:SourceArn`` , supply the hosted zone ARN used in creating the query logging configuration. For example, ``aws:SourceArn: arn:aws:route53:::hostedzone/hosted zone ID`` .
        - For ``aws:SourceAccount`` , supply the account ID for the account that creates the query logging configuration. For example, ``aws:SourceAccount:111111111111`` .

        For more information, see `The confused deputy problem <https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html>`_ in the *AWS IAM User Guide* .
        .. epigraph::

           You can't use the CloudWatch console to create or edit a resource policy. You must use the CloudWatch API, one of the AWS SDKs, or the AWS CLI .

        - **Log Streams and Edge Locations** - When Route 53 finishes creating the configuration for DNS query logging, it does the following:
        - Creates a log stream for an edge location the first time that the edge location responds to DNS queries for the specified hosted zone. That log stream is used to log all queries that Route 53 responds to for that edge location.
        - Begins to send query logs to the applicable log stream.

        The name of each log stream is in the following format:

        ``*hosted zone ID* / *edge location code*``

        The edge location code is a three-letter code and an arbitrarily assigned number, for example, DFW3. The three-letter code typically corresponds with the International Air Transport Association airport code for an airport near the edge location. (These abbreviations might change in the future.) For a list of edge locations, see "The Route 53 Global Network" on the `Route 53 Product Details <https://docs.aws.amazon.com/route53/details/>`_ page.

        - **Queries That Are Logged** - Query logs contain only the queries that DNS resolvers forward to Route 53. If a DNS resolver has already cached the response to a query (such as the IP address for a load balancer for example.com), the resolver will continue to return the cached response. It doesn't forward another query to Route 53 until the TTL for the corresponding resource record set expires. Depending on how many DNS queries are submitted for a resource record set, and depending on the TTL for that resource record set, query logs might contain information about only one query out of every several thousand queries that are submitted to DNS. For more information about how DNS works, see `Routing Internet Traffic to Your Website or Web Application <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/welcome-dns-service.html>`_ in the *Amazon Route 53 Developer Guide* .
        - **Log File Format** - For a list of the values in each query log and the format of each value, see `Logging DNS Queries <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html>`_ in the *Amazon Route 53 Developer Guide* .
        - **Pricing** - For information about charges for query logs, see `Amazon CloudWatch Pricing <https://docs.aws.amazon.com/cloudwatch/pricing/>`_ .
        - **How to Stop Logging** - If you want Route 53 to stop sending query logs to CloudWatch Logs, delete the query logging configuration. For more information, see `DeleteQueryLoggingConfig <https://docs.aws.amazon.com/Route53/latest/APIReference/API_DeleteQueryLoggingConfig.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-queryloggingconfig
        '''
        result = self._values.get("query_logging_config")
        return typing.cast(typing.Optional[typing.Union[CfnHostedZone.QueryLoggingConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def vpcs(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnHostedZone.VPCProperty, _IResolvable_da3f097b]]]]:
        '''*Private hosted zones:* A complex type that contains information about the VPCs that are associated with the specified hosted zone.

        .. epigraph::

           For public hosted zones, omit ``VPCs`` , ``VPCId`` , and ``VPCRegion`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-vpcs
        '''
        result = self._values.get("vpcs")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnHostedZone.VPCProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnHostedZoneProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnKeySigningKey(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CfnKeySigningKey",
):
    '''A CloudFormation ``AWS::Route53::KeySigningKey``.

    The ``AWS::Route53::KeySigningKey`` resource creates a new key-signing key (KSK) in a hosted zone. The hosted zone ID is passed as a parameter in the KSK properties. You can specify the properties of this KSK using the ``Name`` , ``Status`` , and ``KeyManagementServiceArn`` properties of the resource.

    :cloudformationResource: AWS::Route53::KeySigningKey
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53 as route53
        
        cfn_key_signing_key = route53.CfnKeySigningKey(self, "MyCfnKeySigningKey",
            hosted_zone_id="hostedZoneId",
            key_management_service_arn="keyManagementServiceArn",
            name="name",
            status="status"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        hosted_zone_id: builtins.str,
        key_management_service_arn: builtins.str,
        name: builtins.str,
        status: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Route53::KeySigningKey``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param hosted_zone_id: The unique string (ID) that is used to identify a hosted zone. For example: ``Z00001111A1ABCaaABC11`` .
        :param key_management_service_arn: The Amazon resource name (ARN) for a customer managed customer master key (CMK) in AWS Key Management Service ( AWS KMS ). The ``KeyManagementServiceArn`` must be unique for each key-signing key (KSK) in a single hosted zone. For example: ``arn:aws:kms:us-east-1:111122223333:key/111a2222-a11b-1ab1-2ab2-1ab21a2b3a111`` .
        :param name: A string used to identify a key-signing key (KSK). ``Name`` can include numbers, letters, and underscores (_). ``Name`` must be unique for each key-signing key in the same hosted zone.
        :param status: A string that represents the current key-signing key (KSK) status. Status can have one of the following values: - **ACTIVE** - The KSK is being used for signing. - **INACTIVE** - The KSK is not being used for signing. - **DELETING** - The KSK is in the process of being deleted. - **ACTION_NEEDED** - There is a problem with the KSK that requires you to take action to resolve. For example, the customer managed key might have been deleted, or the permissions for the customer managed key might have been changed. - **INTERNAL_FAILURE** - There was an error during a request. Before you can continue to work with DNSSEC signing, including actions that involve this KSK, you must correct the problem. For example, you may need to activate or deactivate the KSK.
        '''
        props = CfnKeySigningKeyProps(
            hosted_zone_id=hosted_zone_id,
            key_management_service_arn=key_management_service_arn,
            name=name,
            status=status,
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
    @jsii.member(jsii_name="hostedZoneId")
    def hosted_zone_id(self) -> builtins.str:
        '''The unique string (ID) that is used to identify a hosted zone.

        For example: ``Z00001111A1ABCaaABC11`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html#cfn-route53-keysigningkey-hostedzoneid
        '''
        return typing.cast(builtins.str, jsii.get(self, "hostedZoneId"))

    @hosted_zone_id.setter
    def hosted_zone_id(self, value: builtins.str) -> None:
        jsii.set(self, "hostedZoneId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="keyManagementServiceArn")
    def key_management_service_arn(self) -> builtins.str:
        '''The Amazon resource name (ARN) for a customer managed customer master key (CMK) in AWS Key Management Service ( AWS KMS ).

        The ``KeyManagementServiceArn`` must be unique for each key-signing key (KSK) in a single hosted zone. For example: ``arn:aws:kms:us-east-1:111122223333:key/111a2222-a11b-1ab1-2ab2-1ab21a2b3a111`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html#cfn-route53-keysigningkey-keymanagementservicearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "keyManagementServiceArn"))

    @key_management_service_arn.setter
    def key_management_service_arn(self, value: builtins.str) -> None:
        jsii.set(self, "keyManagementServiceArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A string used to identify a key-signing key (KSK).

        ``Name`` can include numbers, letters, and underscores (_). ``Name`` must be unique for each key-signing key in the same hosted zone.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html#cfn-route53-keysigningkey-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="status")
    def status(self) -> builtins.str:
        '''A string that represents the current key-signing key (KSK) status.

        Status can have one of the following values:

        - **ACTIVE** - The KSK is being used for signing.
        - **INACTIVE** - The KSK is not being used for signing.
        - **DELETING** - The KSK is in the process of being deleted.
        - **ACTION_NEEDED** - There is a problem with the KSK that requires you to take action to resolve. For example, the customer managed key might have been deleted, or the permissions for the customer managed key might have been changed.
        - **INTERNAL_FAILURE** - There was an error during a request. Before you can continue to work with DNSSEC signing, including actions that involve this KSK, you must correct the problem. For example, you may need to activate or deactivate the KSK.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html#cfn-route53-keysigningkey-status
        '''
        return typing.cast(builtins.str, jsii.get(self, "status"))

    @status.setter
    def status(self, value: builtins.str) -> None:
        jsii.set(self, "status", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CfnKeySigningKeyProps",
    jsii_struct_bases=[],
    name_mapping={
        "hosted_zone_id": "hostedZoneId",
        "key_management_service_arn": "keyManagementServiceArn",
        "name": "name",
        "status": "status",
    },
)
class CfnKeySigningKeyProps:
    def __init__(
        self,
        *,
        hosted_zone_id: builtins.str,
        key_management_service_arn: builtins.str,
        name: builtins.str,
        status: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnKeySigningKey``.

        :param hosted_zone_id: The unique string (ID) that is used to identify a hosted zone. For example: ``Z00001111A1ABCaaABC11`` .
        :param key_management_service_arn: The Amazon resource name (ARN) for a customer managed customer master key (CMK) in AWS Key Management Service ( AWS KMS ). The ``KeyManagementServiceArn`` must be unique for each key-signing key (KSK) in a single hosted zone. For example: ``arn:aws:kms:us-east-1:111122223333:key/111a2222-a11b-1ab1-2ab2-1ab21a2b3a111`` .
        :param name: A string used to identify a key-signing key (KSK). ``Name`` can include numbers, letters, and underscores (_). ``Name`` must be unique for each key-signing key in the same hosted zone.
        :param status: A string that represents the current key-signing key (KSK) status. Status can have one of the following values: - **ACTIVE** - The KSK is being used for signing. - **INACTIVE** - The KSK is not being used for signing. - **DELETING** - The KSK is in the process of being deleted. - **ACTION_NEEDED** - There is a problem with the KSK that requires you to take action to resolve. For example, the customer managed key might have been deleted, or the permissions for the customer managed key might have been changed. - **INTERNAL_FAILURE** - There was an error during a request. Before you can continue to work with DNSSEC signing, including actions that involve this KSK, you must correct the problem. For example, you may need to activate or deactivate the KSK.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            cfn_key_signing_key_props = route53.CfnKeySigningKeyProps(
                hosted_zone_id="hostedZoneId",
                key_management_service_arn="keyManagementServiceArn",
                name="name",
                status="status"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "hosted_zone_id": hosted_zone_id,
            "key_management_service_arn": key_management_service_arn,
            "name": name,
            "status": status,
        }

    @builtins.property
    def hosted_zone_id(self) -> builtins.str:
        '''The unique string (ID) that is used to identify a hosted zone.

        For example: ``Z00001111A1ABCaaABC11`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html#cfn-route53-keysigningkey-hostedzoneid
        '''
        result = self._values.get("hosted_zone_id")
        assert result is not None, "Required property 'hosted_zone_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def key_management_service_arn(self) -> builtins.str:
        '''The Amazon resource name (ARN) for a customer managed customer master key (CMK) in AWS Key Management Service ( AWS KMS ).

        The ``KeyManagementServiceArn`` must be unique for each key-signing key (KSK) in a single hosted zone. For example: ``arn:aws:kms:us-east-1:111122223333:key/111a2222-a11b-1ab1-2ab2-1ab21a2b3a111`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html#cfn-route53-keysigningkey-keymanagementservicearn
        '''
        result = self._values.get("key_management_service_arn")
        assert result is not None, "Required property 'key_management_service_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''A string used to identify a key-signing key (KSK).

        ``Name`` can include numbers, letters, and underscores (_). ``Name`` must be unique for each key-signing key in the same hosted zone.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html#cfn-route53-keysigningkey-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def status(self) -> builtins.str:
        '''A string that represents the current key-signing key (KSK) status.

        Status can have one of the following values:

        - **ACTIVE** - The KSK is being used for signing.
        - **INACTIVE** - The KSK is not being used for signing.
        - **DELETING** - The KSK is in the process of being deleted.
        - **ACTION_NEEDED** - There is a problem with the KSK that requires you to take action to resolve. For example, the customer managed key might have been deleted, or the permissions for the customer managed key might have been changed.
        - **INTERNAL_FAILURE** - There was an error during a request. Before you can continue to work with DNSSEC signing, including actions that involve this KSK, you must correct the problem. For example, you may need to activate or deactivate the KSK.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-keysigningkey.html#cfn-route53-keysigningkey-status
        '''
        result = self._values.get("status")
        assert result is not None, "Required property 'status' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnKeySigningKeyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRecordSet(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CfnRecordSet",
):
    '''A CloudFormation ``AWS::Route53::RecordSet``.

    Information about the record that you want to create.

    The ``AWS::Route53::RecordSet`` type can be used as a standalone resource or as an embedded property in the ``AWS::Route53::RecordSetGroup`` type. Note that some ``AWS::Route53::RecordSet`` properties are valid only when used within ``AWS::Route53::RecordSetGroup`` .

    For more information, see `ChangeResourceRecordSets <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html>`_ in the *Amazon Route 53 API Reference* .

    :cloudformationResource: AWS::Route53::RecordSet
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53 as route53
        
        cfn_record_set = route53.CfnRecordSet(self, "MyCfnRecordSet",
            name="name",
            type="type",
        
            # the properties below are optional
            alias_target=route53.CfnRecordSet.AliasTargetProperty(
                dns_name="dnsName",
                hosted_zone_id="hostedZoneId",
        
                # the properties below are optional
                evaluate_target_health=False
            ),
            comment="comment",
            failover="failover",
            geo_location=route53.CfnRecordSet.GeoLocationProperty(
                continent_code="continentCode",
                country_code="countryCode",
                subdivision_code="subdivisionCode"
            ),
            health_check_id="healthCheckId",
            hosted_zone_id="hostedZoneId",
            hosted_zone_name="hostedZoneName",
            multi_value_answer=False,
            region="region",
            resource_records=["resourceRecords"],
            set_identifier="setIdentifier",
            ttl="ttl",
            weight=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        type: builtins.str,
        alias_target: typing.Optional[typing.Union["CfnRecordSet.AliasTargetProperty", _IResolvable_da3f097b]] = None,
        comment: typing.Optional[builtins.str] = None,
        failover: typing.Optional[builtins.str] = None,
        geo_location: typing.Optional[typing.Union["CfnRecordSet.GeoLocationProperty", _IResolvable_da3f097b]] = None,
        health_check_id: typing.Optional[builtins.str] = None,
        hosted_zone_id: typing.Optional[builtins.str] = None,
        hosted_zone_name: typing.Optional[builtins.str] = None,
        multi_value_answer: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        region: typing.Optional[builtins.str] = None,
        resource_records: typing.Optional[typing.Sequence[builtins.str]] = None,
        set_identifier: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[builtins.str] = None,
        weight: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Create a new ``AWS::Route53::RecordSet``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: For ``ChangeResourceRecordSets`` requests, the name of the record that you want to create, update, or delete. For ``ListResourceRecordSets`` responses, the name of a record in the specified hosted zone. *ChangeResourceRecordSets Only* Enter a fully qualified domain name, for example, ``www.example.com`` . You can optionally include a trailing dot. If you omit the trailing dot, Amazon Route 53 assumes that the domain name that you specify is fully qualified. This means that Route 53 treats ``www.example.com`` (without a trailing dot) and ``www.example.com.`` (with a trailing dot) as identical. For information about how to specify characters other than ``a-z`` , ``0-9`` , and ``-`` (hyphen) and how to specify internationalized domain names, see `DNS Domain Name Format <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html>`_ in the *Amazon Route 53 Developer Guide* . You can use the asterisk (*) wildcard to replace the leftmost label in a domain name, for example, ``*.example.com`` . Note the following: - The * must replace the entire label. For example, you can't specify ``*prod.example.com`` or ``prod*.example.com`` . - The * can't replace any of the middle labels, for example, marketing.*.example.com. - If you include * in any position other than the leftmost label in a domain name, DNS treats it as an * character (ASCII 42), not as a wildcard. .. epigraph:: You can't use the * wildcard for resource records sets that have a type of NS. You can use the * wildcard as the leftmost label in a domain name, for example, ``*.example.com`` . You can't use an * for one of the middle labels, for example, ``marketing.*.example.com`` . In addition, the * must replace the entire label; for example, you can't specify ``prod*.example.com`` .
        :param type: The DNS record type. For information about different record types and how data is encoded for them, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* . Valid values for basic resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``DS`` | ``MX`` | ``NAPTR`` | ``NS`` | ``PTR`` | ``SOA`` | ``SPF`` | ``SRV`` | ``TXT`` Values for weighted, latency, geolocation, and failover resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` . When creating a group of weighted, latency, geolocation, or failover resource record sets, specify the same value for all of the resource record sets in the group. Valid values for multivalue answer resource record sets: ``A`` | ``AAAA`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` .. epigraph:: SPF records were formerly used to verify the identity of the sender of email messages. However, we no longer recommend that you create resource record sets for which the value of ``Type`` is ``SPF`` . RFC 7208, *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1* , has been updated to say, "...[I]ts existence and mechanism defined in [RFC4408] have led to some interoperability issues. Accordingly, its use is no longer appropriate for SPF version 1; implementations are not to use it." In RFC 7208, see section 14.1, `The SPF DNS Record Type <https://docs.aws.amazon.com/http://tools.ietf.org/html/rfc7208#section-14.1>`_ . Values for alias resource record sets: - *Amazon API Gateway custom regional APIs and edge-optimized APIs:* ``A`` - *CloudFront distributions:* ``A`` If IPv6 is enabled for the distribution, create two resource record sets to route traffic to your distribution, one with a value of ``A`` and one with a value of ``AAAA`` . - *Amazon API Gateway environment that has a regionalized subdomain* : ``A`` - *ELB load balancers:* ``A`` | ``AAAA`` - *Amazon S3 buckets:* ``A`` - *Amazon Virtual Private Cloud interface VPC endpoints* ``A`` - *Another resource record set in this hosted zone:* Specify the type of the resource record set that you're creating the alias for. All values are supported except ``NS`` and ``SOA`` . .. epigraph:: If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't route traffic to a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.
        :param alias_target: *Alias resource record sets only:* Information about the AWS resource, such as a CloudFront distribution or an Amazon S3 bucket, that you want to route traffic to. If you're creating resource records sets for a private hosted zone, note the following: - You can't create an alias resource record set in a private hosted zone to route traffic to a CloudFront distribution. - Creating geolocation alias resource record sets or latency alias resource record sets in a private hosted zone is unsupported. - For information about creating failover resource record sets in a private hosted zone, see `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ in the *Amazon Route 53 Developer Guide* .
        :param comment: *Optional:* Any comments you want to include about a change batch request.
        :param failover: *Failover resource record sets only:* To configure failover, you add the ``Failover`` element to two resource record sets. For one resource record set, you specify ``PRIMARY`` as the value for ``Failover`` ; for the other resource record set, you specify ``SECONDARY`` . In addition, you include the ``HealthCheckId`` element and specify the health check that you want Amazon Route 53 to perform for each resource record set. Except where noted, the following failover behaviors assume that you have included the ``HealthCheckId`` element in both resource record sets: - When the primary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the secondary resource record set. - When the primary resource record set is unhealthy and the secondary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the secondary resource record set. - When the secondary resource record set is unhealthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the primary resource record set. - If you omit the ``HealthCheckId`` element for the secondary resource record set, and if the primary resource record set is unhealthy, Route 53 always responds to DNS queries with the applicable value from the secondary resource record set. This is true regardless of the health of the associated endpoint. You can't create non-failover resource record sets that have the same values for the ``Name`` and ``Type`` elements as failover resource record sets. For failover alias resource record sets, you must also include the ``EvaluateTargetHealth`` element and set the value to true. For more information about configuring failover for Route 53, see the following topics in the *Amazon Route 53 Developer Guide* : - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_
        :param geo_location: *Geolocation resource record sets only:* A complex type that lets you control how Amazon Route 53 responds to DNS queries based on the geographic origin of the query. For example, if you want all queries from Africa to be routed to a web server with an IP address of ``192.0.2.111`` , create a resource record set with a ``Type`` of ``A`` and a ``ContinentCode`` of ``AF`` . .. epigraph:: Although creating geolocation and geolocation alias resource record sets in a private hosted zone is allowed, it's not supported. If you create separate resource record sets for overlapping geographic regions (for example, one resource record set for a continent and one for a country on the same continent), priority goes to the smallest geographic region. This allows you to route most queries for a continent to one resource and to route queries for a country on that continent to a different resource. You can't create two geolocation resource record sets that specify the same geographic location. The value ``*`` in the ``CountryCode`` element matches all geographic locations that aren't specified in other geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements. .. epigraph:: Geolocation works by mapping IP addresses to locations. However, some IP addresses aren't mapped to geographic locations, so even if you create geolocation resource record sets that cover all seven continents, Route 53 will receive some DNS queries from locations that it can't identify. We recommend that you create a resource record set for which the value of ``CountryCode`` is ``*`` . Two groups of queries are routed to the resource that you specify in this record: queries that come from locations for which you haven't created geolocation resource record sets and queries from IP addresses that aren't mapped to a location. If you don't create a ``*`` resource record set, Route 53 returns a "no answer" response for queries from those locations. You can't create non-geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as geolocation resource record sets.
        :param health_check_id: If you want Amazon Route 53 to return this resource record set in response to a DNS query only when the status of a health check is healthy, include the ``HealthCheckId`` element and specify the ID of the applicable health check. Route 53 determines whether a resource record set is healthy based on one of the following: - By periodically sending a request to the endpoint that is specified in the health check - By aggregating the status of a specified group of health checks (calculated health checks) - By determining the current state of a CloudWatch alarm (CloudWatch metric health checks) .. epigraph:: Route 53 doesn't check the health of the endpoint that is specified in the resource record set, for example, the endpoint specified by the IP address in the ``Value`` element. When you add a ``HealthCheckId`` element to a resource record set, Route 53 checks the health of the endpoint that you specified in the health check. For more information, see the following topics in the *Amazon Route 53 Developer Guide* : - `How Amazon Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_ - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ *When to Specify HealthCheckId* Specifying a value for ``HealthCheckId`` is useful only when Route 53 is choosing between two or more resource record sets to respond to a DNS query, and you want Route 53 to base the choice in part on the status of a health check. Configuring health checks makes sense only in the following configurations: - *Non-alias resource record sets* : You're checking the health of a group of non-alias resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A) and you specify health check IDs for all the resource record sets. If the health check status for a resource record set is healthy, Route 53 includes the record among the records that it responds to DNS queries with. If the health check status for a resource record set is unhealthy, Route 53 stops responding to DNS queries using the value for that resource record set. If the health check status for all resource record sets in the group is unhealthy, Route 53 considers all resource record sets in the group healthy and responds to DNS queries accordingly. - *Alias resource record sets* : You specify the following settings: - You set ``EvaluateTargetHealth`` to true for an alias resource record set in a group of resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A). - You configure the alias resource record set to route traffic to a non-alias resource record set in the same hosted zone. - You specify a health check ID for the non-alias resource record set. If the health check status is healthy, Route 53 considers the alias resource record set to be healthy and includes the alias record among the records that it responds to DNS queries with. If the health check status is unhealthy, Route 53 stops responding to DNS queries using the alias resource record set. .. epigraph:: The alias resource record set can also route traffic to a *group* of non-alias resource record sets that have the same routing policy, name, and type. In that configuration, associate health checks with all of the resource record sets in the group of non-alias resource record sets. *Geolocation Routing* For geolocation resource record sets, if an endpoint is unhealthy, Route 53 looks for a resource record set for the larger, associated geographic region. For example, suppose you have resource record sets for a state in the United States, for the entire United States, for North America, and a resource record set that has ``*`` for ``CountryCode`` is ``*`` , which applies to all locations. If the endpoint for the state resource record set is unhealthy, Route 53 checks for healthy resource record sets in the following order until it finds a resource record set for which the endpoint is healthy: - The United States - North America - The default resource record set *Specifying the Health Check Endpoint by Domain Name* If your health checks specify the endpoint only by domain name, we recommend that you create a separate health check for each endpoint. For example, create a health check for each ``HTTP`` server that is serving content for ``www.example.com`` . For the value of ``FullyQualifiedDomainName`` , specify the domain name of the server (such as ``us-east-2-www.example.com`` ), not the name of the resource record sets ( ``www.example.com`` ). .. epigraph:: Health check results will be unpredictable if you do the following: - Create a health check that has the same value for ``FullyQualifiedDomainName`` as the name of a resource record set. - Associate that health check with the resource record set.
        :param hosted_zone_id: The ID of the hosted zone that you want to create records in. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
        :param hosted_zone_name: The name of the hosted zone that you want to create records in. You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` . When you create a stack using an AWS::Route53::RecordSet that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the HostedZoneName. If AWS CloudFormation cannot find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
        :param multi_value_answer: *Multivalue answer resource record sets only* : To route traffic approximately randomly to multiple resources, such as web servers, create one multivalue answer record for each resource and specify ``true`` for ``MultiValueAnswer`` . Note the following: - If you associate a health check with a multivalue answer resource record set, Amazon Route 53 responds to DNS queries with the corresponding IP address only when the health check is healthy. - If you don't associate a health check with a multivalue answer record, Route 53 always considers the record to be healthy. - Route 53 responds to DNS queries with up to eight healthy records; if you have eight or fewer healthy records, Route 53 responds to all DNS queries with all the healthy records. - If you have more than eight healthy records, Route 53 responds to different DNS resolvers with different combinations of healthy records. - When all records are unhealthy, Route 53 responds to DNS queries with up to eight unhealthy records. - If a resource becomes unavailable after a resolver caches a response, client software typically tries another of the IP addresses in the response. You can't create multivalue answer alias records.
        :param region: *Latency-based resource record sets only:* The Amazon EC2 Region where you created the resource that this resource record set refers to. The resource typically is an AWS resource, such as an EC2 instance or an ELB load balancer, and is referred to by an IP address or a DNS domain name, depending on the record type. .. epigraph:: Although creating latency and latency alias resource record sets in a private hosted zone is allowed, it's not supported. When Amazon Route 53 receives a DNS query for a domain name and type for which you have created latency resource record sets, Route 53 selects the latency resource record set that has the lowest latency between the end user and the associated Amazon EC2 Region. Route 53 then returns the value that is associated with the selected resource record set. Note the following: - You can only specify one ``ResourceRecord`` per latency resource record set. - You can only create one latency resource record set for each Amazon EC2 Region. - You aren't required to create latency resource record sets for all Amazon EC2 Regions. Route 53 will choose the region with the best latency from among the regions that you create latency resource record sets for. - You can't create non-latency resource record sets that have the same values for the ``Name`` and ``Type`` elements as latency resource record sets.
        :param resource_records: One or more values that correspond with the value that you specified for the ``Type`` property. For example, if you specified ``A`` for ``Type`` , you specify one or more IP addresses in IPv4 format for ``ResourceRecords`` . For information about the format of values for each record type, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* . Note the following: - You can specify more than one value for all record types except CNAME and SOA. - The maximum length of a value is 4000 characters. - If you're creating an alias record, omit ``ResourceRecords`` .
        :param set_identifier: *Resource record sets that have a routing policy other than simple:* An identifier that differentiates among multiple resource record sets that have the same combination of name and type, such as multiple weighted resource record sets named acme.example.com that have a type of A. In a group of resource record sets that have the same name and type, the value of ``SetIdentifier`` must be unique for each resource record set. For information about routing policies, see `Choosing a Routing Policy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html>`_ in the *Amazon Route 53 Developer Guide* .
        :param ttl: The resource record cache time to live (TTL), in seconds. Note the following:. - If you're creating or updating an alias resource record set, omit ``TTL`` . Amazon Route 53 uses the value of ``TTL`` for the alias target. - If you're associating this resource record set with a health check (if you're adding a ``HealthCheckId`` element), we recommend that you specify a ``TTL`` of 60 seconds or less so clients respond quickly to changes in health status. - All of the resource record sets in a group of weighted resource record sets must have the same value for ``TTL`` . - If a group of weighted resource record sets includes one or more weighted alias resource record sets for which the alias target is an ELB load balancer, we recommend that you specify a ``TTL`` of 60 seconds for all of the non-alias weighted resource record sets that have the same name and type. Values other than 60 seconds (the TTL for load balancers) will change the effect of the values that you specify for ``Weight`` .
        :param weight: *Weighted resource record sets only:* Among resource record sets that have the same combination of DNS name and type, a value that determines the proportion of DNS queries that Amazon Route 53 responds to using the current resource record set. Route 53 calculates the sum of the weights for the resource record sets that have the same combination of DNS name and type. Route 53 then responds to queries based on the ratio of a resource's weight to the total. Note the following: - You must specify a value for the ``Weight`` element for every weighted resource record set. - You can only specify one ``ResourceRecord`` per weighted resource record set. - You can't create latency, failover, or geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as weighted resource record sets. - You can create a maximum of 100 weighted resource record sets that have the same values for the ``Name`` and ``Type`` elements. - For weighted (but not weighted alias) resource record sets, if you set ``Weight`` to ``0`` for a resource record set, Route 53 never responds to queries with the applicable value for that resource record set. However, if you set ``Weight`` to ``0`` for all resource record sets that have the same combination of DNS name and type, traffic is routed to all resources with equal probability. The effect of setting ``Weight`` to ``0`` is different when you associate health checks with weighted resource record sets. For more information, see `Options for Configuring Route 53 Active-Active and Active-Passive Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-configuring-options.html>`_ in the *Amazon Route 53 Developer Guide* .
        '''
        props = CfnRecordSetProps(
            name=name,
            type=type,
            alias_target=alias_target,
            comment=comment,
            failover=failover,
            geo_location=geo_location,
            health_check_id=health_check_id,
            hosted_zone_id=hosted_zone_id,
            hosted_zone_name=hosted_zone_name,
            multi_value_answer=multi_value_answer,
            region=region,
            resource_records=resource_records,
            set_identifier=set_identifier,
            ttl=ttl,
            weight=weight,
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
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''For ``ChangeResourceRecordSets`` requests, the name of the record that you want to create, update, or delete.

        For ``ListResourceRecordSets`` responses, the name of a record in the specified hosted zone.

        *ChangeResourceRecordSets Only*

        Enter a fully qualified domain name, for example, ``www.example.com`` . You can optionally include a trailing dot. If you omit the trailing dot, Amazon Route 53 assumes that the domain name that you specify is fully qualified. This means that Route 53 treats ``www.example.com`` (without a trailing dot) and ``www.example.com.`` (with a trailing dot) as identical.

        For information about how to specify characters other than ``a-z`` , ``0-9`` , and ``-`` (hyphen) and how to specify internationalized domain names, see `DNS Domain Name Format <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html>`_ in the *Amazon Route 53 Developer Guide* .

        You can use the asterisk (*) wildcard to replace the leftmost label in a domain name, for example, ``*.example.com`` . Note the following:

        - The * must replace the entire label. For example, you can't specify ``*prod.example.com`` or ``prod*.example.com`` .
        - The * can't replace any of the middle labels, for example, marketing.*.example.com.
        - If you include * in any position other than the leftmost label in a domain name, DNS treats it as an * character (ASCII 42), not as a wildcard.

        .. epigraph::

           You can't use the * wildcard for resource records sets that have a type of NS.

        You can use the * wildcard as the leftmost label in a domain name, for example, ``*.example.com`` . You can't use an * for one of the middle labels, for example, ``marketing.*.example.com`` . In addition, the * must replace the entire label; for example, you can't specify ``prod*.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''The DNS record type.

        For information about different record types and how data is encoded for them, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* .

        Valid values for basic resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``DS`` | ``MX`` | ``NAPTR`` | ``NS`` | ``PTR`` | ``SOA`` | ``SPF`` | ``SRV`` | ``TXT``

        Values for weighted, latency, geolocation, and failover resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` . When creating a group of weighted, latency, geolocation, or failover resource record sets, specify the same value for all of the resource record sets in the group.

        Valid values for multivalue answer resource record sets: ``A`` | ``AAAA`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT``
        .. epigraph::

           SPF records were formerly used to verify the identity of the sender of email messages. However, we no longer recommend that you create resource record sets for which the value of ``Type`` is ``SPF`` . RFC 7208, *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1* , has been updated to say, "...[I]ts existence and mechanism defined in [RFC4408] have led to some interoperability issues. Accordingly, its use is no longer appropriate for SPF version 1; implementations are not to use it." In RFC 7208, see section 14.1, `The SPF DNS Record Type <https://docs.aws.amazon.com/http://tools.ietf.org/html/rfc7208#section-14.1>`_ .

        Values for alias resource record sets:

        - *Amazon API Gateway custom regional APIs and edge-optimized APIs:* ``A``
        - *CloudFront distributions:* ``A``

        If IPv6 is enabled for the distribution, create two resource record sets to route traffic to your distribution, one with a value of ``A`` and one with a value of ``AAAA`` .

        - *Amazon API Gateway environment that has a regionalized subdomain* : ``A``
        - *ELB load balancers:* ``A`` | ``AAAA``
        - *Amazon S3 buckets:* ``A``
        - *Amazon Virtual Private Cloud interface VPC endpoints* ``A``
        - *Another resource record set in this hosted zone:* Specify the type of the resource record set that you're creating the alias for. All values are supported except ``NS`` and ``SOA`` .

        .. epigraph::

           If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't route traffic to a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="aliasTarget")
    def alias_target(
        self,
    ) -> typing.Optional[typing.Union["CfnRecordSet.AliasTargetProperty", _IResolvable_da3f097b]]:
        '''*Alias resource record sets only:* Information about the AWS resource, such as a CloudFront distribution or an Amazon S3 bucket, that you want to route traffic to.

        If you're creating resource records sets for a private hosted zone, note the following:

        - You can't create an alias resource record set in a private hosted zone to route traffic to a CloudFront distribution.
        - Creating geolocation alias resource record sets or latency alias resource record sets in a private hosted zone is unsupported.
        - For information about creating failover resource record sets in a private hosted zone, see `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ in the *Amazon Route 53 Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-aliastarget
        '''
        return typing.cast(typing.Optional[typing.Union["CfnRecordSet.AliasTargetProperty", _IResolvable_da3f097b]], jsii.get(self, "aliasTarget"))

    @alias_target.setter
    def alias_target(
        self,
        value: typing.Optional[typing.Union["CfnRecordSet.AliasTargetProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "aliasTarget", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="comment")
    def comment(self) -> typing.Optional[builtins.str]:
        '''*Optional:* Any comments you want to include about a change batch request.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-comment
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "comment"))

    @comment.setter
    def comment(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "comment", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="failover")
    def failover(self) -> typing.Optional[builtins.str]:
        '''*Failover resource record sets only:* To configure failover, you add the ``Failover`` element to two resource record sets.

        For one resource record set, you specify ``PRIMARY`` as the value for ``Failover`` ; for the other resource record set, you specify ``SECONDARY`` . In addition, you include the ``HealthCheckId`` element and specify the health check that you want Amazon Route 53 to perform for each resource record set.

        Except where noted, the following failover behaviors assume that you have included the ``HealthCheckId`` element in both resource record sets:

        - When the primary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the secondary resource record set.
        - When the primary resource record set is unhealthy and the secondary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the secondary resource record set.
        - When the secondary resource record set is unhealthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the primary resource record set.
        - If you omit the ``HealthCheckId`` element for the secondary resource record set, and if the primary resource record set is unhealthy, Route 53 always responds to DNS queries with the applicable value from the secondary resource record set. This is true regardless of the health of the associated endpoint.

        You can't create non-failover resource record sets that have the same values for the ``Name`` and ``Type`` elements as failover resource record sets.

        For failover alias resource record sets, you must also include the ``EvaluateTargetHealth`` element and set the value to true.

        For more information about configuring failover for Route 53, see the following topics in the *Amazon Route 53 Developer Guide* :

        - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_
        - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-failover
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "failover"))

    @failover.setter
    def failover(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "failover", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="geoLocation")
    def geo_location(
        self,
    ) -> typing.Optional[typing.Union["CfnRecordSet.GeoLocationProperty", _IResolvable_da3f097b]]:
        '''*Geolocation resource record sets only:* A complex type that lets you control how Amazon Route 53 responds to DNS queries based on the geographic origin of the query.

        For example, if you want all queries from Africa to be routed to a web server with an IP address of ``192.0.2.111`` , create a resource record set with a ``Type`` of ``A`` and a ``ContinentCode`` of ``AF`` .
        .. epigraph::

           Although creating geolocation and geolocation alias resource record sets in a private hosted zone is allowed, it's not supported.

        If you create separate resource record sets for overlapping geographic regions (for example, one resource record set for a continent and one for a country on the same continent), priority goes to the smallest geographic region. This allows you to route most queries for a continent to one resource and to route queries for a country on that continent to a different resource.

        You can't create two geolocation resource record sets that specify the same geographic location.

        The value ``*`` in the ``CountryCode`` element matches all geographic locations that aren't specified in other geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements.
        .. epigraph::

           Geolocation works by mapping IP addresses to locations. However, some IP addresses aren't mapped to geographic locations, so even if you create geolocation resource record sets that cover all seven continents, Route 53 will receive some DNS queries from locations that it can't identify. We recommend that you create a resource record set for which the value of ``CountryCode`` is ``*`` . Two groups of queries are routed to the resource that you specify in this record: queries that come from locations for which you haven't created geolocation resource record sets and queries from IP addresses that aren't mapped to a location. If you don't create a ``*`` resource record set, Route 53 returns a "no answer" response for queries from those locations.

        You can't create non-geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as geolocation resource record sets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-geolocation
        '''
        return typing.cast(typing.Optional[typing.Union["CfnRecordSet.GeoLocationProperty", _IResolvable_da3f097b]], jsii.get(self, "geoLocation"))

    @geo_location.setter
    def geo_location(
        self,
        value: typing.Optional[typing.Union["CfnRecordSet.GeoLocationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "geoLocation", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckId")
    def health_check_id(self) -> typing.Optional[builtins.str]:
        '''If you want Amazon Route 53 to return this resource record set in response to a DNS query only when the status of a health check is healthy, include the ``HealthCheckId`` element and specify the ID of the applicable health check.

        Route 53 determines whether a resource record set is healthy based on one of the following:

        - By periodically sending a request to the endpoint that is specified in the health check
        - By aggregating the status of a specified group of health checks (calculated health checks)
        - By determining the current state of a CloudWatch alarm (CloudWatch metric health checks)

        .. epigraph::

           Route 53 doesn't check the health of the endpoint that is specified in the resource record set, for example, the endpoint specified by the IP address in the ``Value`` element. When you add a ``HealthCheckId`` element to a resource record set, Route 53 checks the health of the endpoint that you specified in the health check.

        For more information, see the following topics in the *Amazon Route 53 Developer Guide* :

        - `How Amazon Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_
        - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_
        - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_

        *When to Specify HealthCheckId*

        Specifying a value for ``HealthCheckId`` is useful only when Route 53 is choosing between two or more resource record sets to respond to a DNS query, and you want Route 53 to base the choice in part on the status of a health check. Configuring health checks makes sense only in the following configurations:

        - *Non-alias resource record sets* : You're checking the health of a group of non-alias resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A) and you specify health check IDs for all the resource record sets.

        If the health check status for a resource record set is healthy, Route 53 includes the record among the records that it responds to DNS queries with.

        If the health check status for a resource record set is unhealthy, Route 53 stops responding to DNS queries using the value for that resource record set.

        If the health check status for all resource record sets in the group is unhealthy, Route 53 considers all resource record sets in the group healthy and responds to DNS queries accordingly.

        - *Alias resource record sets* : You specify the following settings:
        - You set ``EvaluateTargetHealth`` to true for an alias resource record set in a group of resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A).
        - You configure the alias resource record set to route traffic to a non-alias resource record set in the same hosted zone.
        - You specify a health check ID for the non-alias resource record set.

        If the health check status is healthy, Route 53 considers the alias resource record set to be healthy and includes the alias record among the records that it responds to DNS queries with.

        If the health check status is unhealthy, Route 53 stops responding to DNS queries using the alias resource record set.
        .. epigraph::

           The alias resource record set can also route traffic to a *group* of non-alias resource record sets that have the same routing policy, name, and type. In that configuration, associate health checks with all of the resource record sets in the group of non-alias resource record sets.

        *Geolocation Routing*

        For geolocation resource record sets, if an endpoint is unhealthy, Route 53 looks for a resource record set for the larger, associated geographic region. For example, suppose you have resource record sets for a state in the United States, for the entire United States, for North America, and a resource record set that has ``*`` for ``CountryCode`` is ``*`` , which applies to all locations. If the endpoint for the state resource record set is unhealthy, Route 53 checks for healthy resource record sets in the following order until it finds a resource record set for which the endpoint is healthy:

        - The United States
        - North America
        - The default resource record set

        *Specifying the Health Check Endpoint by Domain Name*

        If your health checks specify the endpoint only by domain name, we recommend that you create a separate health check for each endpoint. For example, create a health check for each ``HTTP`` server that is serving content for ``www.example.com`` . For the value of ``FullyQualifiedDomainName`` , specify the domain name of the server (such as ``us-east-2-www.example.com`` ), not the name of the resource record sets ( ``www.example.com`` ).
        .. epigraph::

           Health check results will be unpredictable if you do the following:

           - Create a health check that has the same value for ``FullyQualifiedDomainName`` as the name of a resource record set.
           - Associate that health check with the resource record set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-healthcheckid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "healthCheckId"))

    @health_check_id.setter
    def health_check_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "healthCheckId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneId")
    def hosted_zone_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the hosted zone that you want to create records in.

        Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-hostedzoneid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "hostedZoneId"))

    @hosted_zone_id.setter
    def hosted_zone_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "hostedZoneId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneName")
    def hosted_zone_name(self) -> typing.Optional[builtins.str]:
        '''The name of the hosted zone that you want to create records in.

        You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` .

        When you create a stack using an AWS::Route53::RecordSet that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the HostedZoneName. If AWS CloudFormation cannot find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack.

        Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-hostedzonename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "hostedZoneName"))

    @hosted_zone_name.setter
    def hosted_zone_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "hostedZoneName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="multiValueAnswer")
    def multi_value_answer(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''*Multivalue answer resource record sets only* : To route traffic approximately randomly to multiple resources, such as web servers, create one multivalue answer record for each resource and specify ``true`` for ``MultiValueAnswer`` .

        Note the following:

        - If you associate a health check with a multivalue answer resource record set, Amazon Route 53 responds to DNS queries with the corresponding IP address only when the health check is healthy.
        - If you don't associate a health check with a multivalue answer record, Route 53 always considers the record to be healthy.
        - Route 53 responds to DNS queries with up to eight healthy records; if you have eight or fewer healthy records, Route 53 responds to all DNS queries with all the healthy records.
        - If you have more than eight healthy records, Route 53 responds to different DNS resolvers with different combinations of healthy records.
        - When all records are unhealthy, Route 53 responds to DNS queries with up to eight unhealthy records.
        - If a resource becomes unavailable after a resolver caches a response, client software typically tries another of the IP addresses in the response.

        You can't create multivalue answer alias records.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-multivalueanswer
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "multiValueAnswer"))

    @multi_value_answer.setter
    def multi_value_answer(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "multiValueAnswer", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="region")
    def region(self) -> typing.Optional[builtins.str]:
        '''*Latency-based resource record sets only:* The Amazon EC2 Region where you created the resource that this resource record set refers to.

        The resource typically is an AWS resource, such as an EC2 instance or an ELB load balancer, and is referred to by an IP address or a DNS domain name, depending on the record type.
        .. epigraph::

           Although creating latency and latency alias resource record sets in a private hosted zone is allowed, it's not supported.

        When Amazon Route 53 receives a DNS query for a domain name and type for which you have created latency resource record sets, Route 53 selects the latency resource record set that has the lowest latency between the end user and the associated Amazon EC2 Region. Route 53 then returns the value that is associated with the selected resource record set.

        Note the following:

        - You can only specify one ``ResourceRecord`` per latency resource record set.
        - You can only create one latency resource record set for each Amazon EC2 Region.
        - You aren't required to create latency resource record sets for all Amazon EC2 Regions. Route 53 will choose the region with the best latency from among the regions that you create latency resource record sets for.
        - You can't create non-latency resource record sets that have the same values for the ``Name`` and ``Type`` elements as latency resource record sets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-region
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "region"))

    @region.setter
    def region(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "region", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceRecords")
    def resource_records(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more values that correspond with the value that you specified for the ``Type`` property.

        For example, if you specified ``A`` for ``Type`` , you specify one or more IP addresses in IPv4 format for ``ResourceRecords`` . For information about the format of values for each record type, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* .

        Note the following:

        - You can specify more than one value for all record types except CNAME and SOA.
        - The maximum length of a value is 4000 characters.
        - If you're creating an alias record, omit ``ResourceRecords`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-resourcerecords
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "resourceRecords"))

    @resource_records.setter
    def resource_records(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "resourceRecords", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="setIdentifier")
    def set_identifier(self) -> typing.Optional[builtins.str]:
        '''*Resource record sets that have a routing policy other than simple:* An identifier that differentiates among multiple resource record sets that have the same combination of name and type, such as multiple weighted resource record sets named acme.example.com that have a type of A. In a group of resource record sets that have the same name and type, the value of ``SetIdentifier`` must be unique for each resource record set.

        For information about routing policies, see `Choosing a Routing Policy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html>`_ in the *Amazon Route 53 Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-setidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "setIdentifier"))

    @set_identifier.setter
    def set_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "setIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ttl")
    def ttl(self) -> typing.Optional[builtins.str]:
        '''The resource record cache time to live (TTL), in seconds. Note the following:.

        - If you're creating or updating an alias resource record set, omit ``TTL`` . Amazon Route 53 uses the value of ``TTL`` for the alias target.
        - If you're associating this resource record set with a health check (if you're adding a ``HealthCheckId`` element), we recommend that you specify a ``TTL`` of 60 seconds or less so clients respond quickly to changes in health status.
        - All of the resource record sets in a group of weighted resource record sets must have the same value for ``TTL`` .
        - If a group of weighted resource record sets includes one or more weighted alias resource record sets for which the alias target is an ELB load balancer, we recommend that you specify a ``TTL`` of 60 seconds for all of the non-alias weighted resource record sets that have the same name and type. Values other than 60 seconds (the TTL for load balancers) will change the effect of the values that you specify for ``Weight`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-ttl
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "ttl"))

    @ttl.setter
    def ttl(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "ttl", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="weight")
    def weight(self) -> typing.Optional[jsii.Number]:
        '''*Weighted resource record sets only:* Among resource record sets that have the same combination of DNS name and type, a value that determines the proportion of DNS queries that Amazon Route 53 responds to using the current resource record set.

        Route 53 calculates the sum of the weights for the resource record sets that have the same combination of DNS name and type. Route 53 then responds to queries based on the ratio of a resource's weight to the total. Note the following:

        - You must specify a value for the ``Weight`` element for every weighted resource record set.
        - You can only specify one ``ResourceRecord`` per weighted resource record set.
        - You can't create latency, failover, or geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as weighted resource record sets.
        - You can create a maximum of 100 weighted resource record sets that have the same values for the ``Name`` and ``Type`` elements.
        - For weighted (but not weighted alias) resource record sets, if you set ``Weight`` to ``0`` for a resource record set, Route 53 never responds to queries with the applicable value for that resource record set. However, if you set ``Weight`` to ``0`` for all resource record sets that have the same combination of DNS name and type, traffic is routed to all resources with equal probability.

        The effect of setting ``Weight`` to ``0`` is different when you associate health checks with weighted resource record sets. For more information, see `Options for Configuring Route 53 Active-Active and Active-Passive Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-configuring-options.html>`_ in the *Amazon Route 53 Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-weight
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "weight"))

    @weight.setter
    def weight(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "weight", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnRecordSet.AliasTargetProperty",
        jsii_struct_bases=[],
        name_mapping={
            "dns_name": "dnsName",
            "hosted_zone_id": "hostedZoneId",
            "evaluate_target_health": "evaluateTargetHealth",
        },
    )
    class AliasTargetProperty:
        def __init__(
            self,
            *,
            dns_name: builtins.str,
            hosted_zone_id: builtins.str,
            evaluate_target_health: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''*Alias records only:* Information about the AWS resource, such as a CloudFront distribution or an Amazon S3 bucket, that you want to route traffic to.

            When creating records for a private hosted zone, note the following:

            - Creating geolocation alias and latency alias records in a private hosted zone is allowed but not supported.
            - For information about creating failover records in a private hosted zone, see `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ .

            :param dns_name: *Alias records only:* The value that you specify depends on where you want to route queries:. - **Amazon API Gateway custom regional APIs and edge-optimized APIs** - Specify the applicable domain name for your API. You can get the applicable value using the AWS CLI command `get-domain-names <https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-domain-names.html>`_ : - For regional APIs, specify the value of ``regionalDomainName`` . - For edge-optimized APIs, specify the value of ``distributionDomainName`` . This is the name of the associated CloudFront distribution, such as ``da1b2c3d4e5.cloudfront.net`` . .. epigraph:: The name of the record that you're creating must match a custom domain name for your API, such as ``api.example.com`` . - **Amazon Virtual Private Cloud interface VPC endpoint** - Enter the API endpoint for the interface endpoint, such as ``vpce-123456789abcdef01-example-us-east-1a.elasticloadbalancing.us-east-1.vpce.amazonaws.com`` . For edge-optimized APIs, this is the domain name for the corresponding CloudFront distribution. You can get the value of ``DnsName`` using the AWS CLI command `describe-vpc-endpoints <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html>`_ . - **CloudFront distribution** - Specify the domain name that CloudFront assigned when you created your distribution. Your CloudFront distribution must include an alternate domain name that matches the name of the record. For example, if the name of the record is *acme.example.com* , your CloudFront distribution must include *acme.example.com* as one of the alternate domain names. For more information, see `Using Alternate Domain Names (CNAMEs) <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html>`_ in the *Amazon CloudFront Developer Guide* . You can't create a record in a private hosted zone to route traffic to a CloudFront distribution. .. epigraph:: For failover alias records, you can't specify a CloudFront distribution for both the primary and secondary records. A distribution must include an alternate domain name that matches the name of the record. However, the primary and secondary records have the same name, and you can't include the same alternate domain name in more than one distribution. - **Elastic Beanstalk environment** - If the domain name for your Elastic Beanstalk environment includes the region that you deployed the environment in, you can create an alias record that routes traffic to the environment. For example, the domain name ``my-environment. *us-west-2* .elasticbeanstalk.com`` is a regionalized domain name. .. epigraph:: For environments that were created before early 2016, the domain name doesn't include the region. To route traffic to these environments, you must create a CNAME record instead of an alias record. Note that you can't create a CNAME record for the root domain name. For example, if your domain name is example.com, you can create a record that routes traffic for acme.example.com to your Elastic Beanstalk environment, but you can't create a record that routes traffic for example.com to your Elastic Beanstalk environment. For Elastic Beanstalk environments that have regionalized subdomains, specify the ``CNAME`` attribute for the environment. You can use the following methods to get the value of the CNAME attribute: - *AWS Management Console* : For information about how to get the value by using the console, see `Using Custom Domains with AWS Elastic Beanstalk <https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html>`_ in the *AWS Elastic Beanstalk Developer Guide* . - *Elastic Beanstalk API* : Use the ``DescribeEnvironments`` action to get the value of the ``CNAME`` attribute. For more information, see `DescribeEnvironments <https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeEnvironments.html>`_ in the *AWS Elastic Beanstalk API Reference* . - *AWS CLI* : Use the ``describe-environments`` command to get the value of the ``CNAME`` attribute. For more information, see `describe-environments <https://docs.aws.amazon.com/cli/latest/reference/elasticbeanstalk/describe-environments.html>`_ in the *AWS CLI* . - **ELB load balancer** - Specify the DNS name that is associated with the load balancer. Get the DNS name by using the AWS Management Console , the ELB API, or the AWS CLI . - *AWS Management Console* : Go to the EC2 page, choose *Load Balancers* in the navigation pane, choose the load balancer, choose the *Description* tab, and get the value of the *DNS name* field. If you're routing traffic to a Classic Load Balancer, get the value that begins with *dualstack* . If you're routing traffic to another type of load balancer, get the value that applies to the record type, A or AAAA. - *Elastic Load Balancing API* : Use ``DescribeLoadBalancers`` to get the value of ``DNSName`` . For more information, see the applicable guide: - Classic Load Balancers: `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancers.html>`_ - Application and Network Load Balancers: `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ - *CloudFormation Fn::GetAtt intrinsic function* : Use the `Fn::GetAtt <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html>`_ intrinsic function to get the value of ``DNSName`` : - `Classic Load Balancers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html#aws-properties-ec2-elb-return-values>`_ . - `Application and Network Load Balancers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-return-values>`_ . - *AWS CLI* : Use ``describe-load-balancers`` to get the value of ``DNSName`` . For more information, see the applicable guide: - Classic Load Balancers: `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html>`_ - Application and Network Load Balancers: `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elbv2/describe-load-balancers.html>`_ - **Global Accelerator accelerator** - Specify the DNS name for your accelerator: - *Global Accelerator API* : To get the DNS name, use `DescribeAccelerator <https://docs.aws.amazon.com/global-accelerator/latest/api/API_DescribeAccelerator.html>`_ . - *AWS CLI* : To get the DNS name, use `describe-accelerator <https://docs.aws.amazon.com/cli/latest/reference/globalaccelerator/describe-accelerator.html>`_ . - **Amazon S3 bucket that is configured as a static website** - Specify the domain name of the Amazon S3 website endpoint that you created the bucket in, for example, ``s3-website.us-east-2.amazonaws.com`` . For more information about valid values, see the table `Amazon S3 Website Endpoints <https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints>`_ in the *Amazon Web Services General Reference* . For more information about using S3 buckets for websites, see `Getting Started with Amazon Route 53 <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/getting-started.html>`_ in the *Amazon Route 53 Developer Guide.* - **Another Route 53 record** - Specify the value of the ``Name`` element for a record in the current hosted zone. .. epigraph:: If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't specify the domain name for a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record that you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.
            :param hosted_zone_id: *Alias resource records sets only* : The value used depends on where you want to route traffic:. - **Amazon API Gateway custom regional APIs and edge-optimized APIs** - Specify the hosted zone ID for your API. You can get the applicable value using the AWS CLI command `get-domain-names <https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-domain-names.html>`_ : - For regional APIs, specify the value of ``regionalHostedZoneId`` . - For edge-optimized APIs, specify the value of ``distributionHostedZoneId`` . - **Amazon Virtual Private Cloud interface VPC endpoint** - Specify the hosted zone ID for your interface endpoint. You can get the value of ``HostedZoneId`` using the AWS CLI command `describe-vpc-endpoints <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html>`_ . - **CloudFront distribution** - Specify ``Z2FDTNDATAQYW2`` . This is always the hosted zone ID when you create an alias record that routes traffic to a CloudFront distribution. .. epigraph:: Alias records for CloudFront can't be created in a private zone. - **Elastic Beanstalk environment** - Specify the hosted zone ID for the region that you created the environment in. The environment must have a regionalized subdomain. For a list of regions and the corresponding hosted zone IDs, see `AWS Elastic Beanstalk endpoints and quotas <https://docs.aws.amazon.com/general/latest/gr/elasticbeanstalk.html>`_ in the *Amazon Web Services General Reference* . - **ELB load balancer** - Specify the value of the hosted zone ID for the load balancer. Use the following methods to get the hosted zone ID: - `Service Endpoints <https://docs.aws.amazon.com/general/latest/gr/elb.html>`_ table in the "Elastic Load Balancing Endpoints and Quotas" topic in the *Amazon Web Services General Reference* : Use the value that corresponds with the region that you created your load balancer in. Note that there are separate columns for Application and Classic Load Balancers and for Network Load Balancers. - *AWS Management Console* : Go to the Amazon EC2 page, choose *Load Balancers* in the navigation pane, select the load balancer, and get the value of the *Hosted zone* field on the *Description* tab. - *Elastic Load Balancing API* : Use ``DescribeLoadBalancers`` to get the applicable value. For more information, see the applicable guide: - Classic Load Balancers: Use `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancers.html>`_ to get the value of ``CanonicalHostedZoneNameID`` . - Application and Network Load Balancers: Use `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ to get the value of ``CanonicalHostedZoneID`` . - *CloudFormation Fn::GetAtt intrinsic function* : Use the `Fn::GetAtt <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html>`_ intrinsic function to get the applicable value: - Classic Load Balancers: Get `CanonicalHostedZoneNameID <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html#aws-properties-ec2-elb-return-values>`_ . - Application and Network Load Balancers: Get `CanonicalHostedZoneID <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-return-values>`_ . - *AWS CLI* : Use ``describe-load-balancers`` to get the applicable value. For more information, see the applicable guide: - Classic Load Balancers: Use `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html>`_ to get the value of ``CanonicalHostedZoneNameID`` . - Application and Network Load Balancers: Use `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elbv2/describe-load-balancers.html>`_ to get the value of ``CanonicalHostedZoneID`` . - **Global Accelerator accelerator** - Specify ``Z2BJ6XQ5FK7U4H`` . - **An Amazon S3 bucket configured as a static website** - Specify the hosted zone ID for the region that you created the bucket in. For more information about valid values, see the table `Amazon S3 Website Endpoints <https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints>`_ in the *Amazon Web Services General Reference* . - **Another Route 53 record in your hosted zone** - Specify the hosted zone ID of your hosted zone. (An alias record can't reference a record in a different hosted zone.)
            :param evaluate_target_health: *Applies only to alias, failover alias, geolocation alias, latency alias, and weighted alias resource record sets:* When ``EvaluateTargetHealth`` is ``true`` , an alias resource record set inherits the health of the referenced AWS resource, such as an ELB load balancer or another resource record set in the hosted zone. Note the following: - **CloudFront distributions** - You can't set ``EvaluateTargetHealth`` to ``true`` when the alias target is a CloudFront distribution. - **Elastic Beanstalk environments that have regionalized subdomains** - If you specify an Elastic Beanstalk environment in ``DNSName`` and the environment contains an ELB load balancer, Elastic Load Balancing routes queries only to the healthy Amazon EC2 instances that are registered with the load balancer. (An environment automatically contains an ELB load balancer if it includes more than one Amazon EC2 instance.) If you set ``EvaluateTargetHealth`` to ``true`` and either no Amazon EC2 instances are healthy or the load balancer itself is unhealthy, Route 53 routes queries to other available resources that are healthy, if any. If the environment contains a single Amazon EC2 instance, there are no special requirements. - **ELB load balancers** - Health checking behavior depends on the type of load balancer: - *Classic Load Balancers* : If you specify an ELB Classic Load Balancer in ``DNSName`` , Elastic Load Balancing routes queries only to the healthy Amazon EC2 instances that are registered with the load balancer. If you set ``EvaluateTargetHealth`` to ``true`` and either no EC2 instances are healthy or the load balancer itself is unhealthy, Route 53 routes queries to other resources. - *Application and Network Load Balancers* : If you specify an ELB Application or Network Load Balancer and you set ``EvaluateTargetHealth`` to ``true`` , Route 53 routes queries to the load balancer based on the health of the target groups that are associated with the load balancer: - For an Application or Network Load Balancer to be considered healthy, every target group that contains targets must contain at least one healthy target. If any target group contains only unhealthy targets, the load balancer is considered unhealthy, and Route 53 routes queries to other resources. - A target group that has no registered targets is considered unhealthy. .. epigraph:: When you create a load balancer, you configure settings for Elastic Load Balancing health checks; they're not Route 53 health checks, but they perform a similar function. Do not create Route 53 health checks for the EC2 instances that you register with an ELB load balancer. - **S3 buckets** - There are no special requirements for setting ``EvaluateTargetHealth`` to ``true`` when the alias target is an S3 bucket. - **Other records in the same hosted zone** - If the AWS resource that you specify in ``DNSName`` is a record or a group of records (for example, a group of weighted records) but is not another alias record, we recommend that you associate a health check with all of the records in the alias target. For more information, see `What Happens When You Omit Health Checks? <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-complex-configs.html#dns-failover-complex-configs-hc-omitting>`_ in the *Amazon Route 53 Developer Guide* . For more information and examples, see `Amazon Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                alias_target_property = route53.CfnRecordSet.AliasTargetProperty(
                    dns_name="dnsName",
                    hosted_zone_id="hostedZoneId",
                
                    # the properties below are optional
                    evaluate_target_health=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dns_name": dns_name,
                "hosted_zone_id": hosted_zone_id,
            }
            if evaluate_target_health is not None:
                self._values["evaluate_target_health"] = evaluate_target_health

        @builtins.property
        def dns_name(self) -> builtins.str:
            '''*Alias records only:* The value that you specify depends on where you want to route queries:.

            - **Amazon API Gateway custom regional APIs and edge-optimized APIs** - Specify the applicable domain name for your API. You can get the applicable value using the AWS CLI command `get-domain-names <https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-domain-names.html>`_ :
            - For regional APIs, specify the value of ``regionalDomainName`` .
            - For edge-optimized APIs, specify the value of ``distributionDomainName`` . This is the name of the associated CloudFront distribution, such as ``da1b2c3d4e5.cloudfront.net`` .

            .. epigraph::

               The name of the record that you're creating must match a custom domain name for your API, such as ``api.example.com`` .

            - **Amazon Virtual Private Cloud interface VPC endpoint** - Enter the API endpoint for the interface endpoint, such as ``vpce-123456789abcdef01-example-us-east-1a.elasticloadbalancing.us-east-1.vpce.amazonaws.com`` . For edge-optimized APIs, this is the domain name for the corresponding CloudFront distribution. You can get the value of ``DnsName`` using the AWS CLI command `describe-vpc-endpoints <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html>`_ .
            - **CloudFront distribution** - Specify the domain name that CloudFront assigned when you created your distribution.

            Your CloudFront distribution must include an alternate domain name that matches the name of the record. For example, if the name of the record is *acme.example.com* , your CloudFront distribution must include *acme.example.com* as one of the alternate domain names. For more information, see `Using Alternate Domain Names (CNAMEs) <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html>`_ in the *Amazon CloudFront Developer Guide* .

            You can't create a record in a private hosted zone to route traffic to a CloudFront distribution.
            .. epigraph::

               For failover alias records, you can't specify a CloudFront distribution for both the primary and secondary records. A distribution must include an alternate domain name that matches the name of the record. However, the primary and secondary records have the same name, and you can't include the same alternate domain name in more than one distribution.

            - **Elastic Beanstalk environment** - If the domain name for your Elastic Beanstalk environment includes the region that you deployed the environment in, you can create an alias record that routes traffic to the environment. For example, the domain name ``my-environment. *us-west-2* .elasticbeanstalk.com`` is a regionalized domain name.

            .. epigraph::

               For environments that were created before early 2016, the domain name doesn't include the region. To route traffic to these environments, you must create a CNAME record instead of an alias record. Note that you can't create a CNAME record for the root domain name. For example, if your domain name is example.com, you can create a record that routes traffic for acme.example.com to your Elastic Beanstalk environment, but you can't create a record that routes traffic for example.com to your Elastic Beanstalk environment.

            For Elastic Beanstalk environments that have regionalized subdomains, specify the ``CNAME`` attribute for the environment. You can use the following methods to get the value of the CNAME attribute:

            - *AWS Management Console* : For information about how to get the value by using the console, see `Using Custom Domains with AWS Elastic Beanstalk <https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html>`_ in the *AWS Elastic Beanstalk Developer Guide* .
            - *Elastic Beanstalk API* : Use the ``DescribeEnvironments`` action to get the value of the ``CNAME`` attribute. For more information, see `DescribeEnvironments <https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeEnvironments.html>`_ in the *AWS Elastic Beanstalk API Reference* .
            - *AWS CLI* : Use the ``describe-environments`` command to get the value of the ``CNAME`` attribute. For more information, see `describe-environments <https://docs.aws.amazon.com/cli/latest/reference/elasticbeanstalk/describe-environments.html>`_ in the *AWS CLI* .
            - **ELB load balancer** - Specify the DNS name that is associated with the load balancer. Get the DNS name by using the AWS Management Console , the ELB API, or the AWS CLI .
            - *AWS Management Console* : Go to the EC2 page, choose *Load Balancers* in the navigation pane, choose the load balancer, choose the *Description* tab, and get the value of the *DNS name* field.

            If you're routing traffic to a Classic Load Balancer, get the value that begins with *dualstack* . If you're routing traffic to another type of load balancer, get the value that applies to the record type, A or AAAA.

            - *Elastic Load Balancing API* : Use ``DescribeLoadBalancers`` to get the value of ``DNSName`` . For more information, see the applicable guide:
            - Classic Load Balancers: `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancers.html>`_
            - Application and Network Load Balancers: `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_
            - *CloudFormation Fn::GetAtt intrinsic function* : Use the `Fn::GetAtt <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html>`_ intrinsic function to get the value of ``DNSName`` :
            - `Classic Load Balancers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html#aws-properties-ec2-elb-return-values>`_ .
            - `Application and Network Load Balancers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-return-values>`_ .
            - *AWS CLI* : Use ``describe-load-balancers`` to get the value of ``DNSName`` . For more information, see the applicable guide:
            - Classic Load Balancers: `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html>`_
            - Application and Network Load Balancers: `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elbv2/describe-load-balancers.html>`_
            - **Global Accelerator accelerator** - Specify the DNS name for your accelerator:
            - *Global Accelerator API* : To get the DNS name, use `DescribeAccelerator <https://docs.aws.amazon.com/global-accelerator/latest/api/API_DescribeAccelerator.html>`_ .
            - *AWS CLI* : To get the DNS name, use `describe-accelerator <https://docs.aws.amazon.com/cli/latest/reference/globalaccelerator/describe-accelerator.html>`_ .
            - **Amazon S3 bucket that is configured as a static website** - Specify the domain name of the Amazon S3 website endpoint that you created the bucket in, for example, ``s3-website.us-east-2.amazonaws.com`` . For more information about valid values, see the table `Amazon S3 Website Endpoints <https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints>`_ in the *Amazon Web Services General Reference* . For more information about using S3 buckets for websites, see `Getting Started with Amazon Route 53 <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/getting-started.html>`_ in the *Amazon Route 53 Developer Guide.*
            - **Another Route 53 record** - Specify the value of the ``Name`` element for a record in the current hosted zone.

            .. epigraph::

               If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't specify the domain name for a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record that you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html#cfn-route53-aliastarget-dnshostname
            '''
            result = self._values.get("dns_name")
            assert result is not None, "Required property 'dns_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def hosted_zone_id(self) -> builtins.str:
            '''*Alias resource records sets only* : The value used depends on where you want to route traffic:.

            - **Amazon API Gateway custom regional APIs and edge-optimized APIs** - Specify the hosted zone ID for your API. You can get the applicable value using the AWS CLI command `get-domain-names <https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-domain-names.html>`_ :
            - For regional APIs, specify the value of ``regionalHostedZoneId`` .
            - For edge-optimized APIs, specify the value of ``distributionHostedZoneId`` .
            - **Amazon Virtual Private Cloud interface VPC endpoint** - Specify the hosted zone ID for your interface endpoint. You can get the value of ``HostedZoneId`` using the AWS CLI command `describe-vpc-endpoints <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html>`_ .
            - **CloudFront distribution** - Specify ``Z2FDTNDATAQYW2`` . This is always the hosted zone ID when you create an alias record that routes traffic to a CloudFront distribution.

            .. epigraph::

               Alias records for CloudFront can't be created in a private zone.

            - **Elastic Beanstalk environment** - Specify the hosted zone ID for the region that you created the environment in. The environment must have a regionalized subdomain. For a list of regions and the corresponding hosted zone IDs, see `AWS Elastic Beanstalk endpoints and quotas <https://docs.aws.amazon.com/general/latest/gr/elasticbeanstalk.html>`_ in the *Amazon Web Services General Reference* .
            - **ELB load balancer** - Specify the value of the hosted zone ID for the load balancer. Use the following methods to get the hosted zone ID:
            - `Service Endpoints <https://docs.aws.amazon.com/general/latest/gr/elb.html>`_ table in the "Elastic Load Balancing Endpoints and Quotas" topic in the *Amazon Web Services General Reference* : Use the value that corresponds with the region that you created your load balancer in. Note that there are separate columns for Application and Classic Load Balancers and for Network Load Balancers.
            - *AWS Management Console* : Go to the Amazon EC2 page, choose *Load Balancers* in the navigation pane, select the load balancer, and get the value of the *Hosted zone* field on the *Description* tab.
            - *Elastic Load Balancing API* : Use ``DescribeLoadBalancers`` to get the applicable value. For more information, see the applicable guide:
            - Classic Load Balancers: Use `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancers.html>`_ to get the value of ``CanonicalHostedZoneNameID`` .
            - Application and Network Load Balancers: Use `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ to get the value of ``CanonicalHostedZoneID`` .
            - *CloudFormation Fn::GetAtt intrinsic function* : Use the `Fn::GetAtt <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html>`_ intrinsic function to get the applicable value:
            - Classic Load Balancers: Get `CanonicalHostedZoneNameID <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html#aws-properties-ec2-elb-return-values>`_ .
            - Application and Network Load Balancers: Get `CanonicalHostedZoneID <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-return-values>`_ .
            - *AWS CLI* : Use ``describe-load-balancers`` to get the applicable value. For more information, see the applicable guide:
            - Classic Load Balancers: Use `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html>`_ to get the value of ``CanonicalHostedZoneNameID`` .
            - Application and Network Load Balancers: Use `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elbv2/describe-load-balancers.html>`_ to get the value of ``CanonicalHostedZoneID`` .
            - **Global Accelerator accelerator** - Specify ``Z2BJ6XQ5FK7U4H`` .
            - **An Amazon S3 bucket configured as a static website** - Specify the hosted zone ID for the region that you created the bucket in. For more information about valid values, see the table `Amazon S3 Website Endpoints <https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints>`_ in the *Amazon Web Services General Reference* .
            - **Another Route 53 record in your hosted zone** - Specify the hosted zone ID of your hosted zone. (An alias record can't reference a record in a different hosted zone.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html#cfn-route53-aliastarget-hostedzoneid
            '''
            result = self._values.get("hosted_zone_id")
            assert result is not None, "Required property 'hosted_zone_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def evaluate_target_health(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''*Applies only to alias, failover alias, geolocation alias, latency alias, and weighted alias resource record sets:* When ``EvaluateTargetHealth`` is ``true`` , an alias resource record set inherits the health of the referenced AWS resource, such as an ELB load balancer or another resource record set in the hosted zone.

            Note the following:

            - **CloudFront distributions** - You can't set ``EvaluateTargetHealth`` to ``true`` when the alias target is a CloudFront distribution.
            - **Elastic Beanstalk environments that have regionalized subdomains** - If you specify an Elastic Beanstalk environment in ``DNSName`` and the environment contains an ELB load balancer, Elastic Load Balancing routes queries only to the healthy Amazon EC2 instances that are registered with the load balancer. (An environment automatically contains an ELB load balancer if it includes more than one Amazon EC2 instance.) If you set ``EvaluateTargetHealth`` to ``true`` and either no Amazon EC2 instances are healthy or the load balancer itself is unhealthy, Route 53 routes queries to other available resources that are healthy, if any.

            If the environment contains a single Amazon EC2 instance, there are no special requirements.

            - **ELB load balancers** - Health checking behavior depends on the type of load balancer:
            - *Classic Load Balancers* : If you specify an ELB Classic Load Balancer in ``DNSName`` , Elastic Load Balancing routes queries only to the healthy Amazon EC2 instances that are registered with the load balancer. If you set ``EvaluateTargetHealth`` to ``true`` and either no EC2 instances are healthy or the load balancer itself is unhealthy, Route 53 routes queries to other resources.
            - *Application and Network Load Balancers* : If you specify an ELB Application or Network Load Balancer and you set ``EvaluateTargetHealth`` to ``true`` , Route 53 routes queries to the load balancer based on the health of the target groups that are associated with the load balancer:
            - For an Application or Network Load Balancer to be considered healthy, every target group that contains targets must contain at least one healthy target. If any target group contains only unhealthy targets, the load balancer is considered unhealthy, and Route 53 routes queries to other resources.
            - A target group that has no registered targets is considered unhealthy.

            .. epigraph::

               When you create a load balancer, you configure settings for Elastic Load Balancing health checks; they're not Route 53 health checks, but they perform a similar function. Do not create Route 53 health checks for the EC2 instances that you register with an ELB load balancer.

            - **S3 buckets** - There are no special requirements for setting ``EvaluateTargetHealth`` to ``true`` when the alias target is an S3 bucket.
            - **Other records in the same hosted zone** - If the AWS resource that you specify in ``DNSName`` is a record or a group of records (for example, a group of weighted records) but is not another alias record, we recommend that you associate a health check with all of the records in the alias target. For more information, see `What Happens When You Omit Health Checks? <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-complex-configs.html#dns-failover-complex-configs-hc-omitting>`_ in the *Amazon Route 53 Developer Guide* .

            For more information and examples, see `Amazon Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html#cfn-route53-aliastarget-evaluatetargethealth
            '''
            result = self._values.get("evaluate_target_health")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AliasTargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnRecordSet.GeoLocationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "continent_code": "continentCode",
            "country_code": "countryCode",
            "subdivision_code": "subdivisionCode",
        },
    )
    class GeoLocationProperty:
        def __init__(
            self,
            *,
            continent_code: typing.Optional[builtins.str] = None,
            country_code: typing.Optional[builtins.str] = None,
            subdivision_code: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A complex type that contains information about a geographic location.

            :param continent_code: For geolocation resource record sets, a two-letter abbreviation that identifies a continent. Route 53 supports the following continent codes:. - *AF* : Africa - *AN* : Antarctica - *AS* : Asia - *EU* : Europe - *OC* : Oceania - *NA* : North America - *SA* : South America Constraint: Specifying ``ContinentCode`` with either ``CountryCode`` or ``SubdivisionCode`` returns an ``InvalidInput`` error.
            :param country_code: For geolocation resource record sets, the two-letter code for a country. Route 53 uses the two-letter country codes that are specified in `ISO standard 3166-1 alpha-2 <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>`_ .
            :param subdivision_code: For geolocation resource record sets, the two-letter code for a state of the United States. Route 53 doesn't support any other values for ``SubdivisionCode`` . For a list of state abbreviations, see `Appendix B: Two–Letter State and Possession Abbreviations <https://docs.aws.amazon.com/https://pe.usps.com/text/pub28/28apb.htm>`_ on the United States Postal Service website. If you specify ``subdivisioncode`` , you must also specify ``US`` for ``CountryCode`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                geo_location_property = route53.CfnRecordSet.GeoLocationProperty(
                    continent_code="continentCode",
                    country_code="countryCode",
                    subdivision_code="subdivisionCode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if continent_code is not None:
                self._values["continent_code"] = continent_code
            if country_code is not None:
                self._values["country_code"] = country_code
            if subdivision_code is not None:
                self._values["subdivision_code"] = subdivision_code

        @builtins.property
        def continent_code(self) -> typing.Optional[builtins.str]:
            '''For geolocation resource record sets, a two-letter abbreviation that identifies a continent. Route 53 supports the following continent codes:.

            - *AF* : Africa
            - *AN* : Antarctica
            - *AS* : Asia
            - *EU* : Europe
            - *OC* : Oceania
            - *NA* : North America
            - *SA* : South America

            Constraint: Specifying ``ContinentCode`` with either ``CountryCode`` or ``SubdivisionCode`` returns an ``InvalidInput`` error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html#cfn-route53-recordset-geolocation-continentcode
            '''
            result = self._values.get("continent_code")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def country_code(self) -> typing.Optional[builtins.str]:
            '''For geolocation resource record sets, the two-letter code for a country.

            Route 53 uses the two-letter country codes that are specified in `ISO standard 3166-1 alpha-2 <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html#cfn-route53-recordset-geolocation-countrycode
            '''
            result = self._values.get("country_code")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def subdivision_code(self) -> typing.Optional[builtins.str]:
            '''For geolocation resource record sets, the two-letter code for a state of the United States.

            Route 53 doesn't support any other values for ``SubdivisionCode`` . For a list of state abbreviations, see `Appendix B: Two–Letter State and Possession Abbreviations <https://docs.aws.amazon.com/https://pe.usps.com/text/pub28/28apb.htm>`_ on the United States Postal Service website.

            If you specify ``subdivisioncode`` , you must also specify ``US`` for ``CountryCode`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html#cfn-route53-recordset-geolocation-subdivisioncode
            '''
            result = self._values.get("subdivision_code")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GeoLocationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnRecordSetGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CfnRecordSetGroup",
):
    '''A CloudFormation ``AWS::Route53::RecordSetGroup``.

    A complex type that contains an optional comment, the name and ID of the hosted zone that you want to make changes in, and values for the records that you want to create.

    :cloudformationResource: AWS::Route53::RecordSetGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53 as route53
        
        cfn_record_set_group = route53.CfnRecordSetGroup(self, "MyCfnRecordSetGroup",
            comment="comment",
            hosted_zone_id="hostedZoneId",
            hosted_zone_name="hostedZoneName",
            record_sets=[route53.CfnRecordSetGroup.RecordSetProperty(
                name="name",
                type="type",
        
                # the properties below are optional
                alias_target=route53.CfnRecordSetGroup.AliasTargetProperty(
                    dns_name="dnsName",
                    hosted_zone_id="hostedZoneId",
        
                    # the properties below are optional
                    evaluate_target_health=False
                ),
                failover="failover",
                geo_location=route53.CfnRecordSetGroup.GeoLocationProperty(
                    continent_code="continentCode",
                    country_code="countryCode",
                    subdivision_code="subdivisionCode"
                ),
                health_check_id="healthCheckId",
                hosted_zone_id="hostedZoneId",
                hosted_zone_name="hostedZoneName",
                multi_value_answer=False,
                region="region",
                resource_records=["resourceRecords"],
                set_identifier="setIdentifier",
                ttl="ttl",
                weight=123
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        comment: typing.Optional[builtins.str] = None,
        hosted_zone_id: typing.Optional[builtins.str] = None,
        hosted_zone_name: typing.Optional[builtins.str] = None,
        record_sets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRecordSetGroup.RecordSetProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Route53::RecordSetGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param comment: *Optional:* Any comments you want to include about a change batch request.
        :param hosted_zone_id: The ID of the hosted zone that you want to create records in. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
        :param hosted_zone_name: The name of the hosted zone that you want to create records in. You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` . When you create a stack using an ``AWS::Route53::RecordSet`` that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the ``HostedZoneName`` . If AWS CloudFormation can't find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
        :param record_sets: A complex type that contains one ``RecordSet`` element for each record that you want to create.
        '''
        props = CfnRecordSetGroupProps(
            comment=comment,
            hosted_zone_id=hosted_zone_id,
            hosted_zone_name=hosted_zone_name,
            record_sets=record_sets,
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
    @jsii.member(jsii_name="comment")
    def comment(self) -> typing.Optional[builtins.str]:
        '''*Optional:* Any comments you want to include about a change batch request.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html#cfn-route53-recordsetgroup-comment
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "comment"))

    @comment.setter
    def comment(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "comment", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneId")
    def hosted_zone_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the hosted zone that you want to create records in.

        Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html#cfn-route53-recordsetgroup-hostedzoneid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "hostedZoneId"))

    @hosted_zone_id.setter
    def hosted_zone_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "hostedZoneId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneName")
    def hosted_zone_name(self) -> typing.Optional[builtins.str]:
        '''The name of the hosted zone that you want to create records in.

        You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` .

        When you create a stack using an ``AWS::Route53::RecordSet`` that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the ``HostedZoneName`` . If AWS CloudFormation can't find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack.

        Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html#cfn-route53-recordsetgroup-hostedzonename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "hostedZoneName"))

    @hosted_zone_name.setter
    def hosted_zone_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "hostedZoneName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="recordSets")
    def record_sets(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRecordSetGroup.RecordSetProperty", _IResolvable_da3f097b]]]]:
        '''A complex type that contains one ``RecordSet`` element for each record that you want to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html#cfn-route53-recordsetgroup-recordsets
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRecordSetGroup.RecordSetProperty", _IResolvable_da3f097b]]]], jsii.get(self, "recordSets"))

    @record_sets.setter
    def record_sets(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRecordSetGroup.RecordSetProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "recordSets", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnRecordSetGroup.AliasTargetProperty",
        jsii_struct_bases=[],
        name_mapping={
            "dns_name": "dnsName",
            "hosted_zone_id": "hostedZoneId",
            "evaluate_target_health": "evaluateTargetHealth",
        },
    )
    class AliasTargetProperty:
        def __init__(
            self,
            *,
            dns_name: builtins.str,
            hosted_zone_id: builtins.str,
            evaluate_target_health: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''*Alias records only:* Information about the AWS resource, such as a CloudFront distribution or an Amazon S3 bucket, that you want to route traffic to.

            When creating records for a private hosted zone, note the following:

            - Creating geolocation alias and latency alias records in a private hosted zone is allowed but not supported.
            - For information about creating failover records in a private hosted zone, see `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ .

            :param dns_name: *Alias records only:* The value that you specify depends on where you want to route queries:. - **Amazon API Gateway custom regional APIs and edge-optimized APIs** - Specify the applicable domain name for your API. You can get the applicable value using the AWS CLI command `get-domain-names <https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-domain-names.html>`_ : - For regional APIs, specify the value of ``regionalDomainName`` . - For edge-optimized APIs, specify the value of ``distributionDomainName`` . This is the name of the associated CloudFront distribution, such as ``da1b2c3d4e5.cloudfront.net`` . .. epigraph:: The name of the record that you're creating must match a custom domain name for your API, such as ``api.example.com`` . - **Amazon Virtual Private Cloud interface VPC endpoint** - Enter the API endpoint for the interface endpoint, such as ``vpce-123456789abcdef01-example-us-east-1a.elasticloadbalancing.us-east-1.vpce.amazonaws.com`` . For edge-optimized APIs, this is the domain name for the corresponding CloudFront distribution. You can get the value of ``DnsName`` using the AWS CLI command `describe-vpc-endpoints <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html>`_ . - **CloudFront distribution** - Specify the domain name that CloudFront assigned when you created your distribution. Your CloudFront distribution must include an alternate domain name that matches the name of the record. For example, if the name of the record is *acme.example.com* , your CloudFront distribution must include *acme.example.com* as one of the alternate domain names. For more information, see `Using Alternate Domain Names (CNAMEs) <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html>`_ in the *Amazon CloudFront Developer Guide* . You can't create a record in a private hosted zone to route traffic to a CloudFront distribution. .. epigraph:: For failover alias records, you can't specify a CloudFront distribution for both the primary and secondary records. A distribution must include an alternate domain name that matches the name of the record. However, the primary and secondary records have the same name, and you can't include the same alternate domain name in more than one distribution. - **Elastic Beanstalk environment** - If the domain name for your Elastic Beanstalk environment includes the region that you deployed the environment in, you can create an alias record that routes traffic to the environment. For example, the domain name ``my-environment. *us-west-2* .elasticbeanstalk.com`` is a regionalized domain name. .. epigraph:: For environments that were created before early 2016, the domain name doesn't include the region. To route traffic to these environments, you must create a CNAME record instead of an alias record. Note that you can't create a CNAME record for the root domain name. For example, if your domain name is example.com, you can create a record that routes traffic for acme.example.com to your Elastic Beanstalk environment, but you can't create a record that routes traffic for example.com to your Elastic Beanstalk environment. For Elastic Beanstalk environments that have regionalized subdomains, specify the ``CNAME`` attribute for the environment. You can use the following methods to get the value of the CNAME attribute: - *AWS Management Console* : For information about how to get the value by using the console, see `Using Custom Domains with AWS Elastic Beanstalk <https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html>`_ in the *AWS Elastic Beanstalk Developer Guide* . - *Elastic Beanstalk API* : Use the ``DescribeEnvironments`` action to get the value of the ``CNAME`` attribute. For more information, see `DescribeEnvironments <https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeEnvironments.html>`_ in the *AWS Elastic Beanstalk API Reference* . - *AWS CLI* : Use the ``describe-environments`` command to get the value of the ``CNAME`` attribute. For more information, see `describe-environments <https://docs.aws.amazon.com/cli/latest/reference/elasticbeanstalk/describe-environments.html>`_ in the *AWS CLI* . - **ELB load balancer** - Specify the DNS name that is associated with the load balancer. Get the DNS name by using the AWS Management Console , the ELB API, or the AWS CLI . - *AWS Management Console* : Go to the EC2 page, choose *Load Balancers* in the navigation pane, choose the load balancer, choose the *Description* tab, and get the value of the *DNS name* field. If you're routing traffic to a Classic Load Balancer, get the value that begins with *dualstack* . If you're routing traffic to another type of load balancer, get the value that applies to the record type, A or AAAA. - *Elastic Load Balancing API* : Use ``DescribeLoadBalancers`` to get the value of ``DNSName`` . For more information, see the applicable guide: - Classic Load Balancers: `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancers.html>`_ - Application and Network Load Balancers: `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ - *CloudFormation Fn::GetAtt intrinsic function* : Use the `Fn::GetAtt <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html>`_ intrinsic function to get the value of ``DNSName`` : - `Classic Load Balancers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html#aws-properties-ec2-elb-return-values>`_ . - `Application and Network Load Balancers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-return-values>`_ . - *AWS CLI* : Use ``describe-load-balancers`` to get the value of ``DNSName`` . For more information, see the applicable guide: - Classic Load Balancers: `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html>`_ - Application and Network Load Balancers: `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elbv2/describe-load-balancers.html>`_ - **Global Accelerator accelerator** - Specify the DNS name for your accelerator: - *Global Accelerator API* : To get the DNS name, use `DescribeAccelerator <https://docs.aws.amazon.com/global-accelerator/latest/api/API_DescribeAccelerator.html>`_ . - *AWS CLI* : To get the DNS name, use `describe-accelerator <https://docs.aws.amazon.com/cli/latest/reference/globalaccelerator/describe-accelerator.html>`_ . - **Amazon S3 bucket that is configured as a static website** - Specify the domain name of the Amazon S3 website endpoint that you created the bucket in, for example, ``s3-website.us-east-2.amazonaws.com`` . For more information about valid values, see the table `Amazon S3 Website Endpoints <https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints>`_ in the *Amazon Web Services General Reference* . For more information about using S3 buckets for websites, see `Getting Started with Amazon Route 53 <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/getting-started.html>`_ in the *Amazon Route 53 Developer Guide.* - **Another Route 53 record** - Specify the value of the ``Name`` element for a record in the current hosted zone. .. epigraph:: If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't specify the domain name for a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record that you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.
            :param hosted_zone_id: *Alias resource records sets only* : The value used depends on where you want to route traffic:. - **Amazon API Gateway custom regional APIs and edge-optimized APIs** - Specify the hosted zone ID for your API. You can get the applicable value using the AWS CLI command `get-domain-names <https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-domain-names.html>`_ : - For regional APIs, specify the value of ``regionalHostedZoneId`` . - For edge-optimized APIs, specify the value of ``distributionHostedZoneId`` . - **Amazon Virtual Private Cloud interface VPC endpoint** - Specify the hosted zone ID for your interface endpoint. You can get the value of ``HostedZoneId`` using the AWS CLI command `describe-vpc-endpoints <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html>`_ . - **CloudFront distribution** - Specify ``Z2FDTNDATAQYW2`` . This is always the hosted zone ID when you create an alias record that routes traffic to a CloudFront distribution. .. epigraph:: Alias records for CloudFront can't be created in a private zone. - **Elastic Beanstalk environment** - Specify the hosted zone ID for the region that you created the environment in. The environment must have a regionalized subdomain. For a list of regions and the corresponding hosted zone IDs, see `AWS Elastic Beanstalk endpoints and quotas <https://docs.aws.amazon.com/general/latest/gr/elasticbeanstalk.html>`_ in the *Amazon Web Services General Reference* . - **ELB load balancer** - Specify the value of the hosted zone ID for the load balancer. Use the following methods to get the hosted zone ID: - `Service Endpoints <https://docs.aws.amazon.com/general/latest/gr/elb.html>`_ table in the "Elastic Load Balancing endpoints and quotas" topic in the *Amazon Web Services General Reference* : Use the value that corresponds with the region that you created your load balancer in. Note that there are separate columns for Application and Classic Load Balancers and for Network Load Balancers. - *AWS Management Console* : Go to the Amazon EC2 page, choose *Load Balancers* in the navigation pane, select the load balancer, and get the value of the *Hosted zone* field on the *Description* tab. - *Elastic Load Balancing API* : Use ``DescribeLoadBalancers`` to get the applicable value. For more information, see the applicable guide: - Classic Load Balancers: Use `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancers.html>`_ to get the value of ``CanonicalHostedZoneNameID`` . - Application and Network Load Balancers: Use `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ to get the value of ``CanonicalHostedZoneID`` . - *CloudFormation Fn::GetAtt intrinsic function* : Use the `Fn::GetAtt <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html>`_ intrinsic function to get the applicable value: - Classic Load Balancers: Get `CanonicalHostedZoneNameID <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html#aws-properties-ec2-elb-return-values>`_ . - Application and Network Load Balancers: Get `CanonicalHostedZoneID <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-return-values>`_ . - *AWS CLI* : Use ``describe-load-balancers`` to get the applicable value. For more information, see the applicable guide: - Classic Load Balancers: Use `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html>`_ to get the value of ``CanonicalHostedZoneNameID`` . - Application and Network Load Balancers: Use `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elbv2/describe-load-balancers.html>`_ to get the value of ``CanonicalHostedZoneID`` . - **Global Accelerator accelerator** - Specify ``Z2BJ6XQ5FK7U4H`` . - **An Amazon S3 bucket configured as a static website** - Specify the hosted zone ID for the region that you created the bucket in. For more information about valid values, see the table `Amazon S3 Website Endpoints <https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints>`_ in the *Amazon Web Services General Reference* . - **Another Route 53 record in your hosted zone** - Specify the hosted zone ID of your hosted zone. (An alias record can't reference a record in a different hosted zone.)
            :param evaluate_target_health: *Applies only to alias records with any routing policy:* When ``EvaluateTargetHealth`` is ``true`` , an alias record inherits the health of the referenced AWS resource, such as an ELB load balancer or another record in the hosted zone. Note the following: - **CloudFront distributions** - You can't set ``EvaluateTargetHealth`` to ``true`` when the alias target is a CloudFront distribution. - **Elastic Beanstalk environments that have regionalized subdomains** - If you specify an Elastic Beanstalk environment in ``DNSName`` and the environment contains an ELB load balancer, Elastic Load Balancing routes queries only to the healthy Amazon EC2 instances that are registered with the load balancer. (An environment automatically contains an ELB load balancer if it includes more than one Amazon EC2 instance.) If you set ``EvaluateTargetHealth`` to ``true`` and either no Amazon EC2 instances are healthy or the load balancer itself is unhealthy, Route 53 routes queries to other available resources that are healthy, if any. If the environment contains a single Amazon EC2 instance, there are no special requirements. - **ELB load balancers** - Health checking behavior depends on the type of load balancer: - *Classic Load Balancers* : If you specify an ELB Classic Load Balancer in ``DNSName`` , Elastic Load Balancing routes queries only to the healthy Amazon EC2 instances that are registered with the load balancer. If you set ``EvaluateTargetHealth`` to ``true`` and either no EC2 instances are healthy or the load balancer itself is unhealthy, Route 53 routes queries to other resources. - *Application and Network Load Balancers* : If you specify an ELB Application or Network Load Balancer and you set ``EvaluateTargetHealth`` to ``true`` , Route 53 routes queries to the load balancer based on the health of the target groups that are associated with the load balancer: - For an Application or Network Load Balancer to be considered healthy, every target group that contains targets must contain at least one healthy target. If any target group contains only unhealthy targets, the load balancer is considered unhealthy, and Route 53 routes queries to other resources. - A target group that has no registered targets is considered unhealthy. .. epigraph:: When you create a load balancer, you configure settings for Elastic Load Balancing health checks; they're not Route 53 health checks, but they perform a similar function. Do not create Route 53 health checks for the EC2 instances that you register with an ELB load balancer. - **S3 buckets** - There are no special requirements for setting ``EvaluateTargetHealth`` to ``true`` when the alias target is an S3 bucket. - **Other records in the same hosted zone** - If the AWS resource that you specify in ``DNSName`` is a record or a group of records (for example, a group of weighted records) but is not another alias record, we recommend that you associate a health check with all of the records in the alias target. For more information, see `What Happens When You Omit Health Checks? <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-complex-configs.html#dns-failover-complex-configs-hc-omitting>`_ in the *Amazon Route 53 Developer Guide* . For more information and examples, see `Amazon Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                alias_target_property = route53.CfnRecordSetGroup.AliasTargetProperty(
                    dns_name="dnsName",
                    hosted_zone_id="hostedZoneId",
                
                    # the properties below are optional
                    evaluate_target_health=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dns_name": dns_name,
                "hosted_zone_id": hosted_zone_id,
            }
            if evaluate_target_health is not None:
                self._values["evaluate_target_health"] = evaluate_target_health

        @builtins.property
        def dns_name(self) -> builtins.str:
            '''*Alias records only:* The value that you specify depends on where you want to route queries:.

            - **Amazon API Gateway custom regional APIs and edge-optimized APIs** - Specify the applicable domain name for your API. You can get the applicable value using the AWS CLI command `get-domain-names <https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-domain-names.html>`_ :
            - For regional APIs, specify the value of ``regionalDomainName`` .
            - For edge-optimized APIs, specify the value of ``distributionDomainName`` . This is the name of the associated CloudFront distribution, such as ``da1b2c3d4e5.cloudfront.net`` .

            .. epigraph::

               The name of the record that you're creating must match a custom domain name for your API, such as ``api.example.com`` .

            - **Amazon Virtual Private Cloud interface VPC endpoint** - Enter the API endpoint for the interface endpoint, such as ``vpce-123456789abcdef01-example-us-east-1a.elasticloadbalancing.us-east-1.vpce.amazonaws.com`` . For edge-optimized APIs, this is the domain name for the corresponding CloudFront distribution. You can get the value of ``DnsName`` using the AWS CLI command `describe-vpc-endpoints <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html>`_ .
            - **CloudFront distribution** - Specify the domain name that CloudFront assigned when you created your distribution.

            Your CloudFront distribution must include an alternate domain name that matches the name of the record. For example, if the name of the record is *acme.example.com* , your CloudFront distribution must include *acme.example.com* as one of the alternate domain names. For more information, see `Using Alternate Domain Names (CNAMEs) <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html>`_ in the *Amazon CloudFront Developer Guide* .

            You can't create a record in a private hosted zone to route traffic to a CloudFront distribution.
            .. epigraph::

               For failover alias records, you can't specify a CloudFront distribution for both the primary and secondary records. A distribution must include an alternate domain name that matches the name of the record. However, the primary and secondary records have the same name, and you can't include the same alternate domain name in more than one distribution.

            - **Elastic Beanstalk environment** - If the domain name for your Elastic Beanstalk environment includes the region that you deployed the environment in, you can create an alias record that routes traffic to the environment. For example, the domain name ``my-environment. *us-west-2* .elasticbeanstalk.com`` is a regionalized domain name.

            .. epigraph::

               For environments that were created before early 2016, the domain name doesn't include the region. To route traffic to these environments, you must create a CNAME record instead of an alias record. Note that you can't create a CNAME record for the root domain name. For example, if your domain name is example.com, you can create a record that routes traffic for acme.example.com to your Elastic Beanstalk environment, but you can't create a record that routes traffic for example.com to your Elastic Beanstalk environment.

            For Elastic Beanstalk environments that have regionalized subdomains, specify the ``CNAME`` attribute for the environment. You can use the following methods to get the value of the CNAME attribute:

            - *AWS Management Console* : For information about how to get the value by using the console, see `Using Custom Domains with AWS Elastic Beanstalk <https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html>`_ in the *AWS Elastic Beanstalk Developer Guide* .
            - *Elastic Beanstalk API* : Use the ``DescribeEnvironments`` action to get the value of the ``CNAME`` attribute. For more information, see `DescribeEnvironments <https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeEnvironments.html>`_ in the *AWS Elastic Beanstalk API Reference* .
            - *AWS CLI* : Use the ``describe-environments`` command to get the value of the ``CNAME`` attribute. For more information, see `describe-environments <https://docs.aws.amazon.com/cli/latest/reference/elasticbeanstalk/describe-environments.html>`_ in the *AWS CLI* .
            - **ELB load balancer** - Specify the DNS name that is associated with the load balancer. Get the DNS name by using the AWS Management Console , the ELB API, or the AWS CLI .
            - *AWS Management Console* : Go to the EC2 page, choose *Load Balancers* in the navigation pane, choose the load balancer, choose the *Description* tab, and get the value of the *DNS name* field.

            If you're routing traffic to a Classic Load Balancer, get the value that begins with *dualstack* . If you're routing traffic to another type of load balancer, get the value that applies to the record type, A or AAAA.

            - *Elastic Load Balancing API* : Use ``DescribeLoadBalancers`` to get the value of ``DNSName`` . For more information, see the applicable guide:
            - Classic Load Balancers: `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancers.html>`_
            - Application and Network Load Balancers: `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_
            - *CloudFormation Fn::GetAtt intrinsic function* : Use the `Fn::GetAtt <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html>`_ intrinsic function to get the value of ``DNSName`` :
            - `Classic Load Balancers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html#aws-properties-ec2-elb-return-values>`_ .
            - `Application and Network Load Balancers <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-return-values>`_ .
            - *AWS CLI* : Use ``describe-load-balancers`` to get the value of ``DNSName`` . For more information, see the applicable guide:
            - Classic Load Balancers: `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html>`_
            - Application and Network Load Balancers: `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elbv2/describe-load-balancers.html>`_
            - **Global Accelerator accelerator** - Specify the DNS name for your accelerator:
            - *Global Accelerator API* : To get the DNS name, use `DescribeAccelerator <https://docs.aws.amazon.com/global-accelerator/latest/api/API_DescribeAccelerator.html>`_ .
            - *AWS CLI* : To get the DNS name, use `describe-accelerator <https://docs.aws.amazon.com/cli/latest/reference/globalaccelerator/describe-accelerator.html>`_ .
            - **Amazon S3 bucket that is configured as a static website** - Specify the domain name of the Amazon S3 website endpoint that you created the bucket in, for example, ``s3-website.us-east-2.amazonaws.com`` . For more information about valid values, see the table `Amazon S3 Website Endpoints <https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints>`_ in the *Amazon Web Services General Reference* . For more information about using S3 buckets for websites, see `Getting Started with Amazon Route 53 <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/getting-started.html>`_ in the *Amazon Route 53 Developer Guide.*
            - **Another Route 53 record** - Specify the value of the ``Name`` element for a record in the current hosted zone.

            .. epigraph::

               If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't specify the domain name for a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record that you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html#cfn-route53-aliastarget-dnshostname
            '''
            result = self._values.get("dns_name")
            assert result is not None, "Required property 'dns_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def hosted_zone_id(self) -> builtins.str:
            '''*Alias resource records sets only* : The value used depends on where you want to route traffic:.

            - **Amazon API Gateway custom regional APIs and edge-optimized APIs** - Specify the hosted zone ID for your API. You can get the applicable value using the AWS CLI command `get-domain-names <https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-domain-names.html>`_ :
            - For regional APIs, specify the value of ``regionalHostedZoneId`` .
            - For edge-optimized APIs, specify the value of ``distributionHostedZoneId`` .
            - **Amazon Virtual Private Cloud interface VPC endpoint** - Specify the hosted zone ID for your interface endpoint. You can get the value of ``HostedZoneId`` using the AWS CLI command `describe-vpc-endpoints <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-vpc-endpoints.html>`_ .
            - **CloudFront distribution** - Specify ``Z2FDTNDATAQYW2`` . This is always the hosted zone ID when you create an alias record that routes traffic to a CloudFront distribution.

            .. epigraph::

               Alias records for CloudFront can't be created in a private zone.

            - **Elastic Beanstalk environment** - Specify the hosted zone ID for the region that you created the environment in. The environment must have a regionalized subdomain. For a list of regions and the corresponding hosted zone IDs, see `AWS Elastic Beanstalk endpoints and quotas <https://docs.aws.amazon.com/general/latest/gr/elasticbeanstalk.html>`_ in the *Amazon Web Services General Reference* .
            - **ELB load balancer** - Specify the value of the hosted zone ID for the load balancer. Use the following methods to get the hosted zone ID:
            - `Service Endpoints <https://docs.aws.amazon.com/general/latest/gr/elb.html>`_ table in the "Elastic Load Balancing endpoints and quotas" topic in the *Amazon Web Services General Reference* : Use the value that corresponds with the region that you created your load balancer in. Note that there are separate columns for Application and Classic Load Balancers and for Network Load Balancers.
            - *AWS Management Console* : Go to the Amazon EC2 page, choose *Load Balancers* in the navigation pane, select the load balancer, and get the value of the *Hosted zone* field on the *Description* tab.
            - *Elastic Load Balancing API* : Use ``DescribeLoadBalancers`` to get the applicable value. For more information, see the applicable guide:
            - Classic Load Balancers: Use `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/2012-06-01/APIReference/API_DescribeLoadBalancers.html>`_ to get the value of ``CanonicalHostedZoneNameID`` .
            - Application and Network Load Balancers: Use `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ to get the value of ``CanonicalHostedZoneID`` .
            - *CloudFormation Fn::GetAtt intrinsic function* : Use the `Fn::GetAtt <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html>`_ intrinsic function to get the applicable value:
            - Classic Load Balancers: Get `CanonicalHostedZoneNameID <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html#aws-properties-ec2-elb-return-values>`_ .
            - Application and Network Load Balancers: Get `CanonicalHostedZoneID <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#aws-resource-elasticloadbalancingv2-loadbalancer-return-values>`_ .
            - *AWS CLI* : Use ``describe-load-balancers`` to get the applicable value. For more information, see the applicable guide:
            - Classic Load Balancers: Use `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elb/describe-load-balancers.html>`_ to get the value of ``CanonicalHostedZoneNameID`` .
            - Application and Network Load Balancers: Use `describe-load-balancers <https://docs.aws.amazon.com/cli/latest/reference/elbv2/describe-load-balancers.html>`_ to get the value of ``CanonicalHostedZoneID`` .
            - **Global Accelerator accelerator** - Specify ``Z2BJ6XQ5FK7U4H`` .
            - **An Amazon S3 bucket configured as a static website** - Specify the hosted zone ID for the region that you created the bucket in. For more information about valid values, see the table `Amazon S3 Website Endpoints <https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints>`_ in the *Amazon Web Services General Reference* .
            - **Another Route 53 record in your hosted zone** - Specify the hosted zone ID of your hosted zone. (An alias record can't reference a record in a different hosted zone.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html#cfn-route53-aliastarget-hostedzoneid
            '''
            result = self._values.get("hosted_zone_id")
            assert result is not None, "Required property 'hosted_zone_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def evaluate_target_health(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''*Applies only to alias records with any routing policy:* When ``EvaluateTargetHealth`` is ``true`` , an alias record inherits the health of the referenced AWS resource, such as an ELB load balancer or another record in the hosted zone.

            Note the following:

            - **CloudFront distributions** - You can't set ``EvaluateTargetHealth`` to ``true`` when the alias target is a CloudFront distribution.
            - **Elastic Beanstalk environments that have regionalized subdomains** - If you specify an Elastic Beanstalk environment in ``DNSName`` and the environment contains an ELB load balancer, Elastic Load Balancing routes queries only to the healthy Amazon EC2 instances that are registered with the load balancer. (An environment automatically contains an ELB load balancer if it includes more than one Amazon EC2 instance.) If you set ``EvaluateTargetHealth`` to ``true`` and either no Amazon EC2 instances are healthy or the load balancer itself is unhealthy, Route 53 routes queries to other available resources that are healthy, if any.

            If the environment contains a single Amazon EC2 instance, there are no special requirements.

            - **ELB load balancers** - Health checking behavior depends on the type of load balancer:
            - *Classic Load Balancers* : If you specify an ELB Classic Load Balancer in ``DNSName`` , Elastic Load Balancing routes queries only to the healthy Amazon EC2 instances that are registered with the load balancer. If you set ``EvaluateTargetHealth`` to ``true`` and either no EC2 instances are healthy or the load balancer itself is unhealthy, Route 53 routes queries to other resources.
            - *Application and Network Load Balancers* : If you specify an ELB Application or Network Load Balancer and you set ``EvaluateTargetHealth`` to ``true`` , Route 53 routes queries to the load balancer based on the health of the target groups that are associated with the load balancer:
            - For an Application or Network Load Balancer to be considered healthy, every target group that contains targets must contain at least one healthy target. If any target group contains only unhealthy targets, the load balancer is considered unhealthy, and Route 53 routes queries to other resources.
            - A target group that has no registered targets is considered unhealthy.

            .. epigraph::

               When you create a load balancer, you configure settings for Elastic Load Balancing health checks; they're not Route 53 health checks, but they perform a similar function. Do not create Route 53 health checks for the EC2 instances that you register with an ELB load balancer.

            - **S3 buckets** - There are no special requirements for setting ``EvaluateTargetHealth`` to ``true`` when the alias target is an S3 bucket.
            - **Other records in the same hosted zone** - If the AWS resource that you specify in ``DNSName`` is a record or a group of records (for example, a group of weighted records) but is not another alias record, we recommend that you associate a health check with all of the records in the alias target. For more information, see `What Happens When You Omit Health Checks? <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-complex-configs.html#dns-failover-complex-configs-hc-omitting>`_ in the *Amazon Route 53 Developer Guide* .

            For more information and examples, see `Amazon Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-aliastarget.html#cfn-route53-aliastarget-evaluatetargethealth
            '''
            result = self._values.get("evaluate_target_health")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AliasTargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnRecordSetGroup.GeoLocationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "continent_code": "continentCode",
            "country_code": "countryCode",
            "subdivision_code": "subdivisionCode",
        },
    )
    class GeoLocationProperty:
        def __init__(
            self,
            *,
            continent_code: typing.Optional[builtins.str] = None,
            country_code: typing.Optional[builtins.str] = None,
            subdivision_code: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A complex type that contains information about a geographic location.

            :param continent_code: For geolocation resource record sets, a two-letter abbreviation that identifies a continent. Route 53 supports the following continent codes:. - *AF* : Africa - *AN* : Antarctica - *AS* : Asia - *EU* : Europe - *OC* : Oceania - *NA* : North America - *SA* : South America Constraint: Specifying ``ContinentCode`` with either ``CountryCode`` or ``SubdivisionCode`` returns an ``InvalidInput`` error.
            :param country_code: For geolocation resource record sets, the two-letter code for a country. Route 53 uses the two-letter country codes that are specified in `ISO standard 3166-1 alpha-2 <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>`_ .
            :param subdivision_code: For geolocation resource record sets, the two-letter code for a state of the United States. Route 53 doesn't support any other values for ``SubdivisionCode`` . For a list of state abbreviations, see `Appendix B: Two–Letter State and Possession Abbreviations <https://docs.aws.amazon.com/https://pe.usps.com/text/pub28/28apb.htm>`_ on the United States Postal Service website. If you specify ``subdivisioncode`` , you must also specify ``US`` for ``CountryCode`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                geo_location_property = route53.CfnRecordSetGroup.GeoLocationProperty(
                    continent_code="continentCode",
                    country_code="countryCode",
                    subdivision_code="subdivisionCode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if continent_code is not None:
                self._values["continent_code"] = continent_code
            if country_code is not None:
                self._values["country_code"] = country_code
            if subdivision_code is not None:
                self._values["subdivision_code"] = subdivision_code

        @builtins.property
        def continent_code(self) -> typing.Optional[builtins.str]:
            '''For geolocation resource record sets, a two-letter abbreviation that identifies a continent. Route 53 supports the following continent codes:.

            - *AF* : Africa
            - *AN* : Antarctica
            - *AS* : Asia
            - *EU* : Europe
            - *OC* : Oceania
            - *NA* : North America
            - *SA* : South America

            Constraint: Specifying ``ContinentCode`` with either ``CountryCode`` or ``SubdivisionCode`` returns an ``InvalidInput`` error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html#cfn-route53-recordsetgroup-geolocation-continentcode
            '''
            result = self._values.get("continent_code")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def country_code(self) -> typing.Optional[builtins.str]:
            '''For geolocation resource record sets, the two-letter code for a country.

            Route 53 uses the two-letter country codes that are specified in `ISO standard 3166-1 alpha-2 <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html#cfn-route53-recordset-geolocation-countrycode
            '''
            result = self._values.get("country_code")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def subdivision_code(self) -> typing.Optional[builtins.str]:
            '''For geolocation resource record sets, the two-letter code for a state of the United States.

            Route 53 doesn't support any other values for ``SubdivisionCode`` . For a list of state abbreviations, see `Appendix B: Two–Letter State and Possession Abbreviations <https://docs.aws.amazon.com/https://pe.usps.com/text/pub28/28apb.htm>`_ on the United States Postal Service website.

            If you specify ``subdivisioncode`` , you must also specify ``US`` for ``CountryCode`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html#cfn-route53-recordset-geolocation-subdivisioncode
            '''
            result = self._values.get("subdivision_code")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GeoLocationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_route53.CfnRecordSetGroup.RecordSetProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "type": "type",
            "alias_target": "aliasTarget",
            "failover": "failover",
            "geo_location": "geoLocation",
            "health_check_id": "healthCheckId",
            "hosted_zone_id": "hostedZoneId",
            "hosted_zone_name": "hostedZoneName",
            "multi_value_answer": "multiValueAnswer",
            "region": "region",
            "resource_records": "resourceRecords",
            "set_identifier": "setIdentifier",
            "ttl": "ttl",
            "weight": "weight",
        },
    )
    class RecordSetProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            type: builtins.str,
            alias_target: typing.Optional[typing.Union["CfnRecordSetGroup.AliasTargetProperty", _IResolvable_da3f097b]] = None,
            failover: typing.Optional[builtins.str] = None,
            geo_location: typing.Optional[typing.Union["CfnRecordSetGroup.GeoLocationProperty", _IResolvable_da3f097b]] = None,
            health_check_id: typing.Optional[builtins.str] = None,
            hosted_zone_id: typing.Optional[builtins.str] = None,
            hosted_zone_name: typing.Optional[builtins.str] = None,
            multi_value_answer: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            region: typing.Optional[builtins.str] = None,
            resource_records: typing.Optional[typing.Sequence[builtins.str]] = None,
            set_identifier: typing.Optional[builtins.str] = None,
            ttl: typing.Optional[builtins.str] = None,
            weight: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Information about one record that you want to create.

            :param name: For ``ChangeResourceRecordSets`` requests, the name of the record that you want to create, update, or delete. For ``ListResourceRecordSets`` responses, the name of a record in the specified hosted zone. *ChangeResourceRecordSets Only* Enter a fully qualified domain name, for example, ``www.example.com`` . You can optionally include a trailing dot. If you omit the trailing dot, Amazon Route 53 assumes that the domain name that you specify is fully qualified. This means that Route 53 treats ``www.example.com`` (without a trailing dot) and ``www.example.com.`` (with a trailing dot) as identical. For information about how to specify characters other than ``a-z`` , ``0-9`` , and ``-`` (hyphen) and how to specify internationalized domain names, see `DNS Domain Name Format <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html>`_ in the *Amazon Route 53 Developer Guide* . You can use the asterisk (*) wildcard to replace the leftmost label in a domain name, for example, ``*.example.com`` . Note the following: - The * must replace the entire label. For example, you can't specify ``*prod.example.com`` or ``prod*.example.com`` . - The * can't replace any of the middle labels, for example, marketing.*.example.com. - If you include * in any position other than the leftmost label in a domain name, DNS treats it as an * character (ASCII 42), not as a wildcard. .. epigraph:: You can't use the * wildcard for resource records sets that have a type of NS. You can use the * wildcard as the leftmost label in a domain name, for example, ``*.example.com`` . You can't use an * for one of the middle labels, for example, ``marketing.*.example.com`` . In addition, the * must replace the entire label; for example, you can't specify ``prod*.example.com`` .
            :param type: The DNS record type. For information about different record types and how data is encoded for them, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* . Valid values for basic resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``DS`` | ``MX`` | ``NAPTR`` | ``NS`` | ``PTR`` | ``SOA`` | ``SPF`` | ``SRV`` | ``TXT`` Values for weighted, latency, geolocation, and failover resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` . When creating a group of weighted, latency, geolocation, or failover resource record sets, specify the same value for all of the resource record sets in the group. Valid values for multivalue answer resource record sets: ``A`` | ``AAAA`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` .. epigraph:: SPF records were formerly used to verify the identity of the sender of email messages. However, we no longer recommend that you create resource record sets for which the value of ``Type`` is ``SPF`` . RFC 7208, *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1* , has been updated to say, "...[I]ts existence and mechanism defined in [RFC4408] have led to some interoperability issues. Accordingly, its use is no longer appropriate for SPF version 1; implementations are not to use it." In RFC 7208, see section 14.1, `The SPF DNS Record Type <https://docs.aws.amazon.com/http://tools.ietf.org/html/rfc7208#section-14.1>`_ . Values for alias resource record sets: - *Amazon API Gateway custom regional APIs and edge-optimized APIs:* ``A`` - *CloudFront distributions:* ``A`` If IPv6 is enabled for the distribution, create two resource record sets to route traffic to your distribution, one with a value of ``A`` and one with a value of ``AAAA`` . - *Amazon API Gateway environment that has a regionalized subdomain* : ``A`` - *ELB load balancers:* ``A`` | ``AAAA`` - *Amazon S3 buckets:* ``A`` - *Amazon Virtual Private Cloud interface VPC endpoints* ``A`` - *Another resource record set in this hosted zone:* Specify the type of the resource record set that you're creating the alias for. All values are supported except ``NS`` and ``SOA`` . .. epigraph:: If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't route traffic to a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.
            :param alias_target: *Alias resource record sets only:* Information about the AWS resource, such as a CloudFront distribution or an Amazon S3 bucket, that you want to route traffic to. If you're creating resource records sets for a private hosted zone, note the following: - You can't create an alias resource record set in a private hosted zone to route traffic to a CloudFront distribution. - Creating geolocation alias resource record sets or latency alias resource record sets in a private hosted zone is unsupported. - For information about creating failover resource record sets in a private hosted zone, see `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ in the *Amazon Route 53 Developer Guide* .
            :param failover: *Failover resource record sets only:* To configure failover, you add the ``Failover`` element to two resource record sets. For one resource record set, you specify ``PRIMARY`` as the value for ``Failover`` ; for the other resource record set, you specify ``SECONDARY`` . In addition, you include the ``HealthCheckId`` element and specify the health check that you want Amazon Route 53 to perform for each resource record set. Except where noted, the following failover behaviors assume that you have included the ``HealthCheckId`` element in both resource record sets: - When the primary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the secondary resource record set. - When the primary resource record set is unhealthy and the secondary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the secondary resource record set. - When the secondary resource record set is unhealthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the primary resource record set. - If you omit the ``HealthCheckId`` element for the secondary resource record set, and if the primary resource record set is unhealthy, Route 53 always responds to DNS queries with the applicable value from the secondary resource record set. This is true regardless of the health of the associated endpoint. You can't create non-failover resource record sets that have the same values for the ``Name`` and ``Type`` elements as failover resource record sets. For failover alias resource record sets, you must also include the ``EvaluateTargetHealth`` element and set the value to true. For more information about configuring failover for Route 53, see the following topics in the *Amazon Route 53 Developer Guide* : - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_
            :param geo_location: *Geolocation resource record sets only:* A complex type that lets you control how Amazon Route 53 responds to DNS queries based on the geographic origin of the query. For example, if you want all queries from Africa to be routed to a web server with an IP address of ``192.0.2.111`` , create a resource record set with a ``Type`` of ``A`` and a ``ContinentCode`` of ``AF`` . .. epigraph:: Although creating geolocation and geolocation alias resource record sets in a private hosted zone is allowed, it's not supported. If you create separate resource record sets for overlapping geographic regions (for example, one resource record set for a continent and one for a country on the same continent), priority goes to the smallest geographic region. This allows you to route most queries for a continent to one resource and to route queries for a country on that continent to a different resource. You can't create two geolocation resource record sets that specify the same geographic location. The value ``*`` in the ``CountryCode`` element matches all geographic locations that aren't specified in other geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements. .. epigraph:: Geolocation works by mapping IP addresses to locations. However, some IP addresses aren't mapped to geographic locations, so even if you create geolocation resource record sets that cover all seven continents, Route 53 will receive some DNS queries from locations that it can't identify. We recommend that you create a resource record set for which the value of ``CountryCode`` is ``*`` . Two groups of queries are routed to the resource that you specify in this record: queries that come from locations for which you haven't created geolocation resource record sets and queries from IP addresses that aren't mapped to a location. If you don't create a ``*`` resource record set, Route 53 returns a "no answer" response for queries from those locations. You can't create non-geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as geolocation resource record sets.
            :param health_check_id: If you want Amazon Route 53 to return this resource record set in response to a DNS query only when the status of a health check is healthy, include the ``HealthCheckId`` element and specify the ID of the applicable health check. Route 53 determines whether a resource record set is healthy based on one of the following: - By periodically sending a request to the endpoint that is specified in the health check - By aggregating the status of a specified group of health checks (calculated health checks) - By determining the current state of a CloudWatch alarm (CloudWatch metric health checks) .. epigraph:: Route 53 doesn't check the health of the endpoint that is specified in the resource record set, for example, the endpoint specified by the IP address in the ``Value`` element. When you add a ``HealthCheckId`` element to a resource record set, Route 53 checks the health of the endpoint that you specified in the health check. For more information, see the following topics in the *Amazon Route 53 Developer Guide* : - `How Amazon Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_ - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ *When to Specify HealthCheckId* Specifying a value for ``HealthCheckId`` is useful only when Route 53 is choosing between two or more resource record sets to respond to a DNS query, and you want Route 53 to base the choice in part on the status of a health check. Configuring health checks makes sense only in the following configurations: - *Non-alias resource record sets* : You're checking the health of a group of non-alias resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A) and you specify health check IDs for all the resource record sets. If the health check status for a resource record set is healthy, Route 53 includes the record among the records that it responds to DNS queries with. If the health check status for a resource record set is unhealthy, Route 53 stops responding to DNS queries using the value for that resource record set. If the health check status for all resource record sets in the group is unhealthy, Route 53 considers all resource record sets in the group healthy and responds to DNS queries accordingly. - *Alias resource record sets* : You specify the following settings: - You set ``EvaluateTargetHealth`` to true for an alias resource record set in a group of resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A). - You configure the alias resource record set to route traffic to a non-alias resource record set in the same hosted zone. - You specify a health check ID for the non-alias resource record set. If the health check status is healthy, Route 53 considers the alias resource record set to be healthy and includes the alias record among the records that it responds to DNS queries with. If the health check status is unhealthy, Route 53 stops responding to DNS queries using the alias resource record set. .. epigraph:: The alias resource record set can also route traffic to a *group* of non-alias resource record sets that have the same routing policy, name, and type. In that configuration, associate health checks with all of the resource record sets in the group of non-alias resource record sets. *Geolocation Routing* For geolocation resource record sets, if an endpoint is unhealthy, Route 53 looks for a resource record set for the larger, associated geographic region. For example, suppose you have resource record sets for a state in the United States, for the entire United States, for North America, and a resource record set that has ``*`` for ``CountryCode`` is ``*`` , which applies to all locations. If the endpoint for the state resource record set is unhealthy, Route 53 checks for healthy resource record sets in the following order until it finds a resource record set for which the endpoint is healthy: - The United States - North America - The default resource record set *Specifying the Health Check Endpoint by Domain Name* If your health checks specify the endpoint only by domain name, we recommend that you create a separate health check for each endpoint. For example, create a health check for each ``HTTP`` server that is serving content for ``www.example.com`` . For the value of ``FullyQualifiedDomainName`` , specify the domain name of the server (such as ``us-east-2-www.example.com`` ), not the name of the resource record sets ( ``www.example.com`` ). .. epigraph:: Health check results will be unpredictable if you do the following: - Create a health check that has the same value for ``FullyQualifiedDomainName`` as the name of a resource record set. - Associate that health check with the resource record set.
            :param hosted_zone_id: The ID of the hosted zone that you want to create records in. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
            :param hosted_zone_name: The name of the hosted zone that you want to create records in. You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` . When you create a stack using an ``AWS::Route53::RecordSet`` that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the ``HostedZoneName`` . If AWS CloudFormation can't find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
            :param multi_value_answer: *Multivalue answer resource record sets only* : To route traffic approximately randomly to multiple resources, such as web servers, create one multivalue answer record for each resource and specify ``true`` for ``MultiValueAnswer`` . Note the following: - If you associate a health check with a multivalue answer resource record set, Amazon Route 53 responds to DNS queries with the corresponding IP address only when the health check is healthy. - If you don't associate a health check with a multivalue answer record, Route 53 always considers the record to be healthy. - Route 53 responds to DNS queries with up to eight healthy records; if you have eight or fewer healthy records, Route 53 responds to all DNS queries with all the healthy records. - If you have more than eight healthy records, Route 53 responds to different DNS resolvers with different combinations of healthy records. - When all records are unhealthy, Route 53 responds to DNS queries with up to eight unhealthy records. - If a resource becomes unavailable after a resolver caches a response, client software typically tries another of the IP addresses in the response. You can't create multivalue answer alias records.
            :param region: *Latency-based resource record sets only:* The Amazon EC2 Region where you created the resource that this resource record set refers to. The resource typically is an AWS resource, such as an EC2 instance or an ELB load balancer, and is referred to by an IP address or a DNS domain name, depending on the record type. .. epigraph:: Although creating latency and latency alias resource record sets in a private hosted zone is allowed, it's not supported. When Amazon Route 53 receives a DNS query for a domain name and type for which you have created latency resource record sets, Route 53 selects the latency resource record set that has the lowest latency between the end user and the associated Amazon EC2 Region. Route 53 then returns the value that is associated with the selected resource record set. Note the following: - You can only specify one ``ResourceRecord`` per latency resource record set. - You can only create one latency resource record set for each Amazon EC2 Region. - You aren't required to create latency resource record sets for all Amazon EC2 Regions. Route 53 will choose the region with the best latency from among the regions that you create latency resource record sets for. - You can't create non-latency resource record sets that have the same values for the ``Name`` and ``Type`` elements as latency resource record sets.
            :param resource_records: Information about the records that you want to create. Each record should be in the format appropriate for the record type specified by the ``Type`` property. For information about different record types and their record formats, see `Values That You Specify When You Create or Edit Amazon Route 53 Records <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values.html>`_ in the *Amazon Route 53 Developer Guide* .
            :param set_identifier: *Resource record sets that have a routing policy other than simple:* An identifier that differentiates among multiple resource record sets that have the same combination of name and type, such as multiple weighted resource record sets named acme.example.com that have a type of A. In a group of resource record sets that have the same name and type, the value of ``SetIdentifier`` must be unique for each resource record set. For information about routing policies, see `Choosing a Routing Policy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html>`_ in the *Amazon Route 53 Developer Guide* .
            :param ttl: The resource record cache time to live (TTL), in seconds. Note the following:. - If you're creating or updating an alias resource record set, omit ``TTL`` . Amazon Route 53 uses the value of ``TTL`` for the alias target. - If you're associating this resource record set with a health check (if you're adding a ``HealthCheckId`` element), we recommend that you specify a ``TTL`` of 60 seconds or less so clients respond quickly to changes in health status. - All of the resource record sets in a group of weighted resource record sets must have the same value for ``TTL`` . - If a group of weighted resource record sets includes one or more weighted alias resource record sets for which the alias target is an ELB load balancer, we recommend that you specify a ``TTL`` of 60 seconds for all of the non-alias weighted resource record sets that have the same name and type. Values other than 60 seconds (the TTL for load balancers) will change the effect of the values that you specify for ``Weight`` .
            :param weight: *Weighted resource record sets only:* Among resource record sets that have the same combination of DNS name and type, a value that determines the proportion of DNS queries that Amazon Route 53 responds to using the current resource record set. Route 53 calculates the sum of the weights for the resource record sets that have the same combination of DNS name and type. Route 53 then responds to queries based on the ratio of a resource's weight to the total. Note the following: - You must specify a value for the ``Weight`` element for every weighted resource record set. - You can only specify one ``ResourceRecord`` per weighted resource record set. - You can't create latency, failover, or geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as weighted resource record sets. - You can create a maximum of 100 weighted resource record sets that have the same values for the ``Name`` and ``Type`` elements. - For weighted (but not weighted alias) resource record sets, if you set ``Weight`` to ``0`` for a resource record set, Route 53 never responds to queries with the applicable value for that resource record set. However, if you set ``Weight`` to ``0`` for all resource record sets that have the same combination of DNS name and type, traffic is routed to all resources with equal probability. The effect of setting ``Weight`` to ``0`` is different when you associate health checks with weighted resource record sets. For more information, see `Options for Configuring Route 53 Active-Active and Active-Passive Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-configuring-options.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_route53 as route53
                
                record_set_property = route53.CfnRecordSetGroup.RecordSetProperty(
                    name="name",
                    type="type",
                
                    # the properties below are optional
                    alias_target=route53.CfnRecordSetGroup.AliasTargetProperty(
                        dns_name="dnsName",
                        hosted_zone_id="hostedZoneId",
                
                        # the properties below are optional
                        evaluate_target_health=False
                    ),
                    failover="failover",
                    geo_location=route53.CfnRecordSetGroup.GeoLocationProperty(
                        continent_code="continentCode",
                        country_code="countryCode",
                        subdivision_code="subdivisionCode"
                    ),
                    health_check_id="healthCheckId",
                    hosted_zone_id="hostedZoneId",
                    hosted_zone_name="hostedZoneName",
                    multi_value_answer=False,
                    region="region",
                    resource_records=["resourceRecords"],
                    set_identifier="setIdentifier",
                    ttl="ttl",
                    weight=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "type": type,
            }
            if alias_target is not None:
                self._values["alias_target"] = alias_target
            if failover is not None:
                self._values["failover"] = failover
            if geo_location is not None:
                self._values["geo_location"] = geo_location
            if health_check_id is not None:
                self._values["health_check_id"] = health_check_id
            if hosted_zone_id is not None:
                self._values["hosted_zone_id"] = hosted_zone_id
            if hosted_zone_name is not None:
                self._values["hosted_zone_name"] = hosted_zone_name
            if multi_value_answer is not None:
                self._values["multi_value_answer"] = multi_value_answer
            if region is not None:
                self._values["region"] = region
            if resource_records is not None:
                self._values["resource_records"] = resource_records
            if set_identifier is not None:
                self._values["set_identifier"] = set_identifier
            if ttl is not None:
                self._values["ttl"] = ttl
            if weight is not None:
                self._values["weight"] = weight

        @builtins.property
        def name(self) -> builtins.str:
            '''For ``ChangeResourceRecordSets`` requests, the name of the record that you want to create, update, or delete.

            For ``ListResourceRecordSets`` responses, the name of a record in the specified hosted zone.

            *ChangeResourceRecordSets Only*

            Enter a fully qualified domain name, for example, ``www.example.com`` . You can optionally include a trailing dot. If you omit the trailing dot, Amazon Route 53 assumes that the domain name that you specify is fully qualified. This means that Route 53 treats ``www.example.com`` (without a trailing dot) and ``www.example.com.`` (with a trailing dot) as identical.

            For information about how to specify characters other than ``a-z`` , ``0-9`` , and ``-`` (hyphen) and how to specify internationalized domain names, see `DNS Domain Name Format <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html>`_ in the *Amazon Route 53 Developer Guide* .

            You can use the asterisk (*) wildcard to replace the leftmost label in a domain name, for example, ``*.example.com`` . Note the following:

            - The * must replace the entire label. For example, you can't specify ``*prod.example.com`` or ``prod*.example.com`` .
            - The * can't replace any of the middle labels, for example, marketing.*.example.com.
            - If you include * in any position other than the leftmost label in a domain name, DNS treats it as an * character (ASCII 42), not as a wildcard.

            .. epigraph::

               You can't use the * wildcard for resource records sets that have a type of NS.

            You can use the * wildcard as the leftmost label in a domain name, for example, ``*.example.com`` . You can't use an * for one of the middle labels, for example, ``marketing.*.example.com`` . In addition, the * must replace the entire label; for example, you can't specify ``prod*.example.com`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''The DNS record type.

            For information about different record types and how data is encoded for them, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* .

            Valid values for basic resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``DS`` | ``MX`` | ``NAPTR`` | ``NS`` | ``PTR`` | ``SOA`` | ``SPF`` | ``SRV`` | ``TXT``

            Values for weighted, latency, geolocation, and failover resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` . When creating a group of weighted, latency, geolocation, or failover resource record sets, specify the same value for all of the resource record sets in the group.

            Valid values for multivalue answer resource record sets: ``A`` | ``AAAA`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT``
            .. epigraph::

               SPF records were formerly used to verify the identity of the sender of email messages. However, we no longer recommend that you create resource record sets for which the value of ``Type`` is ``SPF`` . RFC 7208, *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1* , has been updated to say, "...[I]ts existence and mechanism defined in [RFC4408] have led to some interoperability issues. Accordingly, its use is no longer appropriate for SPF version 1; implementations are not to use it." In RFC 7208, see section 14.1, `The SPF DNS Record Type <https://docs.aws.amazon.com/http://tools.ietf.org/html/rfc7208#section-14.1>`_ .

            Values for alias resource record sets:

            - *Amazon API Gateway custom regional APIs and edge-optimized APIs:* ``A``
            - *CloudFront distributions:* ``A``

            If IPv6 is enabled for the distribution, create two resource record sets to route traffic to your distribution, one with a value of ``A`` and one with a value of ``AAAA`` .

            - *Amazon API Gateway environment that has a regionalized subdomain* : ``A``
            - *ELB load balancers:* ``A`` | ``AAAA``
            - *Amazon S3 buckets:* ``A``
            - *Amazon Virtual Private Cloud interface VPC endpoints* ``A``
            - *Another resource record set in this hosted zone:* Specify the type of the resource record set that you're creating the alias for. All values are supported except ``NS`` and ``SOA`` .

            .. epigraph::

               If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't route traffic to a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def alias_target(
            self,
        ) -> typing.Optional[typing.Union["CfnRecordSetGroup.AliasTargetProperty", _IResolvable_da3f097b]]:
            '''*Alias resource record sets only:* Information about the AWS resource, such as a CloudFront distribution or an Amazon S3 bucket, that you want to route traffic to.

            If you're creating resource records sets for a private hosted zone, note the following:

            - You can't create an alias resource record set in a private hosted zone to route traffic to a CloudFront distribution.
            - Creating geolocation alias resource record sets or latency alias resource record sets in a private hosted zone is unsupported.
            - For information about creating failover resource record sets in a private hosted zone, see `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-aliastarget
            '''
            result = self._values.get("alias_target")
            return typing.cast(typing.Optional[typing.Union["CfnRecordSetGroup.AliasTargetProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def failover(self) -> typing.Optional[builtins.str]:
            '''*Failover resource record sets only:* To configure failover, you add the ``Failover`` element to two resource record sets.

            For one resource record set, you specify ``PRIMARY`` as the value for ``Failover`` ; for the other resource record set, you specify ``SECONDARY`` . In addition, you include the ``HealthCheckId`` element and specify the health check that you want Amazon Route 53 to perform for each resource record set.

            Except where noted, the following failover behaviors assume that you have included the ``HealthCheckId`` element in both resource record sets:

            - When the primary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the secondary resource record set.
            - When the primary resource record set is unhealthy and the secondary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the secondary resource record set.
            - When the secondary resource record set is unhealthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the primary resource record set.
            - If you omit the ``HealthCheckId`` element for the secondary resource record set, and if the primary resource record set is unhealthy, Route 53 always responds to DNS queries with the applicable value from the secondary resource record set. This is true regardless of the health of the associated endpoint.

            You can't create non-failover resource record sets that have the same values for the ``Name`` and ``Type`` elements as failover resource record sets.

            For failover alias resource record sets, you must also include the ``EvaluateTargetHealth`` element and set the value to true.

            For more information about configuring failover for Route 53, see the following topics in the *Amazon Route 53 Developer Guide* :

            - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_
            - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-failover
            '''
            result = self._values.get("failover")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def geo_location(
            self,
        ) -> typing.Optional[typing.Union["CfnRecordSetGroup.GeoLocationProperty", _IResolvable_da3f097b]]:
            '''*Geolocation resource record sets only:* A complex type that lets you control how Amazon Route 53 responds to DNS queries based on the geographic origin of the query.

            For example, if you want all queries from Africa to be routed to a web server with an IP address of ``192.0.2.111`` , create a resource record set with a ``Type`` of ``A`` and a ``ContinentCode`` of ``AF`` .
            .. epigraph::

               Although creating geolocation and geolocation alias resource record sets in a private hosted zone is allowed, it's not supported.

            If you create separate resource record sets for overlapping geographic regions (for example, one resource record set for a continent and one for a country on the same continent), priority goes to the smallest geographic region. This allows you to route most queries for a continent to one resource and to route queries for a country on that continent to a different resource.

            You can't create two geolocation resource record sets that specify the same geographic location.

            The value ``*`` in the ``CountryCode`` element matches all geographic locations that aren't specified in other geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements.
            .. epigraph::

               Geolocation works by mapping IP addresses to locations. However, some IP addresses aren't mapped to geographic locations, so even if you create geolocation resource record sets that cover all seven continents, Route 53 will receive some DNS queries from locations that it can't identify. We recommend that you create a resource record set for which the value of ``CountryCode`` is ``*`` . Two groups of queries are routed to the resource that you specify in this record: queries that come from locations for which you haven't created geolocation resource record sets and queries from IP addresses that aren't mapped to a location. If you don't create a ``*`` resource record set, Route 53 returns a "no answer" response for queries from those locations.

            You can't create non-geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as geolocation resource record sets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-geolocation
            '''
            result = self._values.get("geo_location")
            return typing.cast(typing.Optional[typing.Union["CfnRecordSetGroup.GeoLocationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def health_check_id(self) -> typing.Optional[builtins.str]:
            '''If you want Amazon Route 53 to return this resource record set in response to a DNS query only when the status of a health check is healthy, include the ``HealthCheckId`` element and specify the ID of the applicable health check.

            Route 53 determines whether a resource record set is healthy based on one of the following:

            - By periodically sending a request to the endpoint that is specified in the health check
            - By aggregating the status of a specified group of health checks (calculated health checks)
            - By determining the current state of a CloudWatch alarm (CloudWatch metric health checks)

            .. epigraph::

               Route 53 doesn't check the health of the endpoint that is specified in the resource record set, for example, the endpoint specified by the IP address in the ``Value`` element. When you add a ``HealthCheckId`` element to a resource record set, Route 53 checks the health of the endpoint that you specified in the health check.

            For more information, see the following topics in the *Amazon Route 53 Developer Guide* :

            - `How Amazon Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_
            - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_
            - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_

            *When to Specify HealthCheckId*

            Specifying a value for ``HealthCheckId`` is useful only when Route 53 is choosing between two or more resource record sets to respond to a DNS query, and you want Route 53 to base the choice in part on the status of a health check. Configuring health checks makes sense only in the following configurations:

            - *Non-alias resource record sets* : You're checking the health of a group of non-alias resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A) and you specify health check IDs for all the resource record sets.

            If the health check status for a resource record set is healthy, Route 53 includes the record among the records that it responds to DNS queries with.

            If the health check status for a resource record set is unhealthy, Route 53 stops responding to DNS queries using the value for that resource record set.

            If the health check status for all resource record sets in the group is unhealthy, Route 53 considers all resource record sets in the group healthy and responds to DNS queries accordingly.

            - *Alias resource record sets* : You specify the following settings:
            - You set ``EvaluateTargetHealth`` to true for an alias resource record set in a group of resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A).
            - You configure the alias resource record set to route traffic to a non-alias resource record set in the same hosted zone.
            - You specify a health check ID for the non-alias resource record set.

            If the health check status is healthy, Route 53 considers the alias resource record set to be healthy and includes the alias record among the records that it responds to DNS queries with.

            If the health check status is unhealthy, Route 53 stops responding to DNS queries using the alias resource record set.
            .. epigraph::

               The alias resource record set can also route traffic to a *group* of non-alias resource record sets that have the same routing policy, name, and type. In that configuration, associate health checks with all of the resource record sets in the group of non-alias resource record sets.

            *Geolocation Routing*

            For geolocation resource record sets, if an endpoint is unhealthy, Route 53 looks for a resource record set for the larger, associated geographic region. For example, suppose you have resource record sets for a state in the United States, for the entire United States, for North America, and a resource record set that has ``*`` for ``CountryCode`` is ``*`` , which applies to all locations. If the endpoint for the state resource record set is unhealthy, Route 53 checks for healthy resource record sets in the following order until it finds a resource record set for which the endpoint is healthy:

            - The United States
            - North America
            - The default resource record set

            *Specifying the Health Check Endpoint by Domain Name*

            If your health checks specify the endpoint only by domain name, we recommend that you create a separate health check for each endpoint. For example, create a health check for each ``HTTP`` server that is serving content for ``www.example.com`` . For the value of ``FullyQualifiedDomainName`` , specify the domain name of the server (such as ``us-east-2-www.example.com`` ), not the name of the resource record sets ( ``www.example.com`` ).
            .. epigraph::

               Health check results will be unpredictable if you do the following:

               - Create a health check that has the same value for ``FullyQualifiedDomainName`` as the name of a resource record set.
               - Associate that health check with the resource record set.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-healthcheckid
            '''
            result = self._values.get("health_check_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def hosted_zone_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the hosted zone that you want to create records in.

            Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-hostedzoneid
            '''
            result = self._values.get("hosted_zone_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def hosted_zone_name(self) -> typing.Optional[builtins.str]:
            '''The name of the hosted zone that you want to create records in.

            You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` .

            When you create a stack using an ``AWS::Route53::RecordSet`` that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the ``HostedZoneName`` . If AWS CloudFormation can't find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack.

            Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-hostedzonename
            '''
            result = self._values.get("hosted_zone_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def multi_value_answer(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''*Multivalue answer resource record sets only* : To route traffic approximately randomly to multiple resources, such as web servers, create one multivalue answer record for each resource and specify ``true`` for ``MultiValueAnswer`` .

            Note the following:

            - If you associate a health check with a multivalue answer resource record set, Amazon Route 53 responds to DNS queries with the corresponding IP address only when the health check is healthy.
            - If you don't associate a health check with a multivalue answer record, Route 53 always considers the record to be healthy.
            - Route 53 responds to DNS queries with up to eight healthy records; if you have eight or fewer healthy records, Route 53 responds to all DNS queries with all the healthy records.
            - If you have more than eight healthy records, Route 53 responds to different DNS resolvers with different combinations of healthy records.
            - When all records are unhealthy, Route 53 responds to DNS queries with up to eight unhealthy records.
            - If a resource becomes unavailable after a resolver caches a response, client software typically tries another of the IP addresses in the response.

            You can't create multivalue answer alias records.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-multivalueanswer
            '''
            result = self._values.get("multi_value_answer")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def region(self) -> typing.Optional[builtins.str]:
            '''*Latency-based resource record sets only:* The Amazon EC2 Region where you created the resource that this resource record set refers to.

            The resource typically is an AWS resource, such as an EC2 instance or an ELB load balancer, and is referred to by an IP address or a DNS domain name, depending on the record type.
            .. epigraph::

               Although creating latency and latency alias resource record sets in a private hosted zone is allowed, it's not supported.

            When Amazon Route 53 receives a DNS query for a domain name and type for which you have created latency resource record sets, Route 53 selects the latency resource record set that has the lowest latency between the end user and the associated Amazon EC2 Region. Route 53 then returns the value that is associated with the selected resource record set.

            Note the following:

            - You can only specify one ``ResourceRecord`` per latency resource record set.
            - You can only create one latency resource record set for each Amazon EC2 Region.
            - You aren't required to create latency resource record sets for all Amazon EC2 Regions. Route 53 will choose the region with the best latency from among the regions that you create latency resource record sets for.
            - You can't create non-latency resource record sets that have the same values for the ``Name`` and ``Type`` elements as latency resource record sets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-region
            '''
            result = self._values.get("region")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def resource_records(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Information about the records that you want to create.

            Each record should be in the format appropriate for the record type specified by the ``Type`` property. For information about different record types and their record formats, see `Values That You Specify When You Create or Edit Amazon Route 53 Records <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-values.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-resourcerecords
            '''
            result = self._values.get("resource_records")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def set_identifier(self) -> typing.Optional[builtins.str]:
            '''*Resource record sets that have a routing policy other than simple:* An identifier that differentiates among multiple resource record sets that have the same combination of name and type, such as multiple weighted resource record sets named acme.example.com that have a type of A. In a group of resource record sets that have the same name and type, the value of ``SetIdentifier`` must be unique for each resource record set.

            For information about routing policies, see `Choosing a Routing Policy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-setidentifier
            '''
            result = self._values.get("set_identifier")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ttl(self) -> typing.Optional[builtins.str]:
            '''The resource record cache time to live (TTL), in seconds. Note the following:.

            - If you're creating or updating an alias resource record set, omit ``TTL`` . Amazon Route 53 uses the value of ``TTL`` for the alias target.
            - If you're associating this resource record set with a health check (if you're adding a ``HealthCheckId`` element), we recommend that you specify a ``TTL`` of 60 seconds or less so clients respond quickly to changes in health status.
            - All of the resource record sets in a group of weighted resource record sets must have the same value for ``TTL`` .
            - If a group of weighted resource record sets includes one or more weighted alias resource record sets for which the alias target is an ELB load balancer, we recommend that you specify a ``TTL`` of 60 seconds for all of the non-alias weighted resource record sets that have the same name and type. Values other than 60 seconds (the TTL for load balancers) will change the effect of the values that you specify for ``Weight`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-ttl
            '''
            result = self._values.get("ttl")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def weight(self) -> typing.Optional[jsii.Number]:
            '''*Weighted resource record sets only:* Among resource record sets that have the same combination of DNS name and type, a value that determines the proportion of DNS queries that Amazon Route 53 responds to using the current resource record set.

            Route 53 calculates the sum of the weights for the resource record sets that have the same combination of DNS name and type. Route 53 then responds to queries based on the ratio of a resource's weight to the total. Note the following:

            - You must specify a value for the ``Weight`` element for every weighted resource record set.
            - You can only specify one ``ResourceRecord`` per weighted resource record set.
            - You can't create latency, failover, or geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as weighted resource record sets.
            - You can create a maximum of 100 weighted resource record sets that have the same values for the ``Name`` and ``Type`` elements.
            - For weighted (but not weighted alias) resource record sets, if you set ``Weight`` to ``0`` for a resource record set, Route 53 never responds to queries with the applicable value for that resource record set. However, if you set ``Weight`` to ``0`` for all resource record sets that have the same combination of DNS name and type, traffic is routed to all resources with equal probability.

            The effect of setting ``Weight`` to ``0`` is different when you associate health checks with weighted resource record sets. For more information, see `Options for Configuring Route 53 Active-Active and Active-Passive Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-configuring-options.html>`_ in the *Amazon Route 53 Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-weight
            '''
            result = self._values.get("weight")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RecordSetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CfnRecordSetGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "comment": "comment",
        "hosted_zone_id": "hostedZoneId",
        "hosted_zone_name": "hostedZoneName",
        "record_sets": "recordSets",
    },
)
class CfnRecordSetGroupProps:
    def __init__(
        self,
        *,
        comment: typing.Optional[builtins.str] = None,
        hosted_zone_id: typing.Optional[builtins.str] = None,
        hosted_zone_name: typing.Optional[builtins.str] = None,
        record_sets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnRecordSetGroup.RecordSetProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRecordSetGroup``.

        :param comment: *Optional:* Any comments you want to include about a change batch request.
        :param hosted_zone_id: The ID of the hosted zone that you want to create records in. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
        :param hosted_zone_name: The name of the hosted zone that you want to create records in. You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` . When you create a stack using an ``AWS::Route53::RecordSet`` that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the ``HostedZoneName`` . If AWS CloudFormation can't find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
        :param record_sets: A complex type that contains one ``RecordSet`` element for each record that you want to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            cfn_record_set_group_props = route53.CfnRecordSetGroupProps(
                comment="comment",
                hosted_zone_id="hostedZoneId",
                hosted_zone_name="hostedZoneName",
                record_sets=[route53.CfnRecordSetGroup.RecordSetProperty(
                    name="name",
                    type="type",
            
                    # the properties below are optional
                    alias_target=route53.CfnRecordSetGroup.AliasTargetProperty(
                        dns_name="dnsName",
                        hosted_zone_id="hostedZoneId",
            
                        # the properties below are optional
                        evaluate_target_health=False
                    ),
                    failover="failover",
                    geo_location=route53.CfnRecordSetGroup.GeoLocationProperty(
                        continent_code="continentCode",
                        country_code="countryCode",
                        subdivision_code="subdivisionCode"
                    ),
                    health_check_id="healthCheckId",
                    hosted_zone_id="hostedZoneId",
                    hosted_zone_name="hostedZoneName",
                    multi_value_answer=False,
                    region="region",
                    resource_records=["resourceRecords"],
                    set_identifier="setIdentifier",
                    ttl="ttl",
                    weight=123
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if comment is not None:
            self._values["comment"] = comment
        if hosted_zone_id is not None:
            self._values["hosted_zone_id"] = hosted_zone_id
        if hosted_zone_name is not None:
            self._values["hosted_zone_name"] = hosted_zone_name
        if record_sets is not None:
            self._values["record_sets"] = record_sets

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''*Optional:* Any comments you want to include about a change batch request.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html#cfn-route53-recordsetgroup-comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def hosted_zone_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the hosted zone that you want to create records in.

        Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html#cfn-route53-recordsetgroup-hostedzoneid
        '''
        result = self._values.get("hosted_zone_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def hosted_zone_name(self) -> typing.Optional[builtins.str]:
        '''The name of the hosted zone that you want to create records in.

        You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` .

        When you create a stack using an ``AWS::Route53::RecordSet`` that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the ``HostedZoneName`` . If AWS CloudFormation can't find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack.

        Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html#cfn-route53-recordsetgroup-hostedzonename
        '''
        result = self._values.get("hosted_zone_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_sets(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRecordSetGroup.RecordSetProperty, _IResolvable_da3f097b]]]]:
        '''A complex type that contains one ``RecordSet`` element for each record that you want to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html#cfn-route53-recordsetgroup-recordsets
        '''
        result = self._values.get("record_sets")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRecordSetGroup.RecordSetProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRecordSetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CfnRecordSetProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "type": "type",
        "alias_target": "aliasTarget",
        "comment": "comment",
        "failover": "failover",
        "geo_location": "geoLocation",
        "health_check_id": "healthCheckId",
        "hosted_zone_id": "hostedZoneId",
        "hosted_zone_name": "hostedZoneName",
        "multi_value_answer": "multiValueAnswer",
        "region": "region",
        "resource_records": "resourceRecords",
        "set_identifier": "setIdentifier",
        "ttl": "ttl",
        "weight": "weight",
    },
)
class CfnRecordSetProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        type: builtins.str,
        alias_target: typing.Optional[typing.Union[CfnRecordSet.AliasTargetProperty, _IResolvable_da3f097b]] = None,
        comment: typing.Optional[builtins.str] = None,
        failover: typing.Optional[builtins.str] = None,
        geo_location: typing.Optional[typing.Union[CfnRecordSet.GeoLocationProperty, _IResolvable_da3f097b]] = None,
        health_check_id: typing.Optional[builtins.str] = None,
        hosted_zone_id: typing.Optional[builtins.str] = None,
        hosted_zone_name: typing.Optional[builtins.str] = None,
        multi_value_answer: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        region: typing.Optional[builtins.str] = None,
        resource_records: typing.Optional[typing.Sequence[builtins.str]] = None,
        set_identifier: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[builtins.str] = None,
        weight: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for defining a ``CfnRecordSet``.

        :param name: For ``ChangeResourceRecordSets`` requests, the name of the record that you want to create, update, or delete. For ``ListResourceRecordSets`` responses, the name of a record in the specified hosted zone. *ChangeResourceRecordSets Only* Enter a fully qualified domain name, for example, ``www.example.com`` . You can optionally include a trailing dot. If you omit the trailing dot, Amazon Route 53 assumes that the domain name that you specify is fully qualified. This means that Route 53 treats ``www.example.com`` (without a trailing dot) and ``www.example.com.`` (with a trailing dot) as identical. For information about how to specify characters other than ``a-z`` , ``0-9`` , and ``-`` (hyphen) and how to specify internationalized domain names, see `DNS Domain Name Format <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html>`_ in the *Amazon Route 53 Developer Guide* . You can use the asterisk (*) wildcard to replace the leftmost label in a domain name, for example, ``*.example.com`` . Note the following: - The * must replace the entire label. For example, you can't specify ``*prod.example.com`` or ``prod*.example.com`` . - The * can't replace any of the middle labels, for example, marketing.*.example.com. - If you include * in any position other than the leftmost label in a domain name, DNS treats it as an * character (ASCII 42), not as a wildcard. .. epigraph:: You can't use the * wildcard for resource records sets that have a type of NS. You can use the * wildcard as the leftmost label in a domain name, for example, ``*.example.com`` . You can't use an * for one of the middle labels, for example, ``marketing.*.example.com`` . In addition, the * must replace the entire label; for example, you can't specify ``prod*.example.com`` .
        :param type: The DNS record type. For information about different record types and how data is encoded for them, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* . Valid values for basic resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``DS`` | ``MX`` | ``NAPTR`` | ``NS`` | ``PTR`` | ``SOA`` | ``SPF`` | ``SRV`` | ``TXT`` Values for weighted, latency, geolocation, and failover resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` . When creating a group of weighted, latency, geolocation, or failover resource record sets, specify the same value for all of the resource record sets in the group. Valid values for multivalue answer resource record sets: ``A`` | ``AAAA`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` .. epigraph:: SPF records were formerly used to verify the identity of the sender of email messages. However, we no longer recommend that you create resource record sets for which the value of ``Type`` is ``SPF`` . RFC 7208, *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1* , has been updated to say, "...[I]ts existence and mechanism defined in [RFC4408] have led to some interoperability issues. Accordingly, its use is no longer appropriate for SPF version 1; implementations are not to use it." In RFC 7208, see section 14.1, `The SPF DNS Record Type <https://docs.aws.amazon.com/http://tools.ietf.org/html/rfc7208#section-14.1>`_ . Values for alias resource record sets: - *Amazon API Gateway custom regional APIs and edge-optimized APIs:* ``A`` - *CloudFront distributions:* ``A`` If IPv6 is enabled for the distribution, create two resource record sets to route traffic to your distribution, one with a value of ``A`` and one with a value of ``AAAA`` . - *Amazon API Gateway environment that has a regionalized subdomain* : ``A`` - *ELB load balancers:* ``A`` | ``AAAA`` - *Amazon S3 buckets:* ``A`` - *Amazon Virtual Private Cloud interface VPC endpoints* ``A`` - *Another resource record set in this hosted zone:* Specify the type of the resource record set that you're creating the alias for. All values are supported except ``NS`` and ``SOA`` . .. epigraph:: If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't route traffic to a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.
        :param alias_target: *Alias resource record sets only:* Information about the AWS resource, such as a CloudFront distribution or an Amazon S3 bucket, that you want to route traffic to. If you're creating resource records sets for a private hosted zone, note the following: - You can't create an alias resource record set in a private hosted zone to route traffic to a CloudFront distribution. - Creating geolocation alias resource record sets or latency alias resource record sets in a private hosted zone is unsupported. - For information about creating failover resource record sets in a private hosted zone, see `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ in the *Amazon Route 53 Developer Guide* .
        :param comment: *Optional:* Any comments you want to include about a change batch request.
        :param failover: *Failover resource record sets only:* To configure failover, you add the ``Failover`` element to two resource record sets. For one resource record set, you specify ``PRIMARY`` as the value for ``Failover`` ; for the other resource record set, you specify ``SECONDARY`` . In addition, you include the ``HealthCheckId`` element and specify the health check that you want Amazon Route 53 to perform for each resource record set. Except where noted, the following failover behaviors assume that you have included the ``HealthCheckId`` element in both resource record sets: - When the primary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the secondary resource record set. - When the primary resource record set is unhealthy and the secondary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the secondary resource record set. - When the secondary resource record set is unhealthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the primary resource record set. - If you omit the ``HealthCheckId`` element for the secondary resource record set, and if the primary resource record set is unhealthy, Route 53 always responds to DNS queries with the applicable value from the secondary resource record set. This is true regardless of the health of the associated endpoint. You can't create non-failover resource record sets that have the same values for the ``Name`` and ``Type`` elements as failover resource record sets. For failover alias resource record sets, you must also include the ``EvaluateTargetHealth`` element and set the value to true. For more information about configuring failover for Route 53, see the following topics in the *Amazon Route 53 Developer Guide* : - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_
        :param geo_location: *Geolocation resource record sets only:* A complex type that lets you control how Amazon Route 53 responds to DNS queries based on the geographic origin of the query. For example, if you want all queries from Africa to be routed to a web server with an IP address of ``192.0.2.111`` , create a resource record set with a ``Type`` of ``A`` and a ``ContinentCode`` of ``AF`` . .. epigraph:: Although creating geolocation and geolocation alias resource record sets in a private hosted zone is allowed, it's not supported. If you create separate resource record sets for overlapping geographic regions (for example, one resource record set for a continent and one for a country on the same continent), priority goes to the smallest geographic region. This allows you to route most queries for a continent to one resource and to route queries for a country on that continent to a different resource. You can't create two geolocation resource record sets that specify the same geographic location. The value ``*`` in the ``CountryCode`` element matches all geographic locations that aren't specified in other geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements. .. epigraph:: Geolocation works by mapping IP addresses to locations. However, some IP addresses aren't mapped to geographic locations, so even if you create geolocation resource record sets that cover all seven continents, Route 53 will receive some DNS queries from locations that it can't identify. We recommend that you create a resource record set for which the value of ``CountryCode`` is ``*`` . Two groups of queries are routed to the resource that you specify in this record: queries that come from locations for which you haven't created geolocation resource record sets and queries from IP addresses that aren't mapped to a location. If you don't create a ``*`` resource record set, Route 53 returns a "no answer" response for queries from those locations. You can't create non-geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as geolocation resource record sets.
        :param health_check_id: If you want Amazon Route 53 to return this resource record set in response to a DNS query only when the status of a health check is healthy, include the ``HealthCheckId`` element and specify the ID of the applicable health check. Route 53 determines whether a resource record set is healthy based on one of the following: - By periodically sending a request to the endpoint that is specified in the health check - By aggregating the status of a specified group of health checks (calculated health checks) - By determining the current state of a CloudWatch alarm (CloudWatch metric health checks) .. epigraph:: Route 53 doesn't check the health of the endpoint that is specified in the resource record set, for example, the endpoint specified by the IP address in the ``Value`` element. When you add a ``HealthCheckId`` element to a resource record set, Route 53 checks the health of the endpoint that you specified in the health check. For more information, see the following topics in the *Amazon Route 53 Developer Guide* : - `How Amazon Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_ - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_ - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ *When to Specify HealthCheckId* Specifying a value for ``HealthCheckId`` is useful only when Route 53 is choosing between two or more resource record sets to respond to a DNS query, and you want Route 53 to base the choice in part on the status of a health check. Configuring health checks makes sense only in the following configurations: - *Non-alias resource record sets* : You're checking the health of a group of non-alias resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A) and you specify health check IDs for all the resource record sets. If the health check status for a resource record set is healthy, Route 53 includes the record among the records that it responds to DNS queries with. If the health check status for a resource record set is unhealthy, Route 53 stops responding to DNS queries using the value for that resource record set. If the health check status for all resource record sets in the group is unhealthy, Route 53 considers all resource record sets in the group healthy and responds to DNS queries accordingly. - *Alias resource record sets* : You specify the following settings: - You set ``EvaluateTargetHealth`` to true for an alias resource record set in a group of resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A). - You configure the alias resource record set to route traffic to a non-alias resource record set in the same hosted zone. - You specify a health check ID for the non-alias resource record set. If the health check status is healthy, Route 53 considers the alias resource record set to be healthy and includes the alias record among the records that it responds to DNS queries with. If the health check status is unhealthy, Route 53 stops responding to DNS queries using the alias resource record set. .. epigraph:: The alias resource record set can also route traffic to a *group* of non-alias resource record sets that have the same routing policy, name, and type. In that configuration, associate health checks with all of the resource record sets in the group of non-alias resource record sets. *Geolocation Routing* For geolocation resource record sets, if an endpoint is unhealthy, Route 53 looks for a resource record set for the larger, associated geographic region. For example, suppose you have resource record sets for a state in the United States, for the entire United States, for North America, and a resource record set that has ``*`` for ``CountryCode`` is ``*`` , which applies to all locations. If the endpoint for the state resource record set is unhealthy, Route 53 checks for healthy resource record sets in the following order until it finds a resource record set for which the endpoint is healthy: - The United States - North America - The default resource record set *Specifying the Health Check Endpoint by Domain Name* If your health checks specify the endpoint only by domain name, we recommend that you create a separate health check for each endpoint. For example, create a health check for each ``HTTP`` server that is serving content for ``www.example.com`` . For the value of ``FullyQualifiedDomainName`` , specify the domain name of the server (such as ``us-east-2-www.example.com`` ), not the name of the resource record sets ( ``www.example.com`` ). .. epigraph:: Health check results will be unpredictable if you do the following: - Create a health check that has the same value for ``FullyQualifiedDomainName`` as the name of a resource record set. - Associate that health check with the resource record set.
        :param hosted_zone_id: The ID of the hosted zone that you want to create records in. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
        :param hosted_zone_name: The name of the hosted zone that you want to create records in. You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` . When you create a stack using an AWS::Route53::RecordSet that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the HostedZoneName. If AWS CloudFormation cannot find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack. Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .
        :param multi_value_answer: *Multivalue answer resource record sets only* : To route traffic approximately randomly to multiple resources, such as web servers, create one multivalue answer record for each resource and specify ``true`` for ``MultiValueAnswer`` . Note the following: - If you associate a health check with a multivalue answer resource record set, Amazon Route 53 responds to DNS queries with the corresponding IP address only when the health check is healthy. - If you don't associate a health check with a multivalue answer record, Route 53 always considers the record to be healthy. - Route 53 responds to DNS queries with up to eight healthy records; if you have eight or fewer healthy records, Route 53 responds to all DNS queries with all the healthy records. - If you have more than eight healthy records, Route 53 responds to different DNS resolvers with different combinations of healthy records. - When all records are unhealthy, Route 53 responds to DNS queries with up to eight unhealthy records. - If a resource becomes unavailable after a resolver caches a response, client software typically tries another of the IP addresses in the response. You can't create multivalue answer alias records.
        :param region: *Latency-based resource record sets only:* The Amazon EC2 Region where you created the resource that this resource record set refers to. The resource typically is an AWS resource, such as an EC2 instance or an ELB load balancer, and is referred to by an IP address or a DNS domain name, depending on the record type. .. epigraph:: Although creating latency and latency alias resource record sets in a private hosted zone is allowed, it's not supported. When Amazon Route 53 receives a DNS query for a domain name and type for which you have created latency resource record sets, Route 53 selects the latency resource record set that has the lowest latency between the end user and the associated Amazon EC2 Region. Route 53 then returns the value that is associated with the selected resource record set. Note the following: - You can only specify one ``ResourceRecord`` per latency resource record set. - You can only create one latency resource record set for each Amazon EC2 Region. - You aren't required to create latency resource record sets for all Amazon EC2 Regions. Route 53 will choose the region with the best latency from among the regions that you create latency resource record sets for. - You can't create non-latency resource record sets that have the same values for the ``Name`` and ``Type`` elements as latency resource record sets.
        :param resource_records: One or more values that correspond with the value that you specified for the ``Type`` property. For example, if you specified ``A`` for ``Type`` , you specify one or more IP addresses in IPv4 format for ``ResourceRecords`` . For information about the format of values for each record type, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* . Note the following: - You can specify more than one value for all record types except CNAME and SOA. - The maximum length of a value is 4000 characters. - If you're creating an alias record, omit ``ResourceRecords`` .
        :param set_identifier: *Resource record sets that have a routing policy other than simple:* An identifier that differentiates among multiple resource record sets that have the same combination of name and type, such as multiple weighted resource record sets named acme.example.com that have a type of A. In a group of resource record sets that have the same name and type, the value of ``SetIdentifier`` must be unique for each resource record set. For information about routing policies, see `Choosing a Routing Policy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html>`_ in the *Amazon Route 53 Developer Guide* .
        :param ttl: The resource record cache time to live (TTL), in seconds. Note the following:. - If you're creating or updating an alias resource record set, omit ``TTL`` . Amazon Route 53 uses the value of ``TTL`` for the alias target. - If you're associating this resource record set with a health check (if you're adding a ``HealthCheckId`` element), we recommend that you specify a ``TTL`` of 60 seconds or less so clients respond quickly to changes in health status. - All of the resource record sets in a group of weighted resource record sets must have the same value for ``TTL`` . - If a group of weighted resource record sets includes one or more weighted alias resource record sets for which the alias target is an ELB load balancer, we recommend that you specify a ``TTL`` of 60 seconds for all of the non-alias weighted resource record sets that have the same name and type. Values other than 60 seconds (the TTL for load balancers) will change the effect of the values that you specify for ``Weight`` .
        :param weight: *Weighted resource record sets only:* Among resource record sets that have the same combination of DNS name and type, a value that determines the proportion of DNS queries that Amazon Route 53 responds to using the current resource record set. Route 53 calculates the sum of the weights for the resource record sets that have the same combination of DNS name and type. Route 53 then responds to queries based on the ratio of a resource's weight to the total. Note the following: - You must specify a value for the ``Weight`` element for every weighted resource record set. - You can only specify one ``ResourceRecord`` per weighted resource record set. - You can't create latency, failover, or geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as weighted resource record sets. - You can create a maximum of 100 weighted resource record sets that have the same values for the ``Name`` and ``Type`` elements. - For weighted (but not weighted alias) resource record sets, if you set ``Weight`` to ``0`` for a resource record set, Route 53 never responds to queries with the applicable value for that resource record set. However, if you set ``Weight`` to ``0`` for all resource record sets that have the same combination of DNS name and type, traffic is routed to all resources with equal probability. The effect of setting ``Weight`` to ``0`` is different when you associate health checks with weighted resource record sets. For more information, see `Options for Configuring Route 53 Active-Active and Active-Passive Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-configuring-options.html>`_ in the *Amazon Route 53 Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            cfn_record_set_props = route53.CfnRecordSetProps(
                name="name",
                type="type",
            
                # the properties below are optional
                alias_target=route53.CfnRecordSet.AliasTargetProperty(
                    dns_name="dnsName",
                    hosted_zone_id="hostedZoneId",
            
                    # the properties below are optional
                    evaluate_target_health=False
                ),
                comment="comment",
                failover="failover",
                geo_location=route53.CfnRecordSet.GeoLocationProperty(
                    continent_code="continentCode",
                    country_code="countryCode",
                    subdivision_code="subdivisionCode"
                ),
                health_check_id="healthCheckId",
                hosted_zone_id="hostedZoneId",
                hosted_zone_name="hostedZoneName",
                multi_value_answer=False,
                region="region",
                resource_records=["resourceRecords"],
                set_identifier="setIdentifier",
                ttl="ttl",
                weight=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "type": type,
        }
        if alias_target is not None:
            self._values["alias_target"] = alias_target
        if comment is not None:
            self._values["comment"] = comment
        if failover is not None:
            self._values["failover"] = failover
        if geo_location is not None:
            self._values["geo_location"] = geo_location
        if health_check_id is not None:
            self._values["health_check_id"] = health_check_id
        if hosted_zone_id is not None:
            self._values["hosted_zone_id"] = hosted_zone_id
        if hosted_zone_name is not None:
            self._values["hosted_zone_name"] = hosted_zone_name
        if multi_value_answer is not None:
            self._values["multi_value_answer"] = multi_value_answer
        if region is not None:
            self._values["region"] = region
        if resource_records is not None:
            self._values["resource_records"] = resource_records
        if set_identifier is not None:
            self._values["set_identifier"] = set_identifier
        if ttl is not None:
            self._values["ttl"] = ttl
        if weight is not None:
            self._values["weight"] = weight

    @builtins.property
    def name(self) -> builtins.str:
        '''For ``ChangeResourceRecordSets`` requests, the name of the record that you want to create, update, or delete.

        For ``ListResourceRecordSets`` responses, the name of a record in the specified hosted zone.

        *ChangeResourceRecordSets Only*

        Enter a fully qualified domain name, for example, ``www.example.com`` . You can optionally include a trailing dot. If you omit the trailing dot, Amazon Route 53 assumes that the domain name that you specify is fully qualified. This means that Route 53 treats ``www.example.com`` (without a trailing dot) and ``www.example.com.`` (with a trailing dot) as identical.

        For information about how to specify characters other than ``a-z`` , ``0-9`` , and ``-`` (hyphen) and how to specify internationalized domain names, see `DNS Domain Name Format <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html>`_ in the *Amazon Route 53 Developer Guide* .

        You can use the asterisk (*) wildcard to replace the leftmost label in a domain name, for example, ``*.example.com`` . Note the following:

        - The * must replace the entire label. For example, you can't specify ``*prod.example.com`` or ``prod*.example.com`` .
        - The * can't replace any of the middle labels, for example, marketing.*.example.com.
        - If you include * in any position other than the leftmost label in a domain name, DNS treats it as an * character (ASCII 42), not as a wildcard.

        .. epigraph::

           You can't use the * wildcard for resource records sets that have a type of NS.

        You can use the * wildcard as the leftmost label in a domain name, for example, ``*.example.com`` . You can't use an * for one of the middle labels, for example, ``marketing.*.example.com`` . In addition, the * must replace the entire label; for example, you can't specify ``prod*.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> builtins.str:
        '''The DNS record type.

        For information about different record types and how data is encoded for them, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* .

        Valid values for basic resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``DS`` | ``MX`` | ``NAPTR`` | ``NS`` | ``PTR`` | ``SOA`` | ``SPF`` | ``SRV`` | ``TXT``

        Values for weighted, latency, geolocation, and failover resource record sets: ``A`` | ``AAAA`` | ``CAA`` | ``CNAME`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT`` . When creating a group of weighted, latency, geolocation, or failover resource record sets, specify the same value for all of the resource record sets in the group.

        Valid values for multivalue answer resource record sets: ``A`` | ``AAAA`` | ``MX`` | ``NAPTR`` | ``PTR`` | ``SPF`` | ``SRV`` | ``TXT``
        .. epigraph::

           SPF records were formerly used to verify the identity of the sender of email messages. However, we no longer recommend that you create resource record sets for which the value of ``Type`` is ``SPF`` . RFC 7208, *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1* , has been updated to say, "...[I]ts existence and mechanism defined in [RFC4408] have led to some interoperability issues. Accordingly, its use is no longer appropriate for SPF version 1; implementations are not to use it." In RFC 7208, see section 14.1, `The SPF DNS Record Type <https://docs.aws.amazon.com/http://tools.ietf.org/html/rfc7208#section-14.1>`_ .

        Values for alias resource record sets:

        - *Amazon API Gateway custom regional APIs and edge-optimized APIs:* ``A``
        - *CloudFront distributions:* ``A``

        If IPv6 is enabled for the distribution, create two resource record sets to route traffic to your distribution, one with a value of ``A`` and one with a value of ``AAAA`` .

        - *Amazon API Gateway environment that has a regionalized subdomain* : ``A``
        - *ELB load balancers:* ``A`` | ``AAAA``
        - *Amazon S3 buckets:* ``A``
        - *Amazon Virtual Private Cloud interface VPC endpoints* ``A``
        - *Another resource record set in this hosted zone:* Specify the type of the resource record set that you're creating the alias for. All values are supported except ``NS`` and ``SOA`` .

        .. epigraph::

           If you're creating an alias record that has the same name as the hosted zone (known as the zone apex), you can't route traffic to a record for which the value of ``Type`` is ``CNAME`` . This is because the alias record must have the same type as the record you're routing traffic to, and creating a CNAME record for the zone apex isn't supported even for an alias record.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def alias_target(
        self,
    ) -> typing.Optional[typing.Union[CfnRecordSet.AliasTargetProperty, _IResolvable_da3f097b]]:
        '''*Alias resource record sets only:* Information about the AWS resource, such as a CloudFront distribution or an Amazon S3 bucket, that you want to route traffic to.

        If you're creating resource records sets for a private hosted zone, note the following:

        - You can't create an alias resource record set in a private hosted zone to route traffic to a CloudFront distribution.
        - Creating geolocation alias resource record sets or latency alias resource record sets in a private hosted zone is unsupported.
        - For information about creating failover resource record sets in a private hosted zone, see `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_ in the *Amazon Route 53 Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-aliastarget
        '''
        result = self._values.get("alias_target")
        return typing.cast(typing.Optional[typing.Union[CfnRecordSet.AliasTargetProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''*Optional:* Any comments you want to include about a change batch request.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def failover(self) -> typing.Optional[builtins.str]:
        '''*Failover resource record sets only:* To configure failover, you add the ``Failover`` element to two resource record sets.

        For one resource record set, you specify ``PRIMARY`` as the value for ``Failover`` ; for the other resource record set, you specify ``SECONDARY`` . In addition, you include the ``HealthCheckId`` element and specify the health check that you want Amazon Route 53 to perform for each resource record set.

        Except where noted, the following failover behaviors assume that you have included the ``HealthCheckId`` element in both resource record sets:

        - When the primary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the secondary resource record set.
        - When the primary resource record set is unhealthy and the secondary resource record set is healthy, Route 53 responds to DNS queries with the applicable value from the secondary resource record set.
        - When the secondary resource record set is unhealthy, Route 53 responds to DNS queries with the applicable value from the primary resource record set regardless of the health of the primary resource record set.
        - If you omit the ``HealthCheckId`` element for the secondary resource record set, and if the primary resource record set is unhealthy, Route 53 always responds to DNS queries with the applicable value from the secondary resource record set. This is true regardless of the health of the associated endpoint.

        You can't create non-failover resource record sets that have the same values for the ``Name`` and ``Type`` elements as failover resource record sets.

        For failover alias resource record sets, you must also include the ``EvaluateTargetHealth`` element and set the value to true.

        For more information about configuring failover for Route 53, see the following topics in the *Amazon Route 53 Developer Guide* :

        - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_
        - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-failover
        '''
        result = self._values.get("failover")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def geo_location(
        self,
    ) -> typing.Optional[typing.Union[CfnRecordSet.GeoLocationProperty, _IResolvable_da3f097b]]:
        '''*Geolocation resource record sets only:* A complex type that lets you control how Amazon Route 53 responds to DNS queries based on the geographic origin of the query.

        For example, if you want all queries from Africa to be routed to a web server with an IP address of ``192.0.2.111`` , create a resource record set with a ``Type`` of ``A`` and a ``ContinentCode`` of ``AF`` .
        .. epigraph::

           Although creating geolocation and geolocation alias resource record sets in a private hosted zone is allowed, it's not supported.

        If you create separate resource record sets for overlapping geographic regions (for example, one resource record set for a continent and one for a country on the same continent), priority goes to the smallest geographic region. This allows you to route most queries for a continent to one resource and to route queries for a country on that continent to a different resource.

        You can't create two geolocation resource record sets that specify the same geographic location.

        The value ``*`` in the ``CountryCode`` element matches all geographic locations that aren't specified in other geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements.
        .. epigraph::

           Geolocation works by mapping IP addresses to locations. However, some IP addresses aren't mapped to geographic locations, so even if you create geolocation resource record sets that cover all seven continents, Route 53 will receive some DNS queries from locations that it can't identify. We recommend that you create a resource record set for which the value of ``CountryCode`` is ``*`` . Two groups of queries are routed to the resource that you specify in this record: queries that come from locations for which you haven't created geolocation resource record sets and queries from IP addresses that aren't mapped to a location. If you don't create a ``*`` resource record set, Route 53 returns a "no answer" response for queries from those locations.

        You can't create non-geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as geolocation resource record sets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-geolocation
        '''
        result = self._values.get("geo_location")
        return typing.cast(typing.Optional[typing.Union[CfnRecordSet.GeoLocationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def health_check_id(self) -> typing.Optional[builtins.str]:
        '''If you want Amazon Route 53 to return this resource record set in response to a DNS query only when the status of a health check is healthy, include the ``HealthCheckId`` element and specify the ID of the applicable health check.

        Route 53 determines whether a resource record set is healthy based on one of the following:

        - By periodically sending a request to the endpoint that is specified in the health check
        - By aggregating the status of a specified group of health checks (calculated health checks)
        - By determining the current state of a CloudWatch alarm (CloudWatch metric health checks)

        .. epigraph::

           Route 53 doesn't check the health of the endpoint that is specified in the resource record set, for example, the endpoint specified by the IP address in the ``Value`` element. When you add a ``HealthCheckId`` element to a resource record set, Route 53 checks the health of the endpoint that you specified in the health check.

        For more information, see the following topics in the *Amazon Route 53 Developer Guide* :

        - `How Amazon Route 53 Determines Whether an Endpoint Is Healthy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html>`_
        - `Route 53 Health Checks and DNS Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html>`_
        - `Configuring Failover in a Private Hosted Zone <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-private-hosted-zones.html>`_

        *When to Specify HealthCheckId*

        Specifying a value for ``HealthCheckId`` is useful only when Route 53 is choosing between two or more resource record sets to respond to a DNS query, and you want Route 53 to base the choice in part on the status of a health check. Configuring health checks makes sense only in the following configurations:

        - *Non-alias resource record sets* : You're checking the health of a group of non-alias resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A) and you specify health check IDs for all the resource record sets.

        If the health check status for a resource record set is healthy, Route 53 includes the record among the records that it responds to DNS queries with.

        If the health check status for a resource record set is unhealthy, Route 53 stops responding to DNS queries using the value for that resource record set.

        If the health check status for all resource record sets in the group is unhealthy, Route 53 considers all resource record sets in the group healthy and responds to DNS queries accordingly.

        - *Alias resource record sets* : You specify the following settings:
        - You set ``EvaluateTargetHealth`` to true for an alias resource record set in a group of resource record sets that have the same routing policy, name, and type (such as multiple weighted records named www.example.com with a type of A).
        - You configure the alias resource record set to route traffic to a non-alias resource record set in the same hosted zone.
        - You specify a health check ID for the non-alias resource record set.

        If the health check status is healthy, Route 53 considers the alias resource record set to be healthy and includes the alias record among the records that it responds to DNS queries with.

        If the health check status is unhealthy, Route 53 stops responding to DNS queries using the alias resource record set.
        .. epigraph::

           The alias resource record set can also route traffic to a *group* of non-alias resource record sets that have the same routing policy, name, and type. In that configuration, associate health checks with all of the resource record sets in the group of non-alias resource record sets.

        *Geolocation Routing*

        For geolocation resource record sets, if an endpoint is unhealthy, Route 53 looks for a resource record set for the larger, associated geographic region. For example, suppose you have resource record sets for a state in the United States, for the entire United States, for North America, and a resource record set that has ``*`` for ``CountryCode`` is ``*`` , which applies to all locations. If the endpoint for the state resource record set is unhealthy, Route 53 checks for healthy resource record sets in the following order until it finds a resource record set for which the endpoint is healthy:

        - The United States
        - North America
        - The default resource record set

        *Specifying the Health Check Endpoint by Domain Name*

        If your health checks specify the endpoint only by domain name, we recommend that you create a separate health check for each endpoint. For example, create a health check for each ``HTTP`` server that is serving content for ``www.example.com`` . For the value of ``FullyQualifiedDomainName`` , specify the domain name of the server (such as ``us-east-2-www.example.com`` ), not the name of the resource record sets ( ``www.example.com`` ).
        .. epigraph::

           Health check results will be unpredictable if you do the following:

           - Create a health check that has the same value for ``FullyQualifiedDomainName`` as the name of a resource record set.
           - Associate that health check with the resource record set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-healthcheckid
        '''
        result = self._values.get("health_check_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def hosted_zone_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the hosted zone that you want to create records in.

        Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-hostedzoneid
        '''
        result = self._values.get("hosted_zone_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def hosted_zone_name(self) -> typing.Optional[builtins.str]:
        '''The name of the hosted zone that you want to create records in.

        You must include a trailing dot (for example, ``www.example.com.`` ) as part of the ``HostedZoneName`` .

        When you create a stack using an AWS::Route53::RecordSet that specifies ``HostedZoneName`` , AWS CloudFormation attempts to find a hosted zone whose name matches the HostedZoneName. If AWS CloudFormation cannot find a hosted zone with a matching domain name, or if there is more than one hosted zone with the specified domain name, AWS CloudFormation will not create the stack.

        Specify either ``HostedZoneName`` or ``HostedZoneId`` , but not both. If you have multiple hosted zones with the same domain name, you must specify the hosted zone using ``HostedZoneId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-hostedzonename
        '''
        result = self._values.get("hosted_zone_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def multi_value_answer(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''*Multivalue answer resource record sets only* : To route traffic approximately randomly to multiple resources, such as web servers, create one multivalue answer record for each resource and specify ``true`` for ``MultiValueAnswer`` .

        Note the following:

        - If you associate a health check with a multivalue answer resource record set, Amazon Route 53 responds to DNS queries with the corresponding IP address only when the health check is healthy.
        - If you don't associate a health check with a multivalue answer record, Route 53 always considers the record to be healthy.
        - Route 53 responds to DNS queries with up to eight healthy records; if you have eight or fewer healthy records, Route 53 responds to all DNS queries with all the healthy records.
        - If you have more than eight healthy records, Route 53 responds to different DNS resolvers with different combinations of healthy records.
        - When all records are unhealthy, Route 53 responds to DNS queries with up to eight unhealthy records.
        - If a resource becomes unavailable after a resolver caches a response, client software typically tries another of the IP addresses in the response.

        You can't create multivalue answer alias records.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-multivalueanswer
        '''
        result = self._values.get("multi_value_answer")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def region(self) -> typing.Optional[builtins.str]:
        '''*Latency-based resource record sets only:* The Amazon EC2 Region where you created the resource that this resource record set refers to.

        The resource typically is an AWS resource, such as an EC2 instance or an ELB load balancer, and is referred to by an IP address or a DNS domain name, depending on the record type.
        .. epigraph::

           Although creating latency and latency alias resource record sets in a private hosted zone is allowed, it's not supported.

        When Amazon Route 53 receives a DNS query for a domain name and type for which you have created latency resource record sets, Route 53 selects the latency resource record set that has the lowest latency between the end user and the associated Amazon EC2 Region. Route 53 then returns the value that is associated with the selected resource record set.

        Note the following:

        - You can only specify one ``ResourceRecord`` per latency resource record set.
        - You can only create one latency resource record set for each Amazon EC2 Region.
        - You aren't required to create latency resource record sets for all Amazon EC2 Regions. Route 53 will choose the region with the best latency from among the regions that you create latency resource record sets for.
        - You can't create non-latency resource record sets that have the same values for the ``Name`` and ``Type`` elements as latency resource record sets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-region
        '''
        result = self._values.get("region")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def resource_records(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more values that correspond with the value that you specified for the ``Type`` property.

        For example, if you specified ``A`` for ``Type`` , you specify one or more IP addresses in IPv4 format for ``ResourceRecords`` . For information about the format of values for each record type, see `Supported DNS Resource Record Types <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html>`_ in the *Amazon Route 53 Developer Guide* .

        Note the following:

        - You can specify more than one value for all record types except CNAME and SOA.
        - The maximum length of a value is 4000 characters.
        - If you're creating an alias record, omit ``ResourceRecords`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-resourcerecords
        '''
        result = self._values.get("resource_records")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def set_identifier(self) -> typing.Optional[builtins.str]:
        '''*Resource record sets that have a routing policy other than simple:* An identifier that differentiates among multiple resource record sets that have the same combination of name and type, such as multiple weighted resource record sets named acme.example.com that have a type of A. In a group of resource record sets that have the same name and type, the value of ``SetIdentifier`` must be unique for each resource record set.

        For information about routing policies, see `Choosing a Routing Policy <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html>`_ in the *Amazon Route 53 Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-setidentifier
        '''
        result = self._values.get("set_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[builtins.str]:
        '''The resource record cache time to live (TTL), in seconds. Note the following:.

        - If you're creating or updating an alias resource record set, omit ``TTL`` . Amazon Route 53 uses the value of ``TTL`` for the alias target.
        - If you're associating this resource record set with a health check (if you're adding a ``HealthCheckId`` element), we recommend that you specify a ``TTL`` of 60 seconds or less so clients respond quickly to changes in health status.
        - All of the resource record sets in a group of weighted resource record sets must have the same value for ``TTL`` .
        - If a group of weighted resource record sets includes one or more weighted alias resource record sets for which the alias target is an ELB load balancer, we recommend that you specify a ``TTL`` of 60 seconds for all of the non-alias weighted resource record sets that have the same name and type. Values other than 60 seconds (the TTL for load balancers) will change the effect of the values that you specify for ``Weight`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-ttl
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def weight(self) -> typing.Optional[jsii.Number]:
        '''*Weighted resource record sets only:* Among resource record sets that have the same combination of DNS name and type, a value that determines the proportion of DNS queries that Amazon Route 53 responds to using the current resource record set.

        Route 53 calculates the sum of the weights for the resource record sets that have the same combination of DNS name and type. Route 53 then responds to queries based on the ratio of a resource's weight to the total. Note the following:

        - You must specify a value for the ``Weight`` element for every weighted resource record set.
        - You can only specify one ``ResourceRecord`` per weighted resource record set.
        - You can't create latency, failover, or geolocation resource record sets that have the same values for the ``Name`` and ``Type`` elements as weighted resource record sets.
        - You can create a maximum of 100 weighted resource record sets that have the same values for the ``Name`` and ``Type`` elements.
        - For weighted (but not weighted alias) resource record sets, if you set ``Weight`` to ``0`` for a resource record set, Route 53 never responds to queries with the applicable value for that resource record set. However, if you set ``Weight`` to ``0`` for all resource record sets that have the same combination of DNS name and type, traffic is routed to all resources with equal probability.

        The effect of setting ``Weight`` to ``0`` is different when you associate health checks with weighted resource record sets. For more information, see `Options for Configuring Route 53 Active-Active and Active-Passive Failover <https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-configuring-options.html>`_ in the *Amazon Route 53 Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset.html#cfn-route53-recordset-weight
        '''
        result = self._values.get("weight")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRecordSetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CommonHostedZoneProps",
    jsii_struct_bases=[],
    name_mapping={
        "zone_name": "zoneName",
        "comment": "comment",
        "query_logs_log_group_arn": "queryLogsLogGroupArn",
    },
)
class CommonHostedZoneProps:
    def __init__(
        self,
        *,
        zone_name: builtins.str,
        comment: typing.Optional[builtins.str] = None,
        query_logs_log_group_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Common properties to create a Route 53 hosted zone.

        :param zone_name: The name of the domain. For resource record types that include a domain name, specify a fully qualified domain name.
        :param comment: Any comments that you want to include about the hosted zone. Default: none
        :param query_logs_log_group_arn: The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to. Default: disabled

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            common_hosted_zone_props = route53.CommonHostedZoneProps(
                zone_name="zoneName",
            
                # the properties below are optional
                comment="comment",
                query_logs_log_group_arn="queryLogsLogGroupArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone_name": zone_name,
        }
        if comment is not None:
            self._values["comment"] = comment
        if query_logs_log_group_arn is not None:
            self._values["query_logs_log_group_arn"] = query_logs_log_group_arn

    @builtins.property
    def zone_name(self) -> builtins.str:
        '''The name of the domain.

        For resource record types that include a domain
        name, specify a fully qualified domain name.
        '''
        result = self._values.get("zone_name")
        assert result is not None, "Required property 'zone_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''Any comments that you want to include about the hosted zone.

        :default: none
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def query_logs_log_group_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to.

        :default: disabled
        '''
        result = self._values.get("query_logs_log_group_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CommonHostedZoneProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class CrossAccountZoneDelegationRecord(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CrossAccountZoneDelegationRecord",
):
    '''A Cross Account Zone Delegation record.

    :exampleMetadata: infused

    Example::

        sub_zone = route53.PublicHostedZone(self, "SubZone",
            zone_name="sub.someexample.com"
        )
        
        # import the delegation role by constructing the roleArn
        delegation_role_arn = Stack.of(self).format_arn(
            region="",  # IAM is global in each partition
            service="iam",
            account="parent-account-id",
            resource="role",
            resource_name="MyDelegationRole"
        )
        delegation_role = iam.Role.from_role_arn(self, "DelegationRole", delegation_role_arn)
        
        # create the record
        route53.CrossAccountZoneDelegationRecord(self, "delegate",
            delegated_zone=sub_zone,
            parent_hosted_zone_name="someexample.com",  # or you can use parentHostedZoneId
            delegation_role=delegation_role
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        delegated_zone: "IHostedZone",
        delegation_role: _IRole_235f5d8e,
        parent_hosted_zone_id: typing.Optional[builtins.str] = None,
        parent_hosted_zone_name: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param delegated_zone: The zone to be delegated.
        :param delegation_role: The delegation role in the parent account.
        :param parent_hosted_zone_id: The hosted zone id in the parent account. Default: - no zone id
        :param parent_hosted_zone_name: The hosted zone name in the parent account. Default: - no zone name
        :param removal_policy: The removal policy to apply to the record set. Default: RemovalPolicy.DESTROY
        :param ttl: The resource record cache time to live (TTL). Default: Duration.days(2)
        '''
        props = CrossAccountZoneDelegationRecordProps(
            delegated_zone=delegated_zone,
            delegation_role=delegation_role,
            parent_hosted_zone_id=parent_hosted_zone_id,
            parent_hosted_zone_name=parent_hosted_zone_name,
            removal_policy=removal_policy,
            ttl=ttl,
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CrossAccountZoneDelegationRecordProps",
    jsii_struct_bases=[],
    name_mapping={
        "delegated_zone": "delegatedZone",
        "delegation_role": "delegationRole",
        "parent_hosted_zone_id": "parentHostedZoneId",
        "parent_hosted_zone_name": "parentHostedZoneName",
        "removal_policy": "removalPolicy",
        "ttl": "ttl",
    },
)
class CrossAccountZoneDelegationRecordProps:
    def __init__(
        self,
        *,
        delegated_zone: "IHostedZone",
        delegation_role: _IRole_235f5d8e,
        parent_hosted_zone_id: typing.Optional[builtins.str] = None,
        parent_hosted_zone_name: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Construction properties for a CrossAccountZoneDelegationRecord.

        :param delegated_zone: The zone to be delegated.
        :param delegation_role: The delegation role in the parent account.
        :param parent_hosted_zone_id: The hosted zone id in the parent account. Default: - no zone id
        :param parent_hosted_zone_name: The hosted zone name in the parent account. Default: - no zone name
        :param removal_policy: The removal policy to apply to the record set. Default: RemovalPolicy.DESTROY
        :param ttl: The resource record cache time to live (TTL). Default: Duration.days(2)

        :exampleMetadata: infused

        Example::

            sub_zone = route53.PublicHostedZone(self, "SubZone",
                zone_name="sub.someexample.com"
            )
            
            # import the delegation role by constructing the roleArn
            delegation_role_arn = Stack.of(self).format_arn(
                region="",  # IAM is global in each partition
                service="iam",
                account="parent-account-id",
                resource="role",
                resource_name="MyDelegationRole"
            )
            delegation_role = iam.Role.from_role_arn(self, "DelegationRole", delegation_role_arn)
            
            # create the record
            route53.CrossAccountZoneDelegationRecord(self, "delegate",
                delegated_zone=sub_zone,
                parent_hosted_zone_name="someexample.com",  # or you can use parentHostedZoneId
                delegation_role=delegation_role
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "delegated_zone": delegated_zone,
            "delegation_role": delegation_role,
        }
        if parent_hosted_zone_id is not None:
            self._values["parent_hosted_zone_id"] = parent_hosted_zone_id
        if parent_hosted_zone_name is not None:
            self._values["parent_hosted_zone_name"] = parent_hosted_zone_name
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def delegated_zone(self) -> "IHostedZone":
        '''The zone to be delegated.'''
        result = self._values.get("delegated_zone")
        assert result is not None, "Required property 'delegated_zone' is missing"
        return typing.cast("IHostedZone", result)

    @builtins.property
    def delegation_role(self) -> _IRole_235f5d8e:
        '''The delegation role in the parent account.'''
        result = self._values.get("delegation_role")
        assert result is not None, "Required property 'delegation_role' is missing"
        return typing.cast(_IRole_235f5d8e, result)

    @builtins.property
    def parent_hosted_zone_id(self) -> typing.Optional[builtins.str]:
        '''The hosted zone id in the parent account.

        :default: - no zone id
        '''
        result = self._values.get("parent_hosted_zone_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def parent_hosted_zone_name(self) -> typing.Optional[builtins.str]:
        '''The hosted zone name in the parent account.

        :default: - no zone name
        '''
        result = self._values.get("parent_hosted_zone_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''The removal policy to apply to the record set.

        :default: RemovalPolicy.DESTROY
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.days(2)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CrossAccountZoneDelegationRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.HostedZoneAttributes",
    jsii_struct_bases=[],
    name_mapping={"hosted_zone_id": "hostedZoneId", "zone_name": "zoneName"},
)
class HostedZoneAttributes:
    def __init__(
        self,
        *,
        hosted_zone_id: builtins.str,
        zone_name: builtins.str,
    ) -> None:
        '''Reference to a hosted zone.

        :param hosted_zone_id: Identifier of the hosted zone.
        :param zone_name: Name of the hosted zone.

        :exampleMetadata: infused

        Example::

            zone = route53.HostedZone.from_hosted_zone_attributes(self, "MyZone",
                zone_name="example.com",
                hosted_zone_id="ZOJJZC49E0EPZ"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "hosted_zone_id": hosted_zone_id,
            "zone_name": zone_name,
        }

    @builtins.property
    def hosted_zone_id(self) -> builtins.str:
        '''Identifier of the hosted zone.'''
        result = self._values.get("hosted_zone_id")
        assert result is not None, "Required property 'hosted_zone_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def zone_name(self) -> builtins.str:
        '''Name of the hosted zone.'''
        result = self._values.get("zone_name")
        assert result is not None, "Required property 'zone_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HostedZoneAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.HostedZoneProps",
    jsii_struct_bases=[CommonHostedZoneProps],
    name_mapping={
        "zone_name": "zoneName",
        "comment": "comment",
        "query_logs_log_group_arn": "queryLogsLogGroupArn",
        "vpcs": "vpcs",
    },
)
class HostedZoneProps(CommonHostedZoneProps):
    def __init__(
        self,
        *,
        zone_name: builtins.str,
        comment: typing.Optional[builtins.str] = None,
        query_logs_log_group_arn: typing.Optional[builtins.str] = None,
        vpcs: typing.Optional[typing.Sequence[_IVpc_f30d5663]] = None,
    ) -> None:
        '''Properties of a new hosted zone.

        :param zone_name: The name of the domain. For resource record types that include a domain name, specify a fully qualified domain name.
        :param comment: Any comments that you want to include about the hosted zone. Default: none
        :param query_logs_log_group_arn: The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to. Default: disabled
        :param vpcs: A VPC that you want to associate with this hosted zone. When you specify this property, a private hosted zone will be created. You can associate additional VPCs to this private zone using ``addVpc(vpc)``. Default: public (no VPCs associated)

        :exampleMetadata: infused

        Example::

            hosted_zone = route53.HostedZone(self, "MyHostedZone", zone_name="example.org")
            metric = cloudwatch.Metric(
                namespace="AWS/Route53",
                metric_name="DNSQueries",
                dimensions_map={
                    "HostedZoneId": hosted_zone.hosted_zone_id
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone_name": zone_name,
        }
        if comment is not None:
            self._values["comment"] = comment
        if query_logs_log_group_arn is not None:
            self._values["query_logs_log_group_arn"] = query_logs_log_group_arn
        if vpcs is not None:
            self._values["vpcs"] = vpcs

    @builtins.property
    def zone_name(self) -> builtins.str:
        '''The name of the domain.

        For resource record types that include a domain
        name, specify a fully qualified domain name.
        '''
        result = self._values.get("zone_name")
        assert result is not None, "Required property 'zone_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''Any comments that you want to include about the hosted zone.

        :default: none
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def query_logs_log_group_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to.

        :default: disabled
        '''
        result = self._values.get("query_logs_log_group_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpcs(self) -> typing.Optional[typing.List[_IVpc_f30d5663]]:
        '''A VPC that you want to associate with this hosted zone.

        When you specify
        this property, a private hosted zone will be created.

        You can associate additional VPCs to this private zone using ``addVpc(vpc)``.

        :default: public (no VPCs associated)
        '''
        result = self._values.get("vpcs")
        return typing.cast(typing.Optional[typing.List[_IVpc_f30d5663]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HostedZoneProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.HostedZoneProviderProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain_name": "domainName",
        "private_zone": "privateZone",
        "vpc_id": "vpcId",
    },
)
class HostedZoneProviderProps:
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        private_zone: typing.Optional[builtins.bool] = None,
        vpc_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Zone properties for looking up the Hosted Zone.

        :param domain_name: The zone domain e.g. example.com.
        :param private_zone: Whether the zone that is being looked up is a private hosted zone. Default: false
        :param vpc_id: Specifies the ID of the VPC associated with a private hosted zone. If a VPC ID is provided and privateZone is false, no results will be returned and an error will be raised Default: - No VPC ID

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_s3 as s3
            
            
            record_name = "www"
            domain_name = "example.com"
            
            bucket_website = s3.Bucket(self, "BucketWebsite",
                bucket_name=[record_name, domain_name].join("."),  # www.example.com
                public_read_access=True,
                website_index_document="index.html"
            )
            
            zone = route53.HostedZone.from_lookup(self, "Zone", domain_name=domain_name) # example.com
            
            route53.ARecord(self, "AliasRecord",
                zone=zone,
                record_name=record_name,  # www
                target=route53.RecordTarget.from_alias(targets.BucketWebsiteTarget(bucket_website))
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
        }
        if private_zone is not None:
            self._values["private_zone"] = private_zone
        if vpc_id is not None:
            self._values["vpc_id"] = vpc_id

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The zone domain e.g. example.com.'''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def private_zone(self) -> typing.Optional[builtins.bool]:
        '''Whether the zone that is being looked up is a private hosted zone.

        :default: false
        '''
        result = self._values.get("private_zone")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def vpc_id(self) -> typing.Optional[builtins.str]:
        '''Specifies the ID of the VPC associated with a private hosted zone.

        If a VPC ID is provided and privateZone is false, no results will be returned
        and an error will be raised

        :default: - No VPC ID
        '''
        result = self._values.get("vpc_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HostedZoneProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_route53.IAliasRecordTarget")
class IAliasRecordTarget(typing_extensions.Protocol):
    '''Classes that are valid alias record targets, like CloudFront distributions and load balancers, should implement this interface.'''

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        record: "IRecordSet",
        zone: typing.Optional["IHostedZone"] = None,
    ) -> AliasRecordTargetConfig:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param record: -
        :param zone: -
        '''
        ...


class _IAliasRecordTargetProxy:
    '''Classes that are valid alias record targets, like CloudFront distributions and load balancers, should implement this interface.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_route53.IAliasRecordTarget"

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        record: "IRecordSet",
        zone: typing.Optional["IHostedZone"] = None,
    ) -> AliasRecordTargetConfig:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param record: -
        :param zone: -
        '''
        return typing.cast(AliasRecordTargetConfig, jsii.invoke(self, "bind", [record, zone]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IAliasRecordTarget).__jsii_proxy_class__ = lambda : _IAliasRecordTargetProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_route53.IHostedZone")
class IHostedZone(_IResource_c80c4260, typing_extensions.Protocol):
    '''Imported or created hosted zone.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneArn")
    def hosted_zone_arn(self) -> builtins.str:
        '''ARN of this hosted zone, such as arn:${Partition}:route53:::hostedzone/${Id}.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneId")
    def hosted_zone_id(self) -> builtins.str:
        '''ID of this hosted zone, such as "Z23ABC4XYZL05B".

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="zoneName")
    def zone_name(self) -> builtins.str:
        '''FQDN of this hosted zone.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneNameServers")
    def hosted_zone_name_servers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Returns the set of name servers for the specific hosted zone. For example: ns1.example.com.

        This attribute will be undefined for private hosted zones or hosted zones imported from another stack.

        :attribute: true
        '''
        ...


class _IHostedZoneProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Imported or created hosted zone.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_route53.IHostedZone"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneArn")
    def hosted_zone_arn(self) -> builtins.str:
        '''ARN of this hosted zone, such as arn:${Partition}:route53:::hostedzone/${Id}.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "hostedZoneArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneId")
    def hosted_zone_id(self) -> builtins.str:
        '''ID of this hosted zone, such as "Z23ABC4XYZL05B".

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "hostedZoneId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="zoneName")
    def zone_name(self) -> builtins.str:
        '''FQDN of this hosted zone.'''
        return typing.cast(builtins.str, jsii.get(self, "zoneName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneNameServers")
    def hosted_zone_name_servers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Returns the set of name servers for the specific hosted zone. For example: ns1.example.com.

        This attribute will be undefined for private hosted zones or hosted zones imported from another stack.

        :attribute: true
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "hostedZoneNameServers"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IHostedZone).__jsii_proxy_class__ = lambda : _IHostedZoneProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_route53.IPrivateHostedZone")
class IPrivateHostedZone(IHostedZone, typing_extensions.Protocol):
    '''Represents a Route 53 private hosted zone.'''

    pass


class _IPrivateHostedZoneProxy(
    jsii.proxy_for(IHostedZone) # type: ignore[misc]
):
    '''Represents a Route 53 private hosted zone.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_route53.IPrivateHostedZone"
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IPrivateHostedZone).__jsii_proxy_class__ = lambda : _IPrivateHostedZoneProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_route53.IPublicHostedZone")
class IPublicHostedZone(IHostedZone, typing_extensions.Protocol):
    '''Represents a Route 53 public hosted zone.'''

    pass


class _IPublicHostedZoneProxy(
    jsii.proxy_for(IHostedZone) # type: ignore[misc]
):
    '''Represents a Route 53 public hosted zone.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_route53.IPublicHostedZone"
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IPublicHostedZone).__jsii_proxy_class__ = lambda : _IPublicHostedZoneProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_route53.IRecordSet")
class IRecordSet(_IResource_c80c4260, typing_extensions.Protocol):
    '''A record set.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The domain name of the record.'''
        ...


class _IRecordSetProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A record set.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_route53.IRecordSet"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The domain name of the record.'''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IRecordSet).__jsii_proxy_class__ = lambda : _IRecordSetProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.MxRecordValue",
    jsii_struct_bases=[],
    name_mapping={"host_name": "hostName", "priority": "priority"},
)
class MxRecordValue:
    def __init__(self, *, host_name: builtins.str, priority: jsii.Number) -> None:
        '''Properties for a MX record value.

        :param host_name: The mail server host name.
        :param priority: The priority.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            mx_record_value = route53.MxRecordValue(
                host_name="hostName",
                priority=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "host_name": host_name,
            "priority": priority,
        }

    @builtins.property
    def host_name(self) -> builtins.str:
        '''The mail server host name.'''
        result = self._values.get("host_name")
        assert result is not None, "Required property 'host_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def priority(self) -> jsii.Number:
        '''The priority.'''
        result = self._values.get("priority")
        assert result is not None, "Required property 'priority' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MxRecordValue(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.PrivateHostedZoneProps",
    jsii_struct_bases=[CommonHostedZoneProps],
    name_mapping={
        "zone_name": "zoneName",
        "comment": "comment",
        "query_logs_log_group_arn": "queryLogsLogGroupArn",
        "vpc": "vpc",
    },
)
class PrivateHostedZoneProps(CommonHostedZoneProps):
    def __init__(
        self,
        *,
        zone_name: builtins.str,
        comment: typing.Optional[builtins.str] = None,
        query_logs_log_group_arn: typing.Optional[builtins.str] = None,
        vpc: _IVpc_f30d5663,
    ) -> None:
        '''Properties to create a Route 53 private hosted zone.

        :param zone_name: The name of the domain. For resource record types that include a domain name, specify a fully qualified domain name.
        :param comment: Any comments that you want to include about the hosted zone. Default: none
        :param query_logs_log_group_arn: The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to. Default: disabled
        :param vpc: A VPC that you want to associate with this hosted zone. Private hosted zones must be associated with at least one VPC. You can associated additional VPCs using ``addVpc(vpc)``.

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            
            
            zone = route53.PrivateHostedZone(self, "HostedZone",
                zone_name="fully.qualified.domain.com",
                vpc=vpc
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone_name": zone_name,
            "vpc": vpc,
        }
        if comment is not None:
            self._values["comment"] = comment
        if query_logs_log_group_arn is not None:
            self._values["query_logs_log_group_arn"] = query_logs_log_group_arn

    @builtins.property
    def zone_name(self) -> builtins.str:
        '''The name of the domain.

        For resource record types that include a domain
        name, specify a fully qualified domain name.
        '''
        result = self._values.get("zone_name")
        assert result is not None, "Required property 'zone_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''Any comments that you want to include about the hosted zone.

        :default: none
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def query_logs_log_group_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to.

        :default: disabled
        '''
        result = self._values.get("query_logs_log_group_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''A VPC that you want to associate with this hosted zone.

        Private hosted zones must be associated with at least one VPC. You can
        associated additional VPCs using ``addVpc(vpc)``.
        '''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PrivateHostedZoneProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.PublicHostedZoneProps",
    jsii_struct_bases=[CommonHostedZoneProps],
    name_mapping={
        "zone_name": "zoneName",
        "comment": "comment",
        "query_logs_log_group_arn": "queryLogsLogGroupArn",
        "caa_amazon": "caaAmazon",
        "cross_account_zone_delegation_principal": "crossAccountZoneDelegationPrincipal",
        "cross_account_zone_delegation_role_name": "crossAccountZoneDelegationRoleName",
    },
)
class PublicHostedZoneProps(CommonHostedZoneProps):
    def __init__(
        self,
        *,
        zone_name: builtins.str,
        comment: typing.Optional[builtins.str] = None,
        query_logs_log_group_arn: typing.Optional[builtins.str] = None,
        caa_amazon: typing.Optional[builtins.bool] = None,
        cross_account_zone_delegation_principal: typing.Optional[_IPrincipal_539bb2fd] = None,
        cross_account_zone_delegation_role_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Construction properties for a PublicHostedZone.

        :param zone_name: The name of the domain. For resource record types that include a domain name, specify a fully qualified domain name.
        :param comment: Any comments that you want to include about the hosted zone. Default: none
        :param query_logs_log_group_arn: The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to. Default: disabled
        :param caa_amazon: Whether to create a CAA record to restrict certificate authorities allowed to issue certificates for this domain to Amazon only. Default: false
        :param cross_account_zone_delegation_principal: A principal which is trusted to assume a role for zone delegation. Default: - No delegation configuration
        :param cross_account_zone_delegation_role_name: The name of the role created for cross account delegation. Default: - A role name is generated automatically

        :exampleMetadata: infused

        Example::

            parent_zone = route53.PublicHostedZone(self, "HostedZone",
                zone_name="someexample.com",
                cross_account_zone_delegation_principal=iam.AccountPrincipal("12345678901"),
                cross_account_zone_delegation_role_name="MyDelegationRole"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone_name": zone_name,
        }
        if comment is not None:
            self._values["comment"] = comment
        if query_logs_log_group_arn is not None:
            self._values["query_logs_log_group_arn"] = query_logs_log_group_arn
        if caa_amazon is not None:
            self._values["caa_amazon"] = caa_amazon
        if cross_account_zone_delegation_principal is not None:
            self._values["cross_account_zone_delegation_principal"] = cross_account_zone_delegation_principal
        if cross_account_zone_delegation_role_name is not None:
            self._values["cross_account_zone_delegation_role_name"] = cross_account_zone_delegation_role_name

    @builtins.property
    def zone_name(self) -> builtins.str:
        '''The name of the domain.

        For resource record types that include a domain
        name, specify a fully qualified domain name.
        '''
        result = self._values.get("zone_name")
        assert result is not None, "Required property 'zone_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''Any comments that you want to include about the hosted zone.

        :default: none
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def query_logs_log_group_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to.

        :default: disabled
        '''
        result = self._values.get("query_logs_log_group_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def caa_amazon(self) -> typing.Optional[builtins.bool]:
        '''Whether to create a CAA record to restrict certificate authorities allowed to issue certificates for this domain to Amazon only.

        :default: false
        '''
        result = self._values.get("caa_amazon")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def cross_account_zone_delegation_principal(
        self,
    ) -> typing.Optional[_IPrincipal_539bb2fd]:
        '''A principal which is trusted to assume a role for zone delegation.

        :default: - No delegation configuration
        '''
        result = self._values.get("cross_account_zone_delegation_principal")
        return typing.cast(typing.Optional[_IPrincipal_539bb2fd], result)

    @builtins.property
    def cross_account_zone_delegation_role_name(self) -> typing.Optional[builtins.str]:
        '''The name of the role created for cross account delegation.

        :default: - A role name is generated automatically
        '''
        result = self._values.get("cross_account_zone_delegation_role_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PublicHostedZoneProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IRecordSet)
class RecordSet(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.RecordSet",
):
    '''A record set.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_route53 as route53
        
        # hosted_zone: route53.HostedZone
        # record_target: route53.RecordTarget
        
        record_set = route53.RecordSet(self, "MyRecordSet",
            record_type=route53.RecordType.A,
            target=record_target,
            zone=hosted_zone,
        
            # the properties below are optional
            comment="comment",
            record_name="recordName",
            ttl=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        record_type: "RecordType",
        target: "RecordTarget",
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param record_type: The record type.
        :param target: The target for this record, either ``RecordTarget.fromValues()`` or ``RecordTarget.fromAlias()``.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = RecordSetProps(
            record_type=record_type,
            target=target,
            zone=zone,
            comment=comment,
            record_name=record_name,
            ttl=ttl,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The domain name of the record.'''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.RecordSetOptions",
    jsii_struct_bases=[],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
    },
)
class RecordSetOptions:
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Options for a RecordSet.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            
            record_set_options = route53.RecordSetOptions(
                zone=hosted_zone,
            
                # the properties below are optional
                comment="comment",
                record_name="recordName",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RecordSetOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.RecordSetProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "record_type": "recordType",
        "target": "target",
    },
)
class RecordSetProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        record_type: "RecordType",
        target: "RecordTarget",
    ) -> None:
        '''Construction properties for a RecordSet.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param record_type: The record type.
        :param target: The target for this record, either ``RecordTarget.fromValues()`` or ``RecordTarget.fromAlias()``.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            # record_target: route53.RecordTarget
            
            record_set_props = route53.RecordSetProps(
                record_type=route53.RecordType.A,
                target=record_target,
                zone=hosted_zone,
            
                # the properties below are optional
                comment="comment",
                record_name="recordName",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "record_type": record_type,
            "target": target,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def record_type(self) -> "RecordType":
        '''The record type.'''
        result = self._values.get("record_type")
        assert result is not None, "Required property 'record_type' is missing"
        return typing.cast("RecordType", result)

    @builtins.property
    def target(self) -> "RecordTarget":
        '''The target for this record, either ``RecordTarget.fromValues()`` or ``RecordTarget.fromAlias()``.'''
        result = self._values.get("target")
        assert result is not None, "Required property 'target' is missing"
        return typing.cast("RecordTarget", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RecordSetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class RecordTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.RecordTarget",
):
    '''Type union for a record that accepts multiple types of target.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_cloudfront as cloudfront
        
        # my_zone: route53.HostedZone
        # distribution: cloudfront.CloudFrontWebDistribution
        
        route53.AaaaRecord(self, "Alias",
            zone=my_zone,
            target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(distribution))
        )
    '''

    def __init__(
        self,
        values: typing.Optional[typing.Sequence[builtins.str]] = None,
        alias_target: typing.Optional[IAliasRecordTarget] = None,
    ) -> None:
        '''
        :param values: correspond with the chosen record type (e.g. for 'A' Type, specify one or more IP addresses).
        :param alias_target: alias for targets such as CloudFront distribution to route traffic to.
        '''
        jsii.create(self.__class__, self, [values, alias_target])

    @jsii.member(jsii_name="fromAlias") # type: ignore[misc]
    @builtins.classmethod
    def from_alias(cls, alias_target: IAliasRecordTarget) -> "RecordTarget":
        '''Use an alias as target.

        :param alias_target: -
        '''
        return typing.cast("RecordTarget", jsii.sinvoke(cls, "fromAlias", [alias_target]))

    @jsii.member(jsii_name="fromIpAddresses") # type: ignore[misc]
    @builtins.classmethod
    def from_ip_addresses(cls, *ip_addresses: builtins.str) -> "RecordTarget":
        '''Use ip addresses as target.

        :param ip_addresses: -
        '''
        return typing.cast("RecordTarget", jsii.sinvoke(cls, "fromIpAddresses", [*ip_addresses]))

    @jsii.member(jsii_name="fromValues") # type: ignore[misc]
    @builtins.classmethod
    def from_values(cls, *values: builtins.str) -> "RecordTarget":
        '''Use string values as target.

        :param values: -
        '''
        return typing.cast("RecordTarget", jsii.sinvoke(cls, "fromValues", [*values]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="aliasTarget")
    def alias_target(self) -> typing.Optional[IAliasRecordTarget]:
        '''alias for targets such as CloudFront distribution to route traffic to.'''
        return typing.cast(typing.Optional[IAliasRecordTarget], jsii.get(self, "aliasTarget"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="values")
    def values(self) -> typing.Optional[typing.List[builtins.str]]:
        '''correspond with the chosen record type (e.g. for 'A' Type, specify one or more IP addresses).'''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "values"))


@jsii.enum(jsii_type="aws-cdk-lib.aws_route53.RecordType")
class RecordType(enum.Enum):
    '''The record type.'''

    A = "A"
    '''route traffic to a resource, such as a web server, using an IPv4 address in dotted decimal notation.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#AFormat
    '''
    AAAA = "AAAA"
    '''route traffic to a resource, such as a web server, using an IPv6 address in colon-separated hexadecimal format.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#AAAAFormat
    '''
    CAA = "CAA"
    '''A CAA record specifies which certificate authorities (CAs) are allowed to issue certificates for a domain or subdomain.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#CAAFormat
    '''
    CNAME = "CNAME"
    '''A CNAME record maps DNS queries for the name of the current record, such as acme.example.com, to another domain (example.com or example.net) or subdomain (acme.example.com or zenith.example.org).

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#CNAMEFormat
    '''
    DS = "DS"
    '''A delegation signer (DS) record refers a zone key for a delegated subdomain zone.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#DSFormat
    '''
    MX = "MX"
    '''An MX record specifies the names of your mail servers and, if you have two or more mail servers, the priority order.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#MXFormat
    '''
    NAPTR = "NAPTR"
    '''A Name Authority Pointer (NAPTR) is a type of record that is used by Dynamic Delegation Discovery System (DDDS) applications to convert one value to another or to replace one value with another.

    For example, one common use is to convert phone numbers into SIP URIs.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#NAPTRFormat
    '''
    NS = "NS"
    '''An NS record identifies the name servers for the hosted zone.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#NSFormat
    '''
    PTR = "PTR"
    '''A PTR record maps an IP address to the corresponding domain name.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#PTRFormat
    '''
    SOA = "SOA"
    '''A start of authority (SOA) record provides information about a domain and the corresponding Amazon Route 53 hosted zone.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#SOAFormat
    '''
    SPF = "SPF"
    '''SPF records were formerly used to verify the identity of the sender of email messages.

    Instead of an SPF record, we recommend that you create a TXT record that contains the applicable value.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#SPFFormat
    '''
    SRV = "SRV"
    '''An SRV record Value element consists of four space-separated values.

    The first three values are
    decimal numbers representing priority, weight, and port. The fourth value is a domain name.

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#SRVFormat
    '''
    TXT = "TXT"
    '''A TXT record contains one or more strings that are enclosed in double quotation marks (").

    :see: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html#TXTFormat
    '''


class SrvRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.SrvRecord",
):
    '''A DNS SRV record.

    :resource: AWS::Route53::RecordSet
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_route53 as route53
        
        # hosted_zone: route53.HostedZone
        
        srv_record = route53.SrvRecord(self, "MySrvRecord",
            values=[route53.SrvRecordValue(
                host_name="hostName",
                port=123,
                priority=123,
                weight=123
            )],
            zone=hosted_zone,
        
            # the properties below are optional
            comment="comment",
            record_name="recordName",
            ttl=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        values: typing.Sequence["SrvRecordValue"],
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param values: The values.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = SrvRecordProps(
            values=values, zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.SrvRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "values": "values",
    },
)
class SrvRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Sequence["SrvRecordValue"],
    ) -> None:
        '''Construction properties for a SrvRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param values: The values.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            
            srv_record_props = route53.SrvRecordProps(
                values=[route53.SrvRecordValue(
                    host_name="hostName",
                    port=123,
                    priority=123,
                    weight=123
                )],
                zone=hosted_zone,
            
                # the properties below are optional
                comment="comment",
                record_name="recordName",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "values": values,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def values(self) -> typing.List["SrvRecordValue"]:
        '''The values.'''
        result = self._values.get("values")
        assert result is not None, "Required property 'values' is missing"
        return typing.cast(typing.List["SrvRecordValue"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SrvRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.SrvRecordValue",
    jsii_struct_bases=[],
    name_mapping={
        "host_name": "hostName",
        "port": "port",
        "priority": "priority",
        "weight": "weight",
    },
)
class SrvRecordValue:
    def __init__(
        self,
        *,
        host_name: builtins.str,
        port: jsii.Number,
        priority: jsii.Number,
        weight: jsii.Number,
    ) -> None:
        '''Properties for a SRV record value.

        :param host_name: The server host name.
        :param port: The port.
        :param priority: The priority.
        :param weight: The weight.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_route53 as route53
            
            srv_record_value = route53.SrvRecordValue(
                host_name="hostName",
                port=123,
                priority=123,
                weight=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "host_name": host_name,
            "port": port,
            "priority": priority,
            "weight": weight,
        }

    @builtins.property
    def host_name(self) -> builtins.str:
        '''The server host name.'''
        result = self._values.get("host_name")
        assert result is not None, "Required property 'host_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def port(self) -> jsii.Number:
        '''The port.'''
        result = self._values.get("port")
        assert result is not None, "Required property 'port' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def priority(self) -> jsii.Number:
        '''The priority.'''
        result = self._values.get("priority")
        assert result is not None, "Required property 'priority' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def weight(self) -> jsii.Number:
        '''The weight.'''
        result = self._values.get("weight")
        assert result is not None, "Required property 'weight' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SrvRecordValue(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class TxtRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.TxtRecord",
):
    '''A DNS TXT record.

    :exampleMetadata: infused
    :resource: AWS::Route53::RecordSet

    Example::

        # my_zone: route53.HostedZone
        
        
        route53.TxtRecord(self, "TXTRecord",
            zone=my_zone,
            record_name="_foo",  # If the name ends with a ".", it will be used as-is;
            # if it ends with a "." followed by the zone name, a trailing "." will be added automatically;
            # otherwise, a ".", the zone name, and a trailing "." will be added automatically.
            # Defaults to zone root if not specified.
            values=["Bar!", "Baz?"],
            ttl=Duration.minutes(90)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        values: typing.Sequence[builtins.str],
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param values: The text values.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = TxtRecordProps(
            values=values, zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.TxtRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "values": "values",
    },
)
class TxtRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Sequence[builtins.str],
    ) -> None:
        '''Construction properties for a TxtRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param values: The text values.

        :exampleMetadata: infused

        Example::

            # my_zone: route53.HostedZone
            
            
            route53.TxtRecord(self, "TXTRecord",
                zone=my_zone,
                record_name="_foo",  # If the name ends with a ".", it will be used as-is;
                # if it ends with a "." followed by the zone name, a trailing "." will be added automatically;
                # otherwise, a ".", the zone name, and a trailing "." will be added automatically.
                # Defaults to zone root if not specified.
                values=["Bar!", "Baz?"],
                ttl=Duration.minutes(90)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "values": values,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def values(self) -> typing.List[builtins.str]:
        '''The text values.'''
        result = self._values.get("values")
        assert result is not None, "Required property 'values' is missing"
        return typing.cast(typing.List[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TxtRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class VpcEndpointServiceDomainName(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.VpcEndpointServiceDomainName",
):
    '''A Private DNS configuration for a VPC endpoint service.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        from aws_cdk.aws_route53 import HostedZone, VpcEndpointServiceDomainName
        # zone: HostedZone
        # vpces: ec2.VpcEndpointService
        
        
        VpcEndpointServiceDomainName(self, "EndpointDomain",
            endpoint_service=vpces,
            domain_name="my-stuff.aws-cdk.dev",
            public_hosted_zone=zone
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain_name: builtins.str,
        endpoint_service: _IVpcEndpointService_4ddddab0,
        public_hosted_zone: IPublicHostedZone,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param domain_name: The domain name to use. This domain name must be owned by this account (registered through Route53), or delegated to this account. Domain ownership will be verified by AWS before private DNS can be used.
        :param endpoint_service: The VPC Endpoint Service to configure Private DNS for.
        :param public_hosted_zone: The public hosted zone to use for the domain.
        '''
        props = VpcEndpointServiceDomainNameProps(
            domain_name=domain_name,
            endpoint_service=endpoint_service,
            public_hosted_zone=public_hosted_zone,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The domain name associated with the private DNS configuration.'''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

    @domain_name.setter
    def domain_name(self, value: builtins.str) -> None:
        jsii.set(self, "domainName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.VpcEndpointServiceDomainNameProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain_name": "domainName",
        "endpoint_service": "endpointService",
        "public_hosted_zone": "publicHostedZone",
    },
)
class VpcEndpointServiceDomainNameProps:
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        endpoint_service: _IVpcEndpointService_4ddddab0,
        public_hosted_zone: IPublicHostedZone,
    ) -> None:
        '''Properties to configure a VPC Endpoint Service domain name.

        :param domain_name: The domain name to use. This domain name must be owned by this account (registered through Route53), or delegated to this account. Domain ownership will be verified by AWS before private DNS can be used.
        :param endpoint_service: The VPC Endpoint Service to configure Private DNS for.
        :param public_hosted_zone: The public hosted zone to use for the domain.

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            from aws_cdk.aws_route53 import HostedZone, VpcEndpointServiceDomainName
            # zone: HostedZone
            # vpces: ec2.VpcEndpointService
            
            
            VpcEndpointServiceDomainName(self, "EndpointDomain",
                endpoint_service=vpces,
                domain_name="my-stuff.aws-cdk.dev",
                public_hosted_zone=zone
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
            "endpoint_service": endpoint_service,
            "public_hosted_zone": public_hosted_zone,
        }

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The domain name to use.

        This domain name must be owned by this account (registered through Route53),
        or delegated to this account. Domain ownership will be verified by AWS before
        private DNS can be used.

        :see: https://docs.aws.amazon.com/vpc/latest/userguide/endpoint-services-dns-validation.html
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def endpoint_service(self) -> _IVpcEndpointService_4ddddab0:
        '''The VPC Endpoint Service to configure Private DNS for.'''
        result = self._values.get("endpoint_service")
        assert result is not None, "Required property 'endpoint_service' is missing"
        return typing.cast(_IVpcEndpointService_4ddddab0, result)

    @builtins.property
    def public_hosted_zone(self) -> IPublicHostedZone:
        '''The public hosted zone to use for the domain.'''
        result = self._values.get("public_hosted_zone")
        assert result is not None, "Required property 'public_hosted_zone' is missing"
        return typing.cast(IPublicHostedZone, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VpcEndpointServiceDomainNameProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.ZoneDelegationOptions",
    jsii_struct_bases=[],
    name_mapping={"comment": "comment", "ttl": "ttl"},
)
class ZoneDelegationOptions:
    def __init__(
        self,
        *,
        comment: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Options available when creating a delegation relationship from one PublicHostedZone to another.

        :param comment: A comment to add on the DNS record created to incorporate the delegation. Default: none
        :param ttl: The TTL (Time To Live) of the DNS delegation record in DNS caches. Default: 172800

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            zone_delegation_options = route53.ZoneDelegationOptions(
                comment="comment",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if comment is not None:
            self._values["comment"] = comment
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the DNS record created to incorporate the delegation.

        :default: none
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The TTL (Time To Live) of the DNS delegation record in DNS caches.

        :default: 172800
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ZoneDelegationOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ZoneDelegationRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.ZoneDelegationRecord",
):
    '''A record to delegate further lookups to a different set of name servers.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_route53 as route53
        
        # hosted_zone: route53.HostedZone
        
        zone_delegation_record = route53.ZoneDelegationRecord(self, "MyZoneDelegationRecord",
            name_servers=["nameServers"],
            zone=hosted_zone,
        
            # the properties below are optional
            comment="comment",
            record_name="recordName",
            ttl=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name_servers: typing.Sequence[builtins.str],
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param name_servers: The name servers to report in the delegation records.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = ZoneDelegationRecordProps(
            name_servers=name_servers,
            zone=zone,
            comment=comment,
            record_name=record_name,
            ttl=ttl,
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.ZoneDelegationRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "name_servers": "nameServers",
    },
)
class ZoneDelegationRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        name_servers: typing.Sequence[builtins.str],
    ) -> None:
        '''Construction properties for a ZoneDelegationRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param name_servers: The name servers to report in the delegation records.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            
            zone_delegation_record_props = route53.ZoneDelegationRecordProps(
                name_servers=["nameServers"],
                zone=hosted_zone,
            
                # the properties below are optional
                comment="comment",
                record_name="recordName",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "name_servers": name_servers,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def name_servers(self) -> typing.List[builtins.str]:
        '''The name servers to report in the delegation records.'''
        result = self._values.get("name_servers")
        assert result is not None, "Required property 'name_servers' is missing"
        return typing.cast(typing.List[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ZoneDelegationRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ARecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.ARecord",
):
    '''A DNS A record.

    :exampleMetadata: infused
    :resource: AWS::Route53::RecordSet

    Example::

        import aws_cdk.aws_apigateway as apigw
        
        # zone: route53.HostedZone
        # rest_api: apigw.LambdaRestApi
        
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.ApiGateway(rest_api))
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        target: RecordTarget,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param target: The target.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = ARecordProps(
            target=target, zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.ARecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "target": "target",
    },
)
class ARecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        target: RecordTarget,
    ) -> None:
        '''Construction properties for a ARecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param target: The target.

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_apigateway as apigw
            
            # zone: route53.HostedZone
            # rest_api: apigw.LambdaRestApi
            
            
            route53.ARecord(self, "AliasRecord",
                zone=zone,
                target=route53.RecordTarget.from_alias(targets.ApiGateway(rest_api))
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "target": target,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def target(self) -> RecordTarget:
        '''The target.'''
        result = self._values.get("target")
        assert result is not None, "Required property 'target' is missing"
        return typing.cast(RecordTarget, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ARecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class AaaaRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.AaaaRecord",
):
    '''A DNS AAAA record.

    :exampleMetadata: infused
    :resource: AWS::Route53::RecordSet

    Example::

        import aws_cdk.aws_cloudfront as cloudfront
        
        # my_zone: route53.HostedZone
        # distribution: cloudfront.CloudFrontWebDistribution
        
        route53.AaaaRecord(self, "Alias",
            zone=my_zone,
            target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(distribution))
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        target: RecordTarget,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param target: The target.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = AaaaRecordProps(
            target=target, zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.AaaaRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "target": "target",
    },
)
class AaaaRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        target: RecordTarget,
    ) -> None:
        '''Construction properties for a AaaaRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param target: The target.

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_cloudfront as cloudfront
            
            # my_zone: route53.HostedZone
            # distribution: cloudfront.CloudFrontWebDistribution
            
            route53.AaaaRecord(self, "Alias",
                zone=my_zone,
                target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(distribution))
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "target": target,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def target(self) -> RecordTarget:
        '''The target.'''
        result = self._values.get("target")
        assert result is not None, "Required property 'target' is missing"
        return typing.cast(RecordTarget, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AaaaRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CaaAmazonRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
    },
)
class CaaAmazonRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Construction properties for a CaaAmazonRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            
            caa_amazon_record_props = route53.CaaAmazonRecordProps(
                zone=hosted_zone,
            
                # the properties below are optional
                comment="comment",
                record_name="recordName",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CaaAmazonRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class CaaRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CaaRecord",
):
    '''A DNS CAA record.

    :resource: AWS::Route53::RecordSet
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_route53 as route53
        
        # hosted_zone: route53.HostedZone
        
        caa_record = route53.CaaRecord(self, "MyCaaRecord",
            values=[route53.CaaRecordValue(
                flag=123,
                tag=route53.CaaTag.ISSUE,
                value="value"
            )],
            zone=hosted_zone,
        
            # the properties below are optional
            comment="comment",
            record_name="recordName",
            ttl=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        values: typing.Sequence[CaaRecordValue],
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param values: The values.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = CaaRecordProps(
            values=values, zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CaaRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "values": "values",
    },
)
class CaaRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Sequence[CaaRecordValue],
    ) -> None:
        '''Construction properties for a CaaRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param values: The values.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            
            caa_record_props = route53.CaaRecordProps(
                values=[route53.CaaRecordValue(
                    flag=123,
                    tag=route53.CaaTag.ISSUE,
                    value="value"
                )],
                zone=hosted_zone,
            
                # the properties below are optional
                comment="comment",
                record_name="recordName",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "values": values,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def values(self) -> typing.List[CaaRecordValue]:
        '''The values.'''
        result = self._values.get("values")
        assert result is not None, "Required property 'values' is missing"
        return typing.cast(typing.List[CaaRecordValue], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CaaRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class CnameRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CnameRecord",
):
    '''A DNS CNAME record.

    :resource: AWS::Route53::RecordSet
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_route53 as route53
        
        # hosted_zone: route53.HostedZone
        
        cname_record = route53.CnameRecord(self, "MyCnameRecord",
            domain_name="domainName",
            zone=hosted_zone,
        
            # the properties below are optional
            comment="comment",
            record_name="recordName",
            ttl=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain_name: builtins.str,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param domain_name: The domain name.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = CnameRecordProps(
            domain_name=domain_name,
            zone=zone,
            comment=comment,
            record_name=record_name,
            ttl=ttl,
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.CnameRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "domain_name": "domainName",
    },
)
class CnameRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        domain_name: builtins.str,
    ) -> None:
        '''Construction properties for a CnameRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param domain_name: The domain name.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            
            cname_record_props = route53.CnameRecordProps(
                domain_name="domainName",
                zone=hosted_zone,
            
                # the properties below are optional
                comment="comment",
                record_name="recordName",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "domain_name": domain_name,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The domain name.'''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CnameRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class DsRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.DsRecord",
):
    '''A DNS DS record.

    :exampleMetadata: infused
    :resource: AWS::Route53::RecordSet

    Example::

        # my_zone: route53.HostedZone
        
        
        route53.DsRecord(self, "DSRecord",
            zone=my_zone,
            record_name="foo",
            values=["12345 3 1 123456789abcdef67890123456789abcdef67890"
            ],
            ttl=Duration.minutes(90)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        values: typing.Sequence[builtins.str],
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param values: The DS values.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = DsRecordProps(
            values=values, zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.DsRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "values": "values",
    },
)
class DsRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Sequence[builtins.str],
    ) -> None:
        '''Construction properties for a DSRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param values: The DS values.

        :exampleMetadata: infused

        Example::

            # my_zone: route53.HostedZone
            
            
            route53.DsRecord(self, "DSRecord",
                zone=my_zone,
                record_name="foo",
                values=["12345 3 1 123456789abcdef67890123456789abcdef67890"
                ],
                ttl=Duration.minutes(90)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "values": values,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def values(self) -> typing.List[builtins.str]:
        '''The DS values.'''
        result = self._values.get("values")
        assert result is not None, "Required property 'values' is missing"
        return typing.cast(typing.List[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DsRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IHostedZone)
class HostedZone(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.HostedZone",
):
    '''Container for records, and records contain information about how to route traffic for a specific domain, such as example.com and its subdomains (acme.example.com, zenith.example.com).

    :exampleMetadata: infused

    Example::

        my_hosted_zone = route53.HostedZone(self, "HostedZone",
            zone_name="example.com"
        )
        acm.Certificate(self, "Certificate",
            domain_name="hello.example.com",
            validation=acm.CertificateValidation.from_dns(my_hosted_zone)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        vpcs: typing.Optional[typing.Sequence[_IVpc_f30d5663]] = None,
        zone_name: builtins.str,
        comment: typing.Optional[builtins.str] = None,
        query_logs_log_group_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param vpcs: A VPC that you want to associate with this hosted zone. When you specify this property, a private hosted zone will be created. You can associate additional VPCs to this private zone using ``addVpc(vpc)``. Default: public (no VPCs associated)
        :param zone_name: The name of the domain. For resource record types that include a domain name, specify a fully qualified domain name.
        :param comment: Any comments that you want to include about the hosted zone. Default: none
        :param query_logs_log_group_arn: The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to. Default: disabled
        '''
        props = HostedZoneProps(
            vpcs=vpcs,
            zone_name=zone_name,
            comment=comment,
            query_logs_log_group_arn=query_logs_log_group_arn,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromHostedZoneAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_hosted_zone_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        hosted_zone_id: builtins.str,
        zone_name: builtins.str,
    ) -> IHostedZone:
        '''Imports a hosted zone from another stack.

        Use when both hosted zone ID and hosted zone name are known.

        :param scope: the parent Construct for this Construct.
        :param id: the logical name of this Construct.
        :param hosted_zone_id: Identifier of the hosted zone.
        :param zone_name: Name of the hosted zone.
        '''
        attrs = HostedZoneAttributes(
            hosted_zone_id=hosted_zone_id, zone_name=zone_name
        )

        return typing.cast(IHostedZone, jsii.sinvoke(cls, "fromHostedZoneAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromHostedZoneId") # type: ignore[misc]
    @builtins.classmethod
    def from_hosted_zone_id(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        hosted_zone_id: builtins.str,
    ) -> IHostedZone:
        '''Import a Route 53 hosted zone defined either outside the CDK, or in a different CDK stack.

        Use when hosted zone ID is known. Hosted zone name becomes unavailable through this query.

        :param scope: the parent Construct for this Construct.
        :param id: the logical name of this Construct.
        :param hosted_zone_id: the ID of the hosted zone to import.
        '''
        return typing.cast(IHostedZone, jsii.sinvoke(cls, "fromHostedZoneId", [scope, id, hosted_zone_id]))

    @jsii.member(jsii_name="fromLookup") # type: ignore[misc]
    @builtins.classmethod
    def from_lookup(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain_name: builtins.str,
        private_zone: typing.Optional[builtins.bool] = None,
        vpc_id: typing.Optional[builtins.str] = None,
    ) -> IHostedZone:
        '''Lookup a hosted zone in the current account/region based on query parameters.

        Requires environment, you must specify env for the stack.

        Use to easily query hosted zones.

        :param scope: -
        :param id: -
        :param domain_name: The zone domain e.g. example.com.
        :param private_zone: Whether the zone that is being looked up is a private hosted zone. Default: false
        :param vpc_id: Specifies the ID of the VPC associated with a private hosted zone. If a VPC ID is provided and privateZone is false, no results will be returned and an error will be raised Default: - No VPC ID

        :see: https://docs.aws.amazon.com/cdk/latest/guide/environments.html
        '''
        query = HostedZoneProviderProps(
            domain_name=domain_name, private_zone=private_zone, vpc_id=vpc_id
        )

        return typing.cast(IHostedZone, jsii.sinvoke(cls, "fromLookup", [scope, id, query]))

    @jsii.member(jsii_name="addVpc")
    def add_vpc(self, vpc: _IVpc_f30d5663) -> None:
        '''Add another VPC to this private hosted zone.

        :param vpc: the other VPC to add.
        '''
        return typing.cast(None, jsii.invoke(self, "addVpc", [vpc]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneArn")
    def hosted_zone_arn(self) -> builtins.str:
        '''ARN of this hosted zone, such as arn:${Partition}:route53:::hostedzone/${Id}.'''
        return typing.cast(builtins.str, jsii.get(self, "hostedZoneArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneId")
    def hosted_zone_id(self) -> builtins.str:
        '''ID of this hosted zone, such as "Z23ABC4XYZL05B".'''
        return typing.cast(builtins.str, jsii.get(self, "hostedZoneId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcs")
    def _vpcs(self) -> typing.List[CfnHostedZone.VPCProperty]:
        '''VPCs to which this hosted zone will be added.'''
        return typing.cast(typing.List[CfnHostedZone.VPCProperty], jsii.get(self, "vpcs"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="zoneName")
    def zone_name(self) -> builtins.str:
        '''FQDN of this hosted zone.'''
        return typing.cast(builtins.str, jsii.get(self, "zoneName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedZoneNameServers")
    def hosted_zone_name_servers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Returns the set of name servers for the specific hosted zone. For example: ns1.example.com.

        This attribute will be undefined for private hosted zones or hosted zones imported from another stack.
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "hostedZoneNameServers"))


class MxRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.MxRecord",
):
    '''A DNS MX record.

    :resource: AWS::Route53::RecordSet
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_route53 as route53
        
        # hosted_zone: route53.HostedZone
        
        mx_record = route53.MxRecord(self, "MyMxRecord",
            values=[route53.MxRecordValue(
                host_name="hostName",
                priority=123
            )],
            zone=hosted_zone,
        
            # the properties below are optional
            comment="comment",
            record_name="recordName",
            ttl=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        values: typing.Sequence[MxRecordValue],
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param values: The values.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = MxRecordProps(
            values=values, zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.MxRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "values": "values",
    },
)
class MxRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Sequence[MxRecordValue],
    ) -> None:
        '''Construction properties for a MxRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param values: The values.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            
            mx_record_props = route53.MxRecordProps(
                values=[route53.MxRecordValue(
                    host_name="hostName",
                    priority=123
                )],
                zone=hosted_zone,
            
                # the properties below are optional
                comment="comment",
                record_name="recordName",
                ttl=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "values": values,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def values(self) -> typing.List[MxRecordValue]:
        '''The values.'''
        result = self._values.get("values")
        assert result is not None, "Required property 'values' is missing"
        return typing.cast(typing.List[MxRecordValue], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MxRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class NsRecord(
    RecordSet,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.NsRecord",
):
    '''A DNS NS record.

    :exampleMetadata: infused
    :resource: AWS::Route53::RecordSet

    Example::

        # my_zone: route53.HostedZone
        
        
        route53.NsRecord(self, "NSRecord",
            zone=my_zone,
            record_name="foo",
            values=["ns-1.awsdns.co.uk.", "ns-2.awsdns.com."
            ],
            ttl=Duration.minutes(90)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        values: typing.Sequence[builtins.str],
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param values: The NS values.
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = NsRecordProps(
            values=values, zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_route53.NsRecordProps",
    jsii_struct_bases=[RecordSetOptions],
    name_mapping={
        "zone": "zone",
        "comment": "comment",
        "record_name": "recordName",
        "ttl": "ttl",
        "values": "values",
    },
)
class NsRecordProps(RecordSetOptions):
    def __init__(
        self,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Sequence[builtins.str],
    ) -> None:
        '''Construction properties for a NSRecord.

        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        :param values: The NS values.

        :exampleMetadata: infused

        Example::

            # my_zone: route53.HostedZone
            
            
            route53.NsRecord(self, "NSRecord",
                zone=my_zone,
                record_name="foo",
                values=["ns-1.awsdns.co.uk.", "ns-2.awsdns.com."
                ],
                ttl=Duration.minutes(90)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "zone": zone,
            "values": values,
        }
        if comment is not None:
            self._values["comment"] = comment
        if record_name is not None:
            self._values["record_name"] = record_name
        if ttl is not None:
            self._values["ttl"] = ttl

    @builtins.property
    def zone(self) -> IHostedZone:
        '''The hosted zone in which to define the new record.'''
        result = self._values.get("zone")
        assert result is not None, "Required property 'zone' is missing"
        return typing.cast(IHostedZone, result)

    @builtins.property
    def comment(self) -> typing.Optional[builtins.str]:
        '''A comment to add on the record.

        :default: no comment
        '''
        result = self._values.get("comment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def record_name(self) -> typing.Optional[builtins.str]:
        '''The domain name for this record.

        :default: zone root
        '''
        result = self._values.get("record_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ttl(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The resource record cache time to live (TTL).

        :default: Duration.minutes(30)
        '''
        result = self._values.get("ttl")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def values(self) -> typing.List[builtins.str]:
        '''The NS values.'''
        result = self._values.get("values")
        assert result is not None, "Required property 'values' is missing"
        return typing.cast(typing.List[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NsRecordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IPrivateHostedZone)
class PrivateHostedZone(
    HostedZone,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.PrivateHostedZone",
):
    '''Create a Route53 private hosted zone for use in one or more VPCs.

    Note that ``enableDnsHostnames`` and ``enableDnsSupport`` must have been enabled
    for the VPC you're configuring for private hosted zones.

    :exampleMetadata: infused
    :resource: AWS::Route53::HostedZone

    Example::

        # vpc: ec2.Vpc
        
        
        zone = route53.PrivateHostedZone(self, "HostedZone",
            zone_name="fully.qualified.domain.com",
            vpc=vpc
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        vpc: _IVpc_f30d5663,
        zone_name: builtins.str,
        comment: typing.Optional[builtins.str] = None,
        query_logs_log_group_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param vpc: A VPC that you want to associate with this hosted zone. Private hosted zones must be associated with at least one VPC. You can associated additional VPCs using ``addVpc(vpc)``.
        :param zone_name: The name of the domain. For resource record types that include a domain name, specify a fully qualified domain name.
        :param comment: Any comments that you want to include about the hosted zone. Default: none
        :param query_logs_log_group_arn: The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to. Default: disabled
        '''
        props = PrivateHostedZoneProps(
            vpc=vpc,
            zone_name=zone_name,
            comment=comment,
            query_logs_log_group_arn=query_logs_log_group_arn,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromPrivateHostedZoneId") # type: ignore[misc]
    @builtins.classmethod
    def from_private_hosted_zone_id(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        private_hosted_zone_id: builtins.str,
    ) -> IPrivateHostedZone:
        '''Import a Route 53 private hosted zone defined either outside the CDK, or in a different CDK stack.

        :param scope: the parent Construct for this Construct.
        :param id: the logical name of this Construct.
        :param private_hosted_zone_id: the ID of the private hosted zone to import.
        '''
        return typing.cast(IPrivateHostedZone, jsii.sinvoke(cls, "fromPrivateHostedZoneId", [scope, id, private_hosted_zone_id]))


@jsii.implements(IPublicHostedZone)
class PublicHostedZone(
    HostedZone,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.PublicHostedZone",
):
    '''Create a Route53 public hosted zone.

    :exampleMetadata: infused
    :resource: AWS::Route53::HostedZone

    Example::

        parent_zone = route53.PublicHostedZone(self, "HostedZone",
            zone_name="someexample.com",
            cross_account_zone_delegation_principal=iam.AccountPrincipal("12345678901"),
            cross_account_zone_delegation_role_name="MyDelegationRole"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        caa_amazon: typing.Optional[builtins.bool] = None,
        cross_account_zone_delegation_principal: typing.Optional[_IPrincipal_539bb2fd] = None,
        cross_account_zone_delegation_role_name: typing.Optional[builtins.str] = None,
        zone_name: builtins.str,
        comment: typing.Optional[builtins.str] = None,
        query_logs_log_group_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param caa_amazon: Whether to create a CAA record to restrict certificate authorities allowed to issue certificates for this domain to Amazon only. Default: false
        :param cross_account_zone_delegation_principal: A principal which is trusted to assume a role for zone delegation. Default: - No delegation configuration
        :param cross_account_zone_delegation_role_name: The name of the role created for cross account delegation. Default: - A role name is generated automatically
        :param zone_name: The name of the domain. For resource record types that include a domain name, specify a fully qualified domain name.
        :param comment: Any comments that you want to include about the hosted zone. Default: none
        :param query_logs_log_group_arn: The Amazon Resource Name (ARN) for the log group that you want Amazon Route 53 to send query logs to. Default: disabled
        '''
        props = PublicHostedZoneProps(
            caa_amazon=caa_amazon,
            cross_account_zone_delegation_principal=cross_account_zone_delegation_principal,
            cross_account_zone_delegation_role_name=cross_account_zone_delegation_role_name,
            zone_name=zone_name,
            comment=comment,
            query_logs_log_group_arn=query_logs_log_group_arn,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromPublicHostedZoneId") # type: ignore[misc]
    @builtins.classmethod
    def from_public_hosted_zone_id(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        public_hosted_zone_id: builtins.str,
    ) -> IPublicHostedZone:
        '''Import a Route 53 public hosted zone defined either outside the CDK, or in a different CDK stack.

        :param scope: the parent Construct for this Construct.
        :param id: the logical name of this Construct.
        :param public_hosted_zone_id: the ID of the public hosted zone to import.
        '''
        return typing.cast(IPublicHostedZone, jsii.sinvoke(cls, "fromPublicHostedZoneId", [scope, id, public_hosted_zone_id]))

    @jsii.member(jsii_name="addDelegation")
    def add_delegation(
        self,
        delegate: IPublicHostedZone,
        *,
        comment: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Adds a delegation from this zone to a designated zone.

        :param delegate: the zone being delegated to.
        :param comment: A comment to add on the DNS record created to incorporate the delegation. Default: none
        :param ttl: The TTL (Time To Live) of the DNS delegation record in DNS caches. Default: 172800
        '''
        opts = ZoneDelegationOptions(comment=comment, ttl=ttl)

        return typing.cast(None, jsii.invoke(self, "addDelegation", [delegate, opts]))

    @jsii.member(jsii_name="addVpc")
    def add_vpc(self, _vpc: _IVpc_f30d5663) -> None:
        '''Add another VPC to this private hosted zone.

        :param _vpc: -
        '''
        return typing.cast(None, jsii.invoke(self, "addVpc", [_vpc]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="crossAccountZoneDelegationRole")
    def cross_account_zone_delegation_role(self) -> typing.Optional[_Role_e8c6e11f]:
        '''Role for cross account zone delegation.'''
        return typing.cast(typing.Optional[_Role_e8c6e11f], jsii.get(self, "crossAccountZoneDelegationRole"))


class CaaAmazonRecord(
    CaaRecord,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53.CaaAmazonRecord",
):
    '''A DNS Amazon CAA record.

    A CAA record to restrict certificate authorities allowed
    to issue certificates for a domain to Amazon only.

    :resource: AWS::Route53::RecordSet
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_route53 as route53
        
        # hosted_zone: route53.HostedZone
        
        caa_amazon_record = route53.CaaAmazonRecord(self, "MyCaaAmazonRecord",
            zone=hosted_zone,
        
            # the properties below are optional
            comment="comment",
            record_name="recordName",
            ttl=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        zone: IHostedZone,
        comment: typing.Optional[builtins.str] = None,
        record_name: typing.Optional[builtins.str] = None,
        ttl: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param zone: The hosted zone in which to define the new record.
        :param comment: A comment to add on the record. Default: no comment
        :param record_name: The domain name for this record. Default: zone root
        :param ttl: The resource record cache time to live (TTL). Default: Duration.minutes(30)
        '''
        props = CaaAmazonRecordProps(
            zone=zone, comment=comment, record_name=record_name, ttl=ttl
        )

        jsii.create(self.__class__, self, [scope, id, props])


__all__ = [
    "ARecord",
    "ARecordProps",
    "AaaaRecord",
    "AaaaRecordProps",
    "AliasRecordTargetConfig",
    "CaaAmazonRecord",
    "CaaAmazonRecordProps",
    "CaaRecord",
    "CaaRecordProps",
    "CaaRecordValue",
    "CaaTag",
    "CfnDNSSEC",
    "CfnDNSSECProps",
    "CfnHealthCheck",
    "CfnHealthCheckProps",
    "CfnHostedZone",
    "CfnHostedZoneProps",
    "CfnKeySigningKey",
    "CfnKeySigningKeyProps",
    "CfnRecordSet",
    "CfnRecordSetGroup",
    "CfnRecordSetGroupProps",
    "CfnRecordSetProps",
    "CnameRecord",
    "CnameRecordProps",
    "CommonHostedZoneProps",
    "CrossAccountZoneDelegationRecord",
    "CrossAccountZoneDelegationRecordProps",
    "DsRecord",
    "DsRecordProps",
    "HostedZone",
    "HostedZoneAttributes",
    "HostedZoneProps",
    "HostedZoneProviderProps",
    "IAliasRecordTarget",
    "IHostedZone",
    "IPrivateHostedZone",
    "IPublicHostedZone",
    "IRecordSet",
    "MxRecord",
    "MxRecordProps",
    "MxRecordValue",
    "NsRecord",
    "NsRecordProps",
    "PrivateHostedZone",
    "PrivateHostedZoneProps",
    "PublicHostedZone",
    "PublicHostedZoneProps",
    "RecordSet",
    "RecordSetOptions",
    "RecordSetProps",
    "RecordTarget",
    "RecordType",
    "SrvRecord",
    "SrvRecordProps",
    "SrvRecordValue",
    "TxtRecord",
    "TxtRecordProps",
    "VpcEndpointServiceDomainName",
    "VpcEndpointServiceDomainNameProps",
    "ZoneDelegationOptions",
    "ZoneDelegationRecord",
    "ZoneDelegationRecordProps",
]

publication.publish()
