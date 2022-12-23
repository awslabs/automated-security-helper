'''
# Route53 Alias Record Targets for the CDK Route53 Library

This library contains Route53 Alias Record targets for:

* API Gateway custom domains

  ```python
  import aws_cdk.aws_apigateway as apigw

  # zone: route53.HostedZone
  # rest_api: apigw.LambdaRestApi


  route53.ARecord(self, "AliasRecord",
      zone=zone,
      target=route53.RecordTarget.from_alias(targets.ApiGateway(rest_api))
  )
  ```
* API Gateway V2 custom domains

  ```python
  # Example automatically generated from non-compiling source. May contain errors.
  import aws_cdk.aws_apigatewayv2 as apigwv2

  # zone: route53.HostedZone
  # domain_name: apigwv2.DomainName


  route53.ARecord(self, "AliasRecord",
      zone=zone,
      target=route53.RecordTarget.from_alias(targets.ApiGatewayv2DomainProperties(domain_name.regional_domain_name, domain_name.regional_hosted_zone_id))
  )
  ```
* CloudFront distributions

  ```python
  import aws_cdk.aws_cloudfront as cloudfront

  # zone: route53.HostedZone
  # distribution: cloudfront.CloudFrontWebDistribution


  route53.ARecord(self, "AliasRecord",
      zone=zone,
      target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(distribution))
  )
  ```
* ELBv2 load balancers

  ```python
  import aws_cdk.aws_elasticloadbalancingv2 as elbv2

  # zone: route53.HostedZone
  # lb: elbv2.ApplicationLoadBalancer


  route53.ARecord(self, "AliasRecord",
      zone=zone,
      target=route53.RecordTarget.from_alias(targets.LoadBalancerTarget(lb))
  )
  ```
* Classic load balancers

  ```python
  import aws_cdk.aws_elasticloadbalancing as elb

  # zone: route53.HostedZone
  # lb: elb.LoadBalancer


  route53.ARecord(self, "AliasRecord",
      zone=zone,
      target=route53.RecordTarget.from_alias(targets.ClassicLoadBalancerTarget(lb))
  )
  ```

**Important:** Based on [AWS documentation](https://aws.amazon.com/de/premiumsupport/knowledge-center/alias-resource-record-set-route53-cli/), all alias record in Route 53 that points to a Elastic Load Balancer will always include *dualstack* for the DNSName to resolve IPv4/IPv6 addresses (without *dualstack* IPv6 will not resolve).

For example, if the Amazon-provided DNS for the load balancer is `ALB-xxxxxxx.us-west-2.elb.amazonaws.com`, CDK will create alias target in Route 53 will be `dualstack.ALB-xxxxxxx.us-west-2.elb.amazonaws.com`.

* GlobalAccelerator

  ```python
  import aws_cdk.aws_globalaccelerator as globalaccelerator

  # zone: route53.HostedZone
  # accelerator: globalaccelerator.Accelerator


  route53.ARecord(self, "AliasRecord",
      zone=zone,
      target=route53.RecordTarget.from_alias(targets.GlobalAcceleratorTarget(accelerator))
  )
  ```

**Important:** If you use GlobalAcceleratorDomainTarget, passing a string rather than an instance of IAccelerator, ensure that the string is a valid domain name of an existing Global Accelerator instance.
See [the documentation on DNS addressing](https://docs.aws.amazon.com/global-accelerator/latest/dg/dns-addressing-custom-domains.dns-addressing.html) with Global Accelerator for more info.

* InterfaceVpcEndpoints

**Important:** Based on the CFN docs for VPCEndpoints - [see here](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpcendpoint.html#aws-resource-ec2-vpcendpoint-return-values) - the attributes returned for DnsEntries in CloudFormation is a combination of the hosted zone ID and the DNS name. The entries are ordered as follows: regional public DNS, zonal public DNS, private DNS, and wildcard DNS. This order is not enforced for AWS Marketplace services, and therefore this CDK construct is ONLY guaranteed to work with non-marketplace services.

```python
import aws_cdk.aws_ec2 as ec2

# zone: route53.HostedZone
# interface_vpc_endpoint: ec2.InterfaceVpcEndpoint


route53.ARecord(self, "AliasRecord",
    zone=zone,
    target=route53.RecordTarget.from_alias(targets.InterfaceVpcEndpointTarget(interface_vpc_endpoint))
)
```

* S3 Bucket Website:

**Important:** The Bucket name must strictly match the full DNS name.
See [the Developer Guide](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/getting-started.html) for more info.

```python
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
```

* User pool domain

  ```python
  import aws_cdk.aws_cognito as cognito

  # zone: route53.HostedZone
  # domain: cognito.UserPoolDomain

  route53.ARecord(self, "AliasRecord",
      zone=zone,
      target=route53.RecordTarget.from_alias(targets.UserPoolDomainTarget(domain))
  )
  ```
* Route 53 record

  ```python
  # zone: route53.HostedZone
  # record: route53.ARecord

  route53.ARecord(self, "AliasRecord",
      zone=zone,
      target=route53.RecordTarget.from_alias(targets.Route53RecordTarget(record))
  )
  ```
* Elastic Beanstalk environment:

**Important:** Only supports Elastic Beanstalk environments created after 2016 that have a regional endpoint.

```python
# zone: route53.HostedZone
# ebs_environment_url: str


route53.ARecord(self, "AliasRecord",
    zone=zone,
    target=route53.RecordTarget.from_alias(targets.ElasticBeanstalkEnvironmentEndpointTarget(ebs_environment_url))
)
```

See the documentation of `@aws-cdk/aws-route53` for more information.
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
from ..aws_apigateway import (
    IDomainName as _IDomainName_6c4e4c80, RestApiBase as _RestApiBase_0431da32
)
from ..aws_cloudfront import IDistribution as _IDistribution_7ac752a4
from ..aws_cognito import UserPoolDomain as _UserPoolDomain_f402e168
from ..aws_ec2 import IInterfaceVpcEndpoint as _IInterfaceVpcEndpoint_7481aea1
from ..aws_elasticloadbalancing import LoadBalancer as _LoadBalancer_a894d40e
from ..aws_elasticloadbalancingv2 import ILoadBalancerV2 as _ILoadBalancerV2_4c5c0fbb
from ..aws_globalaccelerator import IAccelerator as _IAccelerator_88df59f2
from ..aws_route53 import (
    AliasRecordTargetConfig as _AliasRecordTargetConfig_588f62e9,
    IAliasRecordTarget as _IAliasRecordTarget_aae9327f,
    IHostedZone as _IHostedZone_9a6907ad,
    IRecordSet as _IRecordSet_7d446a82,
)
from ..aws_s3 import IBucket as _IBucket_42e086fd


@jsii.implements(_IAliasRecordTarget_aae9327f)
class ApiGatewayDomain(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.ApiGatewayDomain",
):
    '''Defines an API Gateway domain name as the alias target.

    Use the ``ApiGateway`` class if you wish to map the alias to an REST API with a
    domain name defined through the ``RestApiProps.domainName`` prop.

    :exampleMetadata: infused

    Example::

        # hosted_zone_for_example_com: Any
        # domain_name: apigateway.DomainName
        
        import aws_cdk.aws_route53 as route53
        import aws_cdk.aws_route53_targets as targets
        
        
        route53.ARecord(self, "CustomDomainAliasRecord",
            zone=hosted_zone_for_example_com,
            target=route53.RecordTarget.from_alias(targets.ApiGatewayDomain(domain_name))
        )
    '''

    def __init__(self, domain_name: _IDomainName_6c4e4c80) -> None:
        '''
        :param domain_name: -
        '''
        jsii.create(self.__class__, self, [domain_name])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class ApiGatewayv2DomainProperties(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.ApiGatewayv2DomainProperties",
):
    '''Defines an API Gateway V2 domain name as the alias target.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        import aws_cdk.aws_apigatewayv2 as apigwv2
        
        # zone: route53.HostedZone
        # domain_name: apigwv2.DomainName
        
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.ApiGatewayv2DomainProperties(domain_name.regional_domain_name, domain_name.regional_hosted_zone_id))
        )
    '''

    def __init__(
        self,
        regional_domain_name: builtins.str,
        regional_hosted_zone_id: builtins.str,
    ) -> None:
        '''
        :param regional_domain_name: the domain name associated with the regional endpoint for this custom domain name.
        :param regional_hosted_zone_id: the region-specific Amazon Route 53 Hosted Zone ID of the regional endpoint.
        '''
        jsii.create(self.__class__, self, [regional_domain_name, regional_hosted_zone_id])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class BucketWebsiteTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.BucketWebsiteTarget",
):
    '''Use a S3 as an alias record target.

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

    def __init__(self, bucket: _IBucket_42e086fd) -> None:
        '''
        :param bucket: -
        '''
        jsii.create(self.__class__, self, [bucket])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class ClassicLoadBalancerTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.ClassicLoadBalancerTarget",
):
    '''Use a classic ELB as an alias record target.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_elasticloadbalancing as elb
        
        # zone: route53.HostedZone
        # lb: elb.LoadBalancer
        
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.ClassicLoadBalancerTarget(lb))
        )
    '''

    def __init__(self, load_balancer: _LoadBalancer_a894d40e) -> None:
        '''
        :param load_balancer: -
        '''
        jsii.create(self.__class__, self, [load_balancer])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class CloudFrontTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.CloudFrontTarget",
):
    '''Use a CloudFront Distribution as an alias record target.

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

    def __init__(self, distribution: _IDistribution_7ac752a4) -> None:
        '''
        :param distribution: -
        '''
        jsii.create(self.__class__, self, [distribution])

    @jsii.member(jsii_name="getHostedZoneId") # type: ignore[misc]
    @builtins.classmethod
    def get_hosted_zone_id(cls, scope: constructs.IConstruct) -> builtins.str:
        '''Get the hosted zone id for the current scope.

        :param scope: - scope in which this resource is defined.
        '''
        return typing.cast(builtins.str, jsii.sinvoke(cls, "getHostedZoneId", [scope]))

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CLOUDFRONT_ZONE_ID")
    def CLOUDFRONT_ZONE_ID(cls) -> builtins.str:
        '''The hosted zone Id if using an alias record in Route53.

        This value never changes.
        '''
        return typing.cast(builtins.str, jsii.sget(cls, "CLOUDFRONT_ZONE_ID"))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class ElasticBeanstalkEnvironmentEndpointTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.ElasticBeanstalkEnvironmentEndpointTarget",
):
    '''Use an Elastic Beanstalk environment URL as an alias record target. E.g. mysampleenvironment.xyz.us-east-1.elasticbeanstalk.com.

    Only supports Elastic Beanstalk environments created after 2016 that have a regional endpoint.

    :exampleMetadata: infused

    Example::

        # zone: route53.HostedZone
        # ebs_environment_url: str
        
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.ElasticBeanstalkEnvironmentEndpointTarget(ebs_environment_url))
        )
    '''

    def __init__(self, environment_endpoint: builtins.str) -> None:
        '''
        :param environment_endpoint: -
        '''
        jsii.create(self.__class__, self, [environment_endpoint])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class GlobalAcceleratorDomainTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.GlobalAcceleratorDomainTarget",
):
    '''Use a Global Accelerator domain name as an alias record target.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_route53_targets as route53_targets
        
        global_accelerator_domain_target = route53_targets.GlobalAcceleratorDomainTarget("acceleratorDomainName")
    '''

    def __init__(self, accelerator_domain_name: builtins.str) -> None:
        '''Create an Alias Target for a Global Accelerator domain name.

        :param accelerator_domain_name: -
        '''
        jsii.create(self.__class__, self, [accelerator_domain_name])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GLOBAL_ACCELERATOR_ZONE_ID")
    def GLOBAL_ACCELERATOR_ZONE_ID(cls) -> builtins.str:
        '''The hosted zone Id if using an alias record in Route53.

        This value never changes.
        Ref: https://docs.aws.amazon.com/general/latest/gr/global_accelerator.html
        '''
        return typing.cast(builtins.str, jsii.sget(cls, "GLOBAL_ACCELERATOR_ZONE_ID"))


class GlobalAcceleratorTarget(
    GlobalAcceleratorDomainTarget,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.GlobalAcceleratorTarget",
):
    '''Use a Global Accelerator instance domain name as an alias record target.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_globalaccelerator as globalaccelerator
        
        # zone: route53.HostedZone
        # accelerator: globalaccelerator.Accelerator
        
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.GlobalAcceleratorTarget(accelerator))
        )
    '''

    def __init__(self, accelerator: _IAccelerator_88df59f2) -> None:
        '''Create an Alias Target for a Global Accelerator instance.

        :param accelerator: -
        '''
        jsii.create(self.__class__, self, [accelerator])


@jsii.implements(_IAliasRecordTarget_aae9327f)
class InterfaceVpcEndpointTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.InterfaceVpcEndpointTarget",
):
    '''Set an InterfaceVpcEndpoint as a target for an ARecord.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_ec2 as ec2
        
        # zone: route53.HostedZone
        # interface_vpc_endpoint: ec2.InterfaceVpcEndpoint
        
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.InterfaceVpcEndpointTarget(interface_vpc_endpoint))
        )
    '''

    def __init__(self, vpc_endpoint: _IInterfaceVpcEndpoint_7481aea1) -> None:
        '''
        :param vpc_endpoint: -
        '''
        jsii.create(self.__class__, self, [vpc_endpoint])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class LoadBalancerTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.LoadBalancerTarget",
):
    '''Use an ELBv2 as an alias record target.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_elasticloadbalancingv2 as elbv2
        
        # zone: route53.HostedZone
        # lb: elbv2.ApplicationLoadBalancer
        
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.LoadBalancerTarget(lb))
        )
    '''

    def __init__(self, load_balancer: _ILoadBalancerV2_4c5c0fbb) -> None:
        '''
        :param load_balancer: -
        '''
        jsii.create(self.__class__, self, [load_balancer])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class Route53RecordTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.Route53RecordTarget",
):
    '''Use another Route 53 record as an alias record target.

    :exampleMetadata: infused

    Example::

        # zone: route53.HostedZone
        # record: route53.ARecord
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.Route53RecordTarget(record))
        )
    '''

    def __init__(self, record: _IRecordSet_7d446a82) -> None:
        '''
        :param record: -
        '''
        jsii.create(self.__class__, self, [record])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, zone]))


@jsii.implements(_IAliasRecordTarget_aae9327f)
class UserPoolDomainTarget(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.UserPoolDomainTarget",
):
    '''Use a user pool domain as an alias record target.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_cognito as cognito
        
        # zone: route53.HostedZone
        # domain: cognito.UserPoolDomain
        
        route53.ARecord(self, "AliasRecord",
            zone=zone,
            target=route53.RecordTarget.from_alias(targets.UserPoolDomainTarget(domain))
        )
    '''

    def __init__(self, domain: _UserPoolDomain_f402e168) -> None:
        '''
        :param domain: -
        '''
        jsii.create(self.__class__, self, [domain])

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        _record: _IRecordSet_7d446a82,
        _zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> _AliasRecordTargetConfig_588f62e9:
        '''Return hosted zone ID and DNS name, usable for Route53 alias targets.

        :param _record: -
        :param _zone: -
        '''
        return typing.cast(_AliasRecordTargetConfig_588f62e9, jsii.invoke(self, "bind", [_record, _zone]))


class ApiGateway(
    ApiGatewayDomain,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_route53_targets.ApiGateway",
):
    '''Defines an API Gateway REST API as the alias target. Requires that the domain name will be defined through ``RestApiProps.domainName``.

    You can direct the alias to any ``apigateway.DomainName`` resource through the
    ``ApiGatewayDomain`` class.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_route53 as route53
        import aws_cdk.aws_route53_targets as targets
        
        # api: apigateway.RestApi
        # hosted_zone_for_example_com: Any
        
        
        route53.ARecord(self, "CustomDomainAliasRecord",
            zone=hosted_zone_for_example_com,
            target=route53.RecordTarget.from_alias(targets.ApiGateway(api))
        )
    '''

    def __init__(self, api: _RestApiBase_0431da32) -> None:
        '''
        :param api: -
        '''
        jsii.create(self.__class__, self, [api])


__all__ = [
    "ApiGateway",
    "ApiGatewayDomain",
    "ApiGatewayv2DomainProperties",
    "BucketWebsiteTarget",
    "ClassicLoadBalancerTarget",
    "CloudFrontTarget",
    "ElasticBeanstalkEnvironmentEndpointTarget",
    "GlobalAcceleratorDomainTarget",
    "GlobalAcceleratorTarget",
    "InterfaceVpcEndpointTarget",
    "LoadBalancerTarget",
    "Route53RecordTarget",
    "UserPoolDomainTarget",
]

publication.publish()
