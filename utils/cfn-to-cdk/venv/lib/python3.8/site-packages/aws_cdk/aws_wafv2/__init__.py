'''
# AWS::WAFv2 Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_wafv2 as wafv2
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-wafv2-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::WAFv2](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_WAFv2.html).

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
class CfnIPSet(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wafv2.CfnIPSet",
):
    '''A CloudFormation ``AWS::WAFv2::IPSet``.

    .. epigraph::

       This is the latest version of *AWS WAF* , named AWS WAF V2, released in November, 2019. For information, including how to migrate your AWS WAF resources from the prior release, see the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

    Use an ``IPSet`` to identify web requests that originate from specific IP addresses or ranges of IP addresses. For example, if you're receiving a lot of requests from a ranges of IP addresses, you can configure AWS WAF to block them using an IP set that lists those IP addresses.

    You use an IP set by providing its Amazon Resource Name (ARN) to the rule statement ``IPSetReferenceStatement`` , when you add a rule to a rule group or web ACL.

    :cloudformationResource: AWS::WAFv2::IPSet
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wafv2 as wafv2
        
        cfn_iPSet = wafv2.CfnIPSet(self, "MyCfnIPSet",
            addresses=["addresses"],
            ip_address_version="ipAddressVersion",
            scope="scope",
        
            # the properties below are optional
            description="description",
            name="name",
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope_: constructs.Construct,
        id: builtins.str,
        *,
        addresses: typing.Sequence[builtins.str],
        ip_address_version: builtins.str,
        scope: builtins.str,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::WAFv2::IPSet``.

        :param scope_: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param addresses: Contains an array of strings that specify one or more IP addresses or blocks of IP addresses in Classless Inter-Domain Routing (CIDR) notation. AWS WAF supports all IPv4 and IPv6 CIDR ranges except for /0. Examples: - To configure AWS WAF to allow, block, or count requests that originated from the IP address 192.0.2.44, specify ``192.0.2.44/32`` . - To configure AWS WAF to allow, block, or count requests that originated from IP addresses from 192.0.2.0 to 192.0.2.255, specify ``192.0.2.0/24`` . - To configure AWS WAF to allow, block, or count requests that originated from the IP address 1111:0000:0000:0000:0000:0000:0000:0111, specify ``1111:0000:0000:0000:0000:0000:0000:0111/128`` . - To configure AWS WAF to allow, block, or count requests that originated from IP addresses 1111:0000:0000:0000:0000:0000:0000:0000 to 1111:0000:0000:0000:ffff:ffff:ffff:ffff, specify ``1111:0000:0000:0000:0000:0000:0000:0000/64`` . For more information about CIDR notation, see the Wikipedia entry `Classless Inter-Domain Routing <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing>`_ .
        :param ip_address_version: Specify IPV4 or IPV6.
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` . .. epigraph:: For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .
        :param description: A description of the IP set that helps with identification.
        :param name: The descriptive name of the IP set. You cannot change the name of an ``IPSet`` after you create it.
        :param tags: Key:value pairs associated with an AWS resource. The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource. .. epigraph:: To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.
        '''
        props = CfnIPSetProps(
            addresses=addresses,
            ip_address_version=ip_address_version,
            scope=scope,
            description=description,
            name=name,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope_, id, props])

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
        '''The Amazon Resource Name (ARN) of the IP set.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the IP set.

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
        '''Key:value pairs associated with an AWS resource.

        The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource.
        .. epigraph::

           To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="addresses")
    def addresses(self) -> typing.List[builtins.str]:
        '''Contains an array of strings that specify one or more IP addresses or blocks of IP addresses in Classless Inter-Domain Routing (CIDR) notation.

        AWS WAF supports all IPv4 and IPv6 CIDR ranges except for /0.

        Examples:

        - To configure AWS WAF to allow, block, or count requests that originated from the IP address 192.0.2.44, specify ``192.0.2.44/32`` .
        - To configure AWS WAF to allow, block, or count requests that originated from IP addresses from 192.0.2.0 to 192.0.2.255, specify ``192.0.2.0/24`` .
        - To configure AWS WAF to allow, block, or count requests that originated from the IP address 1111:0000:0000:0000:0000:0000:0000:0111, specify ``1111:0000:0000:0000:0000:0000:0000:0111/128`` .
        - To configure AWS WAF to allow, block, or count requests that originated from IP addresses 1111:0000:0000:0000:0000:0000:0000:0000 to 1111:0000:0000:0000:ffff:ffff:ffff:ffff, specify ``1111:0000:0000:0000:0000:0000:0000:0000/64`` .

        For more information about CIDR notation, see the Wikipedia entry `Classless Inter-Domain Routing <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-addresses
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "addresses"))

    @addresses.setter
    def addresses(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "addresses", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ipAddressVersion")
    def ip_address_version(self) -> builtins.str:
        '''Specify IPV4 or IPV6.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-ipaddressversion
        '''
        return typing.cast(builtins.str, jsii.get(self, "ipAddressVersion"))

    @ip_address_version.setter
    def ip_address_version(self, value: builtins.str) -> None:
        jsii.set(self, "ipAddressVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scope")
    def scope(self) -> builtins.str:
        '''Specifies whether this is for an Amazon CloudFront distribution or for a regional application.

        A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` .
        .. epigraph::

           For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-scope
        '''
        return typing.cast(builtins.str, jsii.get(self, "scope"))

    @scope.setter
    def scope(self, value: builtins.str) -> None:
        jsii.set(self, "scope", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the IP set that helps with identification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The descriptive name of the IP set.

        You cannot change the name of an ``IPSet`` after you create it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wafv2.CfnIPSetProps",
    jsii_struct_bases=[],
    name_mapping={
        "addresses": "addresses",
        "ip_address_version": "ipAddressVersion",
        "scope": "scope",
        "description": "description",
        "name": "name",
        "tags": "tags",
    },
)
class CfnIPSetProps:
    def __init__(
        self,
        *,
        addresses: typing.Sequence[builtins.str],
        ip_address_version: builtins.str,
        scope: builtins.str,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnIPSet``.

        :param addresses: Contains an array of strings that specify one or more IP addresses or blocks of IP addresses in Classless Inter-Domain Routing (CIDR) notation. AWS WAF supports all IPv4 and IPv6 CIDR ranges except for /0. Examples: - To configure AWS WAF to allow, block, or count requests that originated from the IP address 192.0.2.44, specify ``192.0.2.44/32`` . - To configure AWS WAF to allow, block, or count requests that originated from IP addresses from 192.0.2.0 to 192.0.2.255, specify ``192.0.2.0/24`` . - To configure AWS WAF to allow, block, or count requests that originated from the IP address 1111:0000:0000:0000:0000:0000:0000:0111, specify ``1111:0000:0000:0000:0000:0000:0000:0111/128`` . - To configure AWS WAF to allow, block, or count requests that originated from IP addresses 1111:0000:0000:0000:0000:0000:0000:0000 to 1111:0000:0000:0000:ffff:ffff:ffff:ffff, specify ``1111:0000:0000:0000:0000:0000:0000:0000/64`` . For more information about CIDR notation, see the Wikipedia entry `Classless Inter-Domain Routing <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing>`_ .
        :param ip_address_version: Specify IPV4 or IPV6.
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` . .. epigraph:: For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .
        :param description: A description of the IP set that helps with identification.
        :param name: The descriptive name of the IP set. You cannot change the name of an ``IPSet`` after you create it.
        :param tags: Key:value pairs associated with an AWS resource. The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource. .. epigraph:: To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wafv2 as wafv2
            
            cfn_iPSet_props = wafv2.CfnIPSetProps(
                addresses=["addresses"],
                ip_address_version="ipAddressVersion",
                scope="scope",
            
                # the properties below are optional
                description="description",
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "addresses": addresses,
            "ip_address_version": ip_address_version,
            "scope": scope,
        }
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def addresses(self) -> typing.List[builtins.str]:
        '''Contains an array of strings that specify one or more IP addresses or blocks of IP addresses in Classless Inter-Domain Routing (CIDR) notation.

        AWS WAF supports all IPv4 and IPv6 CIDR ranges except for /0.

        Examples:

        - To configure AWS WAF to allow, block, or count requests that originated from the IP address 192.0.2.44, specify ``192.0.2.44/32`` .
        - To configure AWS WAF to allow, block, or count requests that originated from IP addresses from 192.0.2.0 to 192.0.2.255, specify ``192.0.2.0/24`` .
        - To configure AWS WAF to allow, block, or count requests that originated from the IP address 1111:0000:0000:0000:0000:0000:0000:0111, specify ``1111:0000:0000:0000:0000:0000:0000:0111/128`` .
        - To configure AWS WAF to allow, block, or count requests that originated from IP addresses 1111:0000:0000:0000:0000:0000:0000:0000 to 1111:0000:0000:0000:ffff:ffff:ffff:ffff, specify ``1111:0000:0000:0000:0000:0000:0000:0000/64`` .

        For more information about CIDR notation, see the Wikipedia entry `Classless Inter-Domain Routing <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-addresses
        '''
        result = self._values.get("addresses")
        assert result is not None, "Required property 'addresses' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def ip_address_version(self) -> builtins.str:
        '''Specify IPV4 or IPV6.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-ipaddressversion
        '''
        result = self._values.get("ip_address_version")
        assert result is not None, "Required property 'ip_address_version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def scope(self) -> builtins.str:
        '''Specifies whether this is for an Amazon CloudFront distribution or for a regional application.

        A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` .
        .. epigraph::

           For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-scope
        '''
        result = self._values.get("scope")
        assert result is not None, "Required property 'scope' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the IP set that helps with identification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The descriptive name of the IP set.

        You cannot change the name of an ``IPSet`` after you create it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Key:value pairs associated with an AWS resource.

        The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource.
        .. epigraph::

           To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-ipset.html#cfn-wafv2-ipset-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnIPSetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLoggingConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wafv2.CfnLoggingConfiguration",
):
    '''A CloudFormation ``AWS::WAFv2::LoggingConfiguration``.

    Defines an association between logging destinations and a web ACL resource, for logging from AWS WAF . As part of the association, you can specify parts of the standard logging fields to keep out of the logs and you can specify filters so that you log only a subset of the logging records.
    .. epigraph::

       You can define one logging destination per web ACL.

    You can access information about the traffic that AWS WAF inspects using the following steps:

    - Create your logging destination. You can use an Amazon CloudWatch Logs log group, an Amazon Simple Storage Service (Amazon S3) bucket, or an Amazon Kinesis Data Firehose. For information about configuring logging destinations and the permissions that are required for each, see `Logging web ACL traffic information <https://docs.aws.amazon.com/waf/latest/developerguide/logging.html>`_ in the *AWS WAF Developer Guide* .
    - Associate your logging destination to your web ACL using a ``PutLoggingConfiguration`` request.

    When you successfully enable logging using a ``PutLoggingConfiguration`` request, AWS WAF creates an additional role or policy that is required to write logs to the logging destination. For an Amazon CloudWatch Logs log group, AWS WAF creates a resource policy on the log group. For an Amazon S3 bucket, AWS WAF creates a bucket policy. For an Amazon Kinesis Data Firehose, AWS WAF creates a service-linked role.

    For additional information about web ACL logging, see `Logging web ACL traffic information <https://docs.aws.amazon.com/waf/latest/developerguide/logging.html>`_ in the *AWS WAF Developer Guide* .

    :cloudformationResource: AWS::WAFv2::LoggingConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wafv2 as wafv2
        
        # json_body: Any
        # logging_filter: Any
        # method: Any
        # query_string: Any
        # single_header: Any
        # uri_path: Any
        
        cfn_logging_configuration = wafv2.CfnLoggingConfiguration(self, "MyCfnLoggingConfiguration",
            log_destination_configs=["logDestinationConfigs"],
            resource_arn="resourceArn",
        
            # the properties below are optional
            logging_filter=logging_filter,
            redacted_fields=[wafv2.CfnLoggingConfiguration.FieldToMatchProperty(
                json_body=json_body,
                method=method,
                query_string=query_string,
                single_header=single_header,
                uri_path=uri_path
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        log_destination_configs: typing.Sequence[builtins.str],
        resource_arn: builtins.str,
        logging_filter: typing.Any = None,
        redacted_fields: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLoggingConfiguration.FieldToMatchProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::WAFv2::LoggingConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param log_destination_configs: The Amazon Resource Names (ARNs) of the logging destinations that you want to associate with the web ACL.
        :param resource_arn: The Amazon Resource Name (ARN) of the web ACL that you want to associate with ``LogDestinationConfigs`` .
        :param logging_filter: Filtering that specifies which web requests are kept in the logs and which are dropped. You can filter on the rule action and on the web request labels that were applied by matching rules during web ACL evaluation.
        :param redacted_fields: The parts of the request that you want to keep out of the logs. For example, if you redact the ``SingleHeader`` field, the ``HEADER`` field in the firehose will be ``xxx`` . .. epigraph:: You can specify only the following fields for redaction: ``UriPath`` , ``QueryString`` , ``SingleHeader`` , ``Method`` , and ``JsonBody`` .
        '''
        props = CfnLoggingConfigurationProps(
            log_destination_configs=log_destination_configs,
            resource_arn=resource_arn,
            logging_filter=logging_filter,
            redacted_fields=redacted_fields,
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
    @jsii.member(jsii_name="attrManagedByFirewallManager")
    def attr_managed_by_firewall_manager(self) -> _IResolvable_da3f097b:
        '''Indicates whether the logging configuration was created by AWS Firewall Manager , as part of an AWS WAF policy configuration.

        If true, only Firewall Manager can modify or delete the configuration.

        :cloudformationAttribute: ManagedByFirewallManager
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrManagedByFirewallManager"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logDestinationConfigs")
    def log_destination_configs(self) -> typing.List[builtins.str]:
        '''The Amazon Resource Names (ARNs) of the logging destinations that you want to associate with the web ACL.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html#cfn-wafv2-loggingconfiguration-logdestinationconfigs
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "logDestinationConfigs"))

    @log_destination_configs.setter
    def log_destination_configs(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "logDestinationConfigs", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loggingFilter")
    def logging_filter(self) -> typing.Any:
        '''Filtering that specifies which web requests are kept in the logs and which are dropped.

        You can filter on the rule action and on the web request labels that were applied by matching rules during web ACL evaluation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html#cfn-wafv2-loggingconfiguration-loggingfilter
        '''
        return typing.cast(typing.Any, jsii.get(self, "loggingFilter"))

    @logging_filter.setter
    def logging_filter(self, value: typing.Any) -> None:
        jsii.set(self, "loggingFilter", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceArn")
    def resource_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the web ACL that you want to associate with ``LogDestinationConfigs`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html#cfn-wafv2-loggingconfiguration-resourcearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "resourceArn"))

    @resource_arn.setter
    def resource_arn(self, value: builtins.str) -> None:
        jsii.set(self, "resourceArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="redactedFields")
    def redacted_fields(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoggingConfiguration.FieldToMatchProperty", _IResolvable_da3f097b]]]]:
        '''The parts of the request that you want to keep out of the logs.

        For example, if you redact the ``SingleHeader`` field, the ``HEADER`` field in the firehose will be ``xxx`` .
        .. epigraph::

           You can specify only the following fields for redaction: ``UriPath`` , ``QueryString`` , ``SingleHeader`` , ``Method`` , and ``JsonBody`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html#cfn-wafv2-loggingconfiguration-redactedfields
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoggingConfiguration.FieldToMatchProperty", _IResolvable_da3f097b]]]], jsii.get(self, "redactedFields"))

    @redacted_fields.setter
    def redacted_fields(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoggingConfiguration.FieldToMatchProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "redactedFields", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnLoggingConfiguration.FieldToMatchProperty",
        jsii_struct_bases=[],
        name_mapping={
            "json_body": "jsonBody",
            "method": "method",
            "query_string": "queryString",
            "single_header": "singleHeader",
            "uri_path": "uriPath",
        },
    )
    class FieldToMatchProperty:
        def __init__(
            self,
            *,
            json_body: typing.Any = None,
            method: typing.Any = None,
            query_string: typing.Any = None,
            single_header: typing.Any = None,
            uri_path: typing.Any = None,
        ) -> None:
            '''The parts of the request that you want to keep out of the logs.

            For example, if you redact the ``SingleHeader`` field, the ``HEADER`` field in the firehose will be ``xxx`` .

            JSON specification for a ``QueryString`` field to match:

            ``"FieldToMatch": { "QueryString": {} }``

            Example JSON for a ``Method`` field to match specification:

            ``"FieldToMatch": { "Method": { "Name": "DELETE" } }``

            :param json_body: Redact the JSON body from the logs.
            :param method: Redact the method from the logs.
            :param query_string: Redact the query string from the logs.
            :param single_header: Redact the header from the logs.
            :param uri_path: Redact the URI path from the logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-loggingconfiguration-fieldtomatch.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # json_body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # uri_path: Any
                
                field_to_match_property = wafv2.CfnLoggingConfiguration.FieldToMatchProperty(
                    json_body=json_body,
                    method=method,
                    query_string=query_string,
                    single_header=single_header,
                    uri_path=uri_path
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if json_body is not None:
                self._values["json_body"] = json_body
            if method is not None:
                self._values["method"] = method
            if query_string is not None:
                self._values["query_string"] = query_string
            if single_header is not None:
                self._values["single_header"] = single_header
            if uri_path is not None:
                self._values["uri_path"] = uri_path

        @builtins.property
        def json_body(self) -> typing.Any:
            '''Redact the JSON body from the logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-loggingconfiguration-fieldtomatch.html#cfn-wafv2-loggingconfiguration-fieldtomatch-jsonbody
            '''
            result = self._values.get("json_body")
            return typing.cast(typing.Any, result)

        @builtins.property
        def method(self) -> typing.Any:
            '''Redact the method from the logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-loggingconfiguration-fieldtomatch.html#cfn-wafv2-loggingconfiguration-fieldtomatch-method
            '''
            result = self._values.get("method")
            return typing.cast(typing.Any, result)

        @builtins.property
        def query_string(self) -> typing.Any:
            '''Redact the query string from the logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-loggingconfiguration-fieldtomatch.html#cfn-wafv2-loggingconfiguration-fieldtomatch-querystring
            '''
            result = self._values.get("query_string")
            return typing.cast(typing.Any, result)

        @builtins.property
        def single_header(self) -> typing.Any:
            '''Redact the header from the logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-loggingconfiguration-fieldtomatch.html#cfn-wafv2-loggingconfiguration-fieldtomatch-singleheader
            '''
            result = self._values.get("single_header")
            return typing.cast(typing.Any, result)

        @builtins.property
        def uri_path(self) -> typing.Any:
            '''Redact the URI path from the logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-loggingconfiguration-fieldtomatch.html#cfn-wafv2-loggingconfiguration-fieldtomatch-uripath
            '''
            result = self._values.get("uri_path")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FieldToMatchProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wafv2.CfnLoggingConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "log_destination_configs": "logDestinationConfigs",
        "resource_arn": "resourceArn",
        "logging_filter": "loggingFilter",
        "redacted_fields": "redactedFields",
    },
)
class CfnLoggingConfigurationProps:
    def __init__(
        self,
        *,
        log_destination_configs: typing.Sequence[builtins.str],
        resource_arn: builtins.str,
        logging_filter: typing.Any = None,
        redacted_fields: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnLoggingConfiguration.FieldToMatchProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnLoggingConfiguration``.

        :param log_destination_configs: The Amazon Resource Names (ARNs) of the logging destinations that you want to associate with the web ACL.
        :param resource_arn: The Amazon Resource Name (ARN) of the web ACL that you want to associate with ``LogDestinationConfigs`` .
        :param logging_filter: Filtering that specifies which web requests are kept in the logs and which are dropped. You can filter on the rule action and on the web request labels that were applied by matching rules during web ACL evaluation.
        :param redacted_fields: The parts of the request that you want to keep out of the logs. For example, if you redact the ``SingleHeader`` field, the ``HEADER`` field in the firehose will be ``xxx`` . .. epigraph:: You can specify only the following fields for redaction: ``UriPath`` , ``QueryString`` , ``SingleHeader`` , ``Method`` , and ``JsonBody`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wafv2 as wafv2
            
            # json_body: Any
            # logging_filter: Any
            # method: Any
            # query_string: Any
            # single_header: Any
            # uri_path: Any
            
            cfn_logging_configuration_props = wafv2.CfnLoggingConfigurationProps(
                log_destination_configs=["logDestinationConfigs"],
                resource_arn="resourceArn",
            
                # the properties below are optional
                logging_filter=logging_filter,
                redacted_fields=[wafv2.CfnLoggingConfiguration.FieldToMatchProperty(
                    json_body=json_body,
                    method=method,
                    query_string=query_string,
                    single_header=single_header,
                    uri_path=uri_path
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "log_destination_configs": log_destination_configs,
            "resource_arn": resource_arn,
        }
        if logging_filter is not None:
            self._values["logging_filter"] = logging_filter
        if redacted_fields is not None:
            self._values["redacted_fields"] = redacted_fields

    @builtins.property
    def log_destination_configs(self) -> typing.List[builtins.str]:
        '''The Amazon Resource Names (ARNs) of the logging destinations that you want to associate with the web ACL.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html#cfn-wafv2-loggingconfiguration-logdestinationconfigs
        '''
        result = self._values.get("log_destination_configs")
        assert result is not None, "Required property 'log_destination_configs' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def resource_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the web ACL that you want to associate with ``LogDestinationConfigs`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html#cfn-wafv2-loggingconfiguration-resourcearn
        '''
        result = self._values.get("resource_arn")
        assert result is not None, "Required property 'resource_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def logging_filter(self) -> typing.Any:
        '''Filtering that specifies which web requests are kept in the logs and which are dropped.

        You can filter on the rule action and on the web request labels that were applied by matching rules during web ACL evaluation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html#cfn-wafv2-loggingconfiguration-loggingfilter
        '''
        result = self._values.get("logging_filter")
        return typing.cast(typing.Any, result)

    @builtins.property
    def redacted_fields(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLoggingConfiguration.FieldToMatchProperty, _IResolvable_da3f097b]]]]:
        '''The parts of the request that you want to keep out of the logs.

        For example, if you redact the ``SingleHeader`` field, the ``HEADER`` field in the firehose will be ``xxx`` .
        .. epigraph::

           You can specify only the following fields for redaction: ``UriPath`` , ``QueryString`` , ``SingleHeader`` , ``Method`` , and ``JsonBody`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-loggingconfiguration.html#cfn-wafv2-loggingconfiguration-redactedfields
        '''
        result = self._values.get("redacted_fields")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLoggingConfiguration.FieldToMatchProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLoggingConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRegexPatternSet(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wafv2.CfnRegexPatternSet",
):
    '''A CloudFormation ``AWS::WAFv2::RegexPatternSet``.

    .. epigraph::

       This is the latest version of *AWS WAF* , named AWS WAF V2, released in November, 2019. For information, including how to migrate your AWS WAF resources from the prior release, see the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

    Use a ``RegexPatternSet`` to have AWS WAF inspect a web request component for a specific set of regular expression patterns.

    You use a regex pattern set by providing its Amazon Resource Name (ARN) to the rule statement ``RegexPatternSetReferenceStatement`` , when you add a rule to a rule group or web ACL.

    :cloudformationResource: AWS::WAFv2::RegexPatternSet
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wafv2 as wafv2
        
        cfn_regex_pattern_set = wafv2.CfnRegexPatternSet(self, "MyCfnRegexPatternSet",
            regular_expression_list=["regularExpressionList"],
            scope="scope",
        
            # the properties below are optional
            description="description",
            name="name",
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope_: constructs.Construct,
        id: builtins.str,
        *,
        regular_expression_list: typing.Sequence[builtins.str],
        scope: builtins.str,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::WAFv2::RegexPatternSet``.

        :param scope_: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param regular_expression_list: The regular expression patterns in the set.
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` . .. epigraph:: For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .
        :param description: A description of the set that helps with identification.
        :param name: The descriptive name of the set. You cannot change the name after you create the set.
        :param tags: Key:value pairs associated with an AWS resource. The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource. .. epigraph:: To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.
        '''
        props = CfnRegexPatternSetProps(
            regular_expression_list=regular_expression_list,
            scope=scope,
            description=description,
            name=name,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope_, id, props])

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
        '''The Amazon Resource Name (ARN) of the regex pattern set.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the regex pattern set.

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
        '''Key:value pairs associated with an AWS resource.

        The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource.
        .. epigraph::

           To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="regularExpressionList")
    def regular_expression_list(self) -> typing.List[builtins.str]:
        '''The regular expression patterns in the set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-regularexpressionlist
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "regularExpressionList"))

    @regular_expression_list.setter
    def regular_expression_list(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "regularExpressionList", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scope")
    def scope(self) -> builtins.str:
        '''Specifies whether this is for an Amazon CloudFront distribution or for a regional application.

        A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` .
        .. epigraph::

           For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-scope
        '''
        return typing.cast(builtins.str, jsii.get(self, "scope"))

    @scope.setter
    def scope(self, value: builtins.str) -> None:
        jsii.set(self, "scope", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the set that helps with identification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The descriptive name of the set.

        You cannot change the name after you create the set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wafv2.CfnRegexPatternSetProps",
    jsii_struct_bases=[],
    name_mapping={
        "regular_expression_list": "regularExpressionList",
        "scope": "scope",
        "description": "description",
        "name": "name",
        "tags": "tags",
    },
)
class CfnRegexPatternSetProps:
    def __init__(
        self,
        *,
        regular_expression_list: typing.Sequence[builtins.str],
        scope: builtins.str,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRegexPatternSet``.

        :param regular_expression_list: The regular expression patterns in the set.
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` . .. epigraph:: For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .
        :param description: A description of the set that helps with identification.
        :param name: The descriptive name of the set. You cannot change the name after you create the set.
        :param tags: Key:value pairs associated with an AWS resource. The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource. .. epigraph:: To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wafv2 as wafv2
            
            cfn_regex_pattern_set_props = wafv2.CfnRegexPatternSetProps(
                regular_expression_list=["regularExpressionList"],
                scope="scope",
            
                # the properties below are optional
                description="description",
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "regular_expression_list": regular_expression_list,
            "scope": scope,
        }
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def regular_expression_list(self) -> typing.List[builtins.str]:
        '''The regular expression patterns in the set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-regularexpressionlist
        '''
        result = self._values.get("regular_expression_list")
        assert result is not None, "Required property 'regular_expression_list' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def scope(self) -> builtins.str:
        '''Specifies whether this is for an Amazon CloudFront distribution or for a regional application.

        A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` .
        .. epigraph::

           For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-scope
        '''
        result = self._values.get("scope")
        assert result is not None, "Required property 'scope' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the set that helps with identification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The descriptive name of the set.

        You cannot change the name after you create the set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Key:value pairs associated with an AWS resource.

        The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource.
        .. epigraph::

           To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-regexpatternset.html#cfn-wafv2-regexpatternset-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRegexPatternSetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRuleGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup",
):
    '''A CloudFormation ``AWS::WAFv2::RuleGroup``.

    .. epigraph::

       This is the latest version of *AWS WAF* , named AWS WAF V2, released in November, 2019. For information, including how to migrate your AWS WAF resources from the prior release, see the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

    Use an ``RuleGroup`` to define a collection of rules for inspecting and controlling web requests. You use a rule group in an ``WebACL`` by providing its Amazon Resource Name (ARN) to the rule statement ``RuleGroupReferenceStatement`` , when you add rules to the web ACL.

    When you create a rule group, you define an immutable capacity limit. If you update a rule group, you must stay within the capacity. This allows others to reuse the rule group with confidence in its capacity requirements.

    :cloudformationResource: AWS::WAFv2::RuleGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wafv2 as wafv2
        
        # all: Any
        # allow: Any
        # all_query_arguments: Any
        # block: Any
        # body: Any
        # captcha: Any
        # count: Any
        # method: Any
        # query_string: Any
        # single_header: Any
        # single_query_argument: Any
        # statement_property_: wafv2.CfnRuleGroup.StatementProperty
        # uri_path: Any
        
        cfn_rule_group = wafv2.CfnRuleGroup(self, "MyCfnRuleGroup",
            capacity=123,
            scope="scope",
            visibility_config=wafv2.CfnRuleGroup.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=False,
                metric_name="metricName",
                sampled_requests_enabled=False
            ),
        
            # the properties below are optional
            custom_response_bodies={
                "custom_response_bodies_key": wafv2.CfnRuleGroup.CustomResponseBodyProperty(
                    content="content",
                    content_type="contentType"
                )
            },
            description="description",
            name="name",
            rules=[wafv2.CfnRuleGroup.RuleProperty(
                name="name",
                priority=123,
                statement=wafv2.CfnRuleGroup.StatementProperty(
                    and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                        statements=[statement_property_]
                    ),
                    byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        positional_constraint="positionalConstraint",
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )],
        
                        # the properties below are optional
                        search_string="searchString",
                        search_string_base64="searchStringBase64"
                    ),
                    geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                        country_codes=["countryCodes"],
                        forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                            fallback_behavior="fallbackBehavior",
                            header_name="headerName"
                        )
                    ),
                    ip_set_reference_statement={
                        "arn": "arn",
        
                        # the properties below are optional
                        "ip_set_forwarded_ip_config": {
                            "fallback_behavior": "fallbackBehavior",
                            "header_name": "headerName",
                            "position": "position"
                        }
                    },
                    label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                        key="key",
                        scope="scope"
                    ),
                    not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                        statement=statement_property_
                    ),
                    or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                        statements=[statement_property_]
                    ),
                    rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                        aggregate_key_type="aggregateKeyType",
                        limit=123,
        
                        # the properties below are optional
                        forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                            fallback_behavior="fallbackBehavior",
                            header_name="headerName"
                        ),
                        scope_down_statement=statement_property_
                    ),
                    regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        regex_string="regexString",
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                        arn="arn",
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                        comparison_operator="comparisonOperator",
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        size=123,
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    )
                ),
                visibility_config=wafv2.CfnRuleGroup.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=False,
                    metric_name="metricName",
                    sampled_requests_enabled=False
                ),
        
                # the properties below are optional
                action=wafv2.CfnRuleGroup.RuleActionProperty(
                    allow=allow,
                    block=block,
                    captcha=captcha,
                    count=count
                ),
                captcha_config=wafv2.CfnRuleGroup.CaptchaConfigProperty(
                    immunity_time_property=wafv2.CfnRuleGroup.ImmunityTimePropertyProperty(
                        immunity_time=123
                    )
                ),
                rule_labels=[wafv2.CfnRuleGroup.LabelProperty(
                    name="name"
                )]
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope_: constructs.Construct,
        id: builtins.str,
        *,
        capacity: jsii.Number,
        scope: builtins.str,
        visibility_config: typing.Union["CfnRuleGroup.VisibilityConfigProperty", _IResolvable_da3f097b],
        custom_response_bodies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnRuleGroup.CustomResponseBodyProperty", _IResolvable_da3f097b]]]] = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.RuleProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::WAFv2::RuleGroup``.

        :param scope_: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param capacity: The web ACL capacity units (WCUs) required for this rule group. When you create your own rule group, you define this, and you cannot change it after creation. When you add or modify the rules in a rule group, AWS WAF enforces this limit. AWS WAF uses WCUs to calculate and control the operating resources that are used to run your rules, rule groups, and web ACLs. AWS WAF calculates capacity differently for each rule type, to reflect the relative cost of each rule. Simple rules that cost little to run use fewer WCUs than more complex rules that use more processing power. Rule group capacity is fixed at creation, which helps users plan their web ACL WCU usage when they use a rule group. The WCU limit for web ACLs is 1,500.
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` . .. epigraph:: For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .
        :param visibility_config: Defines and enables Amazon CloudWatch metrics and web request sample collection.
        :param custom_response_bodies: A map of custom response keys and content bodies. When you create a rule with a block action, you can send a custom response to the web request. You define these for the rule group, and then use them in the rules that you define in the rule group. For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ . For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .
        :param description: A description of the rule group that helps with identification.
        :param name: The descriptive name of the rule group. You cannot change the name of a rule group after you create it.
        :param rules: The rule statements used to identify the web requests that you want to allow, block, or count. Each rule includes one top-level statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.
        :param tags: Key:value pairs associated with an AWS resource. The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource. .. epigraph:: To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.
        '''
        props = CfnRuleGroupProps(
            capacity=capacity,
            scope=scope,
            visibility_config=visibility_config,
            custom_response_bodies=custom_response_bodies,
            description=description,
            name=name,
            rules=rules,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope_, id, props])

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
        '''The Amazon Resource Name (ARN) of the rule group.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrAvailableLabels")
    def attr_available_labels(self) -> _IResolvable_da3f097b:
        '''Labels that rules in this rule group add to matching requests.

        These labels are defined in the ``RuleLabels`` for a ``Rule`` .

        :cloudformationAttribute: AvailableLabels
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrAvailableLabels"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrConsumedLabels")
    def attr_consumed_labels(self) -> _IResolvable_da3f097b:
        '''Labels that rules in this rule group match against.

        Each of these labels is defined in a ``LabelMatchStatement`` specification, in the rule statement.

        :cloudformationAttribute: ConsumedLabels
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrConsumedLabels"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the rule group.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLabelNamespace")
    def attr_label_namespace(self) -> builtins.str:
        '''The label namespace prefix for this rule group.

        All labels added by rules in this rule group have this prefix.

        The syntax for the label namespace prefix for a rule group is the following: ``awswaf:<account ID>:rule group:<rule group name>:``

        When a rule with a label matches a web request, AWS WAF adds the fully qualified label to the request. A fully qualified label is made up of the label namespace from the rule group or web ACL where the rule is defined and the label from the rule, separated by a colon.

        :cloudformationAttribute: LabelNamespace
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLabelNamespace"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Key:value pairs associated with an AWS resource.

        The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource.
        .. epigraph::

           To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="capacity")
    def capacity(self) -> jsii.Number:
        '''The web ACL capacity units (WCUs) required for this rule group.

        When you create your own rule group, you define this, and you cannot change it after creation. When you add or modify the rules in a rule group, AWS WAF enforces this limit.

        AWS WAF uses WCUs to calculate and control the operating resources that are used to run your rules, rule groups, and web ACLs. AWS WAF calculates capacity differently for each rule type, to reflect the relative cost of each rule. Simple rules that cost little to run use fewer WCUs than more complex rules that use more processing power. Rule group capacity is fixed at creation, which helps users plan their web ACL WCU usage when they use a rule group. The WCU limit for web ACLs is 1,500.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-capacity
        '''
        return typing.cast(jsii.Number, jsii.get(self, "capacity"))

    @capacity.setter
    def capacity(self, value: jsii.Number) -> None:
        jsii.set(self, "capacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scope")
    def scope(self) -> builtins.str:
        '''Specifies whether this is for an Amazon CloudFront distribution or for a regional application.

        A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` .
        .. epigraph::

           For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-scope
        '''
        return typing.cast(builtins.str, jsii.get(self, "scope"))

    @scope.setter
    def scope(self, value: builtins.str) -> None:
        jsii.set(self, "scope", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="visibilityConfig")
    def visibility_config(
        self,
    ) -> typing.Union["CfnRuleGroup.VisibilityConfigProperty", _IResolvable_da3f097b]:
        '''Defines and enables Amazon CloudWatch metrics and web request sample collection.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-visibilityconfig
        '''
        return typing.cast(typing.Union["CfnRuleGroup.VisibilityConfigProperty", _IResolvable_da3f097b], jsii.get(self, "visibilityConfig"))

    @visibility_config.setter
    def visibility_config(
        self,
        value: typing.Union["CfnRuleGroup.VisibilityConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "visibilityConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="customResponseBodies")
    def custom_response_bodies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnRuleGroup.CustomResponseBodyProperty", _IResolvable_da3f097b]]]]:
        '''A map of custom response keys and content bodies.

        When you create a rule with a block action, you can send a custom response to the web request. You define these for the rule group, and then use them in the rules that you define in the rule group.

        For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

        For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-customresponsebodies
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnRuleGroup.CustomResponseBodyProperty", _IResolvable_da3f097b]]]], jsii.get(self, "customResponseBodies"))

    @custom_response_bodies.setter
    def custom_response_bodies(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnRuleGroup.CustomResponseBodyProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "customResponseBodies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the rule group that helps with identification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The descriptive name of the rule group.

        You cannot change the name of a rule group after you create it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="rules")
    def rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.RuleProperty", _IResolvable_da3f097b]]]]:
        '''The rule statements used to identify the web requests that you want to allow, block, or count.

        Each rule includes one top-level statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-rules
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.RuleProperty", _IResolvable_da3f097b]]]], jsii.get(self, "rules"))

    @rules.setter
    def rules(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.RuleProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "rules", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.AndStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"statements": "statements"},
    )
    class AndStatementProperty:
        def __init__(
            self,
            *,
            statements: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A logical rule statement used to combine other rule statements with AND logic.

            You provide more than one ``Statement`` within the ``AndStatement`` .

            :param statements: The statements to combine with AND logic. You can use any statements that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-andstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnRuleGroup.StatementProperty
                # uri_path: Any
                
                and_statement_property = wafv2.CfnRuleGroup.AndStatementProperty(
                    statements=[wafv2.CfnRuleGroup.StatementProperty(
                        and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "statements": statements,
            }

        @builtins.property
        def statements(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]]]:
            '''The statements to combine with AND logic.

            You can use any statements that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-andstatement.html#cfn-wafv2-rulegroup-andstatement-statements
            '''
            result = self._values.get("statements")
            assert result is not None, "Required property 'statements' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AndStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.ByteMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_to_match": "fieldToMatch",
            "positional_constraint": "positionalConstraint",
            "text_transformations": "textTransformations",
            "search_string": "searchString",
            "search_string_base64": "searchStringBase64",
        },
    )
    class ByteMatchStatementProperty:
        def __init__(
            self,
            *,
            field_to_match: typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b],
            positional_constraint: builtins.str,
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]],
            search_string: typing.Optional[builtins.str] = None,
            search_string_base64: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A rule statement that defines a string match search for AWS WAF to apply to web requests.

            The byte match statement provides the bytes to search for, the location in requests that you want AWS WAF to search, and other settings. The bytes to search for are typically a string that corresponds with ASCII characters. In the AWS WAF console and the developer guide, this is refered to as a string match statement.

            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param positional_constraint: The area within the portion of a web request that you want AWS WAF to search for ``SearchString`` . Valid values include the following: *CONTAINS* The specified part of the web request must include the value of ``SearchString`` , but the location doesn't matter. *CONTAINS_WORD* The specified part of the web request must include the value of ``SearchString`` , and ``SearchString`` must contain only alphanumeric characters or underscore (A-Z, a-z, 0-9, or _). In addition, ``SearchString`` must be a word, which means that both of the following are true: - ``SearchString`` is at the beginning of the specified part of the web request or is preceded by a character other than an alphanumeric character or underscore (_). Examples include the value of a header and ``;BadBot`` . - ``SearchString`` is at the end of the specified part of the web request or is followed by a character other than an alphanumeric character or underscore (_), for example, ``BadBot;`` and ``-BadBot;`` . *EXACTLY* The value of the specified part of the web request must exactly match the value of ``SearchString`` . *STARTS_WITH* The value of ``SearchString`` must appear at the beginning of the specified part of the web request. *ENDS_WITH* The value of ``SearchString`` must appear at the end of the specified part of the web request.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.
            :param search_string: A string value that you want AWS WAF to search for. AWS WAF searches only in the part of web requests that you designate for inspection in ``FieldToMatch`` . The maximum length of the value is 50 bytes. For alphabetic characters A-Z and a-z, the value is case sensitive. Don't encode this string. Provide the value that you want AWS WAF to search for. AWS CloudFormation automatically base64 encodes the value for you. For example, suppose the value of ``Type`` is ``HEADER`` and the value of ``Data`` is ``User-Agent`` . If you want to search the ``User-Agent`` header for the value ``BadBot`` , you provide the string ``BadBot`` in the value of ``SearchString`` . You must specify either ``SearchString`` or ``SearchStringBase64`` in a ``ByteMatchStatement`` .
            :param search_string_base64: String to search for in a web request component, base64-encoded. If you don't want to encode the string, specify the unencoded value in ``SearchString`` instead. You must specify either ``SearchString`` or ``SearchStringBase64`` in a ``ByteMatchStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-bytematchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                byte_match_statement_property = wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                    field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                            match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    positional_constraint="positionalConstraint",
                    text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )],
                
                    # the properties below are optional
                    search_string="searchString",
                    search_string_base64="searchStringBase64"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "field_to_match": field_to_match,
                "positional_constraint": positional_constraint,
                "text_transformations": text_transformations,
            }
            if search_string is not None:
                self._values["search_string"] = search_string
            if search_string_base64 is not None:
                self._values["search_string_base64"] = search_string_base64

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-bytematchstatement.html#cfn-wafv2-rulegroup-bytematchstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def positional_constraint(self) -> builtins.str:
            '''The area within the portion of a web request that you want AWS WAF to search for ``SearchString`` .

            Valid values include the following:

            *CONTAINS*

            The specified part of the web request must include the value of ``SearchString`` , but the location doesn't matter.

            *CONTAINS_WORD*

            The specified part of the web request must include the value of ``SearchString`` , and ``SearchString`` must contain only alphanumeric characters or underscore (A-Z, a-z, 0-9, or _). In addition, ``SearchString`` must be a word, which means that both of the following are true:

            - ``SearchString`` is at the beginning of the specified part of the web request or is preceded by a character other than an alphanumeric character or underscore (_). Examples include the value of a header and ``;BadBot`` .
            - ``SearchString`` is at the end of the specified part of the web request or is followed by a character other than an alphanumeric character or underscore (_), for example, ``BadBot;`` and ``-BadBot;`` .

            *EXACTLY*

            The value of the specified part of the web request must exactly match the value of ``SearchString`` .

            *STARTS_WITH*

            The value of ``SearchString`` must appear at the beginning of the specified part of the web request.

            *ENDS_WITH*

            The value of ``SearchString`` must appear at the end of the specified part of the web request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-bytematchstatement.html#cfn-wafv2-rulegroup-bytematchstatement-positionalconstraint
            '''
            result = self._values.get("positional_constraint")
            assert result is not None, "Required property 'positional_constraint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-bytematchstatement.html#cfn-wafv2-rulegroup-bytematchstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def search_string(self) -> typing.Optional[builtins.str]:
            '''A string value that you want AWS WAF to search for.

            AWS WAF searches only in the part of web requests that you designate for inspection in ``FieldToMatch`` . The maximum length of the value is 50 bytes. For alphabetic characters A-Z and a-z, the value is case sensitive.

            Don't encode this string. Provide the value that you want AWS WAF to search for. AWS CloudFormation automatically base64 encodes the value for you.

            For example, suppose the value of ``Type`` is ``HEADER`` and the value of ``Data`` is ``User-Agent`` . If you want to search the ``User-Agent`` header for the value ``BadBot`` , you provide the string ``BadBot`` in the value of ``SearchString`` .

            You must specify either ``SearchString`` or ``SearchStringBase64`` in a ``ByteMatchStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-bytematchstatement.html#cfn-wafv2-rulegroup-bytematchstatement-searchstring
            '''
            result = self._values.get("search_string")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def search_string_base64(self) -> typing.Optional[builtins.str]:
            '''String to search for in a web request component, base64-encoded.

            If you don't want to encode the string, specify the unencoded value in ``SearchString`` instead.

            You must specify either ``SearchString`` or ``SearchStringBase64`` in a ``ByteMatchStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-bytematchstatement.html#cfn-wafv2-rulegroup-bytematchstatement-searchstringbase64
            '''
            result = self._values.get("search_string_base64")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ByteMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.CaptchaConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"immunity_time_property": "immunityTimeProperty"},
    )
    class CaptchaConfigProperty:
        def __init__(
            self,
            *,
            immunity_time_property: typing.Optional[typing.Union["CfnRuleGroup.ImmunityTimePropertyProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies how AWS WAF should handle ``CAPTCHA`` evaluations.

            This is available at the web ACL level and in each rule.

            :param immunity_time_property: Determines how long a ``CAPTCHA`` token remains valid after the client successfully solves a ``CAPTCHA`` puzzle.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-captchaconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                captcha_config_property = wafv2.CfnRuleGroup.CaptchaConfigProperty(
                    immunity_time_property=wafv2.CfnRuleGroup.ImmunityTimePropertyProperty(
                        immunity_time=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if immunity_time_property is not None:
                self._values["immunity_time_property"] = immunity_time_property

        @builtins.property
        def immunity_time_property(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.ImmunityTimePropertyProperty", _IResolvable_da3f097b]]:
            '''Determines how long a ``CAPTCHA`` token remains valid after the client successfully solves a ``CAPTCHA`` puzzle.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-captchaconfig.html#cfn-wafv2-rulegroup-captchaconfig-immunitytimeproperty
            '''
            result = self._values.get("immunity_time_property")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.ImmunityTimePropertyProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CaptchaConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.CustomResponseBodyProperty",
        jsii_struct_bases=[],
        name_mapping={"content": "content", "content_type": "contentType"},
    )
    class CustomResponseBodyProperty:
        def __init__(
            self,
            *,
            content: builtins.str,
            content_type: builtins.str,
        ) -> None:
            '''The response body to use in a custom response to a web request.

            This is referenced by key from the ``CustomResponse`` ``CustomResponseBodyKey`` .

            :param content: The payload of the custom response. You can use JSON escape strings in JSON content. To do this, you must specify JSON content in the ``ContentType`` setting. For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .
            :param content_type: The type of content in the payload that you are defining in the ``Content`` string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-customresponsebody.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                custom_response_body_property = wafv2.CfnRuleGroup.CustomResponseBodyProperty(
                    content="content",
                    content_type="contentType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "content": content,
                "content_type": content_type,
            }

        @builtins.property
        def content(self) -> builtins.str:
            '''The payload of the custom response.

            You can use JSON escape strings in JSON content. To do this, you must specify JSON content in the ``ContentType`` setting.

            For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-customresponsebody.html#cfn-wafv2-rulegroup-customresponsebody-content
            '''
            result = self._values.get("content")
            assert result is not None, "Required property 'content' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def content_type(self) -> builtins.str:
            '''The type of content in the payload that you are defining in the ``Content`` string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-customresponsebody.html#cfn-wafv2-rulegroup-customresponsebody-contenttype
            '''
            result = self._values.get("content_type")
            assert result is not None, "Required property 'content_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomResponseBodyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.FieldToMatchProperty",
        jsii_struct_bases=[],
        name_mapping={
            "all_query_arguments": "allQueryArguments",
            "body": "body",
            "json_body": "jsonBody",
            "method": "method",
            "query_string": "queryString",
            "single_header": "singleHeader",
            "single_query_argument": "singleQueryArgument",
            "uri_path": "uriPath",
        },
    )
    class FieldToMatchProperty:
        def __init__(
            self,
            *,
            all_query_arguments: typing.Any = None,
            body: typing.Any = None,
            json_body: typing.Optional[typing.Union["CfnRuleGroup.JsonBodyProperty", _IResolvable_da3f097b]] = None,
            method: typing.Any = None,
            query_string: typing.Any = None,
            single_header: typing.Any = None,
            single_query_argument: typing.Any = None,
            uri_path: typing.Any = None,
        ) -> None:
            '''The part of a web request that you want AWS WAF to inspect.

            Include the single ``FieldToMatch`` type that you want to inspect, with additional specifications as needed, according to the type. You specify a single request component in ``FieldToMatch`` for each rule statement that requires it. To inspect more than one component of a web request, create a separate rule statement for each component.

            :param all_query_arguments: Inspect all query arguments.
            :param body: Inspect the request body, which immediately follows the request headers. This is the part of a request that contains any additional data that you want to send to your web server as the HTTP request body, such as data from a form. Note that only the first 8 KB (8192 bytes) of the request body are forwarded to AWS WAF for inspection by the underlying host service. If you don't need to inspect more than 8 KB, you can guarantee that you don't allow additional bytes in by combining a statement that inspects the body of the web request, such as the ``ByteMatchStatement`` or ``RegexPatternSetReferenceStatement`` , with a ``SizeConstraintStatement`` that enforces an 8 KB size limit on the body of the request. AWS WAF doesn't support inspecting the entire contents of web requests whose bodies exceed the 8 KB limit.
            :param json_body: Inspect the request body as JSON. The request body immediately follows the request headers. This is the part of a request that contains any additional data that you want to send to your web server as the HTTP request body, such as data from a form. Note that only the first 8 KB (8192 bytes) of the request body are forwarded to AWS WAF for inspection by the underlying host service. If you don't need to inspect more than 8 KB, you can guarantee that you don't allow additional bytes in by combining a statement that inspects the body of the web request, such as the ``ByteMatchStatement`` or ``RegexPatternSetReferenceStatement`` , with a ``SizeConstraintStatement`` that enforces an 8 KB size limit on the body of the request. AWS WAF doesn't support inspecting the entire contents of web requests whose bodies exceed the 8 KB limit.
            :param method: Inspect the HTTP method. The method indicates the type of operation that the request is asking the origin to perform.
            :param query_string: Inspect the query string. This is the part of a URL that appears after a ``?`` character, if any.
            :param single_header: Inspect a single header. Provide the name of the header to inspect, for example, ``User-Agent`` or ``Referer`` . This setting isn't case sensitive.
            :param single_query_argument: Inspect a single query argument. Provide the name of the query argument to inspect, such as *UserName* or *SalesRegion* . The name can be up to 30 characters long and isn't case sensitive.
            :param uri_path: Inspect the request URI path. This is the part of a web request that identifies a resource, for example, ``/images/daily-ad.jpg`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                field_to_match_property = wafv2.CfnRuleGroup.FieldToMatchProperty(
                    all_query_arguments=all_query_arguments,
                    body=body,
                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                            all=all,
                            included_paths=["includedPaths"]
                        ),
                        match_scope="matchScope",
                
                        # the properties below are optional
                        invalid_fallback_behavior="invalidFallbackBehavior"
                    ),
                    method=method,
                    query_string=query_string,
                    single_header=single_header,
                    single_query_argument=single_query_argument,
                    uri_path=uri_path
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if all_query_arguments is not None:
                self._values["all_query_arguments"] = all_query_arguments
            if body is not None:
                self._values["body"] = body
            if json_body is not None:
                self._values["json_body"] = json_body
            if method is not None:
                self._values["method"] = method
            if query_string is not None:
                self._values["query_string"] = query_string
            if single_header is not None:
                self._values["single_header"] = single_header
            if single_query_argument is not None:
                self._values["single_query_argument"] = single_query_argument
            if uri_path is not None:
                self._values["uri_path"] = uri_path

        @builtins.property
        def all_query_arguments(self) -> typing.Any:
            '''Inspect all query arguments.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html#cfn-wafv2-rulegroup-fieldtomatch-allqueryarguments
            '''
            result = self._values.get("all_query_arguments")
            return typing.cast(typing.Any, result)

        @builtins.property
        def body(self) -> typing.Any:
            '''Inspect the request body, which immediately follows the request headers.

            This is the part of a request that contains any additional data that you want to send to your web server as the HTTP request body, such as data from a form.

            Note that only the first 8 KB (8192 bytes) of the request body are forwarded to AWS WAF for inspection by the underlying host service. If you don't need to inspect more than 8 KB, you can guarantee that you don't allow additional bytes in by combining a statement that inspects the body of the web request, such as the ``ByteMatchStatement`` or ``RegexPatternSetReferenceStatement`` , with a ``SizeConstraintStatement`` that enforces an 8 KB size limit on the body of the request. AWS WAF doesn't support inspecting the entire contents of web requests whose bodies exceed the 8 KB limit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html#cfn-wafv2-rulegroup-fieldtomatch-body
            '''
            result = self._values.get("body")
            return typing.cast(typing.Any, result)

        @builtins.property
        def json_body(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.JsonBodyProperty", _IResolvable_da3f097b]]:
            '''Inspect the request body as JSON.

            The request body immediately follows the request headers. This is the part of a request that contains any additional data that you want to send to your web server as the HTTP request body, such as data from a form.

            Note that only the first 8 KB (8192 bytes) of the request body are forwarded to AWS WAF for inspection by the underlying host service. If you don't need to inspect more than 8 KB, you can guarantee that you don't allow additional bytes in by combining a statement that inspects the body of the web request, such as the ``ByteMatchStatement`` or ``RegexPatternSetReferenceStatement`` , with a ``SizeConstraintStatement`` that enforces an 8 KB size limit on the body of the request. AWS WAF doesn't support inspecting the entire contents of web requests whose bodies exceed the 8 KB limit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html#cfn-wafv2-rulegroup-fieldtomatch-jsonbody
            '''
            result = self._values.get("json_body")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.JsonBodyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def method(self) -> typing.Any:
            '''Inspect the HTTP method.

            The method indicates the type of operation that the request is asking the origin to perform.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html#cfn-wafv2-rulegroup-fieldtomatch-method
            '''
            result = self._values.get("method")
            return typing.cast(typing.Any, result)

        @builtins.property
        def query_string(self) -> typing.Any:
            '''Inspect the query string.

            This is the part of a URL that appears after a ``?`` character, if any.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html#cfn-wafv2-rulegroup-fieldtomatch-querystring
            '''
            result = self._values.get("query_string")
            return typing.cast(typing.Any, result)

        @builtins.property
        def single_header(self) -> typing.Any:
            '''Inspect a single header.

            Provide the name of the header to inspect, for example, ``User-Agent`` or ``Referer`` . This setting isn't case sensitive.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html#cfn-wafv2-rulegroup-fieldtomatch-singleheader
            '''
            result = self._values.get("single_header")
            return typing.cast(typing.Any, result)

        @builtins.property
        def single_query_argument(self) -> typing.Any:
            '''Inspect a single query argument.

            Provide the name of the query argument to inspect, such as *UserName* or *SalesRegion* . The name can be up to 30 characters long and isn't case sensitive.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html#cfn-wafv2-rulegroup-fieldtomatch-singlequeryargument
            '''
            result = self._values.get("single_query_argument")
            return typing.cast(typing.Any, result)

        @builtins.property
        def uri_path(self) -> typing.Any:
            '''Inspect the request URI path.

            This is the part of a web request that identifies a resource, for example, ``/images/daily-ad.jpg`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-fieldtomatch.html#cfn-wafv2-rulegroup-fieldtomatch-uripath
            '''
            result = self._values.get("uri_path")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FieldToMatchProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "fallback_behavior": "fallbackBehavior",
            "header_name": "headerName",
        },
    )
    class ForwardedIPConfigurationProperty:
        def __init__(
            self,
            *,
            fallback_behavior: builtins.str,
            header_name: builtins.str,
        ) -> None:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            This configuration is used for ``GeoMatchStatement`` and ``RateBasedStatement`` . For ``IPSetReferenceStatement`` , use ``IPSetForwardedIPConfig`` instead.

            AWS WAF only evaluates the first IP address found in the specified HTTP header.

            :param fallback_behavior: The match status to assign to the web request if the request doesn't have a valid IP address in the specified position. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all. You can specify the following fallback behaviors: - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request. - ``NO_MATCH`` - Treat the web request as not matching the rule statement.
            :param header_name: The name of the HTTP header to use for the IP address. For example, to use the X-Forwarded-For (XFF) header, set this to ``X-Forwarded-For`` . .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-forwardedipconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                forwarded_iPConfiguration_property = wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                    fallback_behavior="fallbackBehavior",
                    header_name="headerName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "fallback_behavior": fallback_behavior,
                "header_name": header_name,
            }

        @builtins.property
        def fallback_behavior(self) -> builtins.str:
            '''The match status to assign to the web request if the request doesn't have a valid IP address in the specified position.

            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            You can specify the following fallback behaviors:

            - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request.
            - ``NO_MATCH`` - Treat the web request as not matching the rule statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-forwardedipconfiguration.html#cfn-wafv2-rulegroup-forwardedipconfiguration-fallbackbehavior
            '''
            result = self._values.get("fallback_behavior")
            assert result is not None, "Required property 'fallback_behavior' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def header_name(self) -> builtins.str:
            '''The name of the HTTP header to use for the IP address.

            For example, to use the X-Forwarded-For (XFF) header, set this to ``X-Forwarded-For`` .
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-forwardedipconfiguration.html#cfn-wafv2-rulegroup-forwardedipconfiguration-headername
            '''
            result = self._values.get("header_name")
            assert result is not None, "Required property 'header_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ForwardedIPConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.GeoMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "country_codes": "countryCodes",
            "forwarded_ip_config": "forwardedIpConfig",
        },
    )
    class GeoMatchStatementProperty:
        def __init__(
            self,
            *,
            country_codes: typing.Optional[typing.Sequence[builtins.str]] = None,
            forwarded_ip_config: typing.Optional[typing.Union["CfnRuleGroup.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A rule statement used to identify web requests based on country of origin.

            :param country_codes: An array of two-character country codes, for example, ``[ "US", "CN" ]`` , from the alpha-2 country ISO codes of the ISO 3166 international standard.
            :param forwarded_ip_config: The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-geomatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                geo_match_statement_property = wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                    country_codes=["countryCodes"],
                    forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                        fallback_behavior="fallbackBehavior",
                        header_name="headerName"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if country_codes is not None:
                self._values["country_codes"] = country_codes
            if forwarded_ip_config is not None:
                self._values["forwarded_ip_config"] = forwarded_ip_config

        @builtins.property
        def country_codes(self) -> typing.Optional[typing.List[builtins.str]]:
            '''An array of two-character country codes, for example, ``[ "US", "CN" ]`` , from the alpha-2 country ISO codes of the ISO 3166 international standard.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-geomatchstatement.html#cfn-wafv2-rulegroup-geomatchstatement-countrycodes
            '''
            result = self._values.get("country_codes")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def forwarded_ip_config(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-geomatchstatement.html#cfn-wafv2-rulegroup-geomatchstatement-forwardedipconfig
            '''
            result = self._values.get("forwarded_ip_config")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GeoMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.IPSetForwardedIPConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "fallback_behavior": "fallbackBehavior",
            "header_name": "headerName",
            "position": "position",
        },
    )
    class IPSetForwardedIPConfigurationProperty:
        def __init__(
            self,
            *,
            fallback_behavior: builtins.str,
            header_name: builtins.str,
            position: builtins.str,
        ) -> None:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            This configuration is used only for ``IPSetReferenceStatement`` . For ``GeoMatchStatement`` and ``RateBasedStatement`` , use ``ForwardedIPConfig`` instead.

            :param fallback_behavior: The match status to assign to the web request if the request doesn't have a valid IP address in the specified position. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all. You can specify the following fallback behaviors: - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request. - ``NO_MATCH`` - Treat the web request as not matching the rule statement.
            :param header_name: The name of the HTTP header to use for the IP address. For example, to use the X-Forwarded-For (XFF) header, set this to ``X-Forwarded-For`` . .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.
            :param position: The position in the header to search for the IP address. The header can contain IP addresses of the original client and also of proxies. For example, the header value could be ``10.1.1.1, 127.0.0.0, 10.10.10.10`` where the first IP address identifies the original client and the rest identify proxies that the request went through. The options for this setting are the following: - FIRST - Inspect the first IP address in the list of IP addresses in the header. This is usually the client's original IP. - LAST - Inspect the last IP address in the list of IP addresses in the header. - ANY - Inspect all IP addresses in the header for a match. If the header contains more than 10 IP addresses, AWS WAF inspects the last 10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ipsetforwardedipconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                i_pSet_forwarded_iPConfiguration_property = {
                    "fallback_behavior": "fallbackBehavior",
                    "header_name": "headerName",
                    "position": "position"
                }
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "fallback_behavior": fallback_behavior,
                "header_name": header_name,
                "position": position,
            }

        @builtins.property
        def fallback_behavior(self) -> builtins.str:
            '''The match status to assign to the web request if the request doesn't have a valid IP address in the specified position.

            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            You can specify the following fallback behaviors:

            - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request.
            - ``NO_MATCH`` - Treat the web request as not matching the rule statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ipsetforwardedipconfiguration.html#cfn-wafv2-rulegroup-ipsetforwardedipconfiguration-fallbackbehavior
            '''
            result = self._values.get("fallback_behavior")
            assert result is not None, "Required property 'fallback_behavior' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def header_name(self) -> builtins.str:
            '''The name of the HTTP header to use for the IP address.

            For example, to use the X-Forwarded-For (XFF) header, set this to ``X-Forwarded-For`` .
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ipsetforwardedipconfiguration.html#cfn-wafv2-rulegroup-ipsetforwardedipconfiguration-headername
            '''
            result = self._values.get("header_name")
            assert result is not None, "Required property 'header_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def position(self) -> builtins.str:
            '''The position in the header to search for the IP address.

            The header can contain IP addresses of the original client and also of proxies. For example, the header value could be ``10.1.1.1, 127.0.0.0, 10.10.10.10`` where the first IP address identifies the original client and the rest identify proxies that the request went through.

            The options for this setting are the following:

            - FIRST - Inspect the first IP address in the list of IP addresses in the header. This is usually the client's original IP.
            - LAST - Inspect the last IP address in the list of IP addresses in the header.
            - ANY - Inspect all IP addresses in the header for a match. If the header contains more than 10 IP addresses, AWS WAF inspects the last 10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ipsetforwardedipconfiguration.html#cfn-wafv2-rulegroup-ipsetforwardedipconfiguration-position
            '''
            result = self._values.get("position")
            assert result is not None, "Required property 'position' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IPSetForwardedIPConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.IPSetReferenceStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arn": "arn",
            "ip_set_forwarded_ip_config": "ipSetForwardedIpConfig",
        },
    )
    class IPSetReferenceStatementProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            ip_set_forwarded_ip_config: typing.Optional[typing.Union["CfnRuleGroup.IPSetForwardedIPConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A rule statement used to detect web requests coming from particular IP addresses or address ranges.

            To use this, create an ``IPSet`` that specifies the addresses you want to detect, then use the ARN of that set in this statement.

            Each IP set rule statement references an IP set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.

            :param arn: The Amazon Resource Name (ARN) of the ``IPSet`` that this statement references.
            :param ip_set_forwarded_ip_config: The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ipsetreferencestatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                i_pSet_reference_statement_property = {
                    "arn": "arn",
                
                    # the properties below are optional
                    "ip_set_forwarded_ip_config": {
                        "fallback_behavior": "fallbackBehavior",
                        "header_name": "headerName",
                        "position": "position"
                    }
                }
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
            }
            if ip_set_forwarded_ip_config is not None:
                self._values["ip_set_forwarded_ip_config"] = ip_set_forwarded_ip_config

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the ``IPSet`` that this statement references.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ipsetreferencestatement.html#cfn-wafv2-rulegroup-ipsetreferencestatement-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ip_set_forwarded_ip_config(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.IPSetForwardedIPConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ipsetreferencestatement.html#cfn-wafv2-rulegroup-ipsetreferencestatement-ipsetforwardedipconfig
            '''
            result = self._values.get("ip_set_forwarded_ip_config")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.IPSetForwardedIPConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IPSetReferenceStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.ImmunityTimePropertyProperty",
        jsii_struct_bases=[],
        name_mapping={"immunity_time": "immunityTime"},
    )
    class ImmunityTimePropertyProperty:
        def __init__(self, *, immunity_time: jsii.Number) -> None:
            '''Determines how long a ``CAPTCHA`` token remains valid after the client successfully solves a ``CAPTCHA`` puzzle.

            :param immunity_time: The amount of time, in seconds, that a ``CAPTCHA`` token is valid. The default setting is 300.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-immunitytimeproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                immunity_time_property_property = wafv2.CfnRuleGroup.ImmunityTimePropertyProperty(
                    immunity_time=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "immunity_time": immunity_time,
            }

        @builtins.property
        def immunity_time(self) -> jsii.Number:
            '''The amount of time, in seconds, that a ``CAPTCHA`` token is valid.

            The default setting is 300.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-immunitytimeproperty.html#cfn-wafv2-rulegroup-immunitytimeproperty-immunitytime
            '''
            result = self._values.get("immunity_time")
            assert result is not None, "Required property 'immunity_time' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ImmunityTimePropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.JsonBodyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "match_pattern": "matchPattern",
            "match_scope": "matchScope",
            "invalid_fallback_behavior": "invalidFallbackBehavior",
        },
    )
    class JsonBodyProperty:
        def __init__(
            self,
            *,
            match_pattern: typing.Union["CfnRuleGroup.JsonMatchPatternProperty", _IResolvable_da3f097b],
            match_scope: builtins.str,
            invalid_fallback_behavior: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The body of a web request, inspected as JSON.

            The body immediately follows the request headers. This is used in the ``FieldToMatch`` specification.

            Use the specifications in this object to indicate which parts of the JSON body to inspect using the rule's inspection criteria. AWS WAF inspects only the parts of the JSON that result from the matches that you indicate.

            :param match_pattern: The patterns to look for in the JSON body. AWS WAF inspects the results of these pattern matches against the rule inspection criteria.
            :param match_scope: The parts of the JSON to match against using the ``MatchPattern`` . If you specify ``All`` , AWS WAF matches against keys and values.
            :param invalid_fallback_behavior: What AWS WAF should do if it fails to completely parse the JSON body. The options are the following:. - ``EVALUATE_AS_STRING`` - Inspect the body as plain text. AWS WAF applies the text transformations and inspection criteria that you defined for the JSON inspection to the body text string. - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request. - ``NO_MATCH`` - Treat the web request as not matching the rule statement. If you don't provide this setting, AWS WAF parses and evaluates the content only up to the first parsing failure that it encounters. AWS WAF does its best to parse the entire JSON body, but might be forced to stop for reasons such as invalid characters, duplicate keys, truncation, and any content whose root node isn't an object or an array. AWS WAF parses the JSON in the following examples as two valid key, value pairs: - Missing comma: ``{"key1":"value1""key2":"value2"}`` - Missing colon: ``{"key1":"value1","key2""value2"}`` - Extra colons: ``{"key1"::"value1","key2""value2"}``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-jsonbody.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                
                json_body_property = wafv2.CfnRuleGroup.JsonBodyProperty(
                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                        all=all,
                        included_paths=["includedPaths"]
                    ),
                    match_scope="matchScope",
                
                    # the properties below are optional
                    invalid_fallback_behavior="invalidFallbackBehavior"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "match_pattern": match_pattern,
                "match_scope": match_scope,
            }
            if invalid_fallback_behavior is not None:
                self._values["invalid_fallback_behavior"] = invalid_fallback_behavior

        @builtins.property
        def match_pattern(
            self,
        ) -> typing.Union["CfnRuleGroup.JsonMatchPatternProperty", _IResolvable_da3f097b]:
            '''The patterns to look for in the JSON body.

            AWS WAF inspects the results of these pattern matches against the rule inspection criteria.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-jsonbody.html#cfn-wafv2-rulegroup-jsonbody-matchpattern
            '''
            result = self._values.get("match_pattern")
            assert result is not None, "Required property 'match_pattern' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.JsonMatchPatternProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def match_scope(self) -> builtins.str:
            '''The parts of the JSON to match against using the ``MatchPattern`` .

            If you specify ``All`` , AWS WAF matches against keys and values.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-jsonbody.html#cfn-wafv2-rulegroup-jsonbody-matchscope
            '''
            result = self._values.get("match_scope")
            assert result is not None, "Required property 'match_scope' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def invalid_fallback_behavior(self) -> typing.Optional[builtins.str]:
            '''What AWS WAF should do if it fails to completely parse the JSON body. The options are the following:.

            - ``EVALUATE_AS_STRING`` - Inspect the body as plain text. AWS WAF applies the text transformations and inspection criteria that you defined for the JSON inspection to the body text string.
            - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request.
            - ``NO_MATCH`` - Treat the web request as not matching the rule statement.

            If you don't provide this setting, AWS WAF parses and evaluates the content only up to the first parsing failure that it encounters.

            AWS WAF does its best to parse the entire JSON body, but might be forced to stop for reasons such as invalid characters, duplicate keys, truncation, and any content whose root node isn't an object or an array.

            AWS WAF parses the JSON in the following examples as two valid key, value pairs:

            - Missing comma: ``{"key1":"value1""key2":"value2"}``
            - Missing colon: ``{"key1":"value1","key2""value2"}``
            - Extra colons: ``{"key1"::"value1","key2""value2"}``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-jsonbody.html#cfn-wafv2-rulegroup-jsonbody-invalidfallbackbehavior
            '''
            result = self._values.get("invalid_fallback_behavior")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JsonBodyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.JsonMatchPatternProperty",
        jsii_struct_bases=[],
        name_mapping={"all": "all", "included_paths": "includedPaths"},
    )
    class JsonMatchPatternProperty:
        def __init__(
            self,
            *,
            all: typing.Any = None,
            included_paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The patterns to look for in the JSON body.

            AWS WAF inspects the results of these pattern matches against the rule inspection criteria. This is used with the ``FieldToMatch`` option ``JsonBody`` .

            :param all: Match all of the elements. See also ``MatchScope`` in ``JsonBody`` . You must specify either this setting or the ``IncludedPaths`` setting, but not both.
            :param included_paths: Match only the specified include paths. See also ``MatchScope`` in ``JsonBody`` . Provide the include paths using JSON Pointer syntax. For example, ``"IncludedPaths": ["/dogs/0/name", "/dogs/1/name"]`` . For information about this syntax, see the Internet Engineering Task Force (IETF) documentation `JavaScript Object Notation (JSON) Pointer <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6901>`_ . You must specify either this setting or the ``All`` setting, but not both. .. epigraph:: Don't use this option to include all paths. Instead, use the ``All`` setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-jsonmatchpattern.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                
                json_match_pattern_property = wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                    all=all,
                    included_paths=["includedPaths"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if all is not None:
                self._values["all"] = all
            if included_paths is not None:
                self._values["included_paths"] = included_paths

        @builtins.property
        def all(self) -> typing.Any:
            '''Match all of the elements. See also ``MatchScope`` in ``JsonBody`` .

            You must specify either this setting or the ``IncludedPaths`` setting, but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-jsonmatchpattern.html#cfn-wafv2-rulegroup-jsonmatchpattern-all
            '''
            result = self._values.get("all")
            return typing.cast(typing.Any, result)

        @builtins.property
        def included_paths(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Match only the specified include paths. See also ``MatchScope`` in ``JsonBody`` .

            Provide the include paths using JSON Pointer syntax. For example, ``"IncludedPaths": ["/dogs/0/name", "/dogs/1/name"]`` . For information about this syntax, see the Internet Engineering Task Force (IETF) documentation `JavaScript Object Notation (JSON) Pointer <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6901>`_ .

            You must specify either this setting or the ``All`` setting, but not both.
            .. epigraph::

               Don't use this option to include all paths. Instead, use the ``All`` setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-jsonmatchpattern.html#cfn-wafv2-rulegroup-jsonmatchpattern-includedpaths
            '''
            result = self._values.get("included_paths")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JsonMatchPatternProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.LabelMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "scope": "scope"},
    )
    class LabelMatchStatementProperty:
        def __init__(self, *, key: builtins.str, scope: builtins.str) -> None:
            '''A rule statement that defines a string match search against labels that have been added to the web request by rules that have already run in the web ACL.

            The label match statement provides the label or namespace string to search for. The label string can represent a part or all of the fully qualified label name that had been added to the web request. Fully qualified labels have a prefix, optional namespaces, and label name. The prefix identifies the rule group or web ACL context of the rule that added the label. If you do not provide the fully qualified name in your label match string, AWS WAF performs the search for labels that were added in the same context as the label match statement.

            :param key: The string to match against. The setting you provide for this depends on the match statement's ``Scope`` setting:. - If the ``Scope`` indicates ``LABEL`` , then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name. - If the ``Scope`` indicates ``NAMESPACE`` , then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates. Labels are case sensitive and components of a label must be separated by colon, for example ``NS1:NS2:name`` .
            :param scope: Specify whether you want to match using the label name or just the namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-labelmatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                label_match_statement_property = wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                    key="key",
                    scope="scope"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "scope": scope,
            }

        @builtins.property
        def key(self) -> builtins.str:
            '''The string to match against. The setting you provide for this depends on the match statement's ``Scope`` setting:.

            - If the ``Scope`` indicates ``LABEL`` , then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name.
            - If the ``Scope`` indicates ``NAMESPACE`` , then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates.

            Labels are case sensitive and components of a label must be separated by colon, for example ``NS1:NS2:name`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-labelmatchstatement.html#cfn-wafv2-rulegroup-labelmatchstatement-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def scope(self) -> builtins.str:
            '''Specify whether you want to match using the label name or just the namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-labelmatchstatement.html#cfn-wafv2-rulegroup-labelmatchstatement-scope
            '''
            result = self._values.get("scope")
            assert result is not None, "Required property 'scope' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LabelMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.LabelProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name"},
    )
    class LabelProperty:
        def __init__(self, *, name: builtins.str) -> None:
            '''A single label container.

            This is used as an element of a label array in ``RuleLabels`` inside a ``Rule`` .

            :param name: The label string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-label.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                label_property = wafv2.CfnRuleGroup.LabelProperty(
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The label string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-label.html#cfn-wafv2-rulegroup-label-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LabelProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.LabelSummaryProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name"},
    )
    class LabelSummaryProperty:
        def __init__(self, *, name: typing.Optional[builtins.str] = None) -> None:
            '''List of labels used by one or more of the rules of a ``RuleGroup`` .

            This summary object is used for the following rule group lists:

            - ``AvailableLabels`` - Labels that rules add to matching requests. These labels are defined in the ``RuleLabels`` for a ``Rule`` .
            - ``ConsumedLabels`` - Labels that rules match against. These labels are defined in a ``LabelMatchStatement`` specification, in the rule statement.

            :param name: An individual label specification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-labelsummary.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                label_summary_property = wafv2.CfnRuleGroup.LabelSummaryProperty(
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''An individual label specification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-labelsummary.html#cfn-wafv2-rulegroup-labelsummary-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LabelSummaryProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.NotStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"statement": "statement"},
    )
    class NotStatementProperty:
        def __init__(
            self,
            *,
            statement: typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b],
        ) -> None:
            '''A logical rule statement used to negate the results of another rule statement.

            You provide one ``Statement`` within the ``NotStatement`` .

            :param statement: The statement to negate. You can use any statement that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-notstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnRuleGroup.StatementProperty
                # uri_path: Any
                
                not_statement_property = wafv2.CfnRuleGroup.NotStatementProperty(
                    statement=wafv2.CfnRuleGroup.StatementProperty(
                        and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "statement": statement,
            }

        @builtins.property
        def statement(
            self,
        ) -> typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]:
            '''The statement to negate.

            You can use any statement that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-notstatement.html#cfn-wafv2-rulegroup-notstatement-statement
            '''
            result = self._values.get("statement")
            assert result is not None, "Required property 'statement' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.OrStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"statements": "statements"},
    )
    class OrStatementProperty:
        def __init__(
            self,
            *,
            statements: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A logical rule statement used to combine other rule statements with OR logic.

            You provide more than one ``Statement`` within the ``OrStatement`` .

            :param statements: The statements to combine with OR logic. You can use any statements that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-orstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnRuleGroup.StatementProperty
                # uri_path: Any
                
                or_statement_property = wafv2.CfnRuleGroup.OrStatementProperty(
                    statements=[wafv2.CfnRuleGroup.StatementProperty(
                        and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "statements": statements,
            }

        @builtins.property
        def statements(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]]]:
            '''The statements to combine with OR logic.

            You can use any statements that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-orstatement.html#cfn-wafv2-rulegroup-orstatement-statements
            '''
            result = self._values.get("statements")
            assert result is not None, "Required property 'statements' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OrStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.RateBasedStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "aggregate_key_type": "aggregateKeyType",
            "limit": "limit",
            "forwarded_ip_config": "forwardedIpConfig",
            "scope_down_statement": "scopeDownStatement",
        },
    )
    class RateBasedStatementProperty:
        def __init__(
            self,
            *,
            aggregate_key_type: builtins.str,
            limit: jsii.Number,
            forwarded_ip_config: typing.Optional[typing.Union["CfnRuleGroup.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]] = None,
            scope_down_statement: typing.Optional[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span.

            You can use this to put a temporary block on requests from an IP address that is sending excessive requests.

            When the rule action triggers, AWS WAF blocks additional requests from the IP address until the request rate falls below the limit.

            You can optionally nest another statement inside the rate-based statement, to narrow the scope of the rule so that it only counts requests that match the nested statement. For example, based on recent requests that you have seen from an attacker, you might create a rate-based rule with a nested AND rule statement that contains the following nested statements:

            - An IP match statement with an IP set that specified the address 192.0.2.44.
            - A string match statement that searches in the User-Agent header for the string BadBot.

            In this rate-based rule, you also define a rate limit. For this example, the rate limit is 1,000. Requests that meet both of the conditions in the statements are counted. If the count exceeds 1,000 requests per five minutes, the rule action triggers. Requests that do not meet both conditions are not counted towards the rate limit and are not affected by this rule.

            You cannot nest a ``RateBasedStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.

            :param aggregate_key_type: Setting that indicates how to aggregate the request counts. The options are the following:. - IP - Aggregate the request counts on the IP address from the web request origin. - FORWARDED_IP - Aggregate the request counts on the first IP address in an HTTP header. If you use this, configure the ``ForwardedIPConfig`` , to specify the header to use.
            :param limit: The limit on requests per 5-minute period for a single originating IP address. If the statement includes a ``ScopeDownStatement`` , this limit is applied only to the requests that match the statement.
            :param forwarded_ip_config: The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all. This is required if ``AggregateKeyType`` is set to ``FORWARDED_IP`` .
            :param scope_down_statement: An optional nested statement that narrows the scope of the rate-based statement to matching web requests. This can be any nestable statement, and you can nest statements at any level below this scope-down statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ratebasedstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnRuleGroup.StatementProperty
                # uri_path: Any
                
                rate_based_statement_property = wafv2.CfnRuleGroup.RateBasedStatementProperty(
                    aggregate_key_type="aggregateKeyType",
                    limit=123,
                
                    # the properties below are optional
                    forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                        fallback_behavior="fallbackBehavior",
                        header_name="headerName"
                    ),
                    scope_down_statement=wafv2.CfnRuleGroup.StatementProperty(
                        and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "aggregate_key_type": aggregate_key_type,
                "limit": limit,
            }
            if forwarded_ip_config is not None:
                self._values["forwarded_ip_config"] = forwarded_ip_config
            if scope_down_statement is not None:
                self._values["scope_down_statement"] = scope_down_statement

        @builtins.property
        def aggregate_key_type(self) -> builtins.str:
            '''Setting that indicates how to aggregate the request counts. The options are the following:.

            - IP - Aggregate the request counts on the IP address from the web request origin.
            - FORWARDED_IP - Aggregate the request counts on the first IP address in an HTTP header. If you use this, configure the ``ForwardedIPConfig`` , to specify the header to use.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ratebasedstatement.html#cfn-wafv2-rulegroup-ratebasedstatement-aggregatekeytype
            '''
            result = self._values.get("aggregate_key_type")
            assert result is not None, "Required property 'aggregate_key_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def limit(self) -> jsii.Number:
            '''The limit on requests per 5-minute period for a single originating IP address.

            If the statement includes a ``ScopeDownStatement`` , this limit is applied only to the requests that match the statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ratebasedstatement.html#cfn-wafv2-rulegroup-ratebasedstatement-limit
            '''
            result = self._values.get("limit")
            assert result is not None, "Required property 'limit' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def forwarded_ip_config(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            This is required if ``AggregateKeyType`` is set to ``FORWARDED_IP`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ratebasedstatement.html#cfn-wafv2-rulegroup-ratebasedstatement-forwardedipconfig
            '''
            result = self._values.get("forwarded_ip_config")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def scope_down_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]]:
            '''An optional nested statement that narrows the scope of the rate-based statement to matching web requests.

            This can be any nestable statement, and you can nest statements at any level below this scope-down statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ratebasedstatement.html#cfn-wafv2-rulegroup-ratebasedstatement-scopedownstatement
            '''
            result = self._values.get("scope_down_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RateBasedStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.RegexMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_to_match": "fieldToMatch",
            "regex_string": "regexString",
            "text_transformations": "textTransformations",
        },
    )
    class RegexMatchStatementProperty:
        def __init__(
            self,
            *,
            field_to_match: typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b],
            regex_string: builtins.str,
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A rule statement used to search web request components for a match against a single regular expression.

            :param field_to_match: The part of a web request that you want AWS WAF to inspect. For more information, see ``FieldToMatch`` .
            :param regex_string: The string representing the regular expression.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content of the request component identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-regexmatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                regex_match_statement_property = wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                    field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                            match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    regex_string="regexString",
                    text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "field_to_match": field_to_match,
                "regex_string": regex_string,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            For more information, see ``FieldToMatch`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-regexmatchstatement.html#cfn-wafv2-rulegroup-regexmatchstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def regex_string(self) -> builtins.str:
            '''The string representing the regular expression.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-regexmatchstatement.html#cfn-wafv2-rulegroup-regexmatchstatement-regexstring
            '''
            result = self._values.get("regex_string")
            assert result is not None, "Required property 'regex_string' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content of the request component identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-regexmatchstatement.html#cfn-wafv2-rulegroup-regexmatchstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RegexMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arn": "arn",
            "field_to_match": "fieldToMatch",
            "text_transformations": "textTransformations",
        },
    )
    class RegexPatternSetReferenceStatementProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            field_to_match: typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b],
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A rule statement used to search web request components for matches with regular expressions.

            To use this, create a ``RegexPatternSet`` that specifies the expressions that you want to detect, then use the ARN of that set in this statement. A web request matches the pattern set rule statement if the request component matches any of the patterns in the set.

            Each regex pattern set rule statement references a regex pattern set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.

            :param arn: The Amazon Resource Name (ARN) of the regular expression pattern set that this statement references.
            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-regexpatternsetreferencestatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                regex_pattern_set_reference_statement_property = wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                    arn="arn",
                    field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                            match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
                "field_to_match": field_to_match,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the regular expression pattern set that this statement references.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-regexpatternsetreferencestatement.html#cfn-wafv2-rulegroup-regexpatternsetreferencestatement-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-regexpatternsetreferencestatement.html#cfn-wafv2-rulegroup-regexpatternsetreferencestatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-regexpatternsetreferencestatement.html#cfn-wafv2-rulegroup-regexpatternsetreferencestatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RegexPatternSetReferenceStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.RuleActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "allow": "allow",
            "block": "block",
            "captcha": "captcha",
            "count": "count",
        },
    )
    class RuleActionProperty:
        def __init__(
            self,
            *,
            allow: typing.Any = None,
            block: typing.Any = None,
            captcha: typing.Any = None,
            count: typing.Any = None,
        ) -> None:
            '''The action that AWS WAF should take on a web request when it matches a rule's statement.

            Settings at the web ACL level can override the rule action setting.

            :param allow: Instructs AWS WAF to allow the web request.
            :param block: Instructs AWS WAF to block the web request.
            :param captcha: Specifies that AWS WAF should run a ``CAPTCHA`` check against the request:. - If the request includes a valid, unexpired ``CAPTCHA`` token, AWS WAF allows the web request inspection to proceed to the next rule, similar to a ``CountAction`` . - If the request doesn't include a valid, unexpired ``CAPTCHA`` token, AWS WAF discontinues the web ACL evaluation of the request and blocks it from going to its intended destination. AWS WAF generates a response that it sends back to the client, which includes the following: - The header ``x-amzn-waf-action`` with a value of ``captcha`` . - The HTTP status code ``405 Method Not Allowed`` . - If the request contains an ``Accept`` header with a value of ``text/html`` , the response includes a ``CAPTCHA`` challenge. You can configure the expiration time in the ``CaptchaConfig`` ``ImmunityTimeProperty`` setting at the rule and web ACL level. The rule setting overrides the web ACL setting. This action option is available for rules. It isn't available for web ACL default actions. This is used in the context of other settings, for example to specify values for ``RuleAction`` and web ACL ``DefaultAction`` .
            :param count: Instructs AWS WAF to count the web request and allow it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ruleaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # allow: Any
                # block: Any
                # captcha: Any
                # count: Any
                
                rule_action_property = wafv2.CfnRuleGroup.RuleActionProperty(
                    allow=allow,
                    block=block,
                    captcha=captcha,
                    count=count
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if allow is not None:
                self._values["allow"] = allow
            if block is not None:
                self._values["block"] = block
            if captcha is not None:
                self._values["captcha"] = captcha
            if count is not None:
                self._values["count"] = count

        @builtins.property
        def allow(self) -> typing.Any:
            '''Instructs AWS WAF to allow the web request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ruleaction.html#cfn-wafv2-rulegroup-ruleaction-allow
            '''
            result = self._values.get("allow")
            return typing.cast(typing.Any, result)

        @builtins.property
        def block(self) -> typing.Any:
            '''Instructs AWS WAF to block the web request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ruleaction.html#cfn-wafv2-rulegroup-ruleaction-block
            '''
            result = self._values.get("block")
            return typing.cast(typing.Any, result)

        @builtins.property
        def captcha(self) -> typing.Any:
            '''Specifies that AWS WAF should run a ``CAPTCHA`` check against the request:.

            - If the request includes a valid, unexpired ``CAPTCHA`` token, AWS WAF allows the web request inspection to proceed to the next rule, similar to a ``CountAction`` .
            - If the request doesn't include a valid, unexpired ``CAPTCHA`` token, AWS WAF discontinues the web ACL evaluation of the request and blocks it from going to its intended destination.

            AWS WAF generates a response that it sends back to the client, which includes the following:

            - The header ``x-amzn-waf-action`` with a value of ``captcha`` .
            - The HTTP status code ``405 Method Not Allowed`` .
            - If the request contains an ``Accept`` header with a value of ``text/html`` , the response includes a ``CAPTCHA`` challenge.

            You can configure the expiration time in the ``CaptchaConfig`` ``ImmunityTimeProperty`` setting at the rule and web ACL level. The rule setting overrides the web ACL setting.

            This action option is available for rules. It isn't available for web ACL default actions.

            This is used in the context of other settings, for example to specify values for ``RuleAction`` and web ACL ``DefaultAction`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ruleaction.html#cfn-wafv2-rulegroup-ruleaction-captcha
            '''
            result = self._values.get("captcha")
            return typing.cast(typing.Any, result)

        @builtins.property
        def count(self) -> typing.Any:
            '''Instructs AWS WAF to count the web request and allow it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-ruleaction.html#cfn-wafv2-rulegroup-ruleaction-count
            '''
            result = self._values.get("count")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RuleActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.RuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "priority": "priority",
            "statement": "statement",
            "visibility_config": "visibilityConfig",
            "action": "action",
            "captcha_config": "captchaConfig",
            "rule_labels": "ruleLabels",
        },
    )
    class RuleProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            priority: jsii.Number,
            statement: typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b],
            visibility_config: typing.Union["CfnRuleGroup.VisibilityConfigProperty", _IResolvable_da3f097b],
            action: typing.Optional[typing.Union["CfnRuleGroup.RuleActionProperty", _IResolvable_da3f097b]] = None,
            captcha_config: typing.Optional[typing.Union["CfnRuleGroup.CaptchaConfigProperty", _IResolvable_da3f097b]] = None,
            rule_labels: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.LabelProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A single rule, which you can use to identify web requests that you want to allow, block, or count.

            Each rule includes one top-level Statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.

            :param name: The descriptive name of the rule. You can't change the name of a ``Rule`` after you create it.
            :param priority: If you define more than one ``Rule`` in a ``WebACL`` , AWS WAF evaluates each request against the ``Rules`` in order based on the value of ``Priority`` . AWS WAF processes rules with lower priority first. The priorities don't need to be consecutive, but they must all be different.
            :param statement: The AWS WAF processing statement for the rule, for example ByteMatchStatement or SizeConstraintStatement.
            :param visibility_config: Defines and enables Amazon CloudWatch metrics and web request sample collection.
            :param action: The action that AWS WAF should take on a web request when it matches the rule's statement. Settings at the web ACL level can override the rule action setting.
            :param captcha_config: Specifies how AWS WAF should handle ``CAPTCHA`` evaluations. If you don't specify this, AWS WAF uses the ``CAPTCHA`` configuration that's defined for the web ACL.
            :param rule_labels: Labels to apply to web requests that match the rule match statement. AWS WAF applies fully qualified labels to matching web requests. A fully qualified label is the concatenation of a label namespace and a rule label. The rule's rule group or web ACL defines the label namespace. Rules that run after this rule in the web ACL can match against these labels using a ``LabelMatchStatement`` . For each label, provide a case-sensitive string containing optional namespaces and a label name, according to the following guidelines: - Separate each component of the label with a colon. - Each namespace or name can have up to 128 characters. - You can specify up to 5 namespaces in a label. - Don't use the following reserved words in your label specification: ``aws`` , ``waf`` , ``managed`` , ``rulegroup`` , ``webacl`` , ``regexpatternset`` , or ``ipset`` . For example, ``myLabelName`` or ``nameSpace1:nameSpace2:myLabelName`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-rule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # allow: Any
                # all_query_arguments: Any
                # block: Any
                # body: Any
                # captcha: Any
                # count: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnRuleGroup.StatementProperty
                # uri_path: Any
                
                rule_property = wafv2.CfnRuleGroup.RuleProperty(
                    name="name",
                    priority=123,
                    statement=wafv2.CfnRuleGroup.StatementProperty(
                        and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    ),
                    visibility_config=wafv2.CfnRuleGroup.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=False,
                        metric_name="metricName",
                        sampled_requests_enabled=False
                    ),
                
                    # the properties below are optional
                    action=wafv2.CfnRuleGroup.RuleActionProperty(
                        allow=allow,
                        block=block,
                        captcha=captcha,
                        count=count
                    ),
                    captcha_config=wafv2.CfnRuleGroup.CaptchaConfigProperty(
                        immunity_time_property=wafv2.CfnRuleGroup.ImmunityTimePropertyProperty(
                            immunity_time=123
                        )
                    ),
                    rule_labels=[wafv2.CfnRuleGroup.LabelProperty(
                        name="name"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "priority": priority,
                "statement": statement,
                "visibility_config": visibility_config,
            }
            if action is not None:
                self._values["action"] = action
            if captcha_config is not None:
                self._values["captcha_config"] = captcha_config
            if rule_labels is not None:
                self._values["rule_labels"] = rule_labels

        @builtins.property
        def name(self) -> builtins.str:
            '''The descriptive name of the rule.

            You can't change the name of a ``Rule`` after you create it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-rule.html#cfn-wafv2-rulegroup-rule-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def priority(self) -> jsii.Number:
            '''If you define more than one ``Rule`` in a ``WebACL`` , AWS WAF evaluates each request against the ``Rules`` in order based on the value of ``Priority`` .

            AWS WAF processes rules with lower priority first. The priorities don't need to be consecutive, but they must all be different.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-rule.html#cfn-wafv2-rulegroup-rule-priority
            '''
            result = self._values.get("priority")
            assert result is not None, "Required property 'priority' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def statement(
            self,
        ) -> typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b]:
            '''The AWS WAF processing statement for the rule, for example ByteMatchStatement or SizeConstraintStatement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-rule.html#cfn-wafv2-rulegroup-rule-statement
            '''
            result = self._values.get("statement")
            assert result is not None, "Required property 'statement' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.StatementProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def visibility_config(
            self,
        ) -> typing.Union["CfnRuleGroup.VisibilityConfigProperty", _IResolvable_da3f097b]:
            '''Defines and enables Amazon CloudWatch metrics and web request sample collection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-rule.html#cfn-wafv2-rulegroup-rule-visibilityconfig
            '''
            result = self._values.get("visibility_config")
            assert result is not None, "Required property 'visibility_config' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.VisibilityConfigProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def action(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.RuleActionProperty", _IResolvable_da3f097b]]:
            '''The action that AWS WAF should take on a web request when it matches the rule's statement.

            Settings at the web ACL level can override the rule action setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-rule.html#cfn-wafv2-rulegroup-rule-action
            '''
            result = self._values.get("action")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.RuleActionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def captcha_config(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.CaptchaConfigProperty", _IResolvable_da3f097b]]:
            '''Specifies how AWS WAF should handle ``CAPTCHA`` evaluations.

            If you don't specify this, AWS WAF uses the ``CAPTCHA`` configuration that's defined for the web ACL.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-rule.html#cfn-wafv2-rulegroup-rule-captchaconfig
            '''
            result = self._values.get("captcha_config")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.CaptchaConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def rule_labels(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.LabelProperty", _IResolvable_da3f097b]]]]:
            '''Labels to apply to web requests that match the rule match statement.

            AWS WAF applies fully qualified labels to matching web requests. A fully qualified label is the concatenation of a label namespace and a rule label. The rule's rule group or web ACL defines the label namespace.

            Rules that run after this rule in the web ACL can match against these labels using a ``LabelMatchStatement`` .

            For each label, provide a case-sensitive string containing optional namespaces and a label name, according to the following guidelines:

            - Separate each component of the label with a colon.
            - Each namespace or name can have up to 128 characters.
            - You can specify up to 5 namespaces in a label.
            - Don't use the following reserved words in your label specification: ``aws`` , ``waf`` , ``managed`` , ``rulegroup`` , ``webacl`` , ``regexpatternset`` , or ``ipset`` .

            For example, ``myLabelName`` or ``nameSpace1:nameSpace2:myLabelName`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-rule.html#cfn-wafv2-rulegroup-rule-rulelabels
            '''
            result = self._values.get("rule_labels")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.LabelProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.SizeConstraintStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "comparison_operator": "comparisonOperator",
            "field_to_match": "fieldToMatch",
            "size": "size",
            "text_transformations": "textTransformations",
        },
    )
    class SizeConstraintStatementProperty:
        def __init__(
            self,
            *,
            comparison_operator: builtins.str,
            field_to_match: typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b],
            size: jsii.Number,
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (>) or less than (<).

            For example, you can use a size constraint statement to look for query strings that are longer than 100 bytes.

            If you configure AWS WAF to inspect the request body, AWS WAF inspects only the first 8192 bytes (8 KB). If the request body for your web requests never exceeds 8192 bytes, you can create a size constraint condition and block requests that have a request body greater than 8192 bytes.

            If you choose URI for the value of Part of the request to filter on, the slash (/) in the URI counts as one character. For example, the URI ``/logo.jpg`` is nine characters long.

            :param comparison_operator: The operator to use to compare the request part to the size setting.
            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param size: The size, in byte, to compare to the request part, after any transformations.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-sizeconstraintstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                size_constraint_statement_property = wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                    comparison_operator="comparisonOperator",
                    field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                            match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    size=123,
                    text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "comparison_operator": comparison_operator,
                "field_to_match": field_to_match,
                "size": size,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def comparison_operator(self) -> builtins.str:
            '''The operator to use to compare the request part to the size setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-sizeconstraintstatement.html#cfn-wafv2-rulegroup-sizeconstraintstatement-comparisonoperator
            '''
            result = self._values.get("comparison_operator")
            assert result is not None, "Required property 'comparison_operator' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-sizeconstraintstatement.html#cfn-wafv2-rulegroup-sizeconstraintstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def size(self) -> jsii.Number:
            '''The size, in byte, to compare to the request part, after any transformations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-sizeconstraintstatement.html#cfn-wafv2-rulegroup-sizeconstraintstatement-size
            '''
            result = self._values.get("size")
            assert result is not None, "Required property 'size' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-sizeconstraintstatement.html#cfn-wafv2-rulegroup-sizeconstraintstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SizeConstraintStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.SqliMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_to_match": "fieldToMatch",
            "text_transformations": "textTransformations",
        },
    )
    class SqliMatchStatementProperty:
        def __init__(
            self,
            *,
            field_to_match: typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b],
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Attackers sometimes insert malicious SQL code into web requests in an effort to extract data from your database.

            To allow or block web requests that appear to contain malicious SQL code, create one or more SQL injection match conditions. An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. Later in the process, when you create a web ACL, you specify whether to allow or block requests that appear to contain malicious SQL code.

            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-sqlimatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                sqli_match_statement_property = wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                    field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                            match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "field_to_match": field_to_match,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-sqlimatchstatement.html#cfn-wafv2-rulegroup-sqlimatchstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-sqlimatchstatement.html#cfn-wafv2-rulegroup-sqlimatchstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SqliMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.StatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "and_statement": "andStatement",
            "byte_match_statement": "byteMatchStatement",
            "geo_match_statement": "geoMatchStatement",
            "ip_set_reference_statement": "ipSetReferenceStatement",
            "label_match_statement": "labelMatchStatement",
            "not_statement": "notStatement",
            "or_statement": "orStatement",
            "rate_based_statement": "rateBasedStatement",
            "regex_match_statement": "regexMatchStatement",
            "regex_pattern_set_reference_statement": "regexPatternSetReferenceStatement",
            "size_constraint_statement": "sizeConstraintStatement",
            "sqli_match_statement": "sqliMatchStatement",
            "xss_match_statement": "xssMatchStatement",
        },
    )
    class StatementProperty:
        def __init__(
            self,
            *,
            and_statement: typing.Optional[typing.Union["CfnRuleGroup.AndStatementProperty", _IResolvable_da3f097b]] = None,
            byte_match_statement: typing.Optional[typing.Union["CfnRuleGroup.ByteMatchStatementProperty", _IResolvable_da3f097b]] = None,
            geo_match_statement: typing.Optional[typing.Union["CfnRuleGroup.GeoMatchStatementProperty", _IResolvable_da3f097b]] = None,
            ip_set_reference_statement: typing.Optional[typing.Union["CfnRuleGroup.IPSetReferenceStatementProperty", _IResolvable_da3f097b]] = None,
            label_match_statement: typing.Optional[typing.Union["CfnRuleGroup.LabelMatchStatementProperty", _IResolvable_da3f097b]] = None,
            not_statement: typing.Optional[typing.Union["CfnRuleGroup.NotStatementProperty", _IResolvable_da3f097b]] = None,
            or_statement: typing.Optional[typing.Union["CfnRuleGroup.OrStatementProperty", _IResolvable_da3f097b]] = None,
            rate_based_statement: typing.Optional[typing.Union["CfnRuleGroup.RateBasedStatementProperty", _IResolvable_da3f097b]] = None,
            regex_match_statement: typing.Optional[typing.Union["CfnRuleGroup.RegexMatchStatementProperty", _IResolvable_da3f097b]] = None,
            regex_pattern_set_reference_statement: typing.Optional[typing.Union["CfnRuleGroup.RegexPatternSetReferenceStatementProperty", _IResolvable_da3f097b]] = None,
            size_constraint_statement: typing.Optional[typing.Union["CfnRuleGroup.SizeConstraintStatementProperty", _IResolvable_da3f097b]] = None,
            sqli_match_statement: typing.Optional[typing.Union["CfnRuleGroup.SqliMatchStatementProperty", _IResolvable_da3f097b]] = None,
            xss_match_statement: typing.Optional[typing.Union["CfnRuleGroup.XssMatchStatementProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The processing guidance for a ``Rule`` , used by AWS WAF to determine whether a web request matches the rule.

            :param and_statement: A logical rule statement used to combine other rule statements with AND logic. You provide more than one ``Statement`` within the ``AndStatement`` .
            :param byte_match_statement: A rule statement that defines a string match search for AWS WAF to apply to web requests. The byte match statement provides the bytes to search for, the location in requests that you want AWS WAF to search, and other settings. The bytes to search for are typically a string that corresponds with ASCII characters. In the AWS WAF console and the developer guide, this is refered to as a string match statement.
            :param geo_match_statement: A rule statement used to identify web requests based on country of origin.
            :param ip_set_reference_statement: A rule statement used to detect web requests coming from particular IP addresses or address ranges. To use this, create an ``IPSet`` that specifies the addresses you want to detect, then use the ARN of that set in this statement. Each IP set rule statement references an IP set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.
            :param label_match_statement: A rule statement that defines a string match search against labels that have been added to the web request by rules that have already run in the web ACL. The label match statement provides the label or namespace string to search for. The label string can represent a part or all of the fully qualified label name that had been added to the web request. Fully qualified labels have a prefix, optional namespaces, and label name. The prefix identifies the rule group or web ACL context of the rule that added the label. If you do not provide the fully qualified name in your label match string, AWS WAF performs the search for labels that were added in the same context as the label match statement.
            :param not_statement: A logical rule statement used to negate the results of another rule statement. You provide one ``Statement`` within the ``NotStatement`` .
            :param or_statement: A logical rule statement used to combine other rule statements with OR logic. You provide more than one ``Statement`` within the ``OrStatement`` .
            :param rate_based_statement: A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span. You can use this to put a temporary block on requests from an IP address that is sending excessive requests. When the rule action triggers, AWS WAF blocks additional requests from the IP address until the request rate falls below the limit. You can optionally nest another statement inside the rate-based statement, to narrow the scope of the rule so that it only counts requests that match the nested statement. For example, based on recent requests that you have seen from an attacker, you might create a rate-based rule with a nested AND rule statement that contains the following nested statements: - An IP match statement with an IP set that specified the address 192.0.2.44. - A string match statement that searches in the User-Agent header for the string BadBot. In this rate-based rule, you also define a rate limit. For this example, the rate limit is 1,000. Requests that meet both of the conditions in the statements are counted. If the count exceeds 1,000 requests per five minutes, the rule action triggers. Requests that do not meet both conditions are not counted towards the rate limit and are not affected by this rule. You cannot nest a ``RateBasedStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.
            :param regex_match_statement: A rule statement used to search web request components for a match against a single regular expression.
            :param regex_pattern_set_reference_statement: A rule statement used to search web request components for matches with regular expressions. To use this, create a ``RegexPatternSet`` that specifies the expressions that you want to detect, then use the ARN of that set in this statement. A web request matches the pattern set rule statement if the request component matches any of the patterns in the set. Each regex pattern set rule statement references a regex pattern set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.
            :param size_constraint_statement: A rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (>) or less than (<). For example, you can use a size constraint statement to look for query strings that are longer than 100 bytes. If you configure AWS WAF to inspect the request body, AWS WAF inspects only the first 8192 bytes (8 KB). If the request body for your web requests never exceeds 8192 bytes, you can create a size constraint condition and block requests that have a request body greater than 8192 bytes. If you choose URI for the value of Part of the request to filter on, the slash (/) in the URI counts as one character. For example, the URI ``/logo.jpg`` is nine characters long.
            :param sqli_match_statement: Attackers sometimes insert malicious SQL code into web requests in an effort to extract data from your database. To allow or block web requests that appear to contain malicious SQL code, create one or more SQL injection match conditions. An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. Later in the process, when you create a web ACL, you specify whether to allow or block requests that appear to contain malicious SQL code.
            :param xss_match_statement: A rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests. XSS attacks are those where the attacker uses vulnerabilities in a benign website as a vehicle to inject malicious client-site scripts into other legitimate web browsers. The XSS match statement provides the location in requests that you want AWS WAF to search and text transformations to use on the search area before AWS WAF searches for character sequences that are likely to be malicious strings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # and_statement_property_: wafv2.CfnRuleGroup.AndStatementProperty
                # body: Any
                # method: Any
                # not_statement_property_: wafv2.CfnRuleGroup.NotStatementProperty
                # or_statement_property_: wafv2.CfnRuleGroup.OrStatementProperty
                # query_string: Any
                # rate_based_statement_property_: wafv2.CfnRuleGroup.RateBasedStatementProperty
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnRuleGroup.StatementProperty
                # uri_path: Any
                
                statement_property = wafv2.CfnRuleGroup.StatementProperty(
                    and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                        statements=[wafv2.CfnRuleGroup.StatementProperty(
                            and_statement=and_statement_property_,
                            byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                                statement=statement_property_
                            ),
                            or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                                statements=[statement_property_]
                            ),
                            rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                                aggregate_key_type="aggregateKeyType",
                                limit=123,
                
                                # the properties below are optional
                                forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                ),
                                scope_down_statement=statement_property_
                            ),
                            regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        )]
                    ),
                    byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        positional_constraint="positionalConstraint",
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )],
                
                        # the properties below are optional
                        search_string="searchString",
                        search_string_base64="searchStringBase64"
                    ),
                    geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                        country_codes=["countryCodes"],
                        forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                            fallback_behavior="fallbackBehavior",
                            header_name="headerName"
                        )
                    ),
                    ip_set_reference_statement={
                        "arn": "arn",
                
                        # the properties below are optional
                        "ip_set_forwarded_ip_config": {
                            "fallback_behavior": "fallbackBehavior",
                            "header_name": "headerName",
                            "position": "position"
                        }
                    },
                    label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                        key="key",
                        scope="scope"
                    ),
                    not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                        statement=wafv2.CfnRuleGroup.StatementProperty(
                            and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                                statements=[statement_property_]
                            ),
                            byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            not_statement=not_statement_property_,
                            or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                                statements=[statement_property_]
                            ),
                            rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                                aggregate_key_type="aggregateKeyType",
                                limit=123,
                
                                # the properties below are optional
                                forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                ),
                                scope_down_statement=statement_property_
                            ),
                            regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        )
                    ),
                    or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                        statements=[wafv2.CfnRuleGroup.StatementProperty(
                            and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                                statements=[statement_property_]
                            ),
                            byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                                statement=statement_property_
                            ),
                            or_statement=or_statement_property_,
                            rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                                aggregate_key_type="aggregateKeyType",
                                limit=123,
                
                                # the properties below are optional
                                forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                ),
                                scope_down_statement=statement_property_
                            ),
                            regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        )]
                    ),
                    rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                        aggregate_key_type="aggregateKeyType",
                        limit=123,
                
                        # the properties below are optional
                        forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                            fallback_behavior="fallbackBehavior",
                            header_name="headerName"
                        ),
                        scope_down_statement=wafv2.CfnRuleGroup.StatementProperty(
                            and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                                statements=[statement_property_]
                            ),
                            byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                                statement=statement_property_
                            ),
                            or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                                statements=[statement_property_]
                            ),
                            rate_based_statement=rate_based_statement_property_,
                            regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                        match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        )
                    ),
                    regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        regex_string="regexString",
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                        arn="arn",
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                        comparison_operator="comparisonOperator",
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        size=123,
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                        field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if and_statement is not None:
                self._values["and_statement"] = and_statement
            if byte_match_statement is not None:
                self._values["byte_match_statement"] = byte_match_statement
            if geo_match_statement is not None:
                self._values["geo_match_statement"] = geo_match_statement
            if ip_set_reference_statement is not None:
                self._values["ip_set_reference_statement"] = ip_set_reference_statement
            if label_match_statement is not None:
                self._values["label_match_statement"] = label_match_statement
            if not_statement is not None:
                self._values["not_statement"] = not_statement
            if or_statement is not None:
                self._values["or_statement"] = or_statement
            if rate_based_statement is not None:
                self._values["rate_based_statement"] = rate_based_statement
            if regex_match_statement is not None:
                self._values["regex_match_statement"] = regex_match_statement
            if regex_pattern_set_reference_statement is not None:
                self._values["regex_pattern_set_reference_statement"] = regex_pattern_set_reference_statement
            if size_constraint_statement is not None:
                self._values["size_constraint_statement"] = size_constraint_statement
            if sqli_match_statement is not None:
                self._values["sqli_match_statement"] = sqli_match_statement
            if xss_match_statement is not None:
                self._values["xss_match_statement"] = xss_match_statement

        @builtins.property
        def and_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.AndStatementProperty", _IResolvable_da3f097b]]:
            '''A logical rule statement used to combine other rule statements with AND logic.

            You provide more than one ``Statement`` within the ``AndStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-andstatement
            '''
            result = self._values.get("and_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.AndStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def byte_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.ByteMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement that defines a string match search for AWS WAF to apply to web requests.

            The byte match statement provides the bytes to search for, the location in requests that you want AWS WAF to search, and other settings. The bytes to search for are typically a string that corresponds with ASCII characters. In the AWS WAF console and the developer guide, this is refered to as a string match statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-bytematchstatement
            '''
            result = self._values.get("byte_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.ByteMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def geo_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.GeoMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to identify web requests based on country of origin.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-geomatchstatement
            '''
            result = self._values.get("geo_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.GeoMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def ip_set_reference_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.IPSetReferenceStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to detect web requests coming from particular IP addresses or address ranges.

            To use this, create an ``IPSet`` that specifies the addresses you want to detect, then use the ARN of that set in this statement.

            Each IP set rule statement references an IP set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-ipsetreferencestatement
            '''
            result = self._values.get("ip_set_reference_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.IPSetReferenceStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def label_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.LabelMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement that defines a string match search against labels that have been added to the web request by rules that have already run in the web ACL.

            The label match statement provides the label or namespace string to search for. The label string can represent a part or all of the fully qualified label name that had been added to the web request. Fully qualified labels have a prefix, optional namespaces, and label name. The prefix identifies the rule group or web ACL context of the rule that added the label. If you do not provide the fully qualified name in your label match string, AWS WAF performs the search for labels that were added in the same context as the label match statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-labelmatchstatement
            '''
            result = self._values.get("label_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.LabelMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def not_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.NotStatementProperty", _IResolvable_da3f097b]]:
            '''A logical rule statement used to negate the results of another rule statement.

            You provide one ``Statement`` within the ``NotStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-notstatement
            '''
            result = self._values.get("not_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.NotStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def or_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.OrStatementProperty", _IResolvable_da3f097b]]:
            '''A logical rule statement used to combine other rule statements with OR logic.

            You provide more than one ``Statement`` within the ``OrStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-orstatement
            '''
            result = self._values.get("or_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.OrStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def rate_based_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.RateBasedStatementProperty", _IResolvable_da3f097b]]:
            '''A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span.

            You can use this to put a temporary block on requests from an IP address that is sending excessive requests.

            When the rule action triggers, AWS WAF blocks additional requests from the IP address until the request rate falls below the limit.

            You can optionally nest another statement inside the rate-based statement, to narrow the scope of the rule so that it only counts requests that match the nested statement. For example, based on recent requests that you have seen from an attacker, you might create a rate-based rule with a nested AND rule statement that contains the following nested statements:

            - An IP match statement with an IP set that specified the address 192.0.2.44.
            - A string match statement that searches in the User-Agent header for the string BadBot.

            In this rate-based rule, you also define a rate limit. For this example, the rate limit is 1,000. Requests that meet both of the conditions in the statements are counted. If the count exceeds 1,000 requests per five minutes, the rule action triggers. Requests that do not meet both conditions are not counted towards the rate limit and are not affected by this rule.

            You cannot nest a ``RateBasedStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-ratebasedstatement
            '''
            result = self._values.get("rate_based_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.RateBasedStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def regex_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.RegexMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to search web request components for a match against a single regular expression.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-regexmatchstatement
            '''
            result = self._values.get("regex_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.RegexMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def regex_pattern_set_reference_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.RegexPatternSetReferenceStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to search web request components for matches with regular expressions.

            To use this, create a ``RegexPatternSet`` that specifies the expressions that you want to detect, then use the ARN of that set in this statement. A web request matches the pattern set rule statement if the request component matches any of the patterns in the set.

            Each regex pattern set rule statement references a regex pattern set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-regexpatternsetreferencestatement
            '''
            result = self._values.get("regex_pattern_set_reference_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.RegexPatternSetReferenceStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def size_constraint_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.SizeConstraintStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (>) or less than (<).

            For example, you can use a size constraint statement to look for query strings that are longer than 100 bytes.

            If you configure AWS WAF to inspect the request body, AWS WAF inspects only the first 8192 bytes (8 KB). If the request body for your web requests never exceeds 8192 bytes, you can create a size constraint condition and block requests that have a request body greater than 8192 bytes.

            If you choose URI for the value of Part of the request to filter on, the slash (/) in the URI counts as one character. For example, the URI ``/logo.jpg`` is nine characters long.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-sizeconstraintstatement
            '''
            result = self._values.get("size_constraint_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.SizeConstraintStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sqli_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.SqliMatchStatementProperty", _IResolvable_da3f097b]]:
            '''Attackers sometimes insert malicious SQL code into web requests in an effort to extract data from your database.

            To allow or block web requests that appear to contain malicious SQL code, create one or more SQL injection match conditions. An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. Later in the process, when you create a web ACL, you specify whether to allow or block requests that appear to contain malicious SQL code.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-sqlimatchstatement
            '''
            result = self._values.get("sqli_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.SqliMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def xss_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnRuleGroup.XssMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests.

            XSS attacks are those where the attacker uses vulnerabilities in a benign website as a vehicle to inject malicious client-site scripts into other legitimate web browsers. The XSS match statement provides the location in requests that you want AWS WAF to search and text transformations to use on the search area before AWS WAF searches for character sequences that are likely to be malicious strings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-statement.html#cfn-wafv2-rulegroup-statement-xssmatchstatement
            '''
            result = self._values.get("xss_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnRuleGroup.XssMatchStatementProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.TextTransformationProperty",
        jsii_struct_bases=[],
        name_mapping={"priority": "priority", "type": "type"},
    )
    class TextTransformationProperty:
        def __init__(self, *, priority: jsii.Number, type: builtins.str) -> None:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            :param priority: Sets the relative processing order for multiple transformations that are defined for a rule statement. AWS WAF processes all transformations, from lowest priority to highest, before inspecting the transformed content. The priorities don't need to be consecutive, but they must all be different.
            :param type: You can specify the following transformation types:. *BASE64_DECODE* - Decode a ``Base64`` -encoded string. *BASE64_DECODE_EXT* - Decode a ``Base64`` -encoded string, but use a forgiving implementation that ignores characters that aren't valid. *CMD_LINE* - Command-line transformations. These are helpful in reducing effectiveness of attackers who inject an operating system command-line command and use unusual formatting to disguise some or all of the command. - Delete the following characters: ``\\ " ' ^`` - Delete spaces before the following characters: ``/ (`` - Replace the following characters with a space: ``, ;`` - Replace multiple spaces with one space - Convert uppercase letters (A-Z) to lowercase (a-z) *COMPRESS_WHITE_SPACE* - Replace these characters with a space character (decimal 32): - ``\\f`` , formfeed, decimal 12 - ``\\t`` , tab, decimal 9 - ``\\n`` , newline, decimal 10 - ``\\r`` , carriage return, decimal 13 - ``\\v`` , vertical tab, decimal 11 - Non-breaking space, decimal 160 ``COMPRESS_WHITE_SPACE`` also replaces multiple spaces with one space. *CSS_DECODE* - Decode characters that were encoded using CSS 2.x escape rules ``syndata.html#characters`` . This function uses up to two bytes in the decoding process, so it can help to uncover ASCII characters that were encoded using CSS encoding that wouldn’t typically be encoded. It's also useful in countering evasion, which is a combination of a backslash and non-hexadecimal characters. For example, ``ja\\vascript`` for javascript. *ESCAPE_SEQ_DECODE* - Decode the following ANSI C escape sequences: ``\\a`` , ``\\b`` , ``\\f`` , ``\\n`` , ``\\r`` , ``\\t`` , ``\\v`` , ``\\\\`` , ``\\?`` , ``\\'`` , ``\\"`` , ``\\xHH`` (hexadecimal), ``\\0OOO`` (octal). Encodings that aren't valid remain in the output. *HEX_DECODE* - Decode a string of hexadecimal characters into a binary. *HTML_ENTITY_DECODE* - Replace HTML-encoded characters with unencoded characters. ``HTML_ENTITY_DECODE`` performs these operations: - Replaces ``(ampersand)quot;`` with ``"`` - Replaces ``(ampersand)nbsp;`` with a non-breaking space, decimal 160 - Replaces ``(ampersand)lt;`` with a "less than" symbol - Replaces ``(ampersand)gt;`` with ``>`` - Replaces characters that are represented in hexadecimal format, ``(ampersand)#xhhhh;`` , with the corresponding characters - Replaces characters that are represented in decimal format, ``(ampersand)#nnnn;`` , with the corresponding characters *JS_DECODE* - Decode JavaScript escape sequences. If a ``\\`` ``u`` ``HHHH`` code is in the full-width ASCII code range of ``FF01-FF5E`` , then the higher byte is used to detect and adjust the lower byte. If not, only the lower byte is used and the higher byte is zeroed, causing a possible loss of information. *LOWERCASE* - Convert uppercase letters (A-Z) to lowercase (a-z). *MD5* - Calculate an MD5 hash from the data in the input. The computed hash is in a raw binary form. *NONE* - Specify ``NONE`` if you don't want any text transformations. *NORMALIZE_PATH* - Remove multiple slashes, directory self-references, and directory back-references that are not at the beginning of the input from an input string. *NORMALIZE_PATH_WIN* - This is the same as ``NORMALIZE_PATH`` , but first converts backslash characters to forward slashes. *REMOVE_NULLS* - Remove all ``NULL`` bytes from the input. *REPLACE_COMMENTS* - Replace each occurrence of a C-style comment ( ``/* ... * /`` ) with a single space. Multiple consecutive occurrences are not compressed. Unterminated comments are also replaced with a space (ASCII 0x20). However, a standalone termination of a comment ( ``* /`` ) is not acted upon. *REPLACE_NULLS* - Replace NULL bytes in the input with space characters (ASCII ``0x20`` ). *SQL_HEX_DECODE* - Decode SQL hex data. Example ( ``0x414243`` ) will be decoded to ( ``ABC`` ). *URL_DECODE* - Decode a URL-encoded value. *URL_DECODE_UNI* - Like ``URL_DECODE`` , but with support for Microsoft-specific ``%u`` encoding. If the code is in the full-width ASCII code range of ``FF01-FF5E`` , the higher byte is used to detect and adjust the lower byte. Otherwise, only the lower byte is used and the higher byte is zeroed. *UTF8_TO_UNICODE* - Convert all UTF-8 character sequences to Unicode. This helps input normalization, and minimizing false-positives and false-negatives for non-English languages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-texttransformation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                text_transformation_property = wafv2.CfnRuleGroup.TextTransformationProperty(
                    priority=123,
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "priority": priority,
                "type": type,
            }

        @builtins.property
        def priority(self) -> jsii.Number:
            '''Sets the relative processing order for multiple transformations that are defined for a rule statement.

            AWS WAF processes all transformations, from lowest priority to highest, before inspecting the transformed content. The priorities don't need to be consecutive, but they must all be different.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-texttransformation.html#cfn-wafv2-rulegroup-texttransformation-priority
            '''
            result = self._values.get("priority")
            assert result is not None, "Required property 'priority' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''You can specify the following transformation types:.

            *BASE64_DECODE* - Decode a ``Base64`` -encoded string.

            *BASE64_DECODE_EXT* - Decode a ``Base64`` -encoded string, but use a forgiving implementation that ignores characters that aren't valid.

            *CMD_LINE* - Command-line transformations. These are helpful in reducing effectiveness of attackers who inject an operating system command-line command and use unusual formatting to disguise some or all of the command.

            - Delete the following characters: ``\\ " ' ^``
            - Delete spaces before the following characters: ``/ (``
            - Replace the following characters with a space: ``, ;``
            - Replace multiple spaces with one space
            - Convert uppercase letters (A-Z) to lowercase (a-z)

            *COMPRESS_WHITE_SPACE* - Replace these characters with a space character (decimal 32):

            - ``\\f`` , formfeed, decimal 12
            - ``\\t`` , tab, decimal 9
            - ``\\n`` , newline, decimal 10
            - ``\\r`` , carriage return, decimal 13
            - ``\\v`` , vertical tab, decimal 11
            - Non-breaking space, decimal 160

            ``COMPRESS_WHITE_SPACE`` also replaces multiple spaces with one space.

            *CSS_DECODE* - Decode characters that were encoded using CSS 2.x escape rules ``syndata.html#characters`` . This function uses up to two bytes in the decoding process, so it can help to uncover ASCII characters that were encoded using CSS encoding that wouldn’t typically be encoded. It's also useful in countering evasion, which is a combination of a backslash and non-hexadecimal characters. For example, ``ja\\vascript`` for javascript.

            *ESCAPE_SEQ_DECODE* - Decode the following ANSI C escape sequences: ``\\a`` , ``\\b`` , ``\\f`` , ``\\n`` , ``\\r`` , ``\\t`` , ``\\v`` , ``\\\\`` , ``\\?`` , ``\\'`` , ``\\"`` , ``\\xHH`` (hexadecimal), ``\\0OOO`` (octal). Encodings that aren't valid remain in the output.

            *HEX_DECODE* - Decode a string of hexadecimal characters into a binary.

            *HTML_ENTITY_DECODE* - Replace HTML-encoded characters with unencoded characters. ``HTML_ENTITY_DECODE`` performs these operations:

            - Replaces ``(ampersand)quot;`` with ``"``
            - Replaces ``(ampersand)nbsp;`` with a non-breaking space, decimal 160
            - Replaces ``(ampersand)lt;`` with a "less than" symbol
            - Replaces ``(ampersand)gt;`` with ``>``
            - Replaces characters that are represented in hexadecimal format, ``(ampersand)#xhhhh;`` , with the corresponding characters
            - Replaces characters that are represented in decimal format, ``(ampersand)#nnnn;`` , with the corresponding characters

            *JS_DECODE* - Decode JavaScript escape sequences. If a ``\\`` ``u`` ``HHHH`` code is in the full-width ASCII code range of ``FF01-FF5E`` , then the higher byte is used to detect and adjust the lower byte. If not, only the lower byte is used and the higher byte is zeroed, causing a possible loss of information.

            *LOWERCASE* - Convert uppercase letters (A-Z) to lowercase (a-z).

            *MD5* - Calculate an MD5 hash from the data in the input. The computed hash is in a raw binary form.

            *NONE* - Specify ``NONE`` if you don't want any text transformations.

            *NORMALIZE_PATH* - Remove multiple slashes, directory self-references, and directory back-references that are not at the beginning of the input from an input string.

            *NORMALIZE_PATH_WIN* - This is the same as ``NORMALIZE_PATH`` , but first converts backslash characters to forward slashes.

            *REMOVE_NULLS* - Remove all ``NULL`` bytes from the input.

            *REPLACE_COMMENTS* - Replace each occurrence of a C-style comment ( ``/* ... * /`` ) with a single space. Multiple consecutive occurrences are not compressed. Unterminated comments are also replaced with a space (ASCII 0x20). However, a standalone termination of a comment ( ``* /`` ) is not acted upon.

            *REPLACE_NULLS* - Replace NULL bytes in the input with space characters (ASCII ``0x20`` ).

            *SQL_HEX_DECODE* - Decode SQL hex data. Example ( ``0x414243`` ) will be decoded to ( ``ABC`` ).

            *URL_DECODE* - Decode a URL-encoded value.

            *URL_DECODE_UNI* - Like ``URL_DECODE`` , but with support for Microsoft-specific ``%u`` encoding. If the code is in the full-width ASCII code range of ``FF01-FF5E`` , the higher byte is used to detect and adjust the lower byte. Otherwise, only the lower byte is used and the higher byte is zeroed.

            *UTF8_TO_UNICODE* - Convert all UTF-8 character sequences to Unicode. This helps input normalization, and minimizing false-positives and false-negatives for non-English languages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-texttransformation.html#cfn-wafv2-rulegroup-texttransformation-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TextTransformationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.VisibilityConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_metrics_enabled": "cloudWatchMetricsEnabled",
            "metric_name": "metricName",
            "sampled_requests_enabled": "sampledRequestsEnabled",
        },
    )
    class VisibilityConfigProperty:
        def __init__(
            self,
            *,
            cloud_watch_metrics_enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            metric_name: builtins.str,
            sampled_requests_enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Defines and enables Amazon CloudWatch metrics and web request sample collection.

            :param cloud_watch_metrics_enabled: A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch . For the list of available metrics, see `AWS WAF Metrics <https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics>`_ .
            :param metric_name: The descriptive name of the Amazon CloudWatch metric. The name can contain only alphanumeric characters (A-Z, a-z, 0-9), with length from one to 128 characters. It can't contain whitespace or metric names reserved for AWS WAF , for example "All" and "Default_Action." You can't change a ``MetricName`` after you create a ``VisibilityConfig`` .
            :param sampled_requests_enabled: A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the AWS WAF console.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-visibilityconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                visibility_config_property = wafv2.CfnRuleGroup.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=False,
                    metric_name="metricName",
                    sampled_requests_enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cloud_watch_metrics_enabled": cloud_watch_metrics_enabled,
                "metric_name": metric_name,
                "sampled_requests_enabled": sampled_requests_enabled,
            }

        @builtins.property
        def cloud_watch_metrics_enabled(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch .

            For the list of available metrics, see `AWS WAF Metrics <https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-visibilityconfig.html#cfn-wafv2-rulegroup-visibilityconfig-cloudwatchmetricsenabled
            '''
            result = self._values.get("cloud_watch_metrics_enabled")
            assert result is not None, "Required property 'cloud_watch_metrics_enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def metric_name(self) -> builtins.str:
            '''The descriptive name of the Amazon CloudWatch metric.

            The name can contain only alphanumeric characters (A-Z, a-z, 0-9), with length from one to 128 characters. It can't contain whitespace or metric names reserved for AWS WAF , for example "All" and "Default_Action." You can't change a ``MetricName`` after you create a ``VisibilityConfig`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-visibilityconfig.html#cfn-wafv2-rulegroup-visibilityconfig-metricname
            '''
            result = self._values.get("metric_name")
            assert result is not None, "Required property 'metric_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sampled_requests_enabled(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules.

            You can view the sampled requests through the AWS WAF console.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-visibilityconfig.html#cfn-wafv2-rulegroup-visibilityconfig-sampledrequestsenabled
            '''
            result = self._values.get("sampled_requests_enabled")
            assert result is not None, "Required property 'sampled_requests_enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VisibilityConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroup.XssMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_to_match": "fieldToMatch",
            "text_transformations": "textTransformations",
        },
    )
    class XssMatchStatementProperty:
        def __init__(
            self,
            *,
            field_to_match: typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b],
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests.

            XSS attacks are those where the attacker uses vulnerabilities in a benign website as a vehicle to inject malicious client-site scripts into other legitimate web browsers. The XSS match statement provides the location in requests that you want AWS WAF to search and text transformations to use on the search area before AWS WAF searches for character sequences that are likely to be malicious strings.

            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-xssmatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                xss_match_statement_property = wafv2.CfnRuleGroup.XssMatchStatementProperty(
                    field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                            match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "field_to_match": field_to_match,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-xssmatchstatement.html#cfn-wafv2-rulegroup-xssmatchstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnRuleGroup.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-rulegroup-xssmatchstatement.html#cfn-wafv2-rulegroup-xssmatchstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRuleGroup.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "XssMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wafv2.CfnRuleGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "capacity": "capacity",
        "scope": "scope",
        "visibility_config": "visibilityConfig",
        "custom_response_bodies": "customResponseBodies",
        "description": "description",
        "name": "name",
        "rules": "rules",
        "tags": "tags",
    },
)
class CfnRuleGroupProps:
    def __init__(
        self,
        *,
        capacity: jsii.Number,
        scope: builtins.str,
        visibility_config: typing.Union[CfnRuleGroup.VisibilityConfigProperty, _IResolvable_da3f097b],
        custom_response_bodies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnRuleGroup.CustomResponseBodyProperty, _IResolvable_da3f097b]]]] = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnRuleGroup.RuleProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRuleGroup``.

        :param capacity: The web ACL capacity units (WCUs) required for this rule group. When you create your own rule group, you define this, and you cannot change it after creation. When you add or modify the rules in a rule group, AWS WAF enforces this limit. AWS WAF uses WCUs to calculate and control the operating resources that are used to run your rules, rule groups, and web ACLs. AWS WAF calculates capacity differently for each rule type, to reflect the relative cost of each rule. Simple rules that cost little to run use fewer WCUs than more complex rules that use more processing power. Rule group capacity is fixed at creation, which helps users plan their web ACL WCU usage when they use a rule group. The WCU limit for web ACLs is 1,500.
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` . .. epigraph:: For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .
        :param visibility_config: Defines and enables Amazon CloudWatch metrics and web request sample collection.
        :param custom_response_bodies: A map of custom response keys and content bodies. When you create a rule with a block action, you can send a custom response to the web request. You define these for the rule group, and then use them in the rules that you define in the rule group. For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ . For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .
        :param description: A description of the rule group that helps with identification.
        :param name: The descriptive name of the rule group. You cannot change the name of a rule group after you create it.
        :param rules: The rule statements used to identify the web requests that you want to allow, block, or count. Each rule includes one top-level statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.
        :param tags: Key:value pairs associated with an AWS resource. The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource. .. epigraph:: To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wafv2 as wafv2
            
            # all: Any
            # allow: Any
            # all_query_arguments: Any
            # block: Any
            # body: Any
            # captcha: Any
            # count: Any
            # method: Any
            # query_string: Any
            # single_header: Any
            # single_query_argument: Any
            # statement_property_: wafv2.CfnRuleGroup.StatementProperty
            # uri_path: Any
            
            cfn_rule_group_props = wafv2.CfnRuleGroupProps(
                capacity=123,
                scope="scope",
                visibility_config=wafv2.CfnRuleGroup.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=False,
                    metric_name="metricName",
                    sampled_requests_enabled=False
                ),
            
                # the properties below are optional
                custom_response_bodies={
                    "custom_response_bodies_key": wafv2.CfnRuleGroup.CustomResponseBodyProperty(
                        content="content",
                        content_type="contentType"
                    )
                },
                description="description",
                name="name",
                rules=[wafv2.CfnRuleGroup.RuleProperty(
                    name="name",
                    priority=123,
                    statement=wafv2.CfnRuleGroup.StatementProperty(
                        and_statement=wafv2.CfnRuleGroup.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnRuleGroup.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
            
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnRuleGroup.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
            
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnRuleGroup.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        not_statement=wafv2.CfnRuleGroup.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnRuleGroup.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnRuleGroup.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
            
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnRuleGroup.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnRuleGroup.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnRuleGroup.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnRuleGroup.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnRuleGroup.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnRuleGroup.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnRuleGroup.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnRuleGroup.JsonBodyProperty(
                                    match_pattern=wafv2.CfnRuleGroup.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnRuleGroup.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    ),
                    visibility_config=wafv2.CfnRuleGroup.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=False,
                        metric_name="metricName",
                        sampled_requests_enabled=False
                    ),
            
                    # the properties below are optional
                    action=wafv2.CfnRuleGroup.RuleActionProperty(
                        allow=allow,
                        block=block,
                        captcha=captcha,
                        count=count
                    ),
                    captcha_config=wafv2.CfnRuleGroup.CaptchaConfigProperty(
                        immunity_time_property=wafv2.CfnRuleGroup.ImmunityTimePropertyProperty(
                            immunity_time=123
                        )
                    ),
                    rule_labels=[wafv2.CfnRuleGroup.LabelProperty(
                        name="name"
                    )]
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "capacity": capacity,
            "scope": scope,
            "visibility_config": visibility_config,
        }
        if custom_response_bodies is not None:
            self._values["custom_response_bodies"] = custom_response_bodies
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if rules is not None:
            self._values["rules"] = rules
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def capacity(self) -> jsii.Number:
        '''The web ACL capacity units (WCUs) required for this rule group.

        When you create your own rule group, you define this, and you cannot change it after creation. When you add or modify the rules in a rule group, AWS WAF enforces this limit.

        AWS WAF uses WCUs to calculate and control the operating resources that are used to run your rules, rule groups, and web ACLs. AWS WAF calculates capacity differently for each rule type, to reflect the relative cost of each rule. Simple rules that cost little to run use fewer WCUs than more complex rules that use more processing power. Rule group capacity is fixed at creation, which helps users plan their web ACL WCU usage when they use a rule group. The WCU limit for web ACLs is 1,500.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-capacity
        '''
        result = self._values.get("capacity")
        assert result is not None, "Required property 'capacity' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def scope(self) -> builtins.str:
        '''Specifies whether this is for an Amazon CloudFront distribution or for a regional application.

        A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` .
        .. epigraph::

           For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-scope
        '''
        result = self._values.get("scope")
        assert result is not None, "Required property 'scope' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def visibility_config(
        self,
    ) -> typing.Union[CfnRuleGroup.VisibilityConfigProperty, _IResolvable_da3f097b]:
        '''Defines and enables Amazon CloudWatch metrics and web request sample collection.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-visibilityconfig
        '''
        result = self._values.get("visibility_config")
        assert result is not None, "Required property 'visibility_config' is missing"
        return typing.cast(typing.Union[CfnRuleGroup.VisibilityConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def custom_response_bodies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnRuleGroup.CustomResponseBodyProperty, _IResolvable_da3f097b]]]]:
        '''A map of custom response keys and content bodies.

        When you create a rule with a block action, you can send a custom response to the web request. You define these for the rule group, and then use them in the rules that you define in the rule group.

        For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

        For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-customresponsebodies
        '''
        result = self._values.get("custom_response_bodies")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnRuleGroup.CustomResponseBodyProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the rule group that helps with identification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The descriptive name of the rule group.

        You cannot change the name of a rule group after you create it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRuleGroup.RuleProperty, _IResolvable_da3f097b]]]]:
        '''The rule statements used to identify the web requests that you want to allow, block, or count.

        Each rule includes one top-level statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-rules
        '''
        result = self._values.get("rules")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRuleGroup.RuleProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Key:value pairs associated with an AWS resource.

        The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource.
        .. epigraph::

           To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html#cfn-wafv2-rulegroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRuleGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnWebACL(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL",
):
    '''A CloudFormation ``AWS::WAFv2::WebACL``.

    .. epigraph::

       This is the latest version of *AWS WAF* , named AWS WAF V2, released in November, 2019. For information, including how to migrate your AWS WAF resources from the prior release, see the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

    Use an ``WebACL`` to define a collection of rules to use to inspect and control web requests. Each rule has an action defined (allow, block, or count) for requests that match the statement of the rule. In the web ACL, you assign a default action to take (allow, block) for any request that does not match any of the rules. The rules in a web ACL can contain rule statements that you define explicitly and rule statements that reference rule groups and managed rule groups. You can associate a web ACL with one or more AWS resources to protect. The resources can be an Amazon CloudFront distribution, an Amazon API Gateway REST API, an Application Load Balancer , or an AWS AppSync GraphQL API.

    :cloudformationResource: AWS::WAFv2::WebACL
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wafv2 as wafv2
        
        # all: Any
        # all_query_arguments: Any
        # body: Any
        # count: Any
        # method: Any
        # none: Any
        # query_string: Any
        # single_header: Any
        # single_query_argument: Any
        # statement_property_: wafv2.CfnWebACL.StatementProperty
        # uri_path: Any
        
        cfn_web_aCL = wafv2.CfnWebACL(self, "MyCfnWebACL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(
                allow=wafv2.CfnWebACL.AllowActionProperty(
                    custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                        insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                            name="name",
                            value="value"
                        )]
                    )
                ),
                block=wafv2.CfnWebACL.BlockActionProperty(
                    custom_response=wafv2.CfnWebACL.CustomResponseProperty(
                        response_code=123,
        
                        # the properties below are optional
                        custom_response_body_key="customResponseBodyKey",
                        response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                            name="name",
                            value="value"
                        )]
                    )
                )
            ),
            scope="scope",
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=False,
                metric_name="metricName",
                sampled_requests_enabled=False
            ),
        
            # the properties below are optional
            captcha_config=wafv2.CfnWebACL.CaptchaConfigProperty(
                immunity_time_property=wafv2.CfnWebACL.ImmunityTimePropertyProperty(
                    immunity_time=123
                )
            ),
            custom_response_bodies={
                "custom_response_bodies_key": wafv2.CfnWebACL.CustomResponseBodyProperty(
                    content="content",
                    content_type="contentType"
                )
            },
            description="description",
            name="name",
            rules=[wafv2.CfnWebACL.RuleProperty(
                name="name",
                priority=123,
                statement=wafv2.CfnWebACL.StatementProperty(
                    and_statement=wafv2.CfnWebACL.AndStatementProperty(
                        statements=[statement_property_]
                    ),
                    byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        positional_constraint="positionalConstraint",
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )],
        
                        # the properties below are optional
                        search_string="searchString",
                        search_string_base64="searchStringBase64"
                    ),
                    geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                        country_codes=["countryCodes"],
                        forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                            fallback_behavior="fallbackBehavior",
                            header_name="headerName"
                        )
                    ),
                    ip_set_reference_statement={
                        "arn": "arn",
        
                        # the properties below are optional
                        "ip_set_forwarded_ip_config": {
                            "fallback_behavior": "fallbackBehavior",
                            "header_name": "headerName",
                            "position": "position"
                        }
                    },
                    label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                        key="key",
                        scope="scope"
                    ),
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        name="name",
                        vendor_name="vendorName",
        
                        # the properties below are optional
                        excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                            name="name"
                        )],
                        managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                            login_path="loginPath",
                            password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                identifier="identifier"
                            ),
                            payload_type="payloadType",
                            username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                identifier="identifier"
                            )
                        )],
                        scope_down_statement=statement_property_,
                        version="version"
                    ),
                    not_statement=wafv2.CfnWebACL.NotStatementProperty(
                        statement=statement_property_
                    ),
                    or_statement=wafv2.CfnWebACL.OrStatementProperty(
                        statements=[statement_property_]
                    ),
                    rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                        aggregate_key_type="aggregateKeyType",
                        limit=123,
        
                        # the properties below are optional
                        forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                            fallback_behavior="fallbackBehavior",
                            header_name="headerName"
                        ),
                        scope_down_statement=statement_property_
                    ),
                    regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        regex_string="regexString",
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                        arn="arn",
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                        arn="arn",
        
                        # the properties below are optional
                        excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                            name="name"
                        )]
                    ),
                    size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                        comparison_operator="comparisonOperator",
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        size=123,
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
        
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    )
                ),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=False,
                    metric_name="metricName",
                    sampled_requests_enabled=False
                ),
        
                # the properties below are optional
                action=wafv2.CfnWebACL.RuleActionProperty(
                    allow=wafv2.CfnWebACL.AllowActionProperty(
                        custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                            insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    ),
                    block=wafv2.CfnWebACL.BlockActionProperty(
                        custom_response=wafv2.CfnWebACL.CustomResponseProperty(
                            response_code=123,
        
                            # the properties below are optional
                            custom_response_body_key="customResponseBodyKey",
                            response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    ),
                    captcha=wafv2.CfnWebACL.CaptchaActionProperty(
                        custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                            insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    ),
                    count=wafv2.CfnWebACL.CountActionProperty(
                        custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                            insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    )
                ),
                captcha_config=wafv2.CfnWebACL.CaptchaConfigProperty(
                    immunity_time_property=wafv2.CfnWebACL.ImmunityTimePropertyProperty(
                        immunity_time=123
                    )
                ),
                override_action=wafv2.CfnWebACL.OverrideActionProperty(
                    count=count,
                    none=none
                ),
                rule_labels=[wafv2.CfnWebACL.LabelProperty(
                    name="name"
                )]
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope_: constructs.Construct,
        id: builtins.str,
        *,
        default_action: typing.Union["CfnWebACL.DefaultActionProperty", _IResolvable_da3f097b],
        scope: builtins.str,
        visibility_config: typing.Union["CfnWebACL.VisibilityConfigProperty", _IResolvable_da3f097b],
        captcha_config: typing.Optional[typing.Union["CfnWebACL.CaptchaConfigProperty", _IResolvable_da3f097b]] = None,
        custom_response_bodies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnWebACL.CustomResponseBodyProperty", _IResolvable_da3f097b]]]] = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.RuleProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::WAFv2::WebACL``.

        :param scope_: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param default_action: The action to perform if none of the ``Rules`` contained in the ``WebACL`` match.
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` . .. epigraph:: For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` . For information about how to define the association of the web ACL with your resource, see ``WebACLAssociation`` .
        :param visibility_config: Defines and enables Amazon CloudWatch metrics and web request sample collection.
        :param captcha_config: Specifies how AWS WAF should handle ``CAPTCHA`` evaluations for rules that don't have their own ``CaptchaConfig`` settings. If you don't specify this, AWS WAF uses its default settings for ``CaptchaConfig`` .
        :param custom_response_bodies: A map of custom response keys and content bodies. When you create a rule with a block action, you can send a custom response to the web request. You define these for the web ACL, and then use them in the rules and default actions that you define in the web ACL. For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ . For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .
        :param description: A description of the web ACL that helps with identification.
        :param name: The descriptive name of the web ACL. You cannot change the name of a web ACL after you create it.
        :param rules: The rule statements used to identify the web requests that you want to allow, block, or count. Each rule includes one top-level statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.
        :param tags: Key:value pairs associated with an AWS resource. The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource. .. epigraph:: To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.
        '''
        props = CfnWebACLProps(
            default_action=default_action,
            scope=scope,
            visibility_config=visibility_config,
            captcha_config=captcha_config,
            custom_response_bodies=custom_response_bodies,
            description=description,
            name=name,
            rules=rules,
            tags=tags,
        )

        jsii.create(self.__class__, self, [scope_, id, props])

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
        '''The Amazon Resource Name (ARN) of the web ACL.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCapacity")
    def attr_capacity(self) -> jsii.Number:
        '''The current web ACL capacity (WCU) usage by the web ACL.

        :cloudformationAttribute: Capacity
        '''
        return typing.cast(jsii.Number, jsii.get(self, "attrCapacity"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the web ACL.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLabelNamespace")
    def attr_label_namespace(self) -> builtins.str:
        '''The label namespace prefix for this web ACL.

        All labels added by rules in this web ACL have this prefix.

        The syntax for the label namespace prefix for a web ACL is the following: ``awswaf:<account ID>:webacl:<web ACL name>:``

        When a rule with a label matches a web request, AWS WAF adds the fully qualified label to the request. A fully qualified label is made up of the label namespace from the rule group or web ACL where the rule is defined and the label from the rule, separated by a colon.

        :cloudformationAttribute: LabelNamespace
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLabelNamespace"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Key:value pairs associated with an AWS resource.

        The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource.
        .. epigraph::

           To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultAction")
    def default_action(
        self,
    ) -> typing.Union["CfnWebACL.DefaultActionProperty", _IResolvable_da3f097b]:
        '''The action to perform if none of the ``Rules`` contained in the ``WebACL`` match.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-defaultaction
        '''
        return typing.cast(typing.Union["CfnWebACL.DefaultActionProperty", _IResolvable_da3f097b], jsii.get(self, "defaultAction"))

    @default_action.setter
    def default_action(
        self,
        value: typing.Union["CfnWebACL.DefaultActionProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "defaultAction", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scope")
    def scope(self) -> builtins.str:
        '''Specifies whether this is for an Amazon CloudFront distribution or for a regional application.

        A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` .
        .. epigraph::

           For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .

        For information about how to define the association of the web ACL with your resource, see ``WebACLAssociation`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-scope
        '''
        return typing.cast(builtins.str, jsii.get(self, "scope"))

    @scope.setter
    def scope(self, value: builtins.str) -> None:
        jsii.set(self, "scope", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="visibilityConfig")
    def visibility_config(
        self,
    ) -> typing.Union["CfnWebACL.VisibilityConfigProperty", _IResolvable_da3f097b]:
        '''Defines and enables Amazon CloudWatch metrics and web request sample collection.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-visibilityconfig
        '''
        return typing.cast(typing.Union["CfnWebACL.VisibilityConfigProperty", _IResolvable_da3f097b], jsii.get(self, "visibilityConfig"))

    @visibility_config.setter
    def visibility_config(
        self,
        value: typing.Union["CfnWebACL.VisibilityConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "visibilityConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="captchaConfig")
    def captcha_config(
        self,
    ) -> typing.Optional[typing.Union["CfnWebACL.CaptchaConfigProperty", _IResolvable_da3f097b]]:
        '''Specifies how AWS WAF should handle ``CAPTCHA`` evaluations for rules that don't have their own ``CaptchaConfig`` settings.

        If you don't specify this, AWS WAF uses its default settings for ``CaptchaConfig`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-captchaconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnWebACL.CaptchaConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "captchaConfig"))

    @captcha_config.setter
    def captcha_config(
        self,
        value: typing.Optional[typing.Union["CfnWebACL.CaptchaConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "captchaConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="customResponseBodies")
    def custom_response_bodies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnWebACL.CustomResponseBodyProperty", _IResolvable_da3f097b]]]]:
        '''A map of custom response keys and content bodies.

        When you create a rule with a block action, you can send a custom response to the web request. You define these for the web ACL, and then use them in the rules and default actions that you define in the web ACL.

        For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

        For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-customresponsebodies
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnWebACL.CustomResponseBodyProperty", _IResolvable_da3f097b]]]], jsii.get(self, "customResponseBodies"))

    @custom_response_bodies.setter
    def custom_response_bodies(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnWebACL.CustomResponseBodyProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "customResponseBodies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the web ACL that helps with identification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The descriptive name of the web ACL.

        You cannot change the name of a web ACL after you create it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="rules")
    def rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.RuleProperty", _IResolvable_da3f097b]]]]:
        '''The rule statements used to identify the web requests that you want to allow, block, or count.

        Each rule includes one top-level statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-rules
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.RuleProperty", _IResolvable_da3f097b]]]], jsii.get(self, "rules"))

    @rules.setter
    def rules(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.RuleProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "rules", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.AllowActionProperty",
        jsii_struct_bases=[],
        name_mapping={"custom_request_handling": "customRequestHandling"},
    )
    class AllowActionProperty:
        def __init__(
            self,
            *,
            custom_request_handling: typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies that AWS WAF should allow requests.

            This is used only in the context of other settings, for example to specify values for the web ACL and rule group ``RuleAction`` and for the web ACL ``DefaultAction`` .

            :param custom_request_handling: Defines custom handling for the web request. For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-allowaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                allow_action_property = wafv2.CfnWebACL.AllowActionProperty(
                    custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                        insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                            name="name",
                            value="value"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if custom_request_handling is not None:
                self._values["custom_request_handling"] = custom_request_handling

        @builtins.property
        def custom_request_handling(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]]:
            '''Defines custom handling for the web request.

            For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-allowaction.html#cfn-wafv2-webacl-allowaction-customrequesthandling
            '''
            result = self._values.get("custom_request_handling")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AllowActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.AndStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"statements": "statements"},
    )
    class AndStatementProperty:
        def __init__(
            self,
            *,
            statements: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A logical rule statement used to combine other rule statements with AND logic.

            You provide more than one ``Statement`` within the ``AndStatement`` .

            :param statements: The statements to combine with AND logic. You can use any statements that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-andstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnWebACL.StatementProperty
                # uri_path: Any
                
                and_statement_property = wafv2.CfnWebACL.AndStatementProperty(
                    statements=[wafv2.CfnWebACL.StatementProperty(
                        and_statement=wafv2.CfnWebACL.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="name",
                            vendor_name="vendorName",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )],
                            managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                login_path="loginPath",
                                password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                ),
                                payload_type="payloadType",
                                username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                )
                            )],
                            scope_down_statement=statement_property_,
                            version="version"
                        ),
                        not_statement=wafv2.CfnWebACL.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnWebACL.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                            arn="arn",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "statements": statements,
            }

        @builtins.property
        def statements(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]]]:
            '''The statements to combine with AND logic.

            You can use any statements that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-andstatement.html#cfn-wafv2-webacl-andstatement-statements
            '''
            result = self._values.get("statements")
            assert result is not None, "Required property 'statements' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AndStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.BlockActionProperty",
        jsii_struct_bases=[],
        name_mapping={"custom_response": "customResponse"},
    )
    class BlockActionProperty:
        def __init__(
            self,
            *,
            custom_response: typing.Optional[typing.Union["CfnWebACL.CustomResponseProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies that AWS WAF should block requests.

            This is used only in the context of other settings, for example to specify values for the web ACL and rule group ``RuleAction`` and for the web ACL ``DefaultAction`` .

            :param custom_response: Defines a custom response for the web request. For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-blockaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                block_action_property = wafv2.CfnWebACL.BlockActionProperty(
                    custom_response=wafv2.CfnWebACL.CustomResponseProperty(
                        response_code=123,
                
                        # the properties below are optional
                        custom_response_body_key="customResponseBodyKey",
                        response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                            name="name",
                            value="value"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if custom_response is not None:
                self._values["custom_response"] = custom_response

        @builtins.property
        def custom_response(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.CustomResponseProperty", _IResolvable_da3f097b]]:
            '''Defines a custom response for the web request.

            For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-blockaction.html#cfn-wafv2-webacl-blockaction-customresponse
            '''
            result = self._values.get("custom_response")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.CustomResponseProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BlockActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.ByteMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_to_match": "fieldToMatch",
            "positional_constraint": "positionalConstraint",
            "text_transformations": "textTransformations",
            "search_string": "searchString",
            "search_string_base64": "searchStringBase64",
        },
    )
    class ByteMatchStatementProperty:
        def __init__(
            self,
            *,
            field_to_match: typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b],
            positional_constraint: builtins.str,
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]],
            search_string: typing.Optional[builtins.str] = None,
            search_string_base64: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A rule statement that defines a string match search for AWS WAF to apply to web requests.

            The byte match statement provides the bytes to search for, the location in requests that you want AWS WAF to search, and other settings. The bytes to search for are typically a string that corresponds with ASCII characters. In the AWS WAF console and the developer guide, this is refered to as a string match statement.

            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param positional_constraint: The area within the portion of a web request that you want AWS WAF to search for ``SearchString`` . Valid values include the following: *CONTAINS* The specified part of the web request must include the value of ``SearchString`` , but the location doesn't matter. *CONTAINS_WORD* The specified part of the web request must include the value of ``SearchString`` , and ``SearchString`` must contain only alphanumeric characters or underscore (A-Z, a-z, 0-9, or _). In addition, ``SearchString`` must be a word, which means that both of the following are true: - ``SearchString`` is at the beginning of the specified part of the web request or is preceded by a character other than an alphanumeric character or underscore (_). Examples include the value of a header and ``;BadBot`` . - ``SearchString`` is at the end of the specified part of the web request or is followed by a character other than an alphanumeric character or underscore (_), for example, ``BadBot;`` and ``-BadBot;`` . *EXACTLY* The value of the specified part of the web request must exactly match the value of ``SearchString`` . *STARTS_WITH* The value of ``SearchString`` must appear at the beginning of the specified part of the web request. *ENDS_WITH* The value of ``SearchString`` must appear at the end of the specified part of the web request.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.
            :param search_string: A string value that you want AWS WAF to search for. AWS WAF searches only in the part of web requests that you designate for inspection in ``FieldToMatch`` . The maximum length of the value is 50 bytes. For alphabetic characters A-Z and a-z, the value is case sensitive. Don't encode this string. Provide the value that you want AWS WAF to search for. AWS CloudFormation automatically base64 encodes the value for you. For example, suppose the value of ``Type`` is ``HEADER`` and the value of ``Data`` is ``User-Agent`` . If you want to search the ``User-Agent`` header for the value ``BadBot`` , you provide the string ``BadBot`` in the value of ``SearchString`` . You must specify either ``SearchString`` or ``SearchStringBase64`` in a ``ByteMatchStatement`` .
            :param search_string_base64: String to search for in a web request component, base64-encoded. If you don't want to encode the string, specify the unencoded value in ``SearchString`` instead. You must specify either ``SearchString`` or ``SearchStringBase64`` in a ``ByteMatchStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-bytematchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                byte_match_statement_property = wafv2.CfnWebACL.ByteMatchStatementProperty(
                    field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnWebACL.JsonBodyProperty(
                            match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    positional_constraint="positionalConstraint",
                    text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )],
                
                    # the properties below are optional
                    search_string="searchString",
                    search_string_base64="searchStringBase64"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "field_to_match": field_to_match,
                "positional_constraint": positional_constraint,
                "text_transformations": text_transformations,
            }
            if search_string is not None:
                self._values["search_string"] = search_string
            if search_string_base64 is not None:
                self._values["search_string_base64"] = search_string_base64

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-bytematchstatement.html#cfn-wafv2-webacl-bytematchstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def positional_constraint(self) -> builtins.str:
            '''The area within the portion of a web request that you want AWS WAF to search for ``SearchString`` .

            Valid values include the following:

            *CONTAINS*

            The specified part of the web request must include the value of ``SearchString`` , but the location doesn't matter.

            *CONTAINS_WORD*

            The specified part of the web request must include the value of ``SearchString`` , and ``SearchString`` must contain only alphanumeric characters or underscore (A-Z, a-z, 0-9, or _). In addition, ``SearchString`` must be a word, which means that both of the following are true:

            - ``SearchString`` is at the beginning of the specified part of the web request or is preceded by a character other than an alphanumeric character or underscore (_). Examples include the value of a header and ``;BadBot`` .
            - ``SearchString`` is at the end of the specified part of the web request or is followed by a character other than an alphanumeric character or underscore (_), for example, ``BadBot;`` and ``-BadBot;`` .

            *EXACTLY*

            The value of the specified part of the web request must exactly match the value of ``SearchString`` .

            *STARTS_WITH*

            The value of ``SearchString`` must appear at the beginning of the specified part of the web request.

            *ENDS_WITH*

            The value of ``SearchString`` must appear at the end of the specified part of the web request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-bytematchstatement.html#cfn-wafv2-webacl-bytematchstatement-positionalconstraint
            '''
            result = self._values.get("positional_constraint")
            assert result is not None, "Required property 'positional_constraint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-bytematchstatement.html#cfn-wafv2-webacl-bytematchstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def search_string(self) -> typing.Optional[builtins.str]:
            '''A string value that you want AWS WAF to search for.

            AWS WAF searches only in the part of web requests that you designate for inspection in ``FieldToMatch`` . The maximum length of the value is 50 bytes. For alphabetic characters A-Z and a-z, the value is case sensitive.

            Don't encode this string. Provide the value that you want AWS WAF to search for. AWS CloudFormation automatically base64 encodes the value for you.

            For example, suppose the value of ``Type`` is ``HEADER`` and the value of ``Data`` is ``User-Agent`` . If you want to search the ``User-Agent`` header for the value ``BadBot`` , you provide the string ``BadBot`` in the value of ``SearchString`` .

            You must specify either ``SearchString`` or ``SearchStringBase64`` in a ``ByteMatchStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-bytematchstatement.html#cfn-wafv2-webacl-bytematchstatement-searchstring
            '''
            result = self._values.get("search_string")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def search_string_base64(self) -> typing.Optional[builtins.str]:
            '''String to search for in a web request component, base64-encoded.

            If you don't want to encode the string, specify the unencoded value in ``SearchString`` instead.

            You must specify either ``SearchString`` or ``SearchStringBase64`` in a ``ByteMatchStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-bytematchstatement.html#cfn-wafv2-webacl-bytematchstatement-searchstringbase64
            '''
            result = self._values.get("search_string_base64")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ByteMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.CaptchaActionProperty",
        jsii_struct_bases=[],
        name_mapping={"custom_request_handling": "customRequestHandling"},
    )
    class CaptchaActionProperty:
        def __init__(
            self,
            *,
            custom_request_handling: typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies that AWS WAF should run a ``CAPTCHA`` check against the request:.

            - If the request includes a valid, unexpired ``CAPTCHA`` token, AWS WAF allows the web request inspection to proceed to the next rule, similar to a ``CountAction`` .
            - If the request doesn't include a valid, unexpired ``CAPTCHA`` token, AWS WAF discontinues the web ACL evaluation of the request and blocks it from going to its intended destination.

            AWS WAF generates a response that it sends back to the client, which includes the following:

            - The header ``x-amzn-waf-action`` with a value of ``captcha`` .
            - The HTTP status code ``405 Method Not Allowed`` .
            - If the request contains an ``Accept`` header with a value of ``text/html`` , the response includes a ``CAPTCHA`` challenge.

            You can configure the expiration time in the ``CaptchaConfig`` ``ImmunityTimeProperty`` setting at the rule and web ACL level. The rule setting overrides the web ACL setting.

            This action option is available for rules. It isn't available for web ACL default actions.

            This is used in the context of other settings, for example to specify values for ``RuleAction`` and web ACL ``DefaultAction`` .

            :param custom_request_handling: Defines custom handling for the web request. For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-captchaaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                captcha_action_property = wafv2.CfnWebACL.CaptchaActionProperty(
                    custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                        insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                            name="name",
                            value="value"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if custom_request_handling is not None:
                self._values["custom_request_handling"] = custom_request_handling

        @builtins.property
        def custom_request_handling(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]]:
            '''Defines custom handling for the web request.

            For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-captchaaction.html#cfn-wafv2-webacl-captchaaction-customrequesthandling
            '''
            result = self._values.get("custom_request_handling")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CaptchaActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.CaptchaConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"immunity_time_property": "immunityTimeProperty"},
    )
    class CaptchaConfigProperty:
        def __init__(
            self,
            *,
            immunity_time_property: typing.Optional[typing.Union["CfnWebACL.ImmunityTimePropertyProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies how AWS WAF should handle ``CAPTCHA`` evaluations.

            This is available at the web ACL level and in each rule.

            :param immunity_time_property: Determines how long a ``CAPTCHA`` token remains valid after the client successfully solves a ``CAPTCHA`` puzzle.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-captchaconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                captcha_config_property = wafv2.CfnWebACL.CaptchaConfigProperty(
                    immunity_time_property=wafv2.CfnWebACL.ImmunityTimePropertyProperty(
                        immunity_time=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if immunity_time_property is not None:
                self._values["immunity_time_property"] = immunity_time_property

        @builtins.property
        def immunity_time_property(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.ImmunityTimePropertyProperty", _IResolvable_da3f097b]]:
            '''Determines how long a ``CAPTCHA`` token remains valid after the client successfully solves a ``CAPTCHA`` puzzle.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-captchaconfig.html#cfn-wafv2-webacl-captchaconfig-immunitytimeproperty
            '''
            result = self._values.get("immunity_time_property")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.ImmunityTimePropertyProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CaptchaConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.CountActionProperty",
        jsii_struct_bases=[],
        name_mapping={"custom_request_handling": "customRequestHandling"},
    )
    class CountActionProperty:
        def __init__(
            self,
            *,
            custom_request_handling: typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies that AWS WAF should count requests.

            This is used only in the context of other settings, for example to specify values for the web ACL and rule group ``RuleAction`` and for the web ACL ``DefaultAction`` .

            :param custom_request_handling: Defines custom handling for the web request. For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-countaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                count_action_property = wafv2.CfnWebACL.CountActionProperty(
                    custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                        insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                            name="name",
                            value="value"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if custom_request_handling is not None:
                self._values["custom_request_handling"] = custom_request_handling

        @builtins.property
        def custom_request_handling(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]]:
            '''Defines custom handling for the web request.

            For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-countaction.html#cfn-wafv2-webacl-countaction-customrequesthandling
            '''
            result = self._values.get("custom_request_handling")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.CustomRequestHandlingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CountActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.CustomHTTPHeaderProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class CustomHTTPHeaderProperty:
        def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
            '''A custom header for custom request and response handling.

            This is used in ``CustomResponse`` and ``CustomRequestHandling`` .

            :param name: The name of the custom header. For custom request header insertion, when AWS WAF inserts the header into the request, it prefixes this name ``x-amzn-waf-`` , to avoid confusion with the headers that are already in the request. For example, for the header name ``sample`` , AWS WAF inserts the header ``x-amzn-waf-sample`` .
            :param value: The value of the custom header.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customhttpheader.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                custom_hTTPHeader_property = wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                    name="name",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "value": value,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the custom header.

            For custom request header insertion, when AWS WAF inserts the header into the request, it prefixes this name ``x-amzn-waf-`` , to avoid confusion with the headers that are already in the request. For example, for the header name ``sample`` , AWS WAF inserts the header ``x-amzn-waf-sample`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customhttpheader.html#cfn-wafv2-webacl-customhttpheader-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value of the custom header.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customhttpheader.html#cfn-wafv2-webacl-customhttpheader-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomHTTPHeaderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.CustomRequestHandlingProperty",
        jsii_struct_bases=[],
        name_mapping={"insert_headers": "insertHeaders"},
    )
    class CustomRequestHandlingProperty:
        def __init__(
            self,
            *,
            insert_headers: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.CustomHTTPHeaderProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Custom request handling behavior that inserts custom headers into a web request.

            You can add custom request handling for the rule actions allow and count.

            For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :param insert_headers: The HTTP headers to insert into the request. Duplicate header names are not allowed. For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customrequesthandling.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                custom_request_handling_property = wafv2.CfnWebACL.CustomRequestHandlingProperty(
                    insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                        name="name",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "insert_headers": insert_headers,
            }

        @builtins.property
        def insert_headers(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.CustomHTTPHeaderProperty", _IResolvable_da3f097b]]]:
            '''The HTTP headers to insert into the request. Duplicate header names are not allowed.

            For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customrequesthandling.html#cfn-wafv2-webacl-customrequesthandling-insertheaders
            '''
            result = self._values.get("insert_headers")
            assert result is not None, "Required property 'insert_headers' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.CustomHTTPHeaderProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomRequestHandlingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.CustomResponseBodyProperty",
        jsii_struct_bases=[],
        name_mapping={"content": "content", "content_type": "contentType"},
    )
    class CustomResponseBodyProperty:
        def __init__(
            self,
            *,
            content: builtins.str,
            content_type: builtins.str,
        ) -> None:
            '''The response body to use in a custom response to a web request.

            This is referenced by key from the ``CustomResponse`` ``CustomResponseBodyKey`` .

            :param content: The payload of the custom response. You can use JSON escape strings in JSON content. To do this, you must specify JSON content in the ``ContentType`` setting. For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .
            :param content_type: The type of content in the payload that you are defining in the ``Content`` string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customresponsebody.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                custom_response_body_property = wafv2.CfnWebACL.CustomResponseBodyProperty(
                    content="content",
                    content_type="contentType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "content": content,
                "content_type": content_type,
            }

        @builtins.property
        def content(self) -> builtins.str:
            '''The payload of the custom response.

            You can use JSON escape strings in JSON content. To do this, you must specify JSON content in the ``ContentType`` setting.

            For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customresponsebody.html#cfn-wafv2-webacl-customresponsebody-content
            '''
            result = self._values.get("content")
            assert result is not None, "Required property 'content' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def content_type(self) -> builtins.str:
            '''The type of content in the payload that you are defining in the ``Content`` string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customresponsebody.html#cfn-wafv2-webacl-customresponsebody-contenttype
            '''
            result = self._values.get("content_type")
            assert result is not None, "Required property 'content_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomResponseBodyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.CustomResponseProperty",
        jsii_struct_bases=[],
        name_mapping={
            "response_code": "responseCode",
            "custom_response_body_key": "customResponseBodyKey",
            "response_headers": "responseHeaders",
        },
    )
    class CustomResponseProperty:
        def __init__(
            self,
            *,
            response_code: jsii.Number,
            custom_response_body_key: typing.Optional[builtins.str] = None,
            response_headers: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.CustomHTTPHeaderProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A custom response to send to the client.

            You can define a custom response for rule actions and default web ACL actions that are set to ``BlockAction`` .

            For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :param response_code: The HTTP status code to return to the client. For a list of status codes that you can use in your custom reqponses, see `Supported status codes for custom response <https://docs.aws.amazon.com/waf/latest/developerguide/customizing-the-response-status-codes.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .
            :param custom_response_body_key: References the response body that you want AWS WAF to return to the web request client. You can define a custom response for a rule action or a default web ACL action that is set to block. To do this, you first define the response body key and value in the ``CustomResponseBodies`` setting for the ``WebACL`` or ``RuleGroup`` where you want to use it. Then, in the rule action or web ACL default action ``BlockAction`` setting, you reference the response body using this key.
            :param response_headers: The HTTP headers to use in the response. Duplicate header names are not allowed. For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customresponse.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                custom_response_property = wafv2.CfnWebACL.CustomResponseProperty(
                    response_code=123,
                
                    # the properties below are optional
                    custom_response_body_key="customResponseBodyKey",
                    response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                        name="name",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "response_code": response_code,
            }
            if custom_response_body_key is not None:
                self._values["custom_response_body_key"] = custom_response_body_key
            if response_headers is not None:
                self._values["response_headers"] = response_headers

        @builtins.property
        def response_code(self) -> jsii.Number:
            '''The HTTP status code to return to the client.

            For a list of status codes that you can use in your custom reqponses, see `Supported status codes for custom response <https://docs.aws.amazon.com/waf/latest/developerguide/customizing-the-response-status-codes.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customresponse.html#cfn-wafv2-webacl-customresponse-responsecode
            '''
            result = self._values.get("response_code")
            assert result is not None, "Required property 'response_code' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def custom_response_body_key(self) -> typing.Optional[builtins.str]:
            '''References the response body that you want AWS WAF to return to the web request client.

            You can define a custom response for a rule action or a default web ACL action that is set to block. To do this, you first define the response body key and value in the ``CustomResponseBodies`` setting for the ``WebACL`` or ``RuleGroup`` where you want to use it. Then, in the rule action or web ACL default action ``BlockAction`` setting, you reference the response body using this key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customresponse.html#cfn-wafv2-webacl-customresponse-customresponsebodykey
            '''
            result = self._values.get("custom_response_body_key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def response_headers(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.CustomHTTPHeaderProperty", _IResolvable_da3f097b]]]]:
            '''The HTTP headers to use in the response. Duplicate header names are not allowed.

            For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-customresponse.html#cfn-wafv2-webacl-customresponse-responseheaders
            '''
            result = self._values.get("response_headers")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.CustomHTTPHeaderProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomResponseProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.DefaultActionProperty",
        jsii_struct_bases=[],
        name_mapping={"allow": "allow", "block": "block"},
    )
    class DefaultActionProperty:
        def __init__(
            self,
            *,
            allow: typing.Optional[typing.Union["CfnWebACL.AllowActionProperty", _IResolvable_da3f097b]] = None,
            block: typing.Optional[typing.Union["CfnWebACL.BlockActionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''In a ``WebACL`` , this is the action that you want AWS WAF to perform when a web request doesn't match any of the rules in the ``WebACL`` .

            The default action must be a terminating action, so count is not allowed.

            :param allow: Specifies that AWS WAF should allow requests by default.
            :param block: Specifies that AWS WAF should block requests by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-defaultaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                default_action_property = wafv2.CfnWebACL.DefaultActionProperty(
                    allow=wafv2.CfnWebACL.AllowActionProperty(
                        custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                            insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    ),
                    block=wafv2.CfnWebACL.BlockActionProperty(
                        custom_response=wafv2.CfnWebACL.CustomResponseProperty(
                            response_code=123,
                
                            # the properties below are optional
                            custom_response_body_key="customResponseBodyKey",
                            response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if allow is not None:
                self._values["allow"] = allow
            if block is not None:
                self._values["block"] = block

        @builtins.property
        def allow(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.AllowActionProperty", _IResolvable_da3f097b]]:
            '''Specifies that AWS WAF should allow requests by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-defaultaction.html#cfn-wafv2-webacl-defaultaction-allow
            '''
            result = self._values.get("allow")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.AllowActionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def block(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.BlockActionProperty", _IResolvable_da3f097b]]:
            '''Specifies that AWS WAF should block requests by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-defaultaction.html#cfn-wafv2-webacl-defaultaction-block
            '''
            result = self._values.get("block")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.BlockActionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DefaultActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.ExcludedRuleProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name"},
    )
    class ExcludedRuleProperty:
        def __init__(self, *, name: builtins.str) -> None:
            '''Specifies a single rule to exclude from the rule group.

            Excluding a rule overrides its action setting for the rule group in the web ACL, setting it to ``COUNT`` . This effectively excludes the rule from acting on web requests.

            :param name: The name of the rule to exclude.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-excludedrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                excluded_rule_property = wafv2.CfnWebACL.ExcludedRuleProperty(
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the rule to exclude.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-excludedrule.html#cfn-wafv2-webacl-excludedrule-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExcludedRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.FieldIdentifierProperty",
        jsii_struct_bases=[],
        name_mapping={"identifier": "identifier"},
    )
    class FieldIdentifierProperty:
        def __init__(self, *, identifier: builtins.str) -> None:
            '''The identifier of the username or password field, used in the ``ManagedRuleGroupConfig`` settings.

            :param identifier: The name of the username or password field, used in the ``ManagedRuleGroupConfig`` settings. When the ``PayloadType`` is ``JSON`` , the identifier must be in JSON pointer syntax. For example ``/form/username`` . For information about the JSON Pointer syntax, see the Internet Engineering Task Force (IETF) documentation `JavaScript Object Notation (JSON) Pointer <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6901>`_ . When the ``PayloadType`` is ``FORM_ENCODED`` , use the HTML form names. For example, ``username`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldidentifier.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                field_identifier_property = wafv2.CfnWebACL.FieldIdentifierProperty(
                    identifier="identifier"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "identifier": identifier,
            }

        @builtins.property
        def identifier(self) -> builtins.str:
            '''The name of the username or password field, used in the ``ManagedRuleGroupConfig`` settings.

            When the ``PayloadType`` is ``JSON`` , the identifier must be in JSON pointer syntax. For example ``/form/username`` . For information about the JSON Pointer syntax, see the Internet Engineering Task Force (IETF) documentation `JavaScript Object Notation (JSON) Pointer <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6901>`_ .

            When the ``PayloadType`` is ``FORM_ENCODED`` , use the HTML form names. For example, ``username`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldidentifier.html#cfn-wafv2-webacl-fieldidentifier-identifier
            '''
            result = self._values.get("identifier")
            assert result is not None, "Required property 'identifier' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FieldIdentifierProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.FieldToMatchProperty",
        jsii_struct_bases=[],
        name_mapping={
            "all_query_arguments": "allQueryArguments",
            "body": "body",
            "json_body": "jsonBody",
            "method": "method",
            "query_string": "queryString",
            "single_header": "singleHeader",
            "single_query_argument": "singleQueryArgument",
            "uri_path": "uriPath",
        },
    )
    class FieldToMatchProperty:
        def __init__(
            self,
            *,
            all_query_arguments: typing.Any = None,
            body: typing.Any = None,
            json_body: typing.Optional[typing.Union["CfnWebACL.JsonBodyProperty", _IResolvable_da3f097b]] = None,
            method: typing.Any = None,
            query_string: typing.Any = None,
            single_header: typing.Any = None,
            single_query_argument: typing.Any = None,
            uri_path: typing.Any = None,
        ) -> None:
            '''The part of a web request that you want AWS WAF to inspect.

            Include the single ``FieldToMatch`` type that you want to inspect, with additional specifications as needed, according to the type. You specify a single request component in ``FieldToMatch`` for each rule statement that requires it. To inspect more than one component of a web request, create a separate rule statement for each component.

            :param all_query_arguments: Inspect all query arguments.
            :param body: Inspect the request body, which immediately follows the request headers. This is the part of a request that contains any additional data that you want to send to your web server as the HTTP request body, such as data from a form. Note that only the first 8 KB (8192 bytes) of the request body are forwarded to AWS WAF for inspection by the underlying host service. If you don't need to inspect more than 8 KB, you can guarantee that you don't allow additional bytes in by combining a statement that inspects the body of the web request, such as the ``ByteMatchStatement`` or ``RegexPatternSetReferenceStatement`` , with a ``SizeConstraintStatement`` that enforces an 8 KB size limit on the body of the request. AWS WAF doesn't support inspecting the entire contents of web requests whose bodies exceed the 8 KB limit.
            :param json_body: Inspect the request body as JSON. The request body immediately follows the request headers. This is the part of a request that contains any additional data that you want to send to your web server as the HTTP request body, such as data from a form. Note that only the first 8 KB (8192 bytes) of the request body are forwarded to AWS WAF for inspection by the underlying host service. If you don't need to inspect more than 8 KB, you can guarantee that you don't allow additional bytes in by combining a statement that inspects the body of the web request, such as the ``ByteMatchStatement`` or ``RegexPatternSetReferenceStatement`` , with a ``SizeConstraintStatement`` that enforces an 8 KB size limit on the body of the request. AWS WAF doesn't support inspecting the entire contents of web requests whose bodies exceed the 8 KB limit.
            :param method: Inspect the HTTP method. The method indicates the type of operation that the request is asking the origin to perform.
            :param query_string: Inspect the query string. This is the part of a URL that appears after a ``?`` character, if any.
            :param single_header: Inspect a single header. Provide the name of the header to inspect, for example, ``User-Agent`` or ``Referer`` . This setting isn't case sensitive.
            :param single_query_argument: Inspect a single query argument. Provide the name of the query argument to inspect, such as *UserName* or *SalesRegion* . The name can be up to 30 characters long and isn't case sensitive.
            :param uri_path: Inspect the request URI path. This is the part of a web request that identifies a resource, for example, ``/images/daily-ad.jpg`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                field_to_match_property = wafv2.CfnWebACL.FieldToMatchProperty(
                    all_query_arguments=all_query_arguments,
                    body=body,
                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                            all=all,
                            included_paths=["includedPaths"]
                        ),
                        match_scope="matchScope",
                
                        # the properties below are optional
                        invalid_fallback_behavior="invalidFallbackBehavior"
                    ),
                    method=method,
                    query_string=query_string,
                    single_header=single_header,
                    single_query_argument=single_query_argument,
                    uri_path=uri_path
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if all_query_arguments is not None:
                self._values["all_query_arguments"] = all_query_arguments
            if body is not None:
                self._values["body"] = body
            if json_body is not None:
                self._values["json_body"] = json_body
            if method is not None:
                self._values["method"] = method
            if query_string is not None:
                self._values["query_string"] = query_string
            if single_header is not None:
                self._values["single_header"] = single_header
            if single_query_argument is not None:
                self._values["single_query_argument"] = single_query_argument
            if uri_path is not None:
                self._values["uri_path"] = uri_path

        @builtins.property
        def all_query_arguments(self) -> typing.Any:
            '''Inspect all query arguments.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html#cfn-wafv2-webacl-fieldtomatch-allqueryarguments
            '''
            result = self._values.get("all_query_arguments")
            return typing.cast(typing.Any, result)

        @builtins.property
        def body(self) -> typing.Any:
            '''Inspect the request body, which immediately follows the request headers.

            This is the part of a request that contains any additional data that you want to send to your web server as the HTTP request body, such as data from a form.

            Note that only the first 8 KB (8192 bytes) of the request body are forwarded to AWS WAF for inspection by the underlying host service. If you don't need to inspect more than 8 KB, you can guarantee that you don't allow additional bytes in by combining a statement that inspects the body of the web request, such as the ``ByteMatchStatement`` or ``RegexPatternSetReferenceStatement`` , with a ``SizeConstraintStatement`` that enforces an 8 KB size limit on the body of the request. AWS WAF doesn't support inspecting the entire contents of web requests whose bodies exceed the 8 KB limit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html#cfn-wafv2-webacl-fieldtomatch-body
            '''
            result = self._values.get("body")
            return typing.cast(typing.Any, result)

        @builtins.property
        def json_body(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.JsonBodyProperty", _IResolvable_da3f097b]]:
            '''Inspect the request body as JSON.

            The request body immediately follows the request headers. This is the part of a request that contains any additional data that you want to send to your web server as the HTTP request body, such as data from a form.

            Note that only the first 8 KB (8192 bytes) of the request body are forwarded to AWS WAF for inspection by the underlying host service. If you don't need to inspect more than 8 KB, you can guarantee that you don't allow additional bytes in by combining a statement that inspects the body of the web request, such as the ``ByteMatchStatement`` or ``RegexPatternSetReferenceStatement`` , with a ``SizeConstraintStatement`` that enforces an 8 KB size limit on the body of the request. AWS WAF doesn't support inspecting the entire contents of web requests whose bodies exceed the 8 KB limit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html#cfn-wafv2-webacl-fieldtomatch-jsonbody
            '''
            result = self._values.get("json_body")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.JsonBodyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def method(self) -> typing.Any:
            '''Inspect the HTTP method.

            The method indicates the type of operation that the request is asking the origin to perform.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html#cfn-wafv2-webacl-fieldtomatch-method
            '''
            result = self._values.get("method")
            return typing.cast(typing.Any, result)

        @builtins.property
        def query_string(self) -> typing.Any:
            '''Inspect the query string.

            This is the part of a URL that appears after a ``?`` character, if any.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html#cfn-wafv2-webacl-fieldtomatch-querystring
            '''
            result = self._values.get("query_string")
            return typing.cast(typing.Any, result)

        @builtins.property
        def single_header(self) -> typing.Any:
            '''Inspect a single header.

            Provide the name of the header to inspect, for example, ``User-Agent`` or ``Referer`` . This setting isn't case sensitive.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html#cfn-wafv2-webacl-fieldtomatch-singleheader
            '''
            result = self._values.get("single_header")
            return typing.cast(typing.Any, result)

        @builtins.property
        def single_query_argument(self) -> typing.Any:
            '''Inspect a single query argument.

            Provide the name of the query argument to inspect, such as *UserName* or *SalesRegion* . The name can be up to 30 characters long and isn't case sensitive.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html#cfn-wafv2-webacl-fieldtomatch-singlequeryargument
            '''
            result = self._values.get("single_query_argument")
            return typing.cast(typing.Any, result)

        @builtins.property
        def uri_path(self) -> typing.Any:
            '''Inspect the request URI path.

            This is the part of a web request that identifies a resource, for example, ``/images/daily-ad.jpg`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-fieldtomatch.html#cfn-wafv2-webacl-fieldtomatch-uripath
            '''
            result = self._values.get("uri_path")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FieldToMatchProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.ForwardedIPConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "fallback_behavior": "fallbackBehavior",
            "header_name": "headerName",
        },
    )
    class ForwardedIPConfigurationProperty:
        def __init__(
            self,
            *,
            fallback_behavior: builtins.str,
            header_name: builtins.str,
        ) -> None:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            This configuration is used for ``GeoMatchStatement`` and ``RateBasedStatement`` . For ``IPSetReferenceStatement`` , use ``IPSetForwardedIPConfig`` instead.

            AWS WAF only evaluates the first IP address found in the specified HTTP header.

            :param fallback_behavior: The match status to assign to the web request if the request doesn't have a valid IP address in the specified position. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all. You can specify the following fallback behaviors: - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request. - ``NO_MATCH`` - Treat the web request as not matching the rule statement.
            :param header_name: The name of the HTTP header to use for the IP address. For example, to use the X-Forwarded-For (XFF) header, set this to ``X-Forwarded-For`` . .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-forwardedipconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                forwarded_iPConfiguration_property = wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                    fallback_behavior="fallbackBehavior",
                    header_name="headerName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "fallback_behavior": fallback_behavior,
                "header_name": header_name,
            }

        @builtins.property
        def fallback_behavior(self) -> builtins.str:
            '''The match status to assign to the web request if the request doesn't have a valid IP address in the specified position.

            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            You can specify the following fallback behaviors:

            - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request.
            - ``NO_MATCH`` - Treat the web request as not matching the rule statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-forwardedipconfiguration.html#cfn-wafv2-webacl-forwardedipconfiguration-fallbackbehavior
            '''
            result = self._values.get("fallback_behavior")
            assert result is not None, "Required property 'fallback_behavior' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def header_name(self) -> builtins.str:
            '''The name of the HTTP header to use for the IP address.

            For example, to use the X-Forwarded-For (XFF) header, set this to ``X-Forwarded-For`` .
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-forwardedipconfiguration.html#cfn-wafv2-webacl-forwardedipconfiguration-headername
            '''
            result = self._values.get("header_name")
            assert result is not None, "Required property 'header_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ForwardedIPConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.GeoMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "country_codes": "countryCodes",
            "forwarded_ip_config": "forwardedIpConfig",
        },
    )
    class GeoMatchStatementProperty:
        def __init__(
            self,
            *,
            country_codes: typing.Optional[typing.Sequence[builtins.str]] = None,
            forwarded_ip_config: typing.Optional[typing.Union["CfnWebACL.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A rule statement used to identify web requests based on country of origin.

            :param country_codes: An array of two-character country codes, for example, ``[ "US", "CN" ]`` , from the alpha-2 country ISO codes of the ISO 3166 international standard.
            :param forwarded_ip_config: The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-geomatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                geo_match_statement_property = wafv2.CfnWebACL.GeoMatchStatementProperty(
                    country_codes=["countryCodes"],
                    forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                        fallback_behavior="fallbackBehavior",
                        header_name="headerName"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if country_codes is not None:
                self._values["country_codes"] = country_codes
            if forwarded_ip_config is not None:
                self._values["forwarded_ip_config"] = forwarded_ip_config

        @builtins.property
        def country_codes(self) -> typing.Optional[typing.List[builtins.str]]:
            '''An array of two-character country codes, for example, ``[ "US", "CN" ]`` , from the alpha-2 country ISO codes of the ISO 3166 international standard.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-geomatchstatement.html#cfn-wafv2-webacl-geomatchstatement-countrycodes
            '''
            result = self._values.get("country_codes")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def forwarded_ip_config(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-geomatchstatement.html#cfn-wafv2-webacl-geomatchstatement-forwardedipconfig
            '''
            result = self._values.get("forwarded_ip_config")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GeoMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.IPSetForwardedIPConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "fallback_behavior": "fallbackBehavior",
            "header_name": "headerName",
            "position": "position",
        },
    )
    class IPSetForwardedIPConfigurationProperty:
        def __init__(
            self,
            *,
            fallback_behavior: builtins.str,
            header_name: builtins.str,
            position: builtins.str,
        ) -> None:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            This configuration is used only for ``IPSetReferenceStatement`` . For ``GeoMatchStatement`` and ``RateBasedStatement`` , use ``ForwardedIPConfig`` instead.

            :param fallback_behavior: The match status to assign to the web request if the request doesn't have a valid IP address in the specified position. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all. You can specify the following fallback behaviors: - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request. - ``NO_MATCH`` - Treat the web request as not matching the rule statement.
            :param header_name: The name of the HTTP header to use for the IP address. For example, to use the X-Forwarded-For (XFF) header, set this to ``X-Forwarded-For`` . .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.
            :param position: The position in the header to search for the IP address. The header can contain IP addresses of the original client and also of proxies. For example, the header value could be ``10.1.1.1, 127.0.0.0, 10.10.10.10`` where the first IP address identifies the original client and the rest identify proxies that the request went through. The options for this setting are the following: - FIRST - Inspect the first IP address in the list of IP addresses in the header. This is usually the client's original IP. - LAST - Inspect the last IP address in the list of IP addresses in the header. - ANY - Inspect all IP addresses in the header for a match. If the header contains more than 10 IP addresses, AWS WAF inspects the last 10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ipsetforwardedipconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                i_pSet_forwarded_iPConfiguration_property = {
                    "fallback_behavior": "fallbackBehavior",
                    "header_name": "headerName",
                    "position": "position"
                }
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "fallback_behavior": fallback_behavior,
                "header_name": header_name,
                "position": position,
            }

        @builtins.property
        def fallback_behavior(self) -> builtins.str:
            '''The match status to assign to the web request if the request doesn't have a valid IP address in the specified position.

            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            You can specify the following fallback behaviors:

            - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request.
            - ``NO_MATCH`` - Treat the web request as not matching the rule statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ipsetforwardedipconfiguration.html#cfn-wafv2-webacl-ipsetforwardedipconfiguration-fallbackbehavior
            '''
            result = self._values.get("fallback_behavior")
            assert result is not None, "Required property 'fallback_behavior' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def header_name(self) -> builtins.str:
            '''The name of the HTTP header to use for the IP address.

            For example, to use the X-Forwarded-For (XFF) header, set this to ``X-Forwarded-For`` .
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ipsetforwardedipconfiguration.html#cfn-wafv2-webacl-ipsetforwardedipconfiguration-headername
            '''
            result = self._values.get("header_name")
            assert result is not None, "Required property 'header_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def position(self) -> builtins.str:
            '''The position in the header to search for the IP address.

            The header can contain IP addresses of the original client and also of proxies. For example, the header value could be ``10.1.1.1, 127.0.0.0, 10.10.10.10`` where the first IP address identifies the original client and the rest identify proxies that the request went through.

            The options for this setting are the following:

            - FIRST - Inspect the first IP address in the list of IP addresses in the header. This is usually the client's original IP.
            - LAST - Inspect the last IP address in the list of IP addresses in the header.
            - ANY - Inspect all IP addresses in the header for a match. If the header contains more than 10 IP addresses, AWS WAF inspects the last 10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ipsetforwardedipconfiguration.html#cfn-wafv2-webacl-ipsetforwardedipconfiguration-position
            '''
            result = self._values.get("position")
            assert result is not None, "Required property 'position' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IPSetForwardedIPConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.IPSetReferenceStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arn": "arn",
            "ip_set_forwarded_ip_config": "ipSetForwardedIpConfig",
        },
    )
    class IPSetReferenceStatementProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            ip_set_forwarded_ip_config: typing.Optional[typing.Union["CfnWebACL.IPSetForwardedIPConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A rule statement used to detect web requests coming from particular IP addresses or address ranges.

            To use this, create an ``IPSet`` that specifies the addresses you want to detect, then use the ARN of that set in this statement.

            Each IP set rule statement references an IP set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.

            :param arn: The Amazon Resource Name (ARN) of the IP set that this statement references.
            :param ip_set_forwarded_ip_config: The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ipsetreferencestatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                i_pSet_reference_statement_property = {
                    "arn": "arn",
                
                    # the properties below are optional
                    "ip_set_forwarded_ip_config": {
                        "fallback_behavior": "fallbackBehavior",
                        "header_name": "headerName",
                        "position": "position"
                    }
                }
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
            }
            if ip_set_forwarded_ip_config is not None:
                self._values["ip_set_forwarded_ip_config"] = ip_set_forwarded_ip_config

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the IP set that this statement references.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ipsetreferencestatement.html#cfn-wafv2-webacl-ipsetreferencestatement-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ip_set_forwarded_ip_config(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.IPSetForwardedIPConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ipsetreferencestatement.html#cfn-wafv2-webacl-ipsetreferencestatement-ipsetforwardedipconfig
            '''
            result = self._values.get("ip_set_forwarded_ip_config")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.IPSetForwardedIPConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IPSetReferenceStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.ImmunityTimePropertyProperty",
        jsii_struct_bases=[],
        name_mapping={"immunity_time": "immunityTime"},
    )
    class ImmunityTimePropertyProperty:
        def __init__(self, *, immunity_time: jsii.Number) -> None:
            '''Determines how long a ``CAPTCHA`` token remains valid after the client successfully solves a ``CAPTCHA`` puzzle.

            :param immunity_time: The amount of time, in seconds, that a ``CAPTCHA`` token is valid. The default setting is 300.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-immunitytimeproperty.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                immunity_time_property_property = wafv2.CfnWebACL.ImmunityTimePropertyProperty(
                    immunity_time=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "immunity_time": immunity_time,
            }

        @builtins.property
        def immunity_time(self) -> jsii.Number:
            '''The amount of time, in seconds, that a ``CAPTCHA`` token is valid.

            The default setting is 300.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-immunitytimeproperty.html#cfn-wafv2-webacl-immunitytimeproperty-immunitytime
            '''
            result = self._values.get("immunity_time")
            assert result is not None, "Required property 'immunity_time' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ImmunityTimePropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.JsonBodyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "match_pattern": "matchPattern",
            "match_scope": "matchScope",
            "invalid_fallback_behavior": "invalidFallbackBehavior",
        },
    )
    class JsonBodyProperty:
        def __init__(
            self,
            *,
            match_pattern: typing.Union["CfnWebACL.JsonMatchPatternProperty", _IResolvable_da3f097b],
            match_scope: builtins.str,
            invalid_fallback_behavior: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The body of a web request, inspected as JSON.

            The body immediately follows the request headers. This is used in the ``FieldToMatch`` specification.

            Use the specifications in this object to indicate which parts of the JSON body to inspect using the rule's inspection criteria. AWS WAF inspects only the parts of the JSON that result from the matches that you indicate.

            :param match_pattern: The patterns to look for in the JSON body. AWS WAF inspects the results of these pattern matches against the rule inspection criteria.
            :param match_scope: The parts of the JSON to match against using the ``MatchPattern`` . If you specify ``All`` , AWS WAF matches against keys and values. Valid Values: ``ALL`` | ``KEY`` | ``VALUE``
            :param invalid_fallback_behavior: What AWS WAF should do if it fails to completely parse the JSON body. The options are the following:. - ``EVALUATE_AS_STRING`` - Inspect the body as plain text. AWS WAF applies the text transformations and inspection criteria that you defined for the JSON inspection to the body text string. - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request. - ``NO_MATCH`` - Treat the web request as not matching the rule statement. If you don't provide this setting, AWS WAF parses and evaluates the content only up to the first parsing failure that it encounters. AWS WAF does its best to parse the entire JSON body, but might be forced to stop for reasons such as invalid characters, duplicate keys, truncation, and any content whose root node isn't an object or an array. AWS WAF parses the JSON in the following examples as two valid key, value pairs: - Missing comma: ``{"key1":"value1""key2":"value2"}`` - Missing colon: ``{"key1":"value1","key2""value2"}`` - Extra colons: ``{"key1"::"value1","key2""value2"}``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-jsonbody.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                
                json_body_property = wafv2.CfnWebACL.JsonBodyProperty(
                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                        all=all,
                        included_paths=["includedPaths"]
                    ),
                    match_scope="matchScope",
                
                    # the properties below are optional
                    invalid_fallback_behavior="invalidFallbackBehavior"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "match_pattern": match_pattern,
                "match_scope": match_scope,
            }
            if invalid_fallback_behavior is not None:
                self._values["invalid_fallback_behavior"] = invalid_fallback_behavior

        @builtins.property
        def match_pattern(
            self,
        ) -> typing.Union["CfnWebACL.JsonMatchPatternProperty", _IResolvable_da3f097b]:
            '''The patterns to look for in the JSON body.

            AWS WAF inspects the results of these pattern matches against the rule inspection criteria.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-jsonbody.html#cfn-wafv2-webacl-jsonbody-matchpattern
            '''
            result = self._values.get("match_pattern")
            assert result is not None, "Required property 'match_pattern' is missing"
            return typing.cast(typing.Union["CfnWebACL.JsonMatchPatternProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def match_scope(self) -> builtins.str:
            '''The parts of the JSON to match against using the ``MatchPattern`` .

            If you specify ``All`` , AWS WAF matches against keys and values.

            Valid Values: ``ALL`` | ``KEY`` | ``VALUE``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-jsonbody.html#cfn-wafv2-webacl-jsonbody-matchscope
            '''
            result = self._values.get("match_scope")
            assert result is not None, "Required property 'match_scope' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def invalid_fallback_behavior(self) -> typing.Optional[builtins.str]:
            '''What AWS WAF should do if it fails to completely parse the JSON body. The options are the following:.

            - ``EVALUATE_AS_STRING`` - Inspect the body as plain text. AWS WAF applies the text transformations and inspection criteria that you defined for the JSON inspection to the body text string.
            - ``MATCH`` - Treat the web request as matching the rule statement. AWS WAF applies the rule action to the request.
            - ``NO_MATCH`` - Treat the web request as not matching the rule statement.

            If you don't provide this setting, AWS WAF parses and evaluates the content only up to the first parsing failure that it encounters.

            AWS WAF does its best to parse the entire JSON body, but might be forced to stop for reasons such as invalid characters, duplicate keys, truncation, and any content whose root node isn't an object or an array.

            AWS WAF parses the JSON in the following examples as two valid key, value pairs:

            - Missing comma: ``{"key1":"value1""key2":"value2"}``
            - Missing colon: ``{"key1":"value1","key2""value2"}``
            - Extra colons: ``{"key1"::"value1","key2""value2"}``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-jsonbody.html#cfn-wafv2-webacl-jsonbody-invalidfallbackbehavior
            '''
            result = self._values.get("invalid_fallback_behavior")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JsonBodyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.JsonMatchPatternProperty",
        jsii_struct_bases=[],
        name_mapping={"all": "all", "included_paths": "includedPaths"},
    )
    class JsonMatchPatternProperty:
        def __init__(
            self,
            *,
            all: typing.Any = None,
            included_paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The patterns to look for in the JSON body.

            AWS WAF inspects the results of these pattern matches against the rule inspection criteria. This is used with the ``FieldToMatch`` option ``JsonBody`` .

            :param all: Match all of the elements. See also ``MatchScope`` in ``JsonBody`` . You must specify either this setting or the ``IncludedPaths`` setting, but not both.
            :param included_paths: Match only the specified include paths. See also ``MatchScope`` in ``JsonBody`` . Provide the include paths using JSON Pointer syntax. For example, ``"IncludedPaths": ["/dogs/0/name", "/dogs/1/name"]`` . For information about this syntax, see the Internet Engineering Task Force (IETF) documentation `JavaScript Object Notation (JSON) Pointer <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6901>`_ . You must specify either this setting or the ``All`` setting, but not both. .. epigraph:: Don't use this option to include all paths. Instead, use the ``All`` setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-jsonmatchpattern.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                
                json_match_pattern_property = wafv2.CfnWebACL.JsonMatchPatternProperty(
                    all=all,
                    included_paths=["includedPaths"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if all is not None:
                self._values["all"] = all
            if included_paths is not None:
                self._values["included_paths"] = included_paths

        @builtins.property
        def all(self) -> typing.Any:
            '''Match all of the elements. See also ``MatchScope`` in ``JsonBody`` .

            You must specify either this setting or the ``IncludedPaths`` setting, but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-jsonmatchpattern.html#cfn-wafv2-webacl-jsonmatchpattern-all
            '''
            result = self._values.get("all")
            return typing.cast(typing.Any, result)

        @builtins.property
        def included_paths(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Match only the specified include paths. See also ``MatchScope`` in ``JsonBody`` .

            Provide the include paths using JSON Pointer syntax. For example, ``"IncludedPaths": ["/dogs/0/name", "/dogs/1/name"]`` . For information about this syntax, see the Internet Engineering Task Force (IETF) documentation `JavaScript Object Notation (JSON) Pointer <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6901>`_ .

            You must specify either this setting or the ``All`` setting, but not both.
            .. epigraph::

               Don't use this option to include all paths. Instead, use the ``All`` setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-jsonmatchpattern.html#cfn-wafv2-webacl-jsonmatchpattern-includedpaths
            '''
            result = self._values.get("included_paths")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "JsonMatchPatternProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.LabelMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "scope": "scope"},
    )
    class LabelMatchStatementProperty:
        def __init__(self, *, key: builtins.str, scope: builtins.str) -> None:
            '''A rule statement that defines a string match search against labels that have been added to the web request by rules that have already run in the web ACL.

            The label match statement provides the label or namespace string to search for. The label string can represent a part or all of the fully qualified label name that had been added to the web request. Fully qualified labels have a prefix, optional namespaces, and label name. The prefix identifies the rule group or web ACL context of the rule that added the label. If you do not provide the fully qualified name in your label match string, AWS WAF performs the search for labels that were added in the same context as the label match statement.

            :param key: The string to match against. The setting you provide for this depends on the match statement's ``Scope`` setting:. - If the ``Scope`` indicates ``LABEL`` , then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name. - If the ``Scope`` indicates ``NAMESPACE`` , then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates. Labels are case sensitive and components of a label must be separated by colon, for example ``NS1:NS2:name`` .
            :param scope: Specify whether you want to match using the label name or just the namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-labelmatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                label_match_statement_property = wafv2.CfnWebACL.LabelMatchStatementProperty(
                    key="key",
                    scope="scope"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "scope": scope,
            }

        @builtins.property
        def key(self) -> builtins.str:
            '''The string to match against. The setting you provide for this depends on the match statement's ``Scope`` setting:.

            - If the ``Scope`` indicates ``LABEL`` , then this specification must include the name and can include any number of preceding namespace specifications and prefix up to providing the fully qualified label name.
            - If the ``Scope`` indicates ``NAMESPACE`` , then this specification can include any number of contiguous namespace strings, and can include the entire label namespace prefix from the rule group or web ACL where the label originates.

            Labels are case sensitive and components of a label must be separated by colon, for example ``NS1:NS2:name`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-labelmatchstatement.html#cfn-wafv2-webacl-labelmatchstatement-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def scope(self) -> builtins.str:
            '''Specify whether you want to match using the label name or just the namespace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-labelmatchstatement.html#cfn-wafv2-webacl-labelmatchstatement-scope
            '''
            result = self._values.get("scope")
            assert result is not None, "Required property 'scope' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LabelMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.LabelProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name"},
    )
    class LabelProperty:
        def __init__(self, *, name: builtins.str) -> None:
            '''A single label container.

            This is used as an element of a label array in ``RuleLabels`` inside a ``Rule`` .

            :param name: The label string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-label.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                label_property = wafv2.CfnWebACL.LabelProperty(
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The label string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-label.html#cfn-wafv2-webacl-label-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LabelProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.ManagedRuleGroupConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "login_path": "loginPath",
            "password_field": "passwordField",
            "payload_type": "payloadType",
            "username_field": "usernameField",
        },
    )
    class ManagedRuleGroupConfigProperty:
        def __init__(
            self,
            *,
            login_path: typing.Optional[builtins.str] = None,
            password_field: typing.Optional[typing.Union["CfnWebACL.FieldIdentifierProperty", _IResolvable_da3f097b]] = None,
            payload_type: typing.Optional[builtins.str] = None,
            username_field: typing.Optional[typing.Union["CfnWebACL.FieldIdentifierProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Additional information that's used by a managed rule group. Most managed rule groups don't require this.

            Use this for the account takeover prevention managed rule group ``AWSManagedRulesATPRuleSet`` , to provide information about the sign-in page of your application.

            :param login_path: The path of the login endpoint for your application. For example, for the URL ``https://example.com/web/login`` , you would provide the path ``/web/login`` .
            :param password_field: Details about your login page password field.
            :param payload_type: The payload type for your login endpoint, either JSON or form encoded.
            :param username_field: Details about your login page username field.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                managed_rule_group_config_property = wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                    login_path="loginPath",
                    password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                        identifier="identifier"
                    ),
                    payload_type="payloadType",
                    username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                        identifier="identifier"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if login_path is not None:
                self._values["login_path"] = login_path
            if password_field is not None:
                self._values["password_field"] = password_field
            if payload_type is not None:
                self._values["payload_type"] = payload_type
            if username_field is not None:
                self._values["username_field"] = username_field

        @builtins.property
        def login_path(self) -> typing.Optional[builtins.str]:
            '''The path of the login endpoint for your application.

            For example, for the URL ``https://example.com/web/login`` , you would provide the path ``/web/login`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupconfig.html#cfn-wafv2-webacl-managedrulegroupconfig-loginpath
            '''
            result = self._values.get("login_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def password_field(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.FieldIdentifierProperty", _IResolvable_da3f097b]]:
            '''Details about your login page password field.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupconfig.html#cfn-wafv2-webacl-managedrulegroupconfig-passwordfield
            '''
            result = self._values.get("password_field")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.FieldIdentifierProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def payload_type(self) -> typing.Optional[builtins.str]:
            '''The payload type for your login endpoint, either JSON or form encoded.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupconfig.html#cfn-wafv2-webacl-managedrulegroupconfig-payloadtype
            '''
            result = self._values.get("payload_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def username_field(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.FieldIdentifierProperty", _IResolvable_da3f097b]]:
            '''Details about your login page username field.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupconfig.html#cfn-wafv2-webacl-managedrulegroupconfig-usernamefield
            '''
            result = self._values.get("username_field")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.FieldIdentifierProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ManagedRuleGroupConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.ManagedRuleGroupStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "vendor_name": "vendorName",
            "excluded_rules": "excludedRules",
            "managed_rule_group_configs": "managedRuleGroupConfigs",
            "scope_down_statement": "scopeDownStatement",
            "version": "version",
        },
    )
    class ManagedRuleGroupStatementProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            vendor_name: builtins.str,
            excluded_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.ExcludedRuleProperty", _IResolvable_da3f097b]]]] = None,
            managed_rule_group_configs: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.ManagedRuleGroupConfigProperty", _IResolvable_da3f097b]]]] = None,
            scope_down_statement: typing.Optional[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]] = None,
            version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A rule statement used to run the rules that are defined in a managed rule group.

            To use this, provide the vendor name and the name of the rule group in this statement.

            You can't nest a ``ManagedRuleGroupStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.

            :param name: The name of the managed rule group. You use this, along with the vendor name, to identify the rule group.
            :param vendor_name: The name of the managed rule group vendor. You use this, along with the rule group name, to identify the rule group.
            :param excluded_rules: The rules whose actions are set to ``COUNT`` by the web ACL, regardless of the action that is configured in the rule. This effectively excludes the rule from acting on web requests.
            :param managed_rule_group_configs: Additional information that's used by a managed rule group. Most managed rule groups don't require this. Use this for the account takeover prevention managed rule group ``AWSManagedRulesATPRuleSet`` , to provide information about the sign-in page of your application.
            :param scope_down_statement: Statement nested inside a managed rule group statement to narrow the scope of the requests that AWS WAF evaluates using the rule group. Requests that match the scope-down statement are evaluated using the rule group. Requests that don't match the scope-down statement are not a match for the managed rule group statement, without any further evaluation.
            :param version: The version of the managed rule group to use. If you specify this, the version setting is fixed until you change it. If you don't specify this, AWS WAF uses the vendor's default version, and then keeps the version at the vendor's default when the vendor updates the managed rule group settings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnWebACL.StatementProperty
                # uri_path: Any
                
                managed_rule_group_statement_property = wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="name",
                    vendor_name="vendorName",
                
                    # the properties below are optional
                    excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                        name="name"
                    )],
                    managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                        login_path="loginPath",
                        password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                            identifier="identifier"
                        ),
                        payload_type="payloadType",
                        username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                            identifier="identifier"
                        )
                    )],
                    scope_down_statement=wafv2.CfnWebACL.StatementProperty(
                        and_statement=wafv2.CfnWebACL.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="name",
                            vendor_name="vendorName",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )],
                            managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                login_path="loginPath",
                                password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                ),
                                payload_type="payloadType",
                                username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                )
                            )],
                            scope_down_statement=statement_property_,
                            version="version"
                        ),
                        not_statement=wafv2.CfnWebACL.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnWebACL.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                            arn="arn",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    ),
                    version="version"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "vendor_name": vendor_name,
            }
            if excluded_rules is not None:
                self._values["excluded_rules"] = excluded_rules
            if managed_rule_group_configs is not None:
                self._values["managed_rule_group_configs"] = managed_rule_group_configs
            if scope_down_statement is not None:
                self._values["scope_down_statement"] = scope_down_statement
            if version is not None:
                self._values["version"] = version

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the managed rule group.

            You use this, along with the vendor name, to identify the rule group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def vendor_name(self) -> builtins.str:
            '''The name of the managed rule group vendor.

            You use this, along with the rule group name, to identify the rule group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-vendorname
            '''
            result = self._values.get("vendor_name")
            assert result is not None, "Required property 'vendor_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def excluded_rules(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.ExcludedRuleProperty", _IResolvable_da3f097b]]]]:
            '''The rules whose actions are set to ``COUNT`` by the web ACL, regardless of the action that is configured in the rule.

            This effectively excludes the rule from acting on web requests.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-excludedrules
            '''
            result = self._values.get("excluded_rules")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.ExcludedRuleProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def managed_rule_group_configs(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.ManagedRuleGroupConfigProperty", _IResolvable_da3f097b]]]]:
            '''Additional information that's used by a managed rule group. Most managed rule groups don't require this.

            Use this for the account takeover prevention managed rule group ``AWSManagedRulesATPRuleSet`` , to provide information about the sign-in page of your application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-managedrulegroupconfigs
            '''
            result = self._values.get("managed_rule_group_configs")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.ManagedRuleGroupConfigProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def scope_down_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]]:
            '''Statement nested inside a managed rule group statement to narrow the scope of the requests that AWS WAF evaluates using the rule group.

            Requests that match the scope-down statement are evaluated using the rule group. Requests that don't match the scope-down statement are not a match for the managed rule group statement, without any further evaluation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-scopedownstatement
            '''
            result = self._values.get("scope_down_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def version(self) -> typing.Optional[builtins.str]:
            '''The version of the managed rule group to use.

            If you specify this, the version setting is fixed until you change it. If you don't specify this, AWS WAF uses the vendor's default version, and then keeps the version at the vendor's default when the vendor updates the managed rule group settings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-version
            '''
            result = self._values.get("version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ManagedRuleGroupStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.NotStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"statement": "statement"},
    )
    class NotStatementProperty:
        def __init__(
            self,
            *,
            statement: typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b],
        ) -> None:
            '''A logical rule statement used to negate the results of another rule statement.

            You provide one ``Statement`` within the ``NotStatement`` .

            :param statement: The statement to negate. You can use any statement that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-notstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnWebACL.StatementProperty
                # uri_path: Any
                
                not_statement_property = wafv2.CfnWebACL.NotStatementProperty(
                    statement=wafv2.CfnWebACL.StatementProperty(
                        and_statement=wafv2.CfnWebACL.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="name",
                            vendor_name="vendorName",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )],
                            managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                login_path="loginPath",
                                password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                ),
                                payload_type="payloadType",
                                username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                )
                            )],
                            scope_down_statement=statement_property_,
                            version="version"
                        ),
                        not_statement=wafv2.CfnWebACL.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnWebACL.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                            arn="arn",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "statement": statement,
            }

        @builtins.property
        def statement(
            self,
        ) -> typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]:
            '''The statement to negate.

            You can use any statement that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-notstatement.html#cfn-wafv2-webacl-notstatement-statement
            '''
            result = self._values.get("statement")
            assert result is not None, "Required property 'statement' is missing"
            return typing.cast(typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.OrStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"statements": "statements"},
    )
    class OrStatementProperty:
        def __init__(
            self,
            *,
            statements: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A logical rule statement used to combine other rule statements with OR logic.

            You provide more than one ``Statement`` within the ``OrStatement`` .

            :param statements: The statements to combine with OR logic. You can use any statements that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-orstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnWebACL.StatementProperty
                # uri_path: Any
                
                or_statement_property = wafv2.CfnWebACL.OrStatementProperty(
                    statements=[wafv2.CfnWebACL.StatementProperty(
                        and_statement=wafv2.CfnWebACL.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="name",
                            vendor_name="vendorName",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )],
                            managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                login_path="loginPath",
                                password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                ),
                                payload_type="payloadType",
                                username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                )
                            )],
                            scope_down_statement=statement_property_,
                            version="version"
                        ),
                        not_statement=wafv2.CfnWebACL.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnWebACL.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                            arn="arn",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "statements": statements,
            }

        @builtins.property
        def statements(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]]]:
            '''The statements to combine with OR logic.

            You can use any statements that can be nested.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-orstatement.html#cfn-wafv2-webacl-orstatement-statements
            '''
            result = self._values.get("statements")
            assert result is not None, "Required property 'statements' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OrStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.OverrideActionProperty",
        jsii_struct_bases=[],
        name_mapping={"count": "count", "none": "none"},
    )
    class OverrideActionProperty:
        def __init__(
            self,
            *,
            count: typing.Any = None,
            none: typing.Any = None,
        ) -> None:
            '''The action to use to override the ``Action`` settings on the rules in the web ACL.

            You can use none, in which case the rule actions are in effect, or count, in which case, if a rule matches a web request, it only counts the match.

            :param count: Override the rule action settings to count.
            :param none: Don't override the rule action settings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-overrideaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # count: Any
                # none: Any
                
                override_action_property = wafv2.CfnWebACL.OverrideActionProperty(
                    count=count,
                    none=none
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if count is not None:
                self._values["count"] = count
            if none is not None:
                self._values["none"] = none

        @builtins.property
        def count(self) -> typing.Any:
            '''Override the rule action settings to count.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-overrideaction.html#cfn-wafv2-webacl-overrideaction-count
            '''
            result = self._values.get("count")
            return typing.cast(typing.Any, result)

        @builtins.property
        def none(self) -> typing.Any:
            '''Don't override the rule action settings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-overrideaction.html#cfn-wafv2-webacl-overrideaction-none
            '''
            result = self._values.get("none")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OverrideActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.RateBasedStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "aggregate_key_type": "aggregateKeyType",
            "limit": "limit",
            "forwarded_ip_config": "forwardedIpConfig",
            "scope_down_statement": "scopeDownStatement",
        },
    )
    class RateBasedStatementProperty:
        def __init__(
            self,
            *,
            aggregate_key_type: builtins.str,
            limit: jsii.Number,
            forwarded_ip_config: typing.Optional[typing.Union["CfnWebACL.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]] = None,
            scope_down_statement: typing.Optional[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span.

            You can use this to put a temporary block on requests from an IP address that is sending excessive requests.

            When the rule action triggers, AWS WAF blocks additional requests from the IP address until the request rate falls below the limit.

            You can optionally nest another statement inside the rate-based statement, to narrow the scope of the rule so that it only counts requests that match the nested statement. For example, based on recent requests that you have seen from an attacker, you might create a rate-based rule with a nested AND rule statement that contains the following nested statements:

            - An IP match statement with an IP set that specified the address 192.0.2.44.
            - A string match statement that searches in the User-Agent header for the string BadBot.

            In this rate-based rule, you also define a rate limit. For this example, the rate limit is 1,000. Requests that meet both of the conditions in the statements are counted. If the count exceeds 1,000 requests per five minutes, the rule action triggers. Requests that do not meet both conditions are not counted towards the rate limit and are not affected by this rule.

            You cannot nest a ``RateBasedStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.

            :param aggregate_key_type: Setting that indicates how to aggregate the request counts. The options are the following:. - IP - Aggregate the request counts on the IP address from the web request origin. - FORWARDED_IP - Aggregate the request counts on the first IP address in an HTTP header. If you use this, configure the ``ForwardedIPConfig`` , to specify the header to use.
            :param limit: The limit on requests per 5-minute period for a single originating IP address. If the statement includes a ``ScopeDownStatement`` , this limit is applied only to the requests that match the statement.
            :param forwarded_ip_config: The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin. Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name. .. epigraph:: If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all. This is required if ``AggregateKeyType`` is set to ``FORWARDED_IP`` .
            :param scope_down_statement: An optional nested statement that narrows the scope of the rate-based statement to matching web requests. This can be any nestable statement, and you can nest statements at any level below this scope-down statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ratebasedstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnWebACL.StatementProperty
                # uri_path: Any
                
                rate_based_statement_property = wafv2.CfnWebACL.RateBasedStatementProperty(
                    aggregate_key_type="aggregateKeyType",
                    limit=123,
                
                    # the properties below are optional
                    forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                        fallback_behavior="fallbackBehavior",
                        header_name="headerName"
                    ),
                    scope_down_statement=wafv2.CfnWebACL.StatementProperty(
                        and_statement=wafv2.CfnWebACL.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="name",
                            vendor_name="vendorName",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )],
                            managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                login_path="loginPath",
                                password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                ),
                                payload_type="payloadType",
                                username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                )
                            )],
                            scope_down_statement=statement_property_,
                            version="version"
                        ),
                        not_statement=wafv2.CfnWebACL.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnWebACL.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                            arn="arn",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "aggregate_key_type": aggregate_key_type,
                "limit": limit,
            }
            if forwarded_ip_config is not None:
                self._values["forwarded_ip_config"] = forwarded_ip_config
            if scope_down_statement is not None:
                self._values["scope_down_statement"] = scope_down_statement

        @builtins.property
        def aggregate_key_type(self) -> builtins.str:
            '''Setting that indicates how to aggregate the request counts. The options are the following:.

            - IP - Aggregate the request counts on the IP address from the web request origin.
            - FORWARDED_IP - Aggregate the request counts on the first IP address in an HTTP header. If you use this, configure the ``ForwardedIPConfig`` , to specify the header to use.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ratebasedstatement.html#cfn-wafv2-webacl-ratebasedstatement-aggregatekeytype
            '''
            result = self._values.get("aggregate_key_type")
            assert result is not None, "Required property 'aggregate_key_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def limit(self) -> jsii.Number:
            '''The limit on requests per 5-minute period for a single originating IP address.

            If the statement includes a ``ScopeDownStatement`` , this limit is applied only to the requests that match the statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ratebasedstatement.html#cfn-wafv2-webacl-ratebasedstatement-limit
            '''
            result = self._values.get("limit")
            assert result is not None, "Required property 'limit' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def forwarded_ip_config(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration for inspecting IP addresses in an HTTP header that you specify, instead of using the IP address that's reported by the web request origin.

            Commonly, this is the X-Forwarded-For (XFF) header, but you can specify any header name.
            .. epigraph::

               If the specified header isn't present in the request, AWS WAF doesn't apply the rule to the web request at all.

            This is required if ``AggregateKeyType`` is set to ``FORWARDED_IP`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ratebasedstatement.html#cfn-wafv2-webacl-ratebasedstatement-forwardedipconfig
            '''
            result = self._values.get("forwarded_ip_config")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.ForwardedIPConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def scope_down_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]]:
            '''An optional nested statement that narrows the scope of the rate-based statement to matching web requests.

            This can be any nestable statement, and you can nest statements at any level below this scope-down statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ratebasedstatement.html#cfn-wafv2-webacl-ratebasedstatement-scopedownstatement
            '''
            result = self._values.get("scope_down_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RateBasedStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.RegexMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_to_match": "fieldToMatch",
            "regex_string": "regexString",
            "text_transformations": "textTransformations",
        },
    )
    class RegexMatchStatementProperty:
        def __init__(
            self,
            *,
            field_to_match: typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b],
            regex_string: builtins.str,
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A rule statement used to search web request components for a match against a single regular expression.

            :param field_to_match: The part of a web request that you want AWS WAF to inspect. For more information, see ``FieldToMatch`` .
            :param regex_string: The string representing the regular expression.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content of the request component identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-regexmatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                regex_match_statement_property = wafv2.CfnWebACL.RegexMatchStatementProperty(
                    field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnWebACL.JsonBodyProperty(
                            match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    regex_string="regexString",
                    text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "field_to_match": field_to_match,
                "regex_string": regex_string,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            For more information, see ``FieldToMatch`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-regexmatchstatement.html#cfn-wafv2-webacl-regexmatchstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def regex_string(self) -> builtins.str:
            '''The string representing the regular expression.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-regexmatchstatement.html#cfn-wafv2-webacl-regexmatchstatement-regexstring
            '''
            result = self._values.get("regex_string")
            assert result is not None, "Required property 'regex_string' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content of the request component identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-regexmatchstatement.html#cfn-wafv2-webacl-regexmatchstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RegexMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arn": "arn",
            "field_to_match": "fieldToMatch",
            "text_transformations": "textTransformations",
        },
    )
    class RegexPatternSetReferenceStatementProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            field_to_match: typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b],
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A rule statement used to search web request components for matches with regular expressions.

            To use this, create a ``RegexPatternSet`` that specifies the expressions that you want to detect, then use that set in this statement. A web request matches the pattern set rule statement if the request component matches any of the patterns in the set.

            Each regex pattern set rule statement references a regex pattern set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.

            :param arn: The Amazon Resource Name (ARN) of the regular expression pattern set that this statement references.
            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-regexpatternsetreferencestatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                regex_pattern_set_reference_statement_property = wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                    arn="arn",
                    field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnWebACL.JsonBodyProperty(
                            match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
                "field_to_match": field_to_match,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the regular expression pattern set that this statement references.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-regexpatternsetreferencestatement.html#cfn-wafv2-webacl-regexpatternsetreferencestatement-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-regexpatternsetreferencestatement.html#cfn-wafv2-webacl-regexpatternsetreferencestatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-regexpatternsetreferencestatement.html#cfn-wafv2-webacl-regexpatternsetreferencestatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RegexPatternSetReferenceStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.RuleActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "allow": "allow",
            "block": "block",
            "captcha": "captcha",
            "count": "count",
        },
    )
    class RuleActionProperty:
        def __init__(
            self,
            *,
            allow: typing.Optional[typing.Union["CfnWebACL.AllowActionProperty", _IResolvable_da3f097b]] = None,
            block: typing.Optional[typing.Union["CfnWebACL.BlockActionProperty", _IResolvable_da3f097b]] = None,
            captcha: typing.Optional[typing.Union["CfnWebACL.CaptchaActionProperty", _IResolvable_da3f097b]] = None,
            count: typing.Optional[typing.Union["CfnWebACL.CountActionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The action that AWS WAF should take on a web request when it matches a rule's statement.

            Settings at the web ACL level can override the rule action setting.

            :param allow: Instructs AWS WAF to allow the web request.
            :param block: Instructs AWS WAF to block the web request.
            :param captcha: Specifies that AWS WAF should run a ``CAPTCHA`` check against the request:. - If the request includes a valid, unexpired ``CAPTCHA`` token, AWS WAF allows the web request inspection to proceed to the next rule, similar to a ``CountAction`` . - If the request doesn't include a valid, unexpired ``CAPTCHA`` token, AWS WAF discontinues the web ACL evaluation of the request and blocks it from going to its intended destination. AWS WAF generates a response that it sends back to the client, which includes the following: - The header ``x-amzn-waf-action`` with a value of ``captcha`` . - The HTTP status code ``405 Method Not Allowed`` . - If the request contains an ``Accept`` header with a value of ``text/html`` , the response includes a ``CAPTCHA`` challenge. You can configure the expiration time in the ``CaptchaConfig`` ``ImmunityTimeProperty`` setting at the rule and web ACL level. The rule setting overrides the web ACL setting. This action option is available for rules. It isn't available for web ACL default actions. This is used in the context of other settings, for example to specify values for ``RuleAction`` and web ACL ``DefaultAction`` .
            :param count: Instructs AWS WAF to count the web request and allow it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ruleaction.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                rule_action_property = wafv2.CfnWebACL.RuleActionProperty(
                    allow=wafv2.CfnWebACL.AllowActionProperty(
                        custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                            insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    ),
                    block=wafv2.CfnWebACL.BlockActionProperty(
                        custom_response=wafv2.CfnWebACL.CustomResponseProperty(
                            response_code=123,
                
                            # the properties below are optional
                            custom_response_body_key="customResponseBodyKey",
                            response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    ),
                    captcha=wafv2.CfnWebACL.CaptchaActionProperty(
                        custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                            insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    ),
                    count=wafv2.CfnWebACL.CountActionProperty(
                        custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                            insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if allow is not None:
                self._values["allow"] = allow
            if block is not None:
                self._values["block"] = block
            if captcha is not None:
                self._values["captcha"] = captcha
            if count is not None:
                self._values["count"] = count

        @builtins.property
        def allow(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.AllowActionProperty", _IResolvable_da3f097b]]:
            '''Instructs AWS WAF to allow the web request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ruleaction.html#cfn-wafv2-webacl-ruleaction-allow
            '''
            result = self._values.get("allow")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.AllowActionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def block(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.BlockActionProperty", _IResolvable_da3f097b]]:
            '''Instructs AWS WAF to block the web request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ruleaction.html#cfn-wafv2-webacl-ruleaction-block
            '''
            result = self._values.get("block")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.BlockActionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def captcha(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.CaptchaActionProperty", _IResolvable_da3f097b]]:
            '''Specifies that AWS WAF should run a ``CAPTCHA`` check against the request:.

            - If the request includes a valid, unexpired ``CAPTCHA`` token, AWS WAF allows the web request inspection to proceed to the next rule, similar to a ``CountAction`` .
            - If the request doesn't include a valid, unexpired ``CAPTCHA`` token, AWS WAF discontinues the web ACL evaluation of the request and blocks it from going to its intended destination.

            AWS WAF generates a response that it sends back to the client, which includes the following:

            - The header ``x-amzn-waf-action`` with a value of ``captcha`` .
            - The HTTP status code ``405 Method Not Allowed`` .
            - If the request contains an ``Accept`` header with a value of ``text/html`` , the response includes a ``CAPTCHA`` challenge.

            You can configure the expiration time in the ``CaptchaConfig`` ``ImmunityTimeProperty`` setting at the rule and web ACL level. The rule setting overrides the web ACL setting.

            This action option is available for rules. It isn't available for web ACL default actions.

            This is used in the context of other settings, for example to specify values for ``RuleAction`` and web ACL ``DefaultAction`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ruleaction.html#cfn-wafv2-webacl-ruleaction-captcha
            '''
            result = self._values.get("captcha")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.CaptchaActionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def count(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.CountActionProperty", _IResolvable_da3f097b]]:
            '''Instructs AWS WAF to count the web request and allow it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-ruleaction.html#cfn-wafv2-webacl-ruleaction-count
            '''
            result = self._values.get("count")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.CountActionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RuleActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.RuleGroupReferenceStatementProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn", "excluded_rules": "excludedRules"},
    )
    class RuleGroupReferenceStatementProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            excluded_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.ExcludedRuleProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A rule statement used to run the rules that are defined in a ``RuleGroup`` .

            To use this, create a rule group with your rules, then provide the ARN of the rule group in this statement.

            You cannot nest a ``RuleGroupReferenceStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.

            :param arn: The Amazon Resource Name (ARN) of the entity.
            :param excluded_rules: The names of rules that are in the referenced rule group, but that you want AWS WAF to exclude from processing for this rule statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rulegroupreferencestatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                rule_group_reference_statement_property = wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                    arn="arn",
                
                    # the properties below are optional
                    excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                        name="name"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
            }
            if excluded_rules is not None:
                self._values["excluded_rules"] = excluded_rules

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the entity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rulegroupreferencestatement.html#cfn-wafv2-webacl-rulegroupreferencestatement-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def excluded_rules(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.ExcludedRuleProperty", _IResolvable_da3f097b]]]]:
            '''The names of rules that are in the referenced rule group, but that you want AWS WAF to exclude from processing for this rule statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rulegroupreferencestatement.html#cfn-wafv2-webacl-rulegroupreferencestatement-excludedrules
            '''
            result = self._values.get("excluded_rules")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.ExcludedRuleProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RuleGroupReferenceStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.RuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "priority": "priority",
            "statement": "statement",
            "visibility_config": "visibilityConfig",
            "action": "action",
            "captcha_config": "captchaConfig",
            "override_action": "overrideAction",
            "rule_labels": "ruleLabels",
        },
    )
    class RuleProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            priority: jsii.Number,
            statement: typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b],
            visibility_config: typing.Union["CfnWebACL.VisibilityConfigProperty", _IResolvable_da3f097b],
            action: typing.Optional[typing.Union["CfnWebACL.RuleActionProperty", _IResolvable_da3f097b]] = None,
            captcha_config: typing.Optional[typing.Union["CfnWebACL.CaptchaConfigProperty", _IResolvable_da3f097b]] = None,
            override_action: typing.Optional[typing.Union["CfnWebACL.OverrideActionProperty", _IResolvable_da3f097b]] = None,
            rule_labels: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.LabelProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A single rule, which you can use to identify web requests that you want to allow, block, or count.

            Each rule includes one top-level Statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.

            :param name: The descriptive name of the rule. You can't change the name of a ``Rule`` after you create it.
            :param priority: If you define more than one ``Rule`` in a ``WebACL`` , AWS WAF evaluates each request against the ``Rules`` in order based on the value of ``Priority`` . AWS WAF processes rules with lower priority first. The priorities don't need to be consecutive, but they must all be different.
            :param statement: The AWS WAF processing statement for the rule, for example ByteMatchStatement or SizeConstraintStatement.
            :param visibility_config: Defines and enables Amazon CloudWatch metrics and web request sample collection.
            :param action: The action that AWS WAF should take on a web request when it matches the rule's statement. Settings at the web ACL level can override the rule action setting. This is used only for rules whose statements don't reference a rule group. Rule statements that reference a rule group are ``RuleGroupReferenceStatement`` and ``ManagedRuleGroupStatement`` . You must set either this ``Action`` setting or the rule's ``OverrideAction`` , but not both: - If the rule statement doesn't reference a rule group, you must set this rule action setting and you must not set the rule's override action setting. - If the rule statement references a rule group, you must not set this action setting, because the actions are already set on the rules inside the rule group. You must set the rule's override action setting to indicate specifically whether to override the actions that are set on the rules in the rule group.
            :param captcha_config: Specifies how AWS WAF should handle ``CAPTCHA`` evaluations. If you don't specify this, AWS WAF uses the ``CAPTCHA`` configuration that's defined for the web ACL.
            :param override_action: The override action to apply to the rules in a rule group, instead of the individual rule action settings. This is used only for rules whose statements reference a rule group. Rule statements that reference a rule group are ``RuleGroupReferenceStatement`` and ``ManagedRuleGroupStatement`` . Set the override action to none to leave the rule group rule actions in effect. Set it to count to only count matches, regardless of the rule action settings. You must set either this ``OverrideAction`` setting or the ``Action`` setting, but not both: - If the rule statement references a rule group, you must set this override action setting and you must not set the rule's action setting. - If the rule statement doesn't reference a rule group, you must set the rule action setting and you must not set the rule's override action setting.
            :param rule_labels: Labels to apply to web requests that match the rule match statement. AWS WAF applies fully qualified labels to matching web requests. A fully qualified label is the concatenation of a label namespace and a rule label. The rule's rule group or web ACL defines the label namespace. Rules that run after this rule in the web ACL can match against these labels using a ``LabelMatchStatement`` . For each label, provide a case-sensitive string containing optional namespaces and a label name, according to the following guidelines: - Separate each component of the label with a colon. - Each namespace or name can have up to 128 characters. - You can specify up to 5 namespaces in a label. - Don't use the following reserved words in your label specification: ``aws`` , ``waf`` , ``managed`` , ``rulegroup`` , ``webacl`` , ``regexpatternset`` , or ``ipset`` . For example, ``myLabelName`` or ``nameSpace1:nameSpace2:myLabelName`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # count: Any
                # method: Any
                # none: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnWebACL.StatementProperty
                # uri_path: Any
                
                rule_property = wafv2.CfnWebACL.RuleProperty(
                    name="name",
                    priority=123,
                    statement=wafv2.CfnWebACL.StatementProperty(
                        and_statement=wafv2.CfnWebACL.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
                
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
                
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="name",
                            vendor_name="vendorName",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )],
                            managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                login_path="loginPath",
                                password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                ),
                                payload_type="payloadType",
                                username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                )
                            )],
                            scope_down_statement=statement_property_,
                            version="version"
                        ),
                        not_statement=wafv2.CfnWebACL.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnWebACL.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
                
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                            arn="arn",
                
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
                
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=False,
                        metric_name="metricName",
                        sampled_requests_enabled=False
                    ),
                
                    # the properties below are optional
                    action=wafv2.CfnWebACL.RuleActionProperty(
                        allow=wafv2.CfnWebACL.AllowActionProperty(
                            custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                                insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        ),
                        block=wafv2.CfnWebACL.BlockActionProperty(
                            custom_response=wafv2.CfnWebACL.CustomResponseProperty(
                                response_code=123,
                
                                # the properties below are optional
                                custom_response_body_key="customResponseBodyKey",
                                response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        ),
                        captcha=wafv2.CfnWebACL.CaptchaActionProperty(
                            custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                                insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        ),
                        count=wafv2.CfnWebACL.CountActionProperty(
                            custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                                insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        )
                    ),
                    captcha_config=wafv2.CfnWebACL.CaptchaConfigProperty(
                        immunity_time_property=wafv2.CfnWebACL.ImmunityTimePropertyProperty(
                            immunity_time=123
                        )
                    ),
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(
                        count=count,
                        none=none
                    ),
                    rule_labels=[wafv2.CfnWebACL.LabelProperty(
                        name="name"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "priority": priority,
                "statement": statement,
                "visibility_config": visibility_config,
            }
            if action is not None:
                self._values["action"] = action
            if captcha_config is not None:
                self._values["captcha_config"] = captcha_config
            if override_action is not None:
                self._values["override_action"] = override_action
            if rule_labels is not None:
                self._values["rule_labels"] = rule_labels

        @builtins.property
        def name(self) -> builtins.str:
            '''The descriptive name of the rule.

            You can't change the name of a ``Rule`` after you create it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html#cfn-wafv2-webacl-rule-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def priority(self) -> jsii.Number:
            '''If you define more than one ``Rule`` in a ``WebACL`` , AWS WAF evaluates each request against the ``Rules`` in order based on the value of ``Priority`` .

            AWS WAF processes rules with lower priority first. The priorities don't need to be consecutive, but they must all be different.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html#cfn-wafv2-webacl-rule-priority
            '''
            result = self._values.get("priority")
            assert result is not None, "Required property 'priority' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def statement(
            self,
        ) -> typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b]:
            '''The AWS WAF processing statement for the rule, for example ByteMatchStatement or SizeConstraintStatement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html#cfn-wafv2-webacl-rule-statement
            '''
            result = self._values.get("statement")
            assert result is not None, "Required property 'statement' is missing"
            return typing.cast(typing.Union["CfnWebACL.StatementProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def visibility_config(
            self,
        ) -> typing.Union["CfnWebACL.VisibilityConfigProperty", _IResolvable_da3f097b]:
            '''Defines and enables Amazon CloudWatch metrics and web request sample collection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html#cfn-wafv2-webacl-rule-visibilityconfig
            '''
            result = self._values.get("visibility_config")
            assert result is not None, "Required property 'visibility_config' is missing"
            return typing.cast(typing.Union["CfnWebACL.VisibilityConfigProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def action(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.RuleActionProperty", _IResolvable_da3f097b]]:
            '''The action that AWS WAF should take on a web request when it matches the rule's statement.

            Settings at the web ACL level can override the rule action setting.

            This is used only for rules whose statements don't reference a rule group. Rule statements that reference a rule group are ``RuleGroupReferenceStatement`` and ``ManagedRuleGroupStatement`` .

            You must set either this ``Action`` setting or the rule's ``OverrideAction`` , but not both:

            - If the rule statement doesn't reference a rule group, you must set this rule action setting and you must not set the rule's override action setting.
            - If the rule statement references a rule group, you must not set this action setting, because the actions are already set on the rules inside the rule group. You must set the rule's override action setting to indicate specifically whether to override the actions that are set on the rules in the rule group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html#cfn-wafv2-webacl-rule-action
            '''
            result = self._values.get("action")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.RuleActionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def captcha_config(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.CaptchaConfigProperty", _IResolvable_da3f097b]]:
            '''Specifies how AWS WAF should handle ``CAPTCHA`` evaluations.

            If you don't specify this, AWS WAF uses the ``CAPTCHA`` configuration that's defined for the web ACL.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html#cfn-wafv2-webacl-rule-captchaconfig
            '''
            result = self._values.get("captcha_config")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.CaptchaConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def override_action(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.OverrideActionProperty", _IResolvable_da3f097b]]:
            '''The override action to apply to the rules in a rule group, instead of the individual rule action settings.

            This is used only for rules whose statements reference a rule group. Rule statements that reference a rule group are ``RuleGroupReferenceStatement`` and ``ManagedRuleGroupStatement`` .

            Set the override action to none to leave the rule group rule actions in effect. Set it to count to only count matches, regardless of the rule action settings.

            You must set either this ``OverrideAction`` setting or the ``Action`` setting, but not both:

            - If the rule statement references a rule group, you must set this override action setting and you must not set the rule's action setting.
            - If the rule statement doesn't reference a rule group, you must set the rule action setting and you must not set the rule's override action setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html#cfn-wafv2-webacl-rule-overrideaction
            '''
            result = self._values.get("override_action")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.OverrideActionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def rule_labels(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.LabelProperty", _IResolvable_da3f097b]]]]:
            '''Labels to apply to web requests that match the rule match statement.

            AWS WAF applies fully qualified labels to matching web requests. A fully qualified label is the concatenation of a label namespace and a rule label. The rule's rule group or web ACL defines the label namespace.

            Rules that run after this rule in the web ACL can match against these labels using a ``LabelMatchStatement`` .

            For each label, provide a case-sensitive string containing optional namespaces and a label name, according to the following guidelines:

            - Separate each component of the label with a colon.
            - Each namespace or name can have up to 128 characters.
            - You can specify up to 5 namespaces in a label.
            - Don't use the following reserved words in your label specification: ``aws`` , ``waf`` , ``managed`` , ``rulegroup`` , ``webacl`` , ``regexpatternset`` , or ``ipset`` .

            For example, ``myLabelName`` or ``nameSpace1:nameSpace2:myLabelName`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-rule.html#cfn-wafv2-webacl-rule-rulelabels
            '''
            result = self._values.get("rule_labels")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.LabelProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.SizeConstraintStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "comparison_operator": "comparisonOperator",
            "field_to_match": "fieldToMatch",
            "size": "size",
            "text_transformations": "textTransformations",
        },
    )
    class SizeConstraintStatementProperty:
        def __init__(
            self,
            *,
            comparison_operator: builtins.str,
            field_to_match: typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b],
            size: jsii.Number,
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (>) or less than (<).

            For example, you can use a size constraint statement to look for query strings that are longer than 100 bytes.

            If you configure AWS WAF to inspect the request body, AWS WAF inspects only the first 8192 bytes (8 KB). If the request body for your web requests never exceeds 8192 bytes, you can create a size constraint condition and block requests that have a request body greater than 8192 bytes.

            If you choose URI for the value of Part of the request to filter on, the slash (/) in the URI counts as one character. For example, the URI ``/logo.jpg`` is nine characters long.

            :param comparison_operator: The operator to use to compare the request part to the size setting.
            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param size: The size, in byte, to compare to the request part, after any transformations.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-sizeconstraintstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                size_constraint_statement_property = wafv2.CfnWebACL.SizeConstraintStatementProperty(
                    comparison_operator="comparisonOperator",
                    field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnWebACL.JsonBodyProperty(
                            match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    size=123,
                    text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "comparison_operator": comparison_operator,
                "field_to_match": field_to_match,
                "size": size,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def comparison_operator(self) -> builtins.str:
            '''The operator to use to compare the request part to the size setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-sizeconstraintstatement.html#cfn-wafv2-webacl-sizeconstraintstatement-comparisonoperator
            '''
            result = self._values.get("comparison_operator")
            assert result is not None, "Required property 'comparison_operator' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-sizeconstraintstatement.html#cfn-wafv2-webacl-sizeconstraintstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def size(self) -> jsii.Number:
            '''The size, in byte, to compare to the request part, after any transformations.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-sizeconstraintstatement.html#cfn-wafv2-webacl-sizeconstraintstatement-size
            '''
            result = self._values.get("size")
            assert result is not None, "Required property 'size' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-sizeconstraintstatement.html#cfn-wafv2-webacl-sizeconstraintstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SizeConstraintStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.SqliMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_to_match": "fieldToMatch",
            "text_transformations": "textTransformations",
        },
    )
    class SqliMatchStatementProperty:
        def __init__(
            self,
            *,
            field_to_match: typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b],
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Attackers sometimes insert malicious SQL code into web requests in an effort to extract data from your database.

            To allow or block web requests that appear to contain malicious SQL code, create one or more SQL injection match conditions. An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. Later in the process, when you create a web ACL, you specify whether to allow or block requests that appear to contain malicious SQL code.

            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-sqlimatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                sqli_match_statement_property = wafv2.CfnWebACL.SqliMatchStatementProperty(
                    field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnWebACL.JsonBodyProperty(
                            match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "field_to_match": field_to_match,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-sqlimatchstatement.html#cfn-wafv2-webacl-sqlimatchstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-sqlimatchstatement.html#cfn-wafv2-webacl-sqlimatchstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SqliMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.StatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "and_statement": "andStatement",
            "byte_match_statement": "byteMatchStatement",
            "geo_match_statement": "geoMatchStatement",
            "ip_set_reference_statement": "ipSetReferenceStatement",
            "label_match_statement": "labelMatchStatement",
            "managed_rule_group_statement": "managedRuleGroupStatement",
            "not_statement": "notStatement",
            "or_statement": "orStatement",
            "rate_based_statement": "rateBasedStatement",
            "regex_match_statement": "regexMatchStatement",
            "regex_pattern_set_reference_statement": "regexPatternSetReferenceStatement",
            "rule_group_reference_statement": "ruleGroupReferenceStatement",
            "size_constraint_statement": "sizeConstraintStatement",
            "sqli_match_statement": "sqliMatchStatement",
            "xss_match_statement": "xssMatchStatement",
        },
    )
    class StatementProperty:
        def __init__(
            self,
            *,
            and_statement: typing.Optional[typing.Union["CfnWebACL.AndStatementProperty", _IResolvable_da3f097b]] = None,
            byte_match_statement: typing.Optional[typing.Union["CfnWebACL.ByteMatchStatementProperty", _IResolvable_da3f097b]] = None,
            geo_match_statement: typing.Optional[typing.Union["CfnWebACL.GeoMatchStatementProperty", _IResolvable_da3f097b]] = None,
            ip_set_reference_statement: typing.Optional[typing.Union["CfnWebACL.IPSetReferenceStatementProperty", _IResolvable_da3f097b]] = None,
            label_match_statement: typing.Optional[typing.Union["CfnWebACL.LabelMatchStatementProperty", _IResolvable_da3f097b]] = None,
            managed_rule_group_statement: typing.Optional[typing.Union["CfnWebACL.ManagedRuleGroupStatementProperty", _IResolvable_da3f097b]] = None,
            not_statement: typing.Optional[typing.Union["CfnWebACL.NotStatementProperty", _IResolvable_da3f097b]] = None,
            or_statement: typing.Optional[typing.Union["CfnWebACL.OrStatementProperty", _IResolvable_da3f097b]] = None,
            rate_based_statement: typing.Optional[typing.Union["CfnWebACL.RateBasedStatementProperty", _IResolvable_da3f097b]] = None,
            regex_match_statement: typing.Optional[typing.Union["CfnWebACL.RegexMatchStatementProperty", _IResolvable_da3f097b]] = None,
            regex_pattern_set_reference_statement: typing.Optional[typing.Union["CfnWebACL.RegexPatternSetReferenceStatementProperty", _IResolvable_da3f097b]] = None,
            rule_group_reference_statement: typing.Optional[typing.Union["CfnWebACL.RuleGroupReferenceStatementProperty", _IResolvable_da3f097b]] = None,
            size_constraint_statement: typing.Optional[typing.Union["CfnWebACL.SizeConstraintStatementProperty", _IResolvable_da3f097b]] = None,
            sqli_match_statement: typing.Optional[typing.Union["CfnWebACL.SqliMatchStatementProperty", _IResolvable_da3f097b]] = None,
            xss_match_statement: typing.Optional[typing.Union["CfnWebACL.XssMatchStatementProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The processing guidance for a ``Rule`` , used by AWS WAF to determine whether a web request matches the rule.

            :param and_statement: A logical rule statement used to combine other rule statements with AND logic. You provide more than one ``Statement`` within the ``AndStatement`` .
            :param byte_match_statement: A rule statement that defines a string match search for AWS WAF to apply to web requests. The byte match statement provides the bytes to search for, the location in requests that you want AWS WAF to search, and other settings. The bytes to search for are typically a string that corresponds with ASCII characters. In the AWS WAF console and the developer guide, this is refered to as a string match statement.
            :param geo_match_statement: A rule statement used to identify web requests based on country of origin.
            :param ip_set_reference_statement: A rule statement used to detect web requests coming from particular IP addresses or address ranges. To use this, create an ``IPSet`` that specifies the addresses you want to detect, then use the ARN of that set in this statement. Each IP set rule statement references an IP set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.
            :param label_match_statement: A rule statement that defines a string match search against labels that have been added to the web request by rules that have already run in the web ACL. The label match statement provides the label or namespace string to search for. The label string can represent a part or all of the fully qualified label name that had been added to the web request. Fully qualified labels have a prefix, optional namespaces, and label name. The prefix identifies the rule group or web ACL context of the rule that added the label. If you do not provide the fully qualified name in your label match string, AWS WAF performs the search for labels that were added in the same context as the label match statement.
            :param managed_rule_group_statement: A rule statement used to run the rules that are defined in a managed rule group. To use this, provide the vendor name and the name of the rule group in this statement. You can't nest a ``ManagedRuleGroupStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.
            :param not_statement: A logical rule statement used to negate the results of another rule statement. You provide one ``Statement`` within the ``NotStatement`` .
            :param or_statement: A logical rule statement used to combine other rule statements with OR logic. You provide more than one ``Statement`` within the ``OrStatement`` .
            :param rate_based_statement: A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span. You can use this to put a temporary block on requests from an IP address that is sending excessive requests. When the rule action triggers, AWS WAF blocks additional requests from the IP address until the request rate falls below the limit. You can optionally nest another statement inside the rate-based statement, to narrow the scope of the rule so that it only counts requests that match the nested statement. For example, based on recent requests that you have seen from an attacker, you might create a rate-based rule with a nested AND rule statement that contains the following nested statements: - An IP match statement with an IP set that specified the address 192.0.2.44. - A string match statement that searches in the User-Agent header for the string BadBot. In this rate-based rule, you also define a rate limit. For this example, the rate limit is 1,000. Requests that meet both of the conditions in the statements are counted. If the count exceeds 1,000 requests per five minutes, the rule action triggers. Requests that do not meet both conditions are not counted towards the rate limit and are not affected by this rule. You cannot nest a ``RateBasedStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.
            :param regex_match_statement: A rule statement used to search web request components for a match against a single regular expression.
            :param regex_pattern_set_reference_statement: A rule statement used to search web request components for matches with regular expressions. To use this, create a ``RegexPatternSet`` that specifies the expressions that you want to detect, then use the ARN of that set in this statement. A web request matches the pattern set rule statement if the request component matches any of the patterns in the set. Each regex pattern set rule statement references a regex pattern set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.
            :param rule_group_reference_statement: A rule statement used to run the rules that are defined in a ``RuleGroup`` . To use this, create a rule group with your rules, then provide the ARN of the rule group in this statement. You cannot nest a ``RuleGroupReferenceStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.
            :param size_constraint_statement: A rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (>) or less than (<). For example, you can use a size constraint statement to look for query strings that are longer than 100 bytes. If you configure AWS WAF to inspect the request body, AWS WAF inspects only the first 8192 bytes (8 KB). If the request body for your web requests never exceeds 8192 bytes, you can create a size constraint condition and block requests that have a request body greater than 8192 bytes. If you choose URI for the value of Part of the request to filter on, the slash (/) in the URI counts as one character. For example, the URI ``/logo.jpg`` is nine characters long.
            :param sqli_match_statement: Attackers sometimes insert malicious SQL code into web requests in an effort to extract data from your database. To allow or block web requests that appear to contain malicious SQL code, create one or more SQL injection match conditions. An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. Later in the process, when you create a web ACL, you specify whether to allow or block requests that appear to contain malicious SQL code.
            :param xss_match_statement: A rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests. XSS attacks are those where the attacker uses vulnerabilities in a benign website as a vehicle to inject malicious client-site scripts into other legitimate web browsers. The XSS match statement provides the location in requests that you want AWS WAF to search and text transformations to use on the search area before AWS WAF searches for character sequences that are likely to be malicious strings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # and_statement_property_: wafv2.CfnWebACL.AndStatementProperty
                # body: Any
                # managed_rule_group_statement_property_: wafv2.CfnWebACL.ManagedRuleGroupStatementProperty
                # method: Any
                # not_statement_property_: wafv2.CfnWebACL.NotStatementProperty
                # or_statement_property_: wafv2.CfnWebACL.OrStatementProperty
                # query_string: Any
                # rate_based_statement_property_: wafv2.CfnWebACL.RateBasedStatementProperty
                # single_header: Any
                # single_query_argument: Any
                # statement_property_: wafv2.CfnWebACL.StatementProperty
                # uri_path: Any
                
                statement_property = wafv2.CfnWebACL.StatementProperty(
                    and_statement=wafv2.CfnWebACL.AndStatementProperty(
                        statements=[wafv2.CfnWebACL.StatementProperty(
                            and_statement=and_statement_property_,
                            byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                                name="name",
                                vendor_name="vendorName",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )],
                                managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                    login_path="loginPath",
                                    password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                        identifier="identifier"
                                    ),
                                    payload_type="payloadType",
                                    username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                        identifier="identifier"
                                    )
                                )],
                                scope_down_statement=statement_property_,
                                version="version"
                            ),
                            not_statement=wafv2.CfnWebACL.NotStatementProperty(
                                statement=statement_property_
                            ),
                            or_statement=wafv2.CfnWebACL.OrStatementProperty(
                                statements=[statement_property_]
                            ),
                            rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                                aggregate_key_type="aggregateKeyType",
                                limit=123,
                
                                # the properties below are optional
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                ),
                                scope_down_statement=statement_property_
                            ),
                            regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                                arn="arn",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        )]
                    ),
                    byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        positional_constraint="positionalConstraint",
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )],
                
                        # the properties below are optional
                        search_string="searchString",
                        search_string_base64="searchStringBase64"
                    ),
                    geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                        country_codes=["countryCodes"],
                        forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                            fallback_behavior="fallbackBehavior",
                            header_name="headerName"
                        )
                    ),
                    ip_set_reference_statement={
                        "arn": "arn",
                
                        # the properties below are optional
                        "ip_set_forwarded_ip_config": {
                            "fallback_behavior": "fallbackBehavior",
                            "header_name": "headerName",
                            "position": "position"
                        }
                    },
                    label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                        key="key",
                        scope="scope"
                    ),
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        name="name",
                        vendor_name="vendorName",
                
                        # the properties below are optional
                        excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                            name="name"
                        )],
                        managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                            login_path="loginPath",
                            password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                identifier="identifier"
                            ),
                            payload_type="payloadType",
                            username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                identifier="identifier"
                            )
                        )],
                        scope_down_statement=wafv2.CfnWebACL.StatementProperty(
                            and_statement=wafv2.CfnWebACL.AndStatementProperty(
                                statements=[statement_property_]
                            ),
                            byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            managed_rule_group_statement=managed_rule_group_statement_property_,
                            not_statement=wafv2.CfnWebACL.NotStatementProperty(
                                statement=statement_property_
                            ),
                            or_statement=wafv2.CfnWebACL.OrStatementProperty(
                                statements=[statement_property_]
                            ),
                            rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                                aggregate_key_type="aggregateKeyType",
                                limit=123,
                
                                # the properties below are optional
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                ),
                                scope_down_statement=statement_property_
                            ),
                            regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                                arn="arn",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        ),
                        version="version"
                    ),
                    not_statement=wafv2.CfnWebACL.NotStatementProperty(
                        statement=wafv2.CfnWebACL.StatementProperty(
                            and_statement=wafv2.CfnWebACL.AndStatementProperty(
                                statements=[statement_property_]
                            ),
                            byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                                name="name",
                                vendor_name="vendorName",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )],
                                managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                    login_path="loginPath",
                                    password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                        identifier="identifier"
                                    ),
                                    payload_type="payloadType",
                                    username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                        identifier="identifier"
                                    )
                                )],
                                scope_down_statement=statement_property_,
                                version="version"
                            ),
                            not_statement=not_statement_property_,
                            or_statement=wafv2.CfnWebACL.OrStatementProperty(
                                statements=[statement_property_]
                            ),
                            rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                                aggregate_key_type="aggregateKeyType",
                                limit=123,
                
                                # the properties below are optional
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                ),
                                scope_down_statement=statement_property_
                            ),
                            regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                                arn="arn",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        )
                    ),
                    or_statement=wafv2.CfnWebACL.OrStatementProperty(
                        statements=[wafv2.CfnWebACL.StatementProperty(
                            and_statement=wafv2.CfnWebACL.AndStatementProperty(
                                statements=[statement_property_]
                            ),
                            byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                                name="name",
                                vendor_name="vendorName",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )],
                                managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                    login_path="loginPath",
                                    password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                        identifier="identifier"
                                    ),
                                    payload_type="payloadType",
                                    username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                        identifier="identifier"
                                    )
                                )],
                                scope_down_statement=statement_property_,
                                version="version"
                            ),
                            not_statement=wafv2.CfnWebACL.NotStatementProperty(
                                statement=statement_property_
                            ),
                            or_statement=or_statement_property_,
                            rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                                aggregate_key_type="aggregateKeyType",
                                limit=123,
                
                                # the properties below are optional
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                ),
                                scope_down_statement=statement_property_
                            ),
                            regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                                arn="arn",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        )]
                    ),
                    rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                        aggregate_key_type="aggregateKeyType",
                        limit=123,
                
                        # the properties below are optional
                        forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                            fallback_behavior="fallbackBehavior",
                            header_name="headerName"
                        ),
                        scope_down_statement=wafv2.CfnWebACL.StatementProperty(
                            and_statement=wafv2.CfnWebACL.AndStatementProperty(
                                statements=[statement_property_]
                            ),
                            byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                positional_constraint="positionalConstraint",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )],
                
                                # the properties below are optional
                                search_string="searchString",
                                search_string_base64="searchStringBase64"
                            ),
                            geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                                country_codes=["countryCodes"],
                                forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                    fallback_behavior="fallbackBehavior",
                                    header_name="headerName"
                                )
                            ),
                            ip_set_reference_statement={
                                "arn": "arn",
                
                                # the properties below are optional
                                "ip_set_forwarded_ip_config": {
                                    "fallback_behavior": "fallbackBehavior",
                                    "header_name": "headerName",
                                    "position": "position"
                                }
                            },
                            label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                                key="key",
                                scope="scope"
                            ),
                            managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                                name="name",
                                vendor_name="vendorName",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )],
                                managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                    login_path="loginPath",
                                    password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                        identifier="identifier"
                                    ),
                                    payload_type="payloadType",
                                    username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                        identifier="identifier"
                                    )
                                )],
                                scope_down_statement=statement_property_,
                                version="version"
                            ),
                            not_statement=wafv2.CfnWebACL.NotStatementProperty(
                                statement=statement_property_
                            ),
                            or_statement=wafv2.CfnWebACL.OrStatementProperty(
                                statements=[statement_property_]
                            ),
                            rate_based_statement=rate_based_statement_property_,
                            regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                regex_string="regexString",
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                                arn="arn",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                                arn="arn",
                
                                # the properties below are optional
                                excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                    name="name"
                                )]
                            ),
                            size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                                comparison_operator="comparisonOperator",
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                size=123,
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            ),
                            xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                                field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                    all_query_arguments=all_query_arguments,
                                    body=body,
                                    json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                        match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                            all=all,
                                            included_paths=["includedPaths"]
                                        ),
                                        match_scope="matchScope",
                
                                        # the properties below are optional
                                        invalid_fallback_behavior="invalidFallbackBehavior"
                                    ),
                                    method=method,
                                    query_string=query_string,
                                    single_header=single_header,
                                    single_query_argument=single_query_argument,
                                    uri_path=uri_path
                                ),
                                text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=123,
                                    type="type"
                                )]
                            )
                        )
                    ),
                    regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        regex_string="regexString",
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                        arn="arn",
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                        arn="arn",
                
                        # the properties below are optional
                        excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                            name="name"
                        )]
                    ),
                    size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                        comparison_operator="comparisonOperator",
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        size=123,
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    ),
                    xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                        field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                            all_query_arguments=all_query_arguments,
                            body=body,
                            json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                    all=all,
                                    included_paths=["includedPaths"]
                                ),
                                match_scope="matchScope",
                
                                # the properties below are optional
                                invalid_fallback_behavior="invalidFallbackBehavior"
                            ),
                            method=method,
                            query_string=query_string,
                            single_header=single_header,
                            single_query_argument=single_query_argument,
                            uri_path=uri_path
                        ),
                        text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                            priority=123,
                            type="type"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if and_statement is not None:
                self._values["and_statement"] = and_statement
            if byte_match_statement is not None:
                self._values["byte_match_statement"] = byte_match_statement
            if geo_match_statement is not None:
                self._values["geo_match_statement"] = geo_match_statement
            if ip_set_reference_statement is not None:
                self._values["ip_set_reference_statement"] = ip_set_reference_statement
            if label_match_statement is not None:
                self._values["label_match_statement"] = label_match_statement
            if managed_rule_group_statement is not None:
                self._values["managed_rule_group_statement"] = managed_rule_group_statement
            if not_statement is not None:
                self._values["not_statement"] = not_statement
            if or_statement is not None:
                self._values["or_statement"] = or_statement
            if rate_based_statement is not None:
                self._values["rate_based_statement"] = rate_based_statement
            if regex_match_statement is not None:
                self._values["regex_match_statement"] = regex_match_statement
            if regex_pattern_set_reference_statement is not None:
                self._values["regex_pattern_set_reference_statement"] = regex_pattern_set_reference_statement
            if rule_group_reference_statement is not None:
                self._values["rule_group_reference_statement"] = rule_group_reference_statement
            if size_constraint_statement is not None:
                self._values["size_constraint_statement"] = size_constraint_statement
            if sqli_match_statement is not None:
                self._values["sqli_match_statement"] = sqli_match_statement
            if xss_match_statement is not None:
                self._values["xss_match_statement"] = xss_match_statement

        @builtins.property
        def and_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.AndStatementProperty", _IResolvable_da3f097b]]:
            '''A logical rule statement used to combine other rule statements with AND logic.

            You provide more than one ``Statement`` within the ``AndStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-andstatement
            '''
            result = self._values.get("and_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.AndStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def byte_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.ByteMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement that defines a string match search for AWS WAF to apply to web requests.

            The byte match statement provides the bytes to search for, the location in requests that you want AWS WAF to search, and other settings. The bytes to search for are typically a string that corresponds with ASCII characters. In the AWS WAF console and the developer guide, this is refered to as a string match statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-bytematchstatement
            '''
            result = self._values.get("byte_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.ByteMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def geo_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.GeoMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to identify web requests based on country of origin.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-geomatchstatement
            '''
            result = self._values.get("geo_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.GeoMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def ip_set_reference_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.IPSetReferenceStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to detect web requests coming from particular IP addresses or address ranges.

            To use this, create an ``IPSet`` that specifies the addresses you want to detect, then use the ARN of that set in this statement.

            Each IP set rule statement references an IP set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-ipsetreferencestatement
            '''
            result = self._values.get("ip_set_reference_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.IPSetReferenceStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def label_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.LabelMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement that defines a string match search against labels that have been added to the web request by rules that have already run in the web ACL.

            The label match statement provides the label or namespace string to search for. The label string can represent a part or all of the fully qualified label name that had been added to the web request. Fully qualified labels have a prefix, optional namespaces, and label name. The prefix identifies the rule group or web ACL context of the rule that added the label. If you do not provide the fully qualified name in your label match string, AWS WAF performs the search for labels that were added in the same context as the label match statement.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-labelmatchstatement
            '''
            result = self._values.get("label_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.LabelMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def managed_rule_group_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.ManagedRuleGroupStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to run the rules that are defined in a managed rule group.

            To use this, provide the vendor name and the name of the rule group in this statement.

            You can't nest a ``ManagedRuleGroupStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-managedrulegroupstatement
            '''
            result = self._values.get("managed_rule_group_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.ManagedRuleGroupStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def not_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.NotStatementProperty", _IResolvable_da3f097b]]:
            '''A logical rule statement used to negate the results of another rule statement.

            You provide one ``Statement`` within the ``NotStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-notstatement
            '''
            result = self._values.get("not_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.NotStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def or_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.OrStatementProperty", _IResolvable_da3f097b]]:
            '''A logical rule statement used to combine other rule statements with OR logic.

            You provide more than one ``Statement`` within the ``OrStatement`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-orstatement
            '''
            result = self._values.get("or_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.OrStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def rate_based_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.RateBasedStatementProperty", _IResolvable_da3f097b]]:
            '''A rate-based rule tracks the rate of requests for each originating IP address, and triggers the rule action when the rate exceeds a limit that you specify on the number of requests in any 5-minute time span.

            You can use this to put a temporary block on requests from an IP address that is sending excessive requests.

            When the rule action triggers, AWS WAF blocks additional requests from the IP address until the request rate falls below the limit.

            You can optionally nest another statement inside the rate-based statement, to narrow the scope of the rule so that it only counts requests that match the nested statement. For example, based on recent requests that you have seen from an attacker, you might create a rate-based rule with a nested AND rule statement that contains the following nested statements:

            - An IP match statement with an IP set that specified the address 192.0.2.44.
            - A string match statement that searches in the User-Agent header for the string BadBot.

            In this rate-based rule, you also define a rate limit. For this example, the rate limit is 1,000. Requests that meet both of the conditions in the statements are counted. If the count exceeds 1,000 requests per five minutes, the rule action triggers. Requests that do not meet both conditions are not counted towards the rate limit and are not affected by this rule.

            You cannot nest a ``RateBasedStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-ratebasedstatement
            '''
            result = self._values.get("rate_based_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.RateBasedStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def regex_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.RegexMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to search web request components for a match against a single regular expression.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-regexmatchstatement
            '''
            result = self._values.get("regex_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.RegexMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def regex_pattern_set_reference_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.RegexPatternSetReferenceStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to search web request components for matches with regular expressions.

            To use this, create a ``RegexPatternSet`` that specifies the expressions that you want to detect, then use the ARN of that set in this statement. A web request matches the pattern set rule statement if the request component matches any of the patterns in the set.

            Each regex pattern set rule statement references a regex pattern set. You create and maintain the set independent of your rules. This allows you to use the single set in multiple rules. When you update the referenced set, AWS WAF automatically updates all rules that reference it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-regexpatternsetreferencestatement
            '''
            result = self._values.get("regex_pattern_set_reference_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.RegexPatternSetReferenceStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def rule_group_reference_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.RuleGroupReferenceStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement used to run the rules that are defined in a ``RuleGroup`` .

            To use this, create a rule group with your rules, then provide the ARN of the rule group in this statement.

            You cannot nest a ``RuleGroupReferenceStatement`` , for example for use inside a ``NotStatement`` or ``OrStatement`` . It can only be referenced as a top-level statement within a rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-rulegroupreferencestatement
            '''
            result = self._values.get("rule_group_reference_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.RuleGroupReferenceStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def size_constraint_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.SizeConstraintStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement that compares a number of bytes against the size of a request component, using a comparison operator, such as greater than (>) or less than (<).

            For example, you can use a size constraint statement to look for query strings that are longer than 100 bytes.

            If you configure AWS WAF to inspect the request body, AWS WAF inspects only the first 8192 bytes (8 KB). If the request body for your web requests never exceeds 8192 bytes, you can create a size constraint condition and block requests that have a request body greater than 8192 bytes.

            If you choose URI for the value of Part of the request to filter on, the slash (/) in the URI counts as one character. For example, the URI ``/logo.jpg`` is nine characters long.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-sizeconstraintstatement
            '''
            result = self._values.get("size_constraint_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.SizeConstraintStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sqli_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.SqliMatchStatementProperty", _IResolvable_da3f097b]]:
            '''Attackers sometimes insert malicious SQL code into web requests in an effort to extract data from your database.

            To allow or block web requests that appear to contain malicious SQL code, create one or more SQL injection match conditions. An SQL injection match condition identifies the part of web requests, such as the URI or the query string, that you want AWS WAF to inspect. Later in the process, when you create a web ACL, you specify whether to allow or block requests that appear to contain malicious SQL code.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-sqlimatchstatement
            '''
            result = self._values.get("sqli_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.SqliMatchStatementProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def xss_match_statement(
            self,
        ) -> typing.Optional[typing.Union["CfnWebACL.XssMatchStatementProperty", _IResolvable_da3f097b]]:
            '''A rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests.

            XSS attacks are those where the attacker uses vulnerabilities in a benign website as a vehicle to inject malicious client-site scripts into other legitimate web browsers. The XSS match statement provides the location in requests that you want AWS WAF to search and text transformations to use on the search area before AWS WAF searches for character sequences that are likely to be malicious strings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-statement.html#cfn-wafv2-webacl-statement-xssmatchstatement
            '''
            result = self._values.get("xss_match_statement")
            return typing.cast(typing.Optional[typing.Union["CfnWebACL.XssMatchStatementProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.TextTransformationProperty",
        jsii_struct_bases=[],
        name_mapping={"priority": "priority", "type": "type"},
    )
    class TextTransformationProperty:
        def __init__(self, *, priority: jsii.Number, type: builtins.str) -> None:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            :param priority: Sets the relative processing order for multiple transformations that are defined for a rule statement. AWS WAF processes all transformations, from lowest priority to highest, before inspecting the transformed content. The priorities don't need to be consecutive, but they must all be different.
            :param type: You can specify the following transformation types:. *BASE64_DECODE* - Decode a ``Base64`` -encoded string. *BASE64_DECODE_EXT* - Decode a ``Base64`` -encoded string, but use a forgiving implementation that ignores characters that aren't valid. *CMD_LINE* - Command-line transformations. These are helpful in reducing effectiveness of attackers who inject an operating system command-line command and use unusual formatting to disguise some or all of the command. - Delete the following characters: ``\\ " ' ^`` - Delete spaces before the following characters: ``/ (`` - Replace the following characters with a space: ``, ;`` - Replace multiple spaces with one space - Convert uppercase letters (A-Z) to lowercase (a-z) *COMPRESS_WHITE_SPACE* - Replace these characters with a space character (decimal 32): - ``\\f`` , formfeed, decimal 12 - ``\\t`` , tab, decimal 9 - ``\\n`` , newline, decimal 10 - ``\\r`` , carriage return, decimal 13 - ``\\v`` , vertical tab, decimal 11 - Non-breaking space, decimal 160 ``COMPRESS_WHITE_SPACE`` also replaces multiple spaces with one space. *CSS_DECODE* - Decode characters that were encoded using CSS 2.x escape rules ``syndata.html#characters`` . This function uses up to two bytes in the decoding process, so it can help to uncover ASCII characters that were encoded using CSS encoding that wouldn’t typically be encoded. It's also useful in countering evasion, which is a combination of a backslash and non-hexadecimal characters. For example, ``ja\\vascript`` for javascript. *ESCAPE_SEQ_DECODE* - Decode the following ANSI C escape sequences: ``\\a`` , ``\\b`` , ``\\f`` , ``\\n`` , ``\\r`` , ``\\t`` , ``\\v`` , ``\\\\`` , ``\\?`` , ``\\'`` , ``\\"`` , ``\\xHH`` (hexadecimal), ``\\0OOO`` (octal). Encodings that aren't valid remain in the output. *HEX_DECODE* - Decode a string of hexadecimal characters into a binary. *HTML_ENTITY_DECODE* - Replace HTML-encoded characters with unencoded characters. ``HTML_ENTITY_DECODE`` performs these operations: - Replaces ``(ampersand)quot;`` with ``"`` - Replaces ``(ampersand)nbsp;`` with a non-breaking space, decimal 160 - Replaces ``(ampersand)lt;`` with a "less than" symbol - Replaces ``(ampersand)gt;`` with ``>`` - Replaces characters that are represented in hexadecimal format, ``(ampersand)#xhhhh;`` , with the corresponding characters - Replaces characters that are represented in decimal format, ``(ampersand)#nnnn;`` , with the corresponding characters *JS_DECODE* - Decode JavaScript escape sequences. If a ``\\`` ``u`` ``HHHH`` code is in the full-width ASCII code range of ``FF01-FF5E`` , then the higher byte is used to detect and adjust the lower byte. If not, only the lower byte is used and the higher byte is zeroed, causing a possible loss of information. *LOWERCASE* - Convert uppercase letters (A-Z) to lowercase (a-z). *MD5* - Calculate an MD5 hash from the data in the input. The computed hash is in a raw binary form. *NONE* - Specify ``NONE`` if you don't want any text transformations. *NORMALIZE_PATH* - Remove multiple slashes, directory self-references, and directory back-references that are not at the beginning of the input from an input string. *NORMALIZE_PATH_WIN* - This is the same as ``NORMALIZE_PATH`` , but first converts backslash characters to forward slashes. *REMOVE_NULLS* - Remove all ``NULL`` bytes from the input. *REPLACE_COMMENTS* - Replace each occurrence of a C-style comment ( ``/* ... * /`` ) with a single space. Multiple consecutive occurrences are not compressed. Unterminated comments are also replaced with a space (ASCII 0x20). However, a standalone termination of a comment ( ``* /`` ) is not acted upon. *REPLACE_NULLS* - Replace NULL bytes in the input with space characters (ASCII ``0x20`` ). *SQL_HEX_DECODE* - Decode SQL hex data. Example ( ``0x414243`` ) will be decoded to ( ``ABC`` ). *URL_DECODE* - Decode a URL-encoded value. *URL_DECODE_UNI* - Like ``URL_DECODE`` , but with support for Microsoft-specific ``%u`` encoding. If the code is in the full-width ASCII code range of ``FF01-FF5E`` , the higher byte is used to detect and adjust the lower byte. Otherwise, only the lower byte is used and the higher byte is zeroed. *UTF8_TO_UNICODE* - Convert all UTF-8 character sequences to Unicode. This helps input normalization, and minimizing false-positives and false-negatives for non-English languages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-texttransformation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                text_transformation_property = wafv2.CfnWebACL.TextTransformationProperty(
                    priority=123,
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "priority": priority,
                "type": type,
            }

        @builtins.property
        def priority(self) -> jsii.Number:
            '''Sets the relative processing order for multiple transformations that are defined for a rule statement.

            AWS WAF processes all transformations, from lowest priority to highest, before inspecting the transformed content. The priorities don't need to be consecutive, but they must all be different.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-texttransformation.html#cfn-wafv2-webacl-texttransformation-priority
            '''
            result = self._values.get("priority")
            assert result is not None, "Required property 'priority' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def type(self) -> builtins.str:
            '''You can specify the following transformation types:.

            *BASE64_DECODE* - Decode a ``Base64`` -encoded string.

            *BASE64_DECODE_EXT* - Decode a ``Base64`` -encoded string, but use a forgiving implementation that ignores characters that aren't valid.

            *CMD_LINE* - Command-line transformations. These are helpful in reducing effectiveness of attackers who inject an operating system command-line command and use unusual formatting to disguise some or all of the command.

            - Delete the following characters: ``\\ " ' ^``
            - Delete spaces before the following characters: ``/ (``
            - Replace the following characters with a space: ``, ;``
            - Replace multiple spaces with one space
            - Convert uppercase letters (A-Z) to lowercase (a-z)

            *COMPRESS_WHITE_SPACE* - Replace these characters with a space character (decimal 32):

            - ``\\f`` , formfeed, decimal 12
            - ``\\t`` , tab, decimal 9
            - ``\\n`` , newline, decimal 10
            - ``\\r`` , carriage return, decimal 13
            - ``\\v`` , vertical tab, decimal 11
            - Non-breaking space, decimal 160

            ``COMPRESS_WHITE_SPACE`` also replaces multiple spaces with one space.

            *CSS_DECODE* - Decode characters that were encoded using CSS 2.x escape rules ``syndata.html#characters`` . This function uses up to two bytes in the decoding process, so it can help to uncover ASCII characters that were encoded using CSS encoding that wouldn’t typically be encoded. It's also useful in countering evasion, which is a combination of a backslash and non-hexadecimal characters. For example, ``ja\\vascript`` for javascript.

            *ESCAPE_SEQ_DECODE* - Decode the following ANSI C escape sequences: ``\\a`` , ``\\b`` , ``\\f`` , ``\\n`` , ``\\r`` , ``\\t`` , ``\\v`` , ``\\\\`` , ``\\?`` , ``\\'`` , ``\\"`` , ``\\xHH`` (hexadecimal), ``\\0OOO`` (octal). Encodings that aren't valid remain in the output.

            *HEX_DECODE* - Decode a string of hexadecimal characters into a binary.

            *HTML_ENTITY_DECODE* - Replace HTML-encoded characters with unencoded characters. ``HTML_ENTITY_DECODE`` performs these operations:

            - Replaces ``(ampersand)quot;`` with ``"``
            - Replaces ``(ampersand)nbsp;`` with a non-breaking space, decimal 160
            - Replaces ``(ampersand)lt;`` with a "less than" symbol
            - Replaces ``(ampersand)gt;`` with ``>``
            - Replaces characters that are represented in hexadecimal format, ``(ampersand)#xhhhh;`` , with the corresponding characters
            - Replaces characters that are represented in decimal format, ``(ampersand)#nnnn;`` , with the corresponding characters

            *JS_DECODE* - Decode JavaScript escape sequences. If a ``\\`` ``u`` ``HHHH`` code is in the full-width ASCII code range of ``FF01-FF5E`` , then the higher byte is used to detect and adjust the lower byte. If not, only the lower byte is used and the higher byte is zeroed, causing a possible loss of information.

            *LOWERCASE* - Convert uppercase letters (A-Z) to lowercase (a-z).

            *MD5* - Calculate an MD5 hash from the data in the input. The computed hash is in a raw binary form.

            *NONE* - Specify ``NONE`` if you don't want any text transformations.

            *NORMALIZE_PATH* - Remove multiple slashes, directory self-references, and directory back-references that are not at the beginning of the input from an input string.

            *NORMALIZE_PATH_WIN* - This is the same as ``NORMALIZE_PATH`` , but first converts backslash characters to forward slashes.

            *REMOVE_NULLS* - Remove all ``NULL`` bytes from the input.

            *REPLACE_COMMENTS* - Replace each occurrence of a C-style comment ( ``/* ... * /`` ) with a single space. Multiple consecutive occurrences are not compressed. Unterminated comments are also replaced with a space (ASCII 0x20). However, a standalone termination of a comment ( ``* /`` ) is not acted upon.

            *REPLACE_NULLS* - Replace NULL bytes in the input with space characters (ASCII ``0x20`` ).

            *SQL_HEX_DECODE* - Decode SQL hex data. Example ( ``0x414243`` ) will be decoded to ( ``ABC`` ).

            *URL_DECODE* - Decode a URL-encoded value.

            *URL_DECODE_UNI* - Like ``URL_DECODE`` , but with support for Microsoft-specific ``%u`` encoding. If the code is in the full-width ASCII code range of ``FF01-FF5E`` , the higher byte is used to detect and adjust the lower byte. Otherwise, only the lower byte is used and the higher byte is zeroed.

            *UTF8_TO_UNICODE* - Convert all UTF-8 character sequences to Unicode. This helps input normalization, and minimizing false-positives and false-negatives for non-English languages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-texttransformation.html#cfn-wafv2-webacl-texttransformation-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TextTransformationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.VisibilityConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_metrics_enabled": "cloudWatchMetricsEnabled",
            "metric_name": "metricName",
            "sampled_requests_enabled": "sampledRequestsEnabled",
        },
    )
    class VisibilityConfigProperty:
        def __init__(
            self,
            *,
            cloud_watch_metrics_enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            metric_name: builtins.str,
            sampled_requests_enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Defines and enables Amazon CloudWatch metrics and web request sample collection.

            :param cloud_watch_metrics_enabled: A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch . For the list of available metrics, see `AWS WAF Metrics <https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics>`_ .
            :param metric_name: The descriptive name of the Amazon CloudWatch metric. The name can contain only alphanumeric characters (A-Z, a-z, 0-9), with length from one to 128 characters. It can't contain whitespace or metric names reserved for AWS WAF , for example "All" and "Default_Action." You can't change a ``MetricName`` after you create a ``VisibilityConfig`` .
            :param sampled_requests_enabled: A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules. You can view the sampled requests through the AWS WAF console.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-visibilityconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                visibility_config_property = wafv2.CfnWebACL.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=False,
                    metric_name="metricName",
                    sampled_requests_enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cloud_watch_metrics_enabled": cloud_watch_metrics_enabled,
                "metric_name": metric_name,
                "sampled_requests_enabled": sampled_requests_enabled,
            }

        @builtins.property
        def cloud_watch_metrics_enabled(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''A boolean indicating whether the associated resource sends metrics to Amazon CloudWatch .

            For the list of available metrics, see `AWS WAF Metrics <https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-visibilityconfig.html#cfn-wafv2-webacl-visibilityconfig-cloudwatchmetricsenabled
            '''
            result = self._values.get("cloud_watch_metrics_enabled")
            assert result is not None, "Required property 'cloud_watch_metrics_enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def metric_name(self) -> builtins.str:
            '''The descriptive name of the Amazon CloudWatch metric.

            The name can contain only alphanumeric characters (A-Z, a-z, 0-9), with length from one to 128 characters. It can't contain whitespace or metric names reserved for AWS WAF , for example "All" and "Default_Action." You can't change a ``MetricName`` after you create a ``VisibilityConfig`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-visibilityconfig.html#cfn-wafv2-webacl-visibilityconfig-metricname
            '''
            result = self._values.get("metric_name")
            assert result is not None, "Required property 'metric_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sampled_requests_enabled(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules.

            You can view the sampled requests through the AWS WAF console.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-visibilityconfig.html#cfn-wafv2-webacl-visibilityconfig-sampledrequestsenabled
            '''
            result = self._values.get("sampled_requests_enabled")
            assert result is not None, "Required property 'sampled_requests_enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VisibilityConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACL.XssMatchStatementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_to_match": "fieldToMatch",
            "text_transformations": "textTransformations",
        },
    )
    class XssMatchStatementProperty:
        def __init__(
            self,
            *,
            field_to_match: typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b],
            text_transformations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A rule statement that defines a cross-site scripting (XSS) match search for AWS WAF to apply to web requests.

            XSS attacks are those where the attacker uses vulnerabilities in a benign website as a vehicle to inject malicious client-site scripts into other legitimate web browsers. The XSS match statement provides the location in requests that you want AWS WAF to search and text transformations to use on the search area before AWS WAF searches for character sequences that are likely to be malicious strings.

            :param field_to_match: The part of a web request that you want AWS WAF to inspect.
            :param text_transformations: Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection. If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-xssmatchstatement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_wafv2 as wafv2
                
                # all: Any
                # all_query_arguments: Any
                # body: Any
                # method: Any
                # query_string: Any
                # single_header: Any
                # single_query_argument: Any
                # uri_path: Any
                
                xss_match_statement_property = wafv2.CfnWebACL.XssMatchStatementProperty(
                    field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                        all_query_arguments=all_query_arguments,
                        body=body,
                        json_body=wafv2.CfnWebACL.JsonBodyProperty(
                            match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                all=all,
                                included_paths=["includedPaths"]
                            ),
                            match_scope="matchScope",
                
                            # the properties below are optional
                            invalid_fallback_behavior="invalidFallbackBehavior"
                        ),
                        method=method,
                        query_string=query_string,
                        single_header=single_header,
                        single_query_argument=single_query_argument,
                        uri_path=uri_path
                    ),
                    text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                        priority=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "field_to_match": field_to_match,
                "text_transformations": text_transformations,
            }

        @builtins.property
        def field_to_match(
            self,
        ) -> typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b]:
            '''The part of a web request that you want AWS WAF to inspect.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-xssmatchstatement.html#cfn-wafv2-webacl-xssmatchstatement-fieldtomatch
            '''
            result = self._values.get("field_to_match")
            assert result is not None, "Required property 'field_to_match' is missing"
            return typing.cast(typing.Union["CfnWebACL.FieldToMatchProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def text_transformations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]]:
            '''Text transformations eliminate some of the unusual formatting that attackers use in web requests in an effort to bypass detection.

            If you specify one or more transformations in a rule statement, AWS WAF performs all transformations on the content identified by ``FieldToMatch`` , starting from the lowest priority setting, before inspecting the content for a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-xssmatchstatement.html#cfn-wafv2-webacl-xssmatchstatement-texttransformations
            '''
            result = self._values.get("text_transformations")
            assert result is not None, "Required property 'text_transformations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWebACL.TextTransformationProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "XssMatchStatementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnWebACLAssociation(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACLAssociation",
):
    '''A CloudFormation ``AWS::WAFv2::WebACLAssociation``.

    .. epigraph::

       This is the latest version of *AWS WAF* , named AWS WAF V2, released in November, 2019. For information, including how to migrate your AWS WAF resources from the prior release, see the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

    Use a web ACL association to define an association between a web ACL and a regional application resource, to protect the resource. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API.

    For Amazon CloudFront , don't use this resource. Instead, use your CloudFront distribution configuration. To associate a web ACL with a distribution, provide the Amazon Resource Name (ARN) of the ``WebACL`` to your CloudFront distribution configuration. To disassociate a web ACL, provide an empty ARN. For information, see `AWS::CloudFront::Distribution <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html>`_ .

    :cloudformationResource: AWS::WAFv2::WebACLAssociation
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webaclassociation.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_wafv2 as wafv2
        
        cfn_web_aCLAssociation = wafv2.CfnWebACLAssociation(self, "MyCfnWebACLAssociation",
            resource_arn="resourceArn",
            web_acl_arn="webAclArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        resource_arn: builtins.str,
        web_acl_arn: builtins.str,
    ) -> None:
        '''Create a new ``AWS::WAFv2::WebACLAssociation``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param resource_arn: The Amazon Resource Name (ARN) of the resource to associate with the web ACL. The ARN must be in one of the following formats: - For an Application Load Balancer : ``arn:aws:elasticloadbalancing: *region* : *account-id* :loadbalancer/app/ *load-balancer-name* / *load-balancer-id*`` - For an Amazon API Gateway REST API: ``arn:aws:apigateway: *region* ::/restapis/ *api-id* /stages/ *stage-name*`` - For an AWS AppSync GraphQL API: ``arn:aws:appsync: *region* : *account-id* :apis/ *GraphQLApiId*`` For Amazon CloudFront , define the association in your CloudFront distribution configuration. To associate a web ACL, provide the Amazon Resource Name (ARN) of the ``WebACL`` to your CloudFront distribution configuration. To disassociate a web ACL, provide an empty ARN. For information, see `AWS::CloudFront::Distribution <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html>`_ .
        :param web_acl_arn: The Amazon Resource Name (ARN) of the web ACL that you want to associate with the resource.
        '''
        props = CfnWebACLAssociationProps(
            resource_arn=resource_arn, web_acl_arn=web_acl_arn
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
    @jsii.member(jsii_name="resourceArn")
    def resource_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the resource to associate with the web ACL.

        The ARN must be in one of the following formats:

        - For an Application Load Balancer : ``arn:aws:elasticloadbalancing: *region* : *account-id* :loadbalancer/app/ *load-balancer-name* / *load-balancer-id*``
        - For an Amazon API Gateway REST API: ``arn:aws:apigateway: *region* ::/restapis/ *api-id* /stages/ *stage-name*``
        - For an AWS AppSync GraphQL API: ``arn:aws:appsync: *region* : *account-id* :apis/ *GraphQLApiId*``

        For Amazon CloudFront , define the association in your CloudFront distribution configuration. To associate a web ACL, provide the Amazon Resource Name (ARN) of the ``WebACL`` to your CloudFront distribution configuration. To disassociate a web ACL, provide an empty ARN. For information, see `AWS::CloudFront::Distribution <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webaclassociation.html#cfn-wafv2-webaclassociation-resourcearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "resourceArn"))

    @resource_arn.setter
    def resource_arn(self, value: builtins.str) -> None:
        jsii.set(self, "resourceArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="webAclArn")
    def web_acl_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the web ACL that you want to associate with the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webaclassociation.html#cfn-wafv2-webaclassociation-webaclarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "webAclArn"))

    @web_acl_arn.setter
    def web_acl_arn(self, value: builtins.str) -> None:
        jsii.set(self, "webAclArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACLAssociationProps",
    jsii_struct_bases=[],
    name_mapping={"resource_arn": "resourceArn", "web_acl_arn": "webAclArn"},
)
class CfnWebACLAssociationProps:
    def __init__(
        self,
        *,
        resource_arn: builtins.str,
        web_acl_arn: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnWebACLAssociation``.

        :param resource_arn: The Amazon Resource Name (ARN) of the resource to associate with the web ACL. The ARN must be in one of the following formats: - For an Application Load Balancer : ``arn:aws:elasticloadbalancing: *region* : *account-id* :loadbalancer/app/ *load-balancer-name* / *load-balancer-id*`` - For an Amazon API Gateway REST API: ``arn:aws:apigateway: *region* ::/restapis/ *api-id* /stages/ *stage-name*`` - For an AWS AppSync GraphQL API: ``arn:aws:appsync: *region* : *account-id* :apis/ *GraphQLApiId*`` For Amazon CloudFront , define the association in your CloudFront distribution configuration. To associate a web ACL, provide the Amazon Resource Name (ARN) of the ``WebACL`` to your CloudFront distribution configuration. To disassociate a web ACL, provide an empty ARN. For information, see `AWS::CloudFront::Distribution <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html>`_ .
        :param web_acl_arn: The Amazon Resource Name (ARN) of the web ACL that you want to associate with the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webaclassociation.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wafv2 as wafv2
            
            cfn_web_aCLAssociation_props = wafv2.CfnWebACLAssociationProps(
                resource_arn="resourceArn",
                web_acl_arn="webAclArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resource_arn": resource_arn,
            "web_acl_arn": web_acl_arn,
        }

    @builtins.property
    def resource_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the resource to associate with the web ACL.

        The ARN must be in one of the following formats:

        - For an Application Load Balancer : ``arn:aws:elasticloadbalancing: *region* : *account-id* :loadbalancer/app/ *load-balancer-name* / *load-balancer-id*``
        - For an Amazon API Gateway REST API: ``arn:aws:apigateway: *region* ::/restapis/ *api-id* /stages/ *stage-name*``
        - For an AWS AppSync GraphQL API: ``arn:aws:appsync: *region* : *account-id* :apis/ *GraphQLApiId*``

        For Amazon CloudFront , define the association in your CloudFront distribution configuration. To associate a web ACL, provide the Amazon Resource Name (ARN) of the ``WebACL`` to your CloudFront distribution configuration. To disassociate a web ACL, provide an empty ARN. For information, see `AWS::CloudFront::Distribution <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webaclassociation.html#cfn-wafv2-webaclassociation-resourcearn
        '''
        result = self._values.get("resource_arn")
        assert result is not None, "Required property 'resource_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def web_acl_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the web ACL that you want to associate with the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webaclassociation.html#cfn-wafv2-webaclassociation-webaclarn
        '''
        result = self._values.get("web_acl_arn")
        assert result is not None, "Required property 'web_acl_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnWebACLAssociationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_wafv2.CfnWebACLProps",
    jsii_struct_bases=[],
    name_mapping={
        "default_action": "defaultAction",
        "scope": "scope",
        "visibility_config": "visibilityConfig",
        "captcha_config": "captchaConfig",
        "custom_response_bodies": "customResponseBodies",
        "description": "description",
        "name": "name",
        "rules": "rules",
        "tags": "tags",
    },
)
class CfnWebACLProps:
    def __init__(
        self,
        *,
        default_action: typing.Union[CfnWebACL.DefaultActionProperty, _IResolvable_da3f097b],
        scope: builtins.str,
        visibility_config: typing.Union[CfnWebACL.VisibilityConfigProperty, _IResolvable_da3f097b],
        captcha_config: typing.Optional[typing.Union[CfnWebACL.CaptchaConfigProperty, _IResolvable_da3f097b]] = None,
        custom_response_bodies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnWebACL.CustomResponseBodyProperty, _IResolvable_da3f097b]]]] = None,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnWebACL.RuleProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnWebACL``.

        :param default_action: The action to perform if none of the ``Rules`` contained in the ``WebACL`` match.
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` . .. epigraph:: For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` . For information about how to define the association of the web ACL with your resource, see ``WebACLAssociation`` .
        :param visibility_config: Defines and enables Amazon CloudWatch metrics and web request sample collection.
        :param captcha_config: Specifies how AWS WAF should handle ``CAPTCHA`` evaluations for rules that don't have their own ``CaptchaConfig`` settings. If you don't specify this, AWS WAF uses its default settings for ``CaptchaConfig`` .
        :param custom_response_bodies: A map of custom response keys and content bodies. When you create a rule with a block action, you can send a custom response to the web request. You define these for the web ACL, and then use them in the rules and default actions that you define in the web ACL. For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ . For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .
        :param description: A description of the web ACL that helps with identification.
        :param name: The descriptive name of the web ACL. You cannot change the name of a web ACL after you create it.
        :param rules: The rule statements used to identify the web requests that you want to allow, block, or count. Each rule includes one top-level statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.
        :param tags: Key:value pairs associated with an AWS resource. The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource. .. epigraph:: To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_wafv2 as wafv2
            
            # all: Any
            # all_query_arguments: Any
            # body: Any
            # count: Any
            # method: Any
            # none: Any
            # query_string: Any
            # single_header: Any
            # single_query_argument: Any
            # statement_property_: wafv2.CfnWebACL.StatementProperty
            # uri_path: Any
            
            cfn_web_aCLProps = wafv2.CfnWebACLProps(
                default_action=wafv2.CfnWebACL.DefaultActionProperty(
                    allow=wafv2.CfnWebACL.AllowActionProperty(
                        custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                            insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    ),
                    block=wafv2.CfnWebACL.BlockActionProperty(
                        custom_response=wafv2.CfnWebACL.CustomResponseProperty(
                            response_code=123,
            
                            # the properties below are optional
                            custom_response_body_key="customResponseBodyKey",
                            response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    )
                ),
                scope="scope",
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=False,
                    metric_name="metricName",
                    sampled_requests_enabled=False
                ),
            
                # the properties below are optional
                captcha_config=wafv2.CfnWebACL.CaptchaConfigProperty(
                    immunity_time_property=wafv2.CfnWebACL.ImmunityTimePropertyProperty(
                        immunity_time=123
                    )
                ),
                custom_response_bodies={
                    "custom_response_bodies_key": wafv2.CfnWebACL.CustomResponseBodyProperty(
                        content="content",
                        content_type="contentType"
                    )
                },
                description="description",
                name="name",
                rules=[wafv2.CfnWebACL.RuleProperty(
                    name="name",
                    priority=123,
                    statement=wafv2.CfnWebACL.StatementProperty(
                        and_statement=wafv2.CfnWebACL.AndStatementProperty(
                            statements=[statement_property_]
                        ),
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            positional_constraint="positionalConstraint",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )],
            
                            # the properties below are optional
                            search_string="searchString",
                            search_string_base64="searchStringBase64"
                        ),
                        geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                            country_codes=["countryCodes"],
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            )
                        ),
                        ip_set_reference_statement={
                            "arn": "arn",
            
                            # the properties below are optional
                            "ip_set_forwarded_ip_config": {
                                "fallback_behavior": "fallbackBehavior",
                                "header_name": "headerName",
                                "position": "position"
                            }
                        },
                        label_match_statement=wafv2.CfnWebACL.LabelMatchStatementProperty(
                            key="key",
                            scope="scope"
                        ),
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="name",
                            vendor_name="vendorName",
            
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )],
                            managed_rule_group_configs=[wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                login_path="loginPath",
                                password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                ),
                                payload_type="payloadType",
                                username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier="identifier"
                                )
                            )],
                            scope_down_statement=statement_property_,
                            version="version"
                        ),
                        not_statement=wafv2.CfnWebACL.NotStatementProperty(
                            statement=statement_property_
                        ),
                        or_statement=wafv2.CfnWebACL.OrStatementProperty(
                            statements=[statement_property_]
                        ),
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            aggregate_key_type="aggregateKeyType",
                            limit=123,
            
                            # the properties below are optional
                            forwarded_ip_config=wafv2.CfnWebACL.ForwardedIPConfigurationProperty(
                                fallback_behavior="fallbackBehavior",
                                header_name="headerName"
                            ),
                            scope_down_statement=statement_property_
                        ),
                        regex_match_statement=wafv2.CfnWebACL.RegexMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            regex_string="regexString",
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        regex_pattern_set_reference_statement=wafv2.CfnWebACL.RegexPatternSetReferenceStatementProperty(
                            arn="arn",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        rule_group_reference_statement=wafv2.CfnWebACL.RuleGroupReferenceStatementProperty(
                            arn="arn",
            
                            # the properties below are optional
                            excluded_rules=[wafv2.CfnWebACL.ExcludedRuleProperty(
                                name="name"
                            )]
                        ),
                        size_constraint_statement=wafv2.CfnWebACL.SizeConstraintStatementProperty(
                            comparison_operator="comparisonOperator",
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            size=123,
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        sqli_match_statement=wafv2.CfnWebACL.SqliMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        ),
                        xss_match_statement=wafv2.CfnWebACL.XssMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                all_query_arguments=all_query_arguments,
                                body=body,
                                json_body=wafv2.CfnWebACL.JsonBodyProperty(
                                    match_pattern=wafv2.CfnWebACL.JsonMatchPatternProperty(
                                        all=all,
                                        included_paths=["includedPaths"]
                                    ),
                                    match_scope="matchScope",
            
                                    # the properties below are optional
                                    invalid_fallback_behavior="invalidFallbackBehavior"
                                ),
                                method=method,
                                query_string=query_string,
                                single_header=single_header,
                                single_query_argument=single_query_argument,
                                uri_path=uri_path
                            ),
                            text_transformations=[wafv2.CfnWebACL.TextTransformationProperty(
                                priority=123,
                                type="type"
                            )]
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=False,
                        metric_name="metricName",
                        sampled_requests_enabled=False
                    ),
            
                    # the properties below are optional
                    action=wafv2.CfnWebACL.RuleActionProperty(
                        allow=wafv2.CfnWebACL.AllowActionProperty(
                            custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                                insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        ),
                        block=wafv2.CfnWebACL.BlockActionProperty(
                            custom_response=wafv2.CfnWebACL.CustomResponseProperty(
                                response_code=123,
            
                                # the properties below are optional
                                custom_response_body_key="customResponseBodyKey",
                                response_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        ),
                        captcha=wafv2.CfnWebACL.CaptchaActionProperty(
                            custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                                insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        ),
                        count=wafv2.CfnWebACL.CountActionProperty(
                            custom_request_handling=wafv2.CfnWebACL.CustomRequestHandlingProperty(
                                insert_headers=[wafv2.CfnWebACL.CustomHTTPHeaderProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        )
                    ),
                    captcha_config=wafv2.CfnWebACL.CaptchaConfigProperty(
                        immunity_time_property=wafv2.CfnWebACL.ImmunityTimePropertyProperty(
                            immunity_time=123
                        )
                    ),
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(
                        count=count,
                        none=none
                    ),
                    rule_labels=[wafv2.CfnWebACL.LabelProperty(
                        name="name"
                    )]
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "default_action": default_action,
            "scope": scope,
            "visibility_config": visibility_config,
        }
        if captcha_config is not None:
            self._values["captcha_config"] = captcha_config
        if custom_response_bodies is not None:
            self._values["custom_response_bodies"] = custom_response_bodies
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if rules is not None:
            self._values["rules"] = rules
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def default_action(
        self,
    ) -> typing.Union[CfnWebACL.DefaultActionProperty, _IResolvable_da3f097b]:
        '''The action to perform if none of the ``Rules`` contained in the ``WebACL`` match.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-defaultaction
        '''
        result = self._values.get("default_action")
        assert result is not None, "Required property 'default_action' is missing"
        return typing.cast(typing.Union[CfnWebACL.DefaultActionProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def scope(self) -> builtins.str:
        '''Specifies whether this is for an Amazon CloudFront distribution or for a regional application.

        A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, or an AWS AppSync GraphQL API. Valid Values are ``CLOUDFRONT`` and ``REGIONAL`` .
        .. epigraph::

           For ``CLOUDFRONT`` , you must create your WAFv2 resources in the US East (N. Virginia) Region, ``us-east-1`` .

        For information about how to define the association of the web ACL with your resource, see ``WebACLAssociation`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-scope
        '''
        result = self._values.get("scope")
        assert result is not None, "Required property 'scope' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def visibility_config(
        self,
    ) -> typing.Union[CfnWebACL.VisibilityConfigProperty, _IResolvable_da3f097b]:
        '''Defines and enables Amazon CloudWatch metrics and web request sample collection.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-visibilityconfig
        '''
        result = self._values.get("visibility_config")
        assert result is not None, "Required property 'visibility_config' is missing"
        return typing.cast(typing.Union[CfnWebACL.VisibilityConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def captcha_config(
        self,
    ) -> typing.Optional[typing.Union[CfnWebACL.CaptchaConfigProperty, _IResolvable_da3f097b]]:
        '''Specifies how AWS WAF should handle ``CAPTCHA`` evaluations for rules that don't have their own ``CaptchaConfig`` settings.

        If you don't specify this, AWS WAF uses its default settings for ``CaptchaConfig`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-captchaconfig
        '''
        result = self._values.get("captcha_config")
        return typing.cast(typing.Optional[typing.Union[CfnWebACL.CaptchaConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def custom_response_bodies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnWebACL.CustomResponseBodyProperty, _IResolvable_da3f097b]]]]:
        '''A map of custom response keys and content bodies.

        When you create a rule with a block action, you can send a custom response to the web request. You define these for the web ACL, and then use them in the rules and default actions that you define in the web ACL.

        For information about customizing web requests and responses, see `Customizing web requests and responses in AWS WAF <https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

        For information about the limits on count and size for custom request and response settings, see `AWS WAF quotas <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>`_ in the `AWS WAF Developer Guide <https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-customresponsebodies
        '''
        result = self._values.get("custom_response_bodies")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnWebACL.CustomResponseBodyProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the web ACL that helps with identification.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The descriptive name of the web ACL.

        You cannot change the name of a web ACL after you create it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnWebACL.RuleProperty, _IResolvable_da3f097b]]]]:
        '''The rule statements used to identify the web requests that you want to allow, block, or count.

        Each rule includes one top-level statement that AWS WAF uses to identify matching web requests, and parameters that govern how AWS WAF handles them.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-rules
        '''
        result = self._values.get("rules")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnWebACL.RuleProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Key:value pairs associated with an AWS resource.

        The key:value pair can be anything you define. Typically, the tag key represents a category (such as "environment") and the tag value represents a specific value within that category (such as "test," "development," or "production"). You can add up to 50 tags to each AWS resource.
        .. epigraph::

           To modify tags on existing resources, use the AWS WAF APIs or command line interface. With AWS CloudFormation , you can only add tags to AWS WAF resources during resource creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html#cfn-wafv2-webacl-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnWebACLProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnIPSet",
    "CfnIPSetProps",
    "CfnLoggingConfiguration",
    "CfnLoggingConfigurationProps",
    "CfnRegexPatternSet",
    "CfnRegexPatternSetProps",
    "CfnRuleGroup",
    "CfnRuleGroupProps",
    "CfnWebACL",
    "CfnWebACLAssociation",
    "CfnWebACLAssociationProps",
    "CfnWebACLProps",
]

publication.publish()
