'''
# AWS Certificate Manager Construct Library

AWS Certificate Manager (ACM) handles the complexity of creating, storing, and renewing public and private SSL/TLS X.509 certificates and keys that
protect your AWS websites and applications. ACM certificates can secure singular domain names, multiple specific domain names, wildcard domains, or
combinations of these. ACM wildcard certificates can protect an unlimited number of subdomains.

This package provides Constructs for provisioning and referencing ACM certificates which can be used with CloudFront and ELB.

After requesting a certificate, you will need to prove that you own the
domain in question before the certificate will be granted. The CloudFormation
deployment will wait until this verification process has been completed.

Because of this wait time, when using manual validation methods, it's better
to provision your certificates either in a separate stack from your main
service, or provision them manually and import them into your CDK application.

**Note:** There is a limit on total number of ACM certificates that can be requested on an account and region within a year.
The default limit is 2000, but this limit may be (much) lower on new AWS accounts.
See https://docs.aws.amazon.com/acm/latest/userguide/acm-limits.html for more information.

## DNS validation

DNS validation is the preferred method to validate domain ownership, as it has a number of advantages over email validation.
See also [Validate with DNS](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html)
in the AWS Certificate Manager User Guide.

If Amazon Route 53 is your DNS provider for the requested domain, the DNS record can be
created automatically:

```python
my_hosted_zone = route53.HostedZone(self, "HostedZone",
    zone_name="example.com"
)
acm.Certificate(self, "Certificate",
    domain_name="hello.example.com",
    validation=acm.CertificateValidation.from_dns(my_hosted_zone)
)
```

If Route 53 is not your DNS provider, the DNS records must be added manually and the stack will not complete
creating until the records are added.

```python
acm.Certificate(self, "Certificate",
    domain_name="hello.example.com",
    validation=acm.CertificateValidation.from_dns()
)
```

When working with multiple domains, use the `CertificateValidation.fromDnsMultiZone()`:

```python
example_com = route53.HostedZone(self, "ExampleCom",
    zone_name="example.com"
)
example_net = route53.HostedZone(self, "ExampleNet",
    zone_name="example.net"
)

cert = acm.Certificate(self, "Certificate",
    domain_name="test.example.com",
    subject_alternative_names=["cool.example.com", "test.example.net"],
    validation=acm.CertificateValidation.from_dns_multi_zone({
        "test.example.com": example_com,
        "cool.example.com": example_com,
        "test.example.net": example_net
    })
)
```

## Email validation

Email-validated certificates (the default) are validated by receiving an
email on one of a number of predefined domains and following the instructions
in the email.

See [Validate with Email](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-email.html)
in the AWS Certificate Manager User Guide.

```python
acm.Certificate(self, "Certificate",
    domain_name="hello.example.com",
    validation=acm.CertificateValidation.from_email()
)
```

## Cross-region Certificates

ACM certificates that are used with CloudFront -- or higher-level constructs which rely on CloudFront -- must be in the `us-east-1` region.
The `DnsValidatedCertificate` construct exists to facilitate creating these certificates cross-region. This resource can only be used with
Route53-based DNS validation.

```python
# my_hosted_zone: route53.HostedZone

acm.DnsValidatedCertificate(self, "CrossRegionCertificate",
    domain_name="hello.example.com",
    hosted_zone=my_hosted_zone,
    region="us-east-1"
)
```

## Requesting private certificates

AWS Certificate Manager can create [private certificates](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-private.html) issued by [Private Certificate Authority (PCA)](https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaWelcome.html). Validation of private certificates is not necessary.

```python
import aws_cdk.aws_acmpca as acmpca


acm.PrivateCertificate(self, "PrivateCertificate",
    domain_name="test.example.com",
    subject_alternative_names=["cool.example.com", "test.example.net"],  # optional
    certificate_authority=acmpca.CertificateAuthority.from_certificate_authority_arn(self, "CA", "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/023077d8-2bfa-4eb0-8f22-05c96deade77")
)
```

## Importing

If you want to import an existing certificate, you can do so from its ARN:

```python
arn = "arn:aws:..."
certificate = acm.Certificate.from_certificate_arn(self, "Certificate", arn)
```

## Sharing between Stacks

To share the certificate between stacks in the same CDK application, simply
pass the `Certificate` object between the stacks.

## Metrics

The `DaysToExpiry` metric is available via the `metricDaysToExpiry` method for
all certificates. This metric is emitted by AWS Certificates Manager once per
day until the certificate has effectively expired.

An alarm can be created to determine whether a certificate is soon due for
renewal ussing the following code:

```python
import aws_cdk.aws_cloudwatch as cloudwatch

# my_hosted_zone: route53.HostedZone

certificate = acm.Certificate(self, "Certificate",
    domain_name="hello.example.com",
    validation=acm.CertificateValidation.from_dns(my_hosted_zone)
)
certificate.metric_days_to_expiry().create_alarm(self, "Alarm",
    comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
    evaluation_periods=1,
    threshold=45
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
    CfnTag as _CfnTag_f6864754,
    Duration as _Duration_4839e8c3,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    IResource as _IResource_c80c4260,
    ITaggable as _ITaggable_36806126,
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_acmpca import ICertificateAuthority as _ICertificateAuthority_26727cab
from ..aws_cloudwatch import (
    Metric as _Metric_e396a4dc,
    MetricOptions as _MetricOptions_1788b62f,
    Unit as _Unit_61bc6f70,
)
from ..aws_iam import IRole as _IRole_235f5d8e
from ..aws_route53 import IHostedZone as _IHostedZone_9a6907ad


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_certificatemanager.CertificateProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain_name": "domainName",
        "subject_alternative_names": "subjectAlternativeNames",
        "validation": "validation",
    },
)
class CertificateProps:
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        subject_alternative_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        validation: typing.Optional["CertificateValidation"] = None,
    ) -> None:
        '''Properties for your certificate.

        :param domain_name: Fully-qualified domain name to request a certificate for. May contain wildcards, such as ``*.domain.com``.
        :param subject_alternative_names: Alternative domain names on your certificate. Use this to register alternative domain names that represent the same site. Default: - No additional FQDNs will be included as alternative domain names.
        :param validation: How to validate this certificate. Default: CertificateValidation.fromEmail()

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
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
        }
        if subject_alternative_names is not None:
            self._values["subject_alternative_names"] = subject_alternative_names
        if validation is not None:
            self._values["validation"] = validation

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''Fully-qualified domain name to request a certificate for.

        May contain wildcards, such as ``*.domain.com``.
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subject_alternative_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Alternative domain names on your certificate.

        Use this to register alternative domain names that represent the same site.

        :default: - No additional FQDNs will be included as alternative domain names.
        '''
        result = self._values.get("subject_alternative_names")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def validation(self) -> typing.Optional["CertificateValidation"]:
        '''How to validate this certificate.

        :default: CertificateValidation.fromEmail()
        '''
        result = self._values.get("validation")
        return typing.cast(typing.Optional["CertificateValidation"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CertificateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class CertificateValidation(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_certificatemanager.CertificateValidation",
):
    '''How to validate a certificate.

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

    @jsii.member(jsii_name="fromDns") # type: ignore[misc]
    @builtins.classmethod
    def from_dns(
        cls,
        hosted_zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> "CertificateValidation":
        '''Validate the certificate with DNS.

        IMPORTANT: If ``hostedZone`` is not specified, DNS records must be added
        manually and the stack will not complete creating until the records are
        added.

        :param hosted_zone: the hosted zone where DNS records must be created.
        '''
        return typing.cast("CertificateValidation", jsii.sinvoke(cls, "fromDns", [hosted_zone]))

    @jsii.member(jsii_name="fromDnsMultiZone") # type: ignore[misc]
    @builtins.classmethod
    def from_dns_multi_zone(
        cls,
        hosted_zones: typing.Mapping[builtins.str, _IHostedZone_9a6907ad],
    ) -> "CertificateValidation":
        '''Validate the certificate with automatically created DNS records in multiple Amazon Route 53 hosted zones.

        :param hosted_zones: a map of hosted zones where DNS records must be created for the domains in the certificate.
        '''
        return typing.cast("CertificateValidation", jsii.sinvoke(cls, "fromDnsMultiZone", [hosted_zones]))

    @jsii.member(jsii_name="fromEmail") # type: ignore[misc]
    @builtins.classmethod
    def from_email(
        cls,
        validation_domains: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> "CertificateValidation":
        '''Validate the certificate with Email.

        IMPORTANT: if you are creating a certificate as part of your stack, the stack
        will not complete creating until you read and follow the instructions in the
        email that you will receive.

        ACM will send validation emails to the following addresses:

        admin@domain.com
        administrator@domain.com
        hostmaster@domain.com
        postmaster@domain.com
        webmaster@domain.com

        For every domain that you register.

        :param validation_domains: a map of validation domains to use for domains in the certificate.
        '''
        return typing.cast("CertificateValidation", jsii.sinvoke(cls, "fromEmail", [validation_domains]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="method")
    def method(self) -> "ValidationMethod":
        '''The validation method.'''
        return typing.cast("ValidationMethod", jsii.get(self, "method"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="props")
    def props(self) -> "CertificationValidationProps":
        '''Certification validation properties.'''
        return typing.cast("CertificationValidationProps", jsii.get(self, "props"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_certificatemanager.CertificationValidationProps",
    jsii_struct_bases=[],
    name_mapping={
        "hosted_zone": "hostedZone",
        "hosted_zones": "hostedZones",
        "method": "method",
        "validation_domains": "validationDomains",
    },
)
class CertificationValidationProps:
    def __init__(
        self,
        *,
        hosted_zone: typing.Optional[_IHostedZone_9a6907ad] = None,
        hosted_zones: typing.Optional[typing.Mapping[builtins.str, _IHostedZone_9a6907ad]] = None,
        method: typing.Optional["ValidationMethod"] = None,
        validation_domains: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for certificate validation.

        :param hosted_zone: Hosted zone to use for DNS validation. Default: - use email validation
        :param hosted_zones: A map of hosted zones to use for DNS validation. Default: - use ``hostedZone``
        :param method: Validation method. Default: ValidationMethod.EMAIL
        :param validation_domains: Validation domains to use for email validation. Default: - Apex domain

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_certificatemanager as certificatemanager
            from aws_cdk import aws_route53 as route53
            
            # hosted_zone: route53.HostedZone
            
            certification_validation_props = certificatemanager.CertificationValidationProps(
                hosted_zone=hosted_zone,
                hosted_zones={
                    "hosted_zones_key": hosted_zone
                },
                method=certificatemanager.ValidationMethod.EMAIL,
                validation_domains={
                    "validation_domains_key": "validationDomains"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if hosted_zone is not None:
            self._values["hosted_zone"] = hosted_zone
        if hosted_zones is not None:
            self._values["hosted_zones"] = hosted_zones
        if method is not None:
            self._values["method"] = method
        if validation_domains is not None:
            self._values["validation_domains"] = validation_domains

    @builtins.property
    def hosted_zone(self) -> typing.Optional[_IHostedZone_9a6907ad]:
        '''Hosted zone to use for DNS validation.

        :default: - use email validation
        '''
        result = self._values.get("hosted_zone")
        return typing.cast(typing.Optional[_IHostedZone_9a6907ad], result)

    @builtins.property
    def hosted_zones(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, _IHostedZone_9a6907ad]]:
        '''A map of hosted zones to use for DNS validation.

        :default: - use ``hostedZone``
        '''
        result = self._values.get("hosted_zones")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, _IHostedZone_9a6907ad]], result)

    @builtins.property
    def method(self) -> typing.Optional["ValidationMethod"]:
        '''Validation method.

        :default: ValidationMethod.EMAIL
        '''
        result = self._values.get("method")
        return typing.cast(typing.Optional["ValidationMethod"], result)

    @builtins.property
    def validation_domains(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Validation domains to use for email validation.

        :default: - Apex domain
        '''
        result = self._values.get("validation_domains")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CertificationValidationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnAccount(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_certificatemanager.CfnAccount",
):
    '''A CloudFormation ``AWS::CertificateManager::Account``.

    The ``AWS::CertificateManager::Account`` resource defines the expiry event configuration that determines the number of days prior to expiry when ACM starts generating EventBridge events.

    :cloudformationResource: AWS::CertificateManager::Account
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-account.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_certificatemanager as certificatemanager
        
        cfn_account = certificatemanager.CfnAccount(self, "MyCfnAccount",
            expiry_events_configuration=certificatemanager.CfnAccount.ExpiryEventsConfigurationProperty(
                days_before_expiry=123
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        expiry_events_configuration: typing.Union["CfnAccount.ExpiryEventsConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::CertificateManager::Account``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param expiry_events_configuration: Object containing expiration events options associated with an AWS account . For more information, see `ExpiryEventsConfiguration <https://docs.aws.amazon.com/acm/latest/APIReference/API_ExpiryEventsConfiguration.html>`_ in the API reference.
        '''
        props = CfnAccountProps(
            expiry_events_configuration=expiry_events_configuration
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
    @jsii.member(jsii_name="attrAccountId")
    def attr_account_id(self) -> builtins.str:
        '''ID of the AWS account that owns the certificate.

        :cloudformationAttribute: AccountId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAccountId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="expiryEventsConfiguration")
    def expiry_events_configuration(
        self,
    ) -> typing.Union["CfnAccount.ExpiryEventsConfigurationProperty", _IResolvable_da3f097b]:
        '''Object containing expiration events options associated with an AWS account .

        For more information, see `ExpiryEventsConfiguration <https://docs.aws.amazon.com/acm/latest/APIReference/API_ExpiryEventsConfiguration.html>`_ in the API reference.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-account.html#cfn-certificatemanager-account-expiryeventsconfiguration
        '''
        return typing.cast(typing.Union["CfnAccount.ExpiryEventsConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "expiryEventsConfiguration"))

    @expiry_events_configuration.setter
    def expiry_events_configuration(
        self,
        value: typing.Union["CfnAccount.ExpiryEventsConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "expiryEventsConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_certificatemanager.CfnAccount.ExpiryEventsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"days_before_expiry": "daysBeforeExpiry"},
    )
    class ExpiryEventsConfigurationProperty:
        def __init__(
            self,
            *,
            days_before_expiry: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Object containing expiration events options associated with an AWS account .

            For more information, see `ExpiryEventsConfiguration <https://docs.aws.amazon.com/acm/latest/APIReference/API_ExpiryEventsConfiguration.html>`_ in the API reference.

            :param days_before_expiry: This option specifies the number of days prior to certificate expiration when ACM starts generating ``EventBridge`` events. ACM sends one event per day per certificate until the certificate expires. By default, accounts receive events starting 45 days before certificate expiration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-certificatemanager-account-expiryeventsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_certificatemanager as certificatemanager
                
                expiry_events_configuration_property = certificatemanager.CfnAccount.ExpiryEventsConfigurationProperty(
                    days_before_expiry=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if days_before_expiry is not None:
                self._values["days_before_expiry"] = days_before_expiry

        @builtins.property
        def days_before_expiry(self) -> typing.Optional[jsii.Number]:
            '''This option specifies the number of days prior to certificate expiration when ACM starts generating ``EventBridge`` events.

            ACM sends one event per day per certificate until the certificate expires. By default, accounts receive events starting 45 days before certificate expiration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-certificatemanager-account-expiryeventsconfiguration.html#cfn-certificatemanager-account-expiryeventsconfiguration-daysbeforeexpiry
            '''
            result = self._values.get("days_before_expiry")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ExpiryEventsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_certificatemanager.CfnAccountProps",
    jsii_struct_bases=[],
    name_mapping={"expiry_events_configuration": "expiryEventsConfiguration"},
)
class CfnAccountProps:
    def __init__(
        self,
        *,
        expiry_events_configuration: typing.Union[CfnAccount.ExpiryEventsConfigurationProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnAccount``.

        :param expiry_events_configuration: Object containing expiration events options associated with an AWS account . For more information, see `ExpiryEventsConfiguration <https://docs.aws.amazon.com/acm/latest/APIReference/API_ExpiryEventsConfiguration.html>`_ in the API reference.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-account.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_certificatemanager as certificatemanager
            
            cfn_account_props = certificatemanager.CfnAccountProps(
                expiry_events_configuration=certificatemanager.CfnAccount.ExpiryEventsConfigurationProperty(
                    days_before_expiry=123
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "expiry_events_configuration": expiry_events_configuration,
        }

    @builtins.property
    def expiry_events_configuration(
        self,
    ) -> typing.Union[CfnAccount.ExpiryEventsConfigurationProperty, _IResolvable_da3f097b]:
        '''Object containing expiration events options associated with an AWS account .

        For more information, see `ExpiryEventsConfiguration <https://docs.aws.amazon.com/acm/latest/APIReference/API_ExpiryEventsConfiguration.html>`_ in the API reference.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-account.html#cfn-certificatemanager-account-expiryeventsconfiguration
        '''
        result = self._values.get("expiry_events_configuration")
        assert result is not None, "Required property 'expiry_events_configuration' is missing"
        return typing.cast(typing.Union[CfnAccount.ExpiryEventsConfigurationProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAccountProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnCertificate(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_certificatemanager.CfnCertificate",
):
    '''A CloudFormation ``AWS::CertificateManager::Certificate``.

    The ``AWS::CertificateManager::Certificate`` resource requests an AWS Certificate Manager ( ACM ) certificate that you can use to enable secure connections. For example, you can deploy an ACM certificate to an Elastic Load Balancer to enable HTTPS support. For more information, see `RequestCertificate <https://docs.aws.amazon.com/acm/latest/APIReference/API_RequestCertificate.html>`_ in the AWS Certificate Manager API Reference.
    .. epigraph::

       When you use the ``AWS::CertificateManager::Certificate`` resource in a CloudFormation stack, domain validation is handled automatically if all three of the following are true: The certificate domain is hosted in Amazon Route 53, the domain resides in your AWS account , and you are using DNS validation.

       However, if the certificate uses email validation, or if the domain is not hosted in Route 53, then the stack will remain in the ``CREATE_IN_PROGRESS`` state. Further stack operations are delayed until you validate the certificate request, either by acting upon the instructions in the validation email, or by adding a CNAME record to your DNS configuration. For more information, see `Option 1: DNS Validation <https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html>`_ and `Option 2: Email Validation <https://docs.aws.amazon.com/acm/latest/userguide/email-validation.html>`_ .

    :cloudformationResource: AWS::CertificateManager::Certificate
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_certificatemanager as certificatemanager
        
        cfn_certificate = certificatemanager.CfnCertificate(self, "MyCfnCertificate",
            domain_name="domainName",
        
            # the properties below are optional
            certificate_authority_arn="certificateAuthorityArn",
            certificate_transparency_logging_preference="certificateTransparencyLoggingPreference",
            domain_validation_options=[certificatemanager.CfnCertificate.DomainValidationOptionProperty(
                domain_name="domainName",
        
                # the properties below are optional
                hosted_zone_id="hostedZoneId",
                validation_domain="validationDomain"
            )],
            subject_alternative_names=["subjectAlternativeNames"],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            validation_method="validationMethod"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain_name: builtins.str,
        certificate_authority_arn: typing.Optional[builtins.str] = None,
        certificate_transparency_logging_preference: typing.Optional[builtins.str] = None,
        domain_validation_options: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCertificate.DomainValidationOptionProperty", _IResolvable_da3f097b]]]] = None,
        subject_alternative_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        validation_method: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CertificateManager::Certificate``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param domain_name: The fully qualified domain name (FQDN), such as www.example.com, with which you want to secure an ACM certificate. Use an asterisk (*) to create a wildcard certificate that protects several sites in the same domain. For example, ``*.example.com`` protects ``www.example.com`` , ``site.example.com`` , and ``images.example.com.``.
        :param certificate_authority_arn: The Amazon Resource Name (ARN) of the private certificate authority (CA) that will be used to issue the certificate. If you do not provide an ARN and you are trying to request a private certificate, ACM will attempt to issue a public certificate. For more information about private CAs, see the `AWS Certificate Manager Private Certificate Authority (PCA) <https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaWelcome.html>`_ user guide. The ARN must have the following form: ``arn:aws:acm-pca:region:account:certificate-authority/12345678-1234-1234-1234-123456789012``
        :param certificate_transparency_logging_preference: You can opt out of certificate transparency logging by specifying the ``DISABLED`` option. Opt in by specifying ``ENABLED`` . If you do not specify a certificate transparency logging preference on a new CloudFormation template, or if you remove the logging preference from an existing template, this is the same as explicitly enabling the preference. Changing the certificate transparency logging preference will update the existing resource by calling ``UpdateCertificateOptions`` on the certificate. This action will not create a new resource.
        :param domain_validation_options: Domain information that domain name registrars use to verify your identity. .. epigraph:: In order for a AWS::CertificateManager::Certificate to be provisioned and validated in CloudFormation automatically, the ``DomainName`` property needs to be identical to one of the ``DomainName`` property supplied in DomainValidationOptions, if the ValidationMethod is **DNS**. Failing to keep them like-for-like will result in failure to create the domain validation records in Route53.
        :param subject_alternative_names: Additional FQDNs to be included in the Subject Alternative Name extension of the ACM certificate. For example, you can add www.example.net to a certificate for which the ``DomainName`` field is www.example.com if users can reach your site by using either name.
        :param tags: Key-value pairs that can identify the certificate.
        :param validation_method: The method you want to use to validate that you own or control the domain associated with a public certificate. You can `validate with DNS <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html>`_ or `validate with email <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-email.html>`_ . We recommend that you use DNS validation. If not specified, this property defaults to email validation.
        '''
        props = CfnCertificateProps(
            domain_name=domain_name,
            certificate_authority_arn=certificate_authority_arn,
            certificate_transparency_logging_preference=certificate_transparency_logging_preference,
            domain_validation_options=domain_validation_options,
            subject_alternative_names=subject_alternative_names,
            tags=tags,
            validation_method=validation_method,
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
        '''Key-value pairs that can identify the certificate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The fully qualified domain name (FQDN), such as www.example.com, with which you want to secure an ACM certificate. Use an asterisk (*) to create a wildcard certificate that protects several sites in the same domain. For example, ``*.example.com`` protects ``www.example.com`` , ``site.example.com`` , and ``images.example.com.``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-domainname
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

    @domain_name.setter
    def domain_name(self, value: builtins.str) -> None:
        jsii.set(self, "domainName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateAuthorityArn")
    def certificate_authority_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the private certificate authority (CA) that will be used to issue the certificate.

        If you do not provide an ARN and you are trying to request a private certificate, ACM will attempt to issue a public certificate. For more information about private CAs, see the `AWS Certificate Manager Private Certificate Authority (PCA) <https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaWelcome.html>`_ user guide. The ARN must have the following form:

        ``arn:aws:acm-pca:region:account:certificate-authority/12345678-1234-1234-1234-123456789012``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificateauthorityarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificateAuthorityArn"))

    @certificate_authority_arn.setter
    def certificate_authority_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "certificateAuthorityArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateTransparencyLoggingPreference")
    def certificate_transparency_logging_preference(
        self,
    ) -> typing.Optional[builtins.str]:
        '''You can opt out of certificate transparency logging by specifying the ``DISABLED`` option. Opt in by specifying ``ENABLED`` .

        If you do not specify a certificate transparency logging preference on a new CloudFormation template, or if you remove the logging preference from an existing template, this is the same as explicitly enabling the preference.

        Changing the certificate transparency logging preference will update the existing resource by calling ``UpdateCertificateOptions`` on the certificate. This action will not create a new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificatetransparencyloggingpreference
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificateTransparencyLoggingPreference"))

    @certificate_transparency_logging_preference.setter
    def certificate_transparency_logging_preference(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "certificateTransparencyLoggingPreference", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainValidationOptions")
    def domain_validation_options(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCertificate.DomainValidationOptionProperty", _IResolvable_da3f097b]]]]:
        '''Domain information that domain name registrars use to verify your identity.

        .. epigraph::

           In order for a AWS::CertificateManager::Certificate to be provisioned and validated in CloudFormation automatically, the ``DomainName`` property needs to be identical to one of the ``DomainName`` property supplied in DomainValidationOptions, if the ValidationMethod is **DNS**. Failing to keep them like-for-like will result in failure to create the domain validation records in Route53.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-domainvalidationoptions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCertificate.DomainValidationOptionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "domainValidationOptions"))

    @domain_validation_options.setter
    def domain_validation_options(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCertificate.DomainValidationOptionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "domainValidationOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subjectAlternativeNames")
    def subject_alternative_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Additional FQDNs to be included in the Subject Alternative Name extension of the ACM certificate.

        For example, you can add www.example.net to a certificate for which the ``DomainName`` field is www.example.com if users can reach your site by using either name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-subjectalternativenames
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "subjectAlternativeNames"))

    @subject_alternative_names.setter
    def subject_alternative_names(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "subjectAlternativeNames", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="validationMethod")
    def validation_method(self) -> typing.Optional[builtins.str]:
        '''The method you want to use to validate that you own or control the domain associated with a public certificate.

        You can `validate with DNS <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html>`_ or `validate with email <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-email.html>`_ . We recommend that you use DNS validation.

        If not specified, this property defaults to email validation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-validationmethod
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "validationMethod"))

    @validation_method.setter
    def validation_method(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "validationMethod", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_certificatemanager.CfnCertificate.DomainValidationOptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "domain_name": "domainName",
            "hosted_zone_id": "hostedZoneId",
            "validation_domain": "validationDomain",
        },
    )
    class DomainValidationOptionProperty:
        def __init__(
            self,
            *,
            domain_name: builtins.str,
            hosted_zone_id: typing.Optional[builtins.str] = None,
            validation_domain: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``DomainValidationOption`` is a property of the `AWS::CertificateManager::Certificate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html>`_ resource that specifies the AWS Certificate Manager ( ACM ) certificate domain to validate. Depending on the chosen validation method, ACM checks the domain's DNS record for a validation CNAME, or it attempts to send a validation email message to the domain owner.

            :param domain_name: A fully qualified domain name (FQDN) in the certificate request.
            :param hosted_zone_id: The ``HostedZoneId`` option, which is available if you are using Route 53 as your domain registrar, causes ACM to add your CNAME to the domain record. Your list of ``DomainValidationOptions`` must contain one and only one of the domain-validation options, and the ``HostedZoneId`` can be used only when ``DNS`` is specified as your validation method. Use the Route 53 ``ListHostedZones`` API to discover IDs for available hosted zones. This option is required for publicly trusted certificates. .. epigraph:: The ``ListHostedZones`` API returns IDs in the format "/hostedzone/Z111111QQQQQQQ", but CloudFormation requires the IDs to be in the format "Z111111QQQQQQQ". When you change your ``DomainValidationOptions`` , a new resource is created.
            :param validation_domain: The domain name to which you want ACM to send validation emails. This domain name is the suffix of the email addresses that you want ACM to use. This must be the same as the ``DomainName`` value or a superdomain of the ``DomainName`` value. For example, if you request a certificate for ``testing.example.com`` , you can specify ``example.com`` as this value. In that case, ACM sends domain validation emails to the following five addresses: - admin@example.com - administrator@example.com - hostmaster@example.com - postmaster@example.com - webmaster@example.com

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-certificatemanager-certificate-domainvalidationoption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_certificatemanager as certificatemanager
                
                domain_validation_option_property = certificatemanager.CfnCertificate.DomainValidationOptionProperty(
                    domain_name="domainName",
                
                    # the properties below are optional
                    hosted_zone_id="hostedZoneId",
                    validation_domain="validationDomain"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "domain_name": domain_name,
            }
            if hosted_zone_id is not None:
                self._values["hosted_zone_id"] = hosted_zone_id
            if validation_domain is not None:
                self._values["validation_domain"] = validation_domain

        @builtins.property
        def domain_name(self) -> builtins.str:
            '''A fully qualified domain name (FQDN) in the certificate request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-certificatemanager-certificate-domainvalidationoption.html#cfn-certificatemanager-certificate-domainvalidationoptions-domainname
            '''
            result = self._values.get("domain_name")
            assert result is not None, "Required property 'domain_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def hosted_zone_id(self) -> typing.Optional[builtins.str]:
            '''The ``HostedZoneId`` option, which is available if you are using Route 53 as your domain registrar, causes ACM to add your CNAME to the domain record.

            Your list of ``DomainValidationOptions`` must contain one and only one of the domain-validation options, and the ``HostedZoneId`` can be used only when ``DNS`` is specified as your validation method.

            Use the Route 53 ``ListHostedZones`` API to discover IDs for available hosted zones.

            This option is required for publicly trusted certificates.
            .. epigraph::

               The ``ListHostedZones`` API returns IDs in the format "/hostedzone/Z111111QQQQQQQ", but CloudFormation requires the IDs to be in the format "Z111111QQQQQQQ".

            When you change your ``DomainValidationOptions`` , a new resource is created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-certificatemanager-certificate-domainvalidationoption.html#cfn-certificatemanager-certificate-domainvalidationoption-hostedzoneid
            '''
            result = self._values.get("hosted_zone_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def validation_domain(self) -> typing.Optional[builtins.str]:
            '''The domain name to which you want ACM to send validation emails.

            This domain name is the suffix of the email addresses that you want ACM to use. This must be the same as the ``DomainName`` value or a superdomain of the ``DomainName`` value. For example, if you request a certificate for ``testing.example.com`` , you can specify ``example.com`` as this value. In that case, ACM sends domain validation emails to the following five addresses:

            - admin@example.com
            - administrator@example.com
            - hostmaster@example.com
            - postmaster@example.com
            - webmaster@example.com

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-certificatemanager-certificate-domainvalidationoption.html#cfn-certificatemanager-certificate-domainvalidationoption-validationdomain
            '''
            result = self._values.get("validation_domain")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DomainValidationOptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_certificatemanager.CfnCertificateProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain_name": "domainName",
        "certificate_authority_arn": "certificateAuthorityArn",
        "certificate_transparency_logging_preference": "certificateTransparencyLoggingPreference",
        "domain_validation_options": "domainValidationOptions",
        "subject_alternative_names": "subjectAlternativeNames",
        "tags": "tags",
        "validation_method": "validationMethod",
    },
)
class CfnCertificateProps:
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        certificate_authority_arn: typing.Optional[builtins.str] = None,
        certificate_transparency_logging_preference: typing.Optional[builtins.str] = None,
        domain_validation_options: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnCertificate.DomainValidationOptionProperty, _IResolvable_da3f097b]]]] = None,
        subject_alternative_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        validation_method: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnCertificate``.

        :param domain_name: The fully qualified domain name (FQDN), such as www.example.com, with which you want to secure an ACM certificate. Use an asterisk (*) to create a wildcard certificate that protects several sites in the same domain. For example, ``*.example.com`` protects ``www.example.com`` , ``site.example.com`` , and ``images.example.com.``.
        :param certificate_authority_arn: The Amazon Resource Name (ARN) of the private certificate authority (CA) that will be used to issue the certificate. If you do not provide an ARN and you are trying to request a private certificate, ACM will attempt to issue a public certificate. For more information about private CAs, see the `AWS Certificate Manager Private Certificate Authority (PCA) <https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaWelcome.html>`_ user guide. The ARN must have the following form: ``arn:aws:acm-pca:region:account:certificate-authority/12345678-1234-1234-1234-123456789012``
        :param certificate_transparency_logging_preference: You can opt out of certificate transparency logging by specifying the ``DISABLED`` option. Opt in by specifying ``ENABLED`` . If you do not specify a certificate transparency logging preference on a new CloudFormation template, or if you remove the logging preference from an existing template, this is the same as explicitly enabling the preference. Changing the certificate transparency logging preference will update the existing resource by calling ``UpdateCertificateOptions`` on the certificate. This action will not create a new resource.
        :param domain_validation_options: Domain information that domain name registrars use to verify your identity. .. epigraph:: In order for a AWS::CertificateManager::Certificate to be provisioned and validated in CloudFormation automatically, the ``DomainName`` property needs to be identical to one of the ``DomainName`` property supplied in DomainValidationOptions, if the ValidationMethod is **DNS**. Failing to keep them like-for-like will result in failure to create the domain validation records in Route53.
        :param subject_alternative_names: Additional FQDNs to be included in the Subject Alternative Name extension of the ACM certificate. For example, you can add www.example.net to a certificate for which the ``DomainName`` field is www.example.com if users can reach your site by using either name.
        :param tags: Key-value pairs that can identify the certificate.
        :param validation_method: The method you want to use to validate that you own or control the domain associated with a public certificate. You can `validate with DNS <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html>`_ or `validate with email <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-email.html>`_ . We recommend that you use DNS validation. If not specified, this property defaults to email validation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_certificatemanager as certificatemanager
            
            cfn_certificate_props = certificatemanager.CfnCertificateProps(
                domain_name="domainName",
            
                # the properties below are optional
                certificate_authority_arn="certificateAuthorityArn",
                certificate_transparency_logging_preference="certificateTransparencyLoggingPreference",
                domain_validation_options=[certificatemanager.CfnCertificate.DomainValidationOptionProperty(
                    domain_name="domainName",
            
                    # the properties below are optional
                    hosted_zone_id="hostedZoneId",
                    validation_domain="validationDomain"
                )],
                subject_alternative_names=["subjectAlternativeNames"],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                validation_method="validationMethod"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
        }
        if certificate_authority_arn is not None:
            self._values["certificate_authority_arn"] = certificate_authority_arn
        if certificate_transparency_logging_preference is not None:
            self._values["certificate_transparency_logging_preference"] = certificate_transparency_logging_preference
        if domain_validation_options is not None:
            self._values["domain_validation_options"] = domain_validation_options
        if subject_alternative_names is not None:
            self._values["subject_alternative_names"] = subject_alternative_names
        if tags is not None:
            self._values["tags"] = tags
        if validation_method is not None:
            self._values["validation_method"] = validation_method

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The fully qualified domain name (FQDN), such as www.example.com, with which you want to secure an ACM certificate. Use an asterisk (*) to create a wildcard certificate that protects several sites in the same domain. For example, ``*.example.com`` protects ``www.example.com`` , ``site.example.com`` , and ``images.example.com.``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-domainname
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def certificate_authority_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the private certificate authority (CA) that will be used to issue the certificate.

        If you do not provide an ARN and you are trying to request a private certificate, ACM will attempt to issue a public certificate. For more information about private CAs, see the `AWS Certificate Manager Private Certificate Authority (PCA) <https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaWelcome.html>`_ user guide. The ARN must have the following form:

        ``arn:aws:acm-pca:region:account:certificate-authority/12345678-1234-1234-1234-123456789012``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificateauthorityarn
        '''
        result = self._values.get("certificate_authority_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def certificate_transparency_logging_preference(
        self,
    ) -> typing.Optional[builtins.str]:
        '''You can opt out of certificate transparency logging by specifying the ``DISABLED`` option. Opt in by specifying ``ENABLED`` .

        If you do not specify a certificate transparency logging preference on a new CloudFormation template, or if you remove the logging preference from an existing template, this is the same as explicitly enabling the preference.

        Changing the certificate transparency logging preference will update the existing resource by calling ``UpdateCertificateOptions`` on the certificate. This action will not create a new resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificatetransparencyloggingpreference
        '''
        result = self._values.get("certificate_transparency_logging_preference")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def domain_validation_options(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCertificate.DomainValidationOptionProperty, _IResolvable_da3f097b]]]]:
        '''Domain information that domain name registrars use to verify your identity.

        .. epigraph::

           In order for a AWS::CertificateManager::Certificate to be provisioned and validated in CloudFormation automatically, the ``DomainName`` property needs to be identical to one of the ``DomainName`` property supplied in DomainValidationOptions, if the ValidationMethod is **DNS**. Failing to keep them like-for-like will result in failure to create the domain validation records in Route53.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-domainvalidationoptions
        '''
        result = self._values.get("domain_validation_options")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCertificate.DomainValidationOptionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def subject_alternative_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Additional FQDNs to be included in the Subject Alternative Name extension of the ACM certificate.

        For example, you can add www.example.net to a certificate for which the ``DomainName`` field is www.example.com if users can reach your site by using either name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-subjectalternativenames
        '''
        result = self._values.get("subject_alternative_names")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Key-value pairs that can identify the certificate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def validation_method(self) -> typing.Optional[builtins.str]:
        '''The method you want to use to validate that you own or control the domain associated with a public certificate.

        You can `validate with DNS <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html>`_ or `validate with email <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-email.html>`_ . We recommend that you use DNS validation.

        If not specified, this property defaults to email validation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-validationmethod
        '''
        result = self._values.get("validation_method")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCertificateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_certificatemanager.DnsValidatedCertificateProps",
    jsii_struct_bases=[CertificateProps],
    name_mapping={
        "domain_name": "domainName",
        "subject_alternative_names": "subjectAlternativeNames",
        "validation": "validation",
        "hosted_zone": "hostedZone",
        "cleanup_route53_records": "cleanupRoute53Records",
        "custom_resource_role": "customResourceRole",
        "region": "region",
        "route53_endpoint": "route53Endpoint",
    },
)
class DnsValidatedCertificateProps(CertificateProps):
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        subject_alternative_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        validation: typing.Optional[CertificateValidation] = None,
        hosted_zone: _IHostedZone_9a6907ad,
        cleanup_route53_records: typing.Optional[builtins.bool] = None,
        custom_resource_role: typing.Optional[_IRole_235f5d8e] = None,
        region: typing.Optional[builtins.str] = None,
        route53_endpoint: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties to create a DNS validated certificate managed by AWS Certificate Manager.

        :param domain_name: Fully-qualified domain name to request a certificate for. May contain wildcards, such as ``*.domain.com``.
        :param subject_alternative_names: Alternative domain names on your certificate. Use this to register alternative domain names that represent the same site. Default: - No additional FQDNs will be included as alternative domain names.
        :param validation: How to validate this certificate. Default: CertificateValidation.fromEmail()
        :param hosted_zone: Route 53 Hosted Zone used to perform DNS validation of the request. The zone must be authoritative for the domain name specified in the Certificate Request.
        :param cleanup_route53_records: When set to true, when the DnsValidatedCertificate is deleted, the associated Route53 validation records are removed. CAUTION: If multiple certificates share the same domains (and same validation records), this can cause the other certificates to fail renewal and/or not validate. Not recommended for production use. Default: false
        :param custom_resource_role: Role to use for the custom resource that creates the validated certificate. Default: - A new role will be created
        :param region: AWS region that will host the certificate. This is needed especially for certificates used for CloudFront distributions, which require the region to be us-east-1. Default: the region the stack is deployed in.
        :param route53_endpoint: An endpoint of Route53 service, which is not necessary as AWS SDK could figure out the right endpoints for most regions, but for some regions such as those in aws-cn partition, the default endpoint is not working now, hence the right endpoint need to be specified through this prop. Route53 is not been officially launched in China, it is only available for AWS internal accounts now. To make DnsValidatedCertificate work for internal accounts now, a special endpoint needs to be provided. Default: - The AWS SDK will determine the Route53 endpoint to use based on region

        :exampleMetadata: infused

        Example::

            # my_hosted_zone: route53.HostedZone
            
            acm.DnsValidatedCertificate(self, "CrossRegionCertificate",
                domain_name="hello.example.com",
                hosted_zone=my_hosted_zone,
                region="us-east-1"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
            "hosted_zone": hosted_zone,
        }
        if subject_alternative_names is not None:
            self._values["subject_alternative_names"] = subject_alternative_names
        if validation is not None:
            self._values["validation"] = validation
        if cleanup_route53_records is not None:
            self._values["cleanup_route53_records"] = cleanup_route53_records
        if custom_resource_role is not None:
            self._values["custom_resource_role"] = custom_resource_role
        if region is not None:
            self._values["region"] = region
        if route53_endpoint is not None:
            self._values["route53_endpoint"] = route53_endpoint

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''Fully-qualified domain name to request a certificate for.

        May contain wildcards, such as ``*.domain.com``.
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subject_alternative_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Alternative domain names on your certificate.

        Use this to register alternative domain names that represent the same site.

        :default: - No additional FQDNs will be included as alternative domain names.
        '''
        result = self._values.get("subject_alternative_names")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def validation(self) -> typing.Optional[CertificateValidation]:
        '''How to validate this certificate.

        :default: CertificateValidation.fromEmail()
        '''
        result = self._values.get("validation")
        return typing.cast(typing.Optional[CertificateValidation], result)

    @builtins.property
    def hosted_zone(self) -> _IHostedZone_9a6907ad:
        '''Route 53 Hosted Zone used to perform DNS validation of the request.

        The zone
        must be authoritative for the domain name specified in the Certificate Request.
        '''
        result = self._values.get("hosted_zone")
        assert result is not None, "Required property 'hosted_zone' is missing"
        return typing.cast(_IHostedZone_9a6907ad, result)

    @builtins.property
    def cleanup_route53_records(self) -> typing.Optional[builtins.bool]:
        '''When set to true, when the DnsValidatedCertificate is deleted, the associated Route53 validation records are removed.

        CAUTION: If multiple certificates share the same domains (and same validation records),
        this can cause the other certificates to fail renewal and/or not validate.
        Not recommended for production use.

        :default: false
        '''
        result = self._values.get("cleanup_route53_records")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def custom_resource_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''Role to use for the custom resource that creates the validated certificate.

        :default: - A new role will be created
        '''
        result = self._values.get("custom_resource_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def region(self) -> typing.Optional[builtins.str]:
        '''AWS region that will host the certificate.

        This is needed especially
        for certificates used for CloudFront distributions, which require the region
        to be us-east-1.

        :default: the region the stack is deployed in.
        '''
        result = self._values.get("region")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def route53_endpoint(self) -> typing.Optional[builtins.str]:
        '''An endpoint of Route53 service, which is not necessary as AWS SDK could figure out the right endpoints for most regions, but for some regions such as those in aws-cn partition, the default endpoint is not working now, hence the right endpoint need to be specified through this prop.

        Route53 is not been officially launched in China, it is only available for AWS
        internal accounts now. To make DnsValidatedCertificate work for internal accounts
        now, a special endpoint needs to be provided.

        :default: - The AWS SDK will determine the Route53 endpoint to use based on region
        '''
        result = self._values.get("route53_endpoint")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DnsValidatedCertificateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_certificatemanager.ICertificate")
class ICertificate(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents a certificate in AWS Certificate Manager.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> builtins.str:
        '''The certificate's ARN.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="metricDaysToExpiry")
    def metric_days_to_expiry(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the DaysToExpiry metric for this AWS Certificate Manager Certificate. By default, this is the minimum value over 1 day.

        This metric is no longer emitted once the certificate has effectively
        expired, so alarms configured on this metric should probably treat missing
        data as "breaching".

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        ...


class _ICertificateProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents a certificate in AWS Certificate Manager.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_certificatemanager.ICertificate"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> builtins.str:
        '''The certificate's ARN.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "certificateArn"))

    @jsii.member(jsii_name="metricDaysToExpiry")
    def metric_days_to_expiry(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the DaysToExpiry metric for this AWS Certificate Manager Certificate. By default, this is the minimum value over 1 day.

        This metric is no longer emitted once the certificate has effectively
        expired, so alarms configured on this metric should probably treat missing
        data as "breaching".

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricDaysToExpiry", [props]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ICertificate).__jsii_proxy_class__ = lambda : _ICertificateProxy


@jsii.implements(ICertificate)
class PrivateCertificate(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_certificatemanager.PrivateCertificate",
):
    '''A private certificate managed by AWS Certificate Manager.

    :exampleMetadata: infused
    :resource: AWS::CertificateManager::Certificate

    Example::

        import aws_cdk.aws_acmpca as acmpca
        
        
        acm.PrivateCertificate(self, "PrivateCertificate",
            domain_name="test.example.com",
            subject_alternative_names=["cool.example.com", "test.example.net"],  # optional
            certificate_authority=acmpca.CertificateAuthority.from_certificate_authority_arn(self, "CA", "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/023077d8-2bfa-4eb0-8f22-05c96deade77")
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        certificate_authority: _ICertificateAuthority_26727cab,
        domain_name: builtins.str,
        subject_alternative_names: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param certificate_authority: Private certificate authority (CA) that will be used to issue the certificate.
        :param domain_name: Fully-qualified domain name to request a private certificate for. May contain wildcards, such as ``*.domain.com``.
        :param subject_alternative_names: Alternative domain names on your private certificate. Use this to register alternative domain names that represent the same site. Default: - No additional FQDNs will be included as alternative domain names.
        '''
        props = PrivateCertificateProps(
            certificate_authority=certificate_authority,
            domain_name=domain_name,
            subject_alternative_names=subject_alternative_names,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromCertificateArn") # type: ignore[misc]
    @builtins.classmethod
    def from_certificate_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        certificate_arn: builtins.str,
    ) -> ICertificate:
        '''Import a certificate.

        :param scope: -
        :param id: -
        :param certificate_arn: -
        '''
        return typing.cast(ICertificate, jsii.sinvoke(cls, "fromCertificateArn", [scope, id, certificate_arn]))

    @jsii.member(jsii_name="metricDaysToExpiry")
    def metric_days_to_expiry(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the DaysToExpiry metric for this AWS Certificate Manager Certificate. By default, this is the minimum value over 1 day.

        This metric is no longer emitted once the certificate has effectively
        expired, so alarms configured on this metric should probably treat missing
        data as "breaching".

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricDaysToExpiry", [props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> builtins.str:
        '''The certificate's ARN.'''
        return typing.cast(builtins.str, jsii.get(self, "certificateArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="region")
    def _region(self) -> typing.Optional[builtins.str]:
        '''If the certificate is provisionned in a different region than the containing stack, this should be the region in which the certificate lives so we can correctly create ``Metric`` instances.'''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "region"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_certificatemanager.PrivateCertificateProps",
    jsii_struct_bases=[],
    name_mapping={
        "certificate_authority": "certificateAuthority",
        "domain_name": "domainName",
        "subject_alternative_names": "subjectAlternativeNames",
    },
)
class PrivateCertificateProps:
    def __init__(
        self,
        *,
        certificate_authority: _ICertificateAuthority_26727cab,
        domain_name: builtins.str,
        subject_alternative_names: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for your private certificate.

        :param certificate_authority: Private certificate authority (CA) that will be used to issue the certificate.
        :param domain_name: Fully-qualified domain name to request a private certificate for. May contain wildcards, such as ``*.domain.com``.
        :param subject_alternative_names: Alternative domain names on your private certificate. Use this to register alternative domain names that represent the same site. Default: - No additional FQDNs will be included as alternative domain names.

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_acmpca as acmpca
            
            
            acm.PrivateCertificate(self, "PrivateCertificate",
                domain_name="test.example.com",
                subject_alternative_names=["cool.example.com", "test.example.net"],  # optional
                certificate_authority=acmpca.CertificateAuthority.from_certificate_authority_arn(self, "CA", "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/023077d8-2bfa-4eb0-8f22-05c96deade77")
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "certificate_authority": certificate_authority,
            "domain_name": domain_name,
        }
        if subject_alternative_names is not None:
            self._values["subject_alternative_names"] = subject_alternative_names

    @builtins.property
    def certificate_authority(self) -> _ICertificateAuthority_26727cab:
        '''Private certificate authority (CA) that will be used to issue the certificate.'''
        result = self._values.get("certificate_authority")
        assert result is not None, "Required property 'certificate_authority' is missing"
        return typing.cast(_ICertificateAuthority_26727cab, result)

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''Fully-qualified domain name to request a private certificate for.

        May contain wildcards, such as ``*.domain.com``.
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subject_alternative_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Alternative domain names on your private certificate.

        Use this to register alternative domain names that represent the same site.

        :default: - No additional FQDNs will be included as alternative domain names.
        '''
        result = self._values.get("subject_alternative_names")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PrivateCertificateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_certificatemanager.ValidationMethod")
class ValidationMethod(enum.Enum):
    '''Method used to assert ownership of the domain.'''

    EMAIL = "EMAIL"
    '''Send email to a number of email addresses associated with the domain.

    :see: https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-email.html
    '''
    DNS = "DNS"
    '''Validate ownership by adding appropriate DNS records.

    :see: https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-validate-dns.html
    '''


@jsii.implements(ICertificate)
class Certificate(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_certificatemanager.Certificate",
):
    '''A certificate managed by AWS Certificate Manager.

    :exampleMetadata: infused

    Example::

        pool = cognito.UserPool(self, "Pool")
        
        pool.add_domain("CognitoDomain",
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix="my-awesome-app"
            )
        )
        
        certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/11-3336f1-44483d-adc7-9cd375c5169d"
        
        domain_cert = certificatemanager.Certificate.from_certificate_arn(self, "domainCert", certificate_arn)
        pool.add_domain("CustomDomain",
            custom_domain=cognito.CustomDomainOptions(
                domain_name="user.myapp.com",
                certificate=domain_cert
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain_name: builtins.str,
        subject_alternative_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        validation: typing.Optional[CertificateValidation] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param domain_name: Fully-qualified domain name to request a certificate for. May contain wildcards, such as ``*.domain.com``.
        :param subject_alternative_names: Alternative domain names on your certificate. Use this to register alternative domain names that represent the same site. Default: - No additional FQDNs will be included as alternative domain names.
        :param validation: How to validate this certificate. Default: CertificateValidation.fromEmail()
        '''
        props = CertificateProps(
            domain_name=domain_name,
            subject_alternative_names=subject_alternative_names,
            validation=validation,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromCertificateArn") # type: ignore[misc]
    @builtins.classmethod
    def from_certificate_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        certificate_arn: builtins.str,
    ) -> ICertificate:
        '''Import a certificate.

        :param scope: -
        :param id: -
        :param certificate_arn: -
        '''
        return typing.cast(ICertificate, jsii.sinvoke(cls, "fromCertificateArn", [scope, id, certificate_arn]))

    @jsii.member(jsii_name="metricDaysToExpiry")
    def metric_days_to_expiry(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the DaysToExpiry metric for this AWS Certificate Manager Certificate. By default, this is the minimum value over 1 day.

        This metric is no longer emitted once the certificate has effectively
        expired, so alarms configured on this metric should probably treat missing
        data as "breaching".

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricDaysToExpiry", [props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> builtins.str:
        '''The certificate's ARN.'''
        return typing.cast(builtins.str, jsii.get(self, "certificateArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="region")
    def _region(self) -> typing.Optional[builtins.str]:
        '''If the certificate is provisionned in a different region than the containing stack, this should be the region in which the certificate lives so we can correctly create ``Metric`` instances.'''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "region"))


@jsii.implements(ICertificate, _ITaggable_36806126)
class DnsValidatedCertificate(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_certificatemanager.DnsValidatedCertificate",
):
    '''A certificate managed by AWS Certificate Manager.

    Will be automatically
    validated using DNS validation against the specified Route 53 hosted zone.

    :exampleMetadata: infused
    :resource: AWS::CertificateManager::Certificate

    Example::

        # my_hosted_zone: route53.HostedZone
        
        acm.DnsValidatedCertificate(self, "CrossRegionCertificate",
            domain_name="hello.example.com",
            hosted_zone=my_hosted_zone,
            region="us-east-1"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        hosted_zone: _IHostedZone_9a6907ad,
        cleanup_route53_records: typing.Optional[builtins.bool] = None,
        custom_resource_role: typing.Optional[_IRole_235f5d8e] = None,
        region: typing.Optional[builtins.str] = None,
        route53_endpoint: typing.Optional[builtins.str] = None,
        domain_name: builtins.str,
        subject_alternative_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        validation: typing.Optional[CertificateValidation] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param hosted_zone: Route 53 Hosted Zone used to perform DNS validation of the request. The zone must be authoritative for the domain name specified in the Certificate Request.
        :param cleanup_route53_records: When set to true, when the DnsValidatedCertificate is deleted, the associated Route53 validation records are removed. CAUTION: If multiple certificates share the same domains (and same validation records), this can cause the other certificates to fail renewal and/or not validate. Not recommended for production use. Default: false
        :param custom_resource_role: Role to use for the custom resource that creates the validated certificate. Default: - A new role will be created
        :param region: AWS region that will host the certificate. This is needed especially for certificates used for CloudFront distributions, which require the region to be us-east-1. Default: the region the stack is deployed in.
        :param route53_endpoint: An endpoint of Route53 service, which is not necessary as AWS SDK could figure out the right endpoints for most regions, but for some regions such as those in aws-cn partition, the default endpoint is not working now, hence the right endpoint need to be specified through this prop. Route53 is not been officially launched in China, it is only available for AWS internal accounts now. To make DnsValidatedCertificate work for internal accounts now, a special endpoint needs to be provided. Default: - The AWS SDK will determine the Route53 endpoint to use based on region
        :param domain_name: Fully-qualified domain name to request a certificate for. May contain wildcards, such as ``*.domain.com``.
        :param subject_alternative_names: Alternative domain names on your certificate. Use this to register alternative domain names that represent the same site. Default: - No additional FQDNs will be included as alternative domain names.
        :param validation: How to validate this certificate. Default: CertificateValidation.fromEmail()
        '''
        props = DnsValidatedCertificateProps(
            hosted_zone=hosted_zone,
            cleanup_route53_records=cleanup_route53_records,
            custom_resource_role=custom_resource_role,
            region=region,
            route53_endpoint=route53_endpoint,
            domain_name=domain_name,
            subject_alternative_names=subject_alternative_names,
            validation=validation,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="metricDaysToExpiry")
    def metric_days_to_expiry(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the DaysToExpiry metric for this AWS Certificate Manager Certificate. By default, this is the minimum value over 1 day.

        This metric is no longer emitted once the certificate has effectively
        expired, so alarms configured on this metric should probably treat missing
        data as "breaching".

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricDaysToExpiry", [props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> builtins.str:
        '''The certificate's ARN.'''
        return typing.cast(builtins.str, jsii.get(self, "certificateArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Resource Tags.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="region")
    def _region(self) -> typing.Optional[builtins.str]:
        '''If the certificate is provisionned in a different region than the containing stack, this should be the region in which the certificate lives so we can correctly create ``Metric`` instances.'''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "region"))


__all__ = [
    "Certificate",
    "CertificateProps",
    "CertificateValidation",
    "CertificationValidationProps",
    "CfnAccount",
    "CfnAccountProps",
    "CfnCertificate",
    "CfnCertificateProps",
    "DnsValidatedCertificate",
    "DnsValidatedCertificateProps",
    "ICertificate",
    "PrivateCertificate",
    "PrivateCertificateProps",
    "ValidationMethod",
]

publication.publish()
