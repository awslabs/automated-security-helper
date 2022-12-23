'''
# AWS Transfer for SFTP Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_transfer as transfer
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-transfer-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Transfer](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Transfer.html).

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
class CfnServer(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_transfer.CfnServer",
):
    '''A CloudFormation ``AWS::Transfer::Server``.

    Instantiates an auto-scaling virtual server based on the selected file transfer protocol in AWS . When you make updates to your file transfer protocol-enabled server or when you work with users, use the service-generated ``ServerId`` property that is assigned to the newly created server.

    :cloudformationResource: AWS::Transfer::Server
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_transfer as transfer
        
        cfn_server = transfer.CfnServer(self, "MyCfnServer",
            certificate="certificate",
            domain="domain",
            endpoint_details=transfer.CfnServer.EndpointDetailsProperty(
                address_allocation_ids=["addressAllocationIds"],
                security_group_ids=["securityGroupIds"],
                subnet_ids=["subnetIds"],
                vpc_endpoint_id="vpcEndpointId",
                vpc_id="vpcId"
            ),
            endpoint_type="endpointType",
            identity_provider_details=transfer.CfnServer.IdentityProviderDetailsProperty(
                directory_id="directoryId",
                function="function",
                invocation_role="invocationRole",
                url="url"
            ),
            identity_provider_type="identityProviderType",
            logging_role="loggingRole",
            post_authentication_login_banner="postAuthenticationLoginBanner",
            pre_authentication_login_banner="preAuthenticationLoginBanner",
            protocol_details=transfer.CfnServer.ProtocolDetailsProperty(
                passive_ip="passiveIp",
                tls_session_resumption_mode="tlsSessionResumptionMode"
            ),
            protocols=["protocols"],
            security_policy_name="securityPolicyName",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            workflow_details=transfer.CfnServer.WorkflowDetailsProperty(
                on_upload=[transfer.CfnServer.WorkflowDetailProperty(
                    execution_role="executionRole",
                    workflow_id="workflowId"
                )]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        certificate: typing.Optional[builtins.str] = None,
        domain: typing.Optional[builtins.str] = None,
        endpoint_details: typing.Optional[typing.Union["CfnServer.EndpointDetailsProperty", _IResolvable_da3f097b]] = None,
        endpoint_type: typing.Optional[builtins.str] = None,
        identity_provider_details: typing.Optional[typing.Union["CfnServer.IdentityProviderDetailsProperty", _IResolvable_da3f097b]] = None,
        identity_provider_type: typing.Optional[builtins.str] = None,
        logging_role: typing.Optional[builtins.str] = None,
        post_authentication_login_banner: typing.Optional[builtins.str] = None,
        pre_authentication_login_banner: typing.Optional[builtins.str] = None,
        protocol_details: typing.Optional[typing.Union["CfnServer.ProtocolDetailsProperty", _IResolvable_da3f097b]] = None,
        protocols: typing.Optional[typing.Sequence[builtins.str]] = None,
        security_policy_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        workflow_details: typing.Optional[typing.Union["CfnServer.WorkflowDetailsProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Transfer::Server``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param certificate: The Amazon Resource Name (ARN) of the AWS Certificate Manager (ACM) certificate. Required when ``Protocols`` is set to ``FTPS`` . To request a new public certificate, see `Request a public certificate <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html>`_ in the *AWS Certificate Manager User Guide* . To import an existing certificate into ACM, see `Importing certificates into ACM <https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html>`_ in the *AWS Certificate Manager User Guide* . To request a private certificate to use FTPS through private IP addresses, see `Request a private certificate <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-private.html>`_ in the *AWS Certificate Manager User Guide* . Certificates with the following cryptographic algorithms and key sizes are supported: - 2048-bit RSA (RSA_2048) - 4096-bit RSA (RSA_4096) - Elliptic Prime Curve 256 bit (EC_prime256v1) - Elliptic Prime Curve 384 bit (EC_secp384r1) - Elliptic Prime Curve 521 bit (EC_secp521r1) .. epigraph:: The certificate must be a valid SSL/TLS X.509 version 3 certificate with FQDN or IP address specified and information about the issuer.
        :param domain: Specifies the domain of the storage system that is used for file transfers.
        :param endpoint_details: The virtual private cloud (VPC) endpoint settings that are configured for your server. When you host your endpoint within your VPC, you can make it accessible only to resources within your VPC, or you can attach Elastic IP addresses and make it accessible to clients over the internet. Your VPC's default security groups are automatically assigned to your endpoint.
        :param endpoint_type: The type of endpoint that you want your server to use. You can choose to make your server's endpoint publicly accessible (PUBLIC) or host it inside your VPC. With an endpoint that is hosted in a VPC, you can restrict access to your server and resources only within your VPC or choose to make it internet facing by attaching Elastic IP addresses directly to it.
        :param identity_provider_details: Required when ``IdentityProviderType`` is set to ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` . Accepts an array containing all of the information required to use a directory in ``AWS_DIRECTORY_SERVICE`` or invoke a customer-supplied authentication API, including the API Gateway URL. Not required when ``IdentityProviderType`` is set to ``SERVICE_MANAGED`` .
        :param identity_provider_type: Specifies the mode of authentication for a server. The default value is ``SERVICE_MANAGED`` , which allows you to store and access user credentials within the AWS Transfer Family service. Use ``AWS_DIRECTORY_SERVICE`` to provide access to Active Directory groups in AWS Managed Active Directory or Microsoft Active Directory in your on-premises environment or in AWS using AD Connectors. This option also requires you to provide a Directory ID using the ``IdentityProviderDetails`` parameter. Use the ``API_GATEWAY`` value to integrate with an identity provider of your choosing. The ``API_GATEWAY`` setting requires you to provide an API Gateway endpoint URL to call for authentication using the ``IdentityProviderDetails`` parameter. Use the ``AWS_LAMBDA`` value to directly use a Lambda function as your identity provider. If you choose this value, you must specify the ARN for the lambda function in the ``Function`` parameter for the ``IdentityProviderDetails`` data type.
        :param logging_role: Specifies the Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows a server to turn on Amazon CloudWatch logging for Amazon S3 or Amazon EFS events. When set, user activity can be viewed in your CloudWatch logs.
        :param post_authentication_login_banner: Specify a string to display when users connect to a server. This string is displayed after the user authenticates. .. epigraph:: The SFTP protocol does not support post-authentication display banners.
        :param pre_authentication_login_banner: Specify a string to display when users connect to a server. This string is displayed before the user authenticates. For example, the following banner displays details about using the system. ``This system is for the use of authorized users only. Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.``
        :param protocol_details: The protocol settings that are configured for your server. Use the ``PassiveIp`` parameter to indicate passive mode (for FTP and FTPS protocols). Enter a single dotted-quad IPv4 address, such as the external IP address of a firewall, router, or load balancer. Use the ``TlsSessionResumptionMode`` parameter to determine whether or not your Transfer server resumes recent, negotiated sessions through a unique session ID.
        :param protocols: Specifies the file transfer protocol or protocols over which your file transfer protocol client can connect to your server's endpoint. The available protocols are: - ``SFTP`` (Secure Shell (SSH) File Transfer Protocol): File transfer over SSH - ``FTPS`` (File Transfer Protocol Secure): File transfer with TLS encryption - ``FTP`` (File Transfer Protocol): Unencrypted file transfer .. epigraph:: If you select ``FTPS`` , you must choose a certificate stored in AWS Certificate Manager (ACM) which is used to identify your server when clients connect to it over FTPS. If ``Protocol`` includes either ``FTP`` or ``FTPS`` , then the ``EndpointType`` must be ``VPC`` and the ``IdentityProviderType`` must be ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` . If ``Protocol`` includes ``FTP`` , then ``AddressAllocationIds`` cannot be associated. If ``Protocol`` is set only to ``SFTP`` , the ``EndpointType`` can be set to ``PUBLIC`` and the ``IdentityProviderType`` can be set to ``SERVICE_MANAGED`` .
        :param security_policy_name: Specifies the name of the security policy that is attached to the server.
        :param tags: Key-value pairs that can be used to group and search for servers.
        :param workflow_details: Specifies the workflow ID for the workflow to assign and the execution role used for executing the workflow.
        '''
        props = CfnServerProps(
            certificate=certificate,
            domain=domain,
            endpoint_details=endpoint_details,
            endpoint_type=endpoint_type,
            identity_provider_details=identity_provider_details,
            identity_provider_type=identity_provider_type,
            logging_role=logging_role,
            post_authentication_login_banner=post_authentication_login_banner,
            pre_authentication_login_banner=pre_authentication_login_banner,
            protocol_details=protocol_details,
            protocols=protocols,
            security_policy_name=security_policy_name,
            tags=tags,
            workflow_details=workflow_details,
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
        '''The Amazon Resource Name associated with the server, in the form ``arn:aws:transfer:region: *account-id* :server/ *server-id* /`` .

        An example of a server ARN is: ``arn:aws:transfer:us-east-1:123456789012:server/s-01234567890abcdef`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrServerId")
    def attr_server_id(self) -> builtins.str:
        '''The service-assigned ID of the server that is created.

        An example ``ServerId`` is ``s-01234567890abcdef`` .

        :cloudformationAttribute: ServerId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrServerId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Key-value pairs that can be used to group and search for servers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificate")
    def certificate(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the AWS Certificate Manager (ACM) certificate.

        Required when ``Protocols`` is set to ``FTPS`` .

        To request a new public certificate, see `Request a public certificate <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html>`_ in the *AWS Certificate Manager User Guide* .

        To import an existing certificate into ACM, see `Importing certificates into ACM <https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html>`_ in the *AWS Certificate Manager User Guide* .

        To request a private certificate to use FTPS through private IP addresses, see `Request a private certificate <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-private.html>`_ in the *AWS Certificate Manager User Guide* .

        Certificates with the following cryptographic algorithms and key sizes are supported:

        - 2048-bit RSA (RSA_2048)
        - 4096-bit RSA (RSA_4096)
        - Elliptic Prime Curve 256 bit (EC_prime256v1)
        - Elliptic Prime Curve 384 bit (EC_secp384r1)
        - Elliptic Prime Curve 521 bit (EC_secp521r1)

        .. epigraph::

           The certificate must be a valid SSL/TLS X.509 version 3 certificate with FQDN or IP address specified and information about the issuer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-certificate
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificate"))

    @certificate.setter
    def certificate(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "certificate", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domain")
    def domain(self) -> typing.Optional[builtins.str]:
        '''Specifies the domain of the storage system that is used for file transfers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-domain
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "domain"))

    @domain.setter
    def domain(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "domain", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="endpointDetails")
    def endpoint_details(
        self,
    ) -> typing.Optional[typing.Union["CfnServer.EndpointDetailsProperty", _IResolvable_da3f097b]]:
        '''The virtual private cloud (VPC) endpoint settings that are configured for your server.

        When you host your endpoint within your VPC, you can make it accessible only to resources within your VPC, or you can attach Elastic IP addresses and make it accessible to clients over the internet. Your VPC's default security groups are automatically assigned to your endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-endpointdetails
        '''
        return typing.cast(typing.Optional[typing.Union["CfnServer.EndpointDetailsProperty", _IResolvable_da3f097b]], jsii.get(self, "endpointDetails"))

    @endpoint_details.setter
    def endpoint_details(
        self,
        value: typing.Optional[typing.Union["CfnServer.EndpointDetailsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "endpointDetails", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="endpointType")
    def endpoint_type(self) -> typing.Optional[builtins.str]:
        '''The type of endpoint that you want your server to use.

        You can choose to make your server's endpoint publicly accessible (PUBLIC) or host it inside your VPC. With an endpoint that is hosted in a VPC, you can restrict access to your server and resources only within your VPC or choose to make it internet facing by attaching Elastic IP addresses directly to it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-endpointtype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "endpointType"))

    @endpoint_type.setter
    def endpoint_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "endpointType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="identityProviderDetails")
    def identity_provider_details(
        self,
    ) -> typing.Optional[typing.Union["CfnServer.IdentityProviderDetailsProperty", _IResolvable_da3f097b]]:
        '''Required when ``IdentityProviderType`` is set to ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` .

        Accepts an array containing all of the information required to use a directory in ``AWS_DIRECTORY_SERVICE`` or invoke a customer-supplied authentication API, including the API Gateway URL. Not required when ``IdentityProviderType`` is set to ``SERVICE_MANAGED`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-identityproviderdetails
        '''
        return typing.cast(typing.Optional[typing.Union["CfnServer.IdentityProviderDetailsProperty", _IResolvable_da3f097b]], jsii.get(self, "identityProviderDetails"))

    @identity_provider_details.setter
    def identity_provider_details(
        self,
        value: typing.Optional[typing.Union["CfnServer.IdentityProviderDetailsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "identityProviderDetails", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="identityProviderType")
    def identity_provider_type(self) -> typing.Optional[builtins.str]:
        '''Specifies the mode of authentication for a server.

        The default value is ``SERVICE_MANAGED`` , which allows you to store and access user credentials within the AWS Transfer Family service.

        Use ``AWS_DIRECTORY_SERVICE`` to provide access to Active Directory groups in AWS Managed Active Directory or Microsoft Active Directory in your on-premises environment or in AWS using AD Connectors. This option also requires you to provide a Directory ID using the ``IdentityProviderDetails`` parameter.

        Use the ``API_GATEWAY`` value to integrate with an identity provider of your choosing. The ``API_GATEWAY`` setting requires you to provide an API Gateway endpoint URL to call for authentication using the ``IdentityProviderDetails`` parameter.

        Use the ``AWS_LAMBDA`` value to directly use a Lambda function as your identity provider. If you choose this value, you must specify the ARN for the lambda function in the ``Function`` parameter for the ``IdentityProviderDetails`` data type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-identityprovidertype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "identityProviderType"))

    @identity_provider_type.setter
    def identity_provider_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "identityProviderType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loggingRole")
    def logging_role(self) -> typing.Optional[builtins.str]:
        '''Specifies the Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows a server to turn on Amazon CloudWatch logging for Amazon S3 or Amazon EFS events.

        When set, user activity can be viewed in your CloudWatch logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-loggingrole
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "loggingRole"))

    @logging_role.setter
    def logging_role(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "loggingRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="postAuthenticationLoginBanner")
    def post_authentication_login_banner(self) -> typing.Optional[builtins.str]:
        '''Specify a string to display when users connect to a server. This string is displayed after the user authenticates.

        .. epigraph::

           The SFTP protocol does not support post-authentication display banners.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-postauthenticationloginbanner
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "postAuthenticationLoginBanner"))

    @post_authentication_login_banner.setter
    def post_authentication_login_banner(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "postAuthenticationLoginBanner", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preAuthenticationLoginBanner")
    def pre_authentication_login_banner(self) -> typing.Optional[builtins.str]:
        '''Specify a string to display when users connect to a server.

        This string is displayed before the user authenticates. For example, the following banner displays details about using the system.

        ``This system is for the use of authorized users only. Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-preauthenticationloginbanner
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preAuthenticationLoginBanner"))

    @pre_authentication_login_banner.setter
    def pre_authentication_login_banner(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "preAuthenticationLoginBanner", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="protocolDetails")
    def protocol_details(
        self,
    ) -> typing.Optional[typing.Union["CfnServer.ProtocolDetailsProperty", _IResolvable_da3f097b]]:
        '''The protocol settings that are configured for your server.

        Use the ``PassiveIp`` parameter to indicate passive mode (for FTP and FTPS protocols). Enter a single dotted-quad IPv4 address, such as the external IP address of a firewall, router, or load balancer.

        Use the ``TlsSessionResumptionMode`` parameter to determine whether or not your Transfer server resumes recent, negotiated sessions through a unique session ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-protocoldetails
        '''
        return typing.cast(typing.Optional[typing.Union["CfnServer.ProtocolDetailsProperty", _IResolvable_da3f097b]], jsii.get(self, "protocolDetails"))

    @protocol_details.setter
    def protocol_details(
        self,
        value: typing.Optional[typing.Union["CfnServer.ProtocolDetailsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "protocolDetails", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="protocols")
    def protocols(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specifies the file transfer protocol or protocols over which your file transfer protocol client can connect to your server's endpoint.

        The available protocols are:

        - ``SFTP`` (Secure Shell (SSH) File Transfer Protocol): File transfer over SSH
        - ``FTPS`` (File Transfer Protocol Secure): File transfer with TLS encryption
        - ``FTP`` (File Transfer Protocol): Unencrypted file transfer

        .. epigraph::

           If you select ``FTPS`` , you must choose a certificate stored in AWS Certificate Manager (ACM) which is used to identify your server when clients connect to it over FTPS.

           If ``Protocol`` includes either ``FTP`` or ``FTPS`` , then the ``EndpointType`` must be ``VPC`` and the ``IdentityProviderType`` must be ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` .

           If ``Protocol`` includes ``FTP`` , then ``AddressAllocationIds`` cannot be associated.

           If ``Protocol`` is set only to ``SFTP`` , the ``EndpointType`` can be set to ``PUBLIC`` and the ``IdentityProviderType`` can be set to ``SERVICE_MANAGED`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-protocols
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "protocols"))

    @protocols.setter
    def protocols(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "protocols", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityPolicyName")
    def security_policy_name(self) -> typing.Optional[builtins.str]:
        '''Specifies the name of the security policy that is attached to the server.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-securitypolicyname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "securityPolicyName"))

    @security_policy_name.setter
    def security_policy_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "securityPolicyName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workflowDetails")
    def workflow_details(
        self,
    ) -> typing.Optional[typing.Union["CfnServer.WorkflowDetailsProperty", _IResolvable_da3f097b]]:
        '''Specifies the workflow ID for the workflow to assign and the execution role used for executing the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-workflowdetails
        '''
        return typing.cast(typing.Optional[typing.Union["CfnServer.WorkflowDetailsProperty", _IResolvable_da3f097b]], jsii.get(self, "workflowDetails"))

    @workflow_details.setter
    def workflow_details(
        self,
        value: typing.Optional[typing.Union["CfnServer.WorkflowDetailsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "workflowDetails", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_transfer.CfnServer.EndpointDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "address_allocation_ids": "addressAllocationIds",
            "security_group_ids": "securityGroupIds",
            "subnet_ids": "subnetIds",
            "vpc_endpoint_id": "vpcEndpointId",
            "vpc_id": "vpcId",
        },
    )
    class EndpointDetailsProperty:
        def __init__(
            self,
            *,
            address_allocation_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            vpc_endpoint_id: typing.Optional[builtins.str] = None,
            vpc_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The virtual private cloud (VPC) endpoint settings that are configured for your server.

            When you host your endpoint within your VPC, you can make it accessible only to resources within your VPC, or you can attach Elastic IP addresses and make it accessible to clients over the internet. Your VPC's default security groups are automatically assigned to your endpoint.

            :param address_allocation_ids: A list of address allocation IDs that are required to attach an Elastic IP address to your server's endpoint. .. epigraph:: This property can only be set when ``EndpointType`` is set to ``VPC`` and it is only valid in the ``UpdateServer`` API.
            :param security_group_ids: A list of security groups IDs that are available to attach to your server's endpoint. .. epigraph:: This property can only be set when ``EndpointType`` is set to ``VPC`` . You can edit the ``SecurityGroupIds`` property in the `UpdateServer <https://docs.aws.amazon.com/transfer/latest/userguide/API_UpdateServer.html>`_ API only if you are changing the ``EndpointType`` from ``PUBLIC`` or ``VPC_ENDPOINT`` to ``VPC`` . To change security groups associated with your server's VPC endpoint after creation, use the Amazon EC2 `ModifyVpcEndpoint <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVpcEndpoint.html>`_ API.
            :param subnet_ids: A list of subnet IDs that are required to host your server endpoint in your VPC. .. epigraph:: This property can only be set when ``EndpointType`` is set to ``VPC`` .
            :param vpc_endpoint_id: The ID of the VPC endpoint. .. epigraph:: This property can only be set when ``EndpointType`` is set to ``VPC_ENDPOINT`` .
            :param vpc_id: The VPC ID of the virtual private cloud in which the server's endpoint will be hosted. .. epigraph:: This property can only be set when ``EndpointType`` is set to ``VPC`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-endpointdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_transfer as transfer
                
                endpoint_details_property = transfer.CfnServer.EndpointDetailsProperty(
                    address_allocation_ids=["addressAllocationIds"],
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"],
                    vpc_endpoint_id="vpcEndpointId",
                    vpc_id="vpcId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if address_allocation_ids is not None:
                self._values["address_allocation_ids"] = address_allocation_ids
            if security_group_ids is not None:
                self._values["security_group_ids"] = security_group_ids
            if subnet_ids is not None:
                self._values["subnet_ids"] = subnet_ids
            if vpc_endpoint_id is not None:
                self._values["vpc_endpoint_id"] = vpc_endpoint_id
            if vpc_id is not None:
                self._values["vpc_id"] = vpc_id

        @builtins.property
        def address_allocation_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of address allocation IDs that are required to attach an Elastic IP address to your server's endpoint.

            .. epigraph::

               This property can only be set when ``EndpointType`` is set to ``VPC`` and it is only valid in the ``UpdateServer`` API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-endpointdetails.html#cfn-transfer-server-endpointdetails-addressallocationids
            '''
            result = self._values.get("address_allocation_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of security groups IDs that are available to attach to your server's endpoint.

            .. epigraph::

               This property can only be set when ``EndpointType`` is set to ``VPC`` .

               You can edit the ``SecurityGroupIds`` property in the `UpdateServer <https://docs.aws.amazon.com/transfer/latest/userguide/API_UpdateServer.html>`_ API only if you are changing the ``EndpointType`` from ``PUBLIC`` or ``VPC_ENDPOINT`` to ``VPC`` . To change security groups associated with your server's VPC endpoint after creation, use the Amazon EC2 `ModifyVpcEndpoint <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVpcEndpoint.html>`_ API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-endpointdetails.html#cfn-transfer-server-endpointdetails-securitygroupids
            '''
            result = self._values.get("security_group_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of subnet IDs that are required to host your server endpoint in your VPC.

            .. epigraph::

               This property can only be set when ``EndpointType`` is set to ``VPC`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-endpointdetails.html#cfn-transfer-server-endpointdetails-subnetids
            '''
            result = self._values.get("subnet_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def vpc_endpoint_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the VPC endpoint.

            .. epigraph::

               This property can only be set when ``EndpointType`` is set to ``VPC_ENDPOINT`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-endpointdetails.html#cfn-transfer-server-endpointdetails-vpcendpointid
            '''
            result = self._values.get("vpc_endpoint_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def vpc_id(self) -> typing.Optional[builtins.str]:
            '''The VPC ID of the virtual private cloud in which the server's endpoint will be hosted.

            .. epigraph::

               This property can only be set when ``EndpointType`` is set to ``VPC`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-endpointdetails.html#cfn-transfer-server-endpointdetails-vpcid
            '''
            result = self._values.get("vpc_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EndpointDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_transfer.CfnServer.IdentityProviderDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "directory_id": "directoryId",
            "function": "function",
            "invocation_role": "invocationRole",
            "url": "url",
        },
    )
    class IdentityProviderDetailsProperty:
        def __init__(
            self,
            *,
            directory_id: typing.Optional[builtins.str] = None,
            function: typing.Optional[builtins.str] = None,
            invocation_role: typing.Optional[builtins.str] = None,
            url: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Required when ``IdentityProviderType`` is set to ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` .

            Accepts an array containing all of the information required to use a directory in ``AWS_DIRECTORY_SERVICE`` or invoke a customer-supplied authentication API, including the API Gateway URL. Not required when ``IdentityProviderType`` is set to ``SERVICE_MANAGED`` .

            :param directory_id: The identifier of the AWS Directory Service directory that you want to stop sharing.
            :param function: The ARN for a lambda function to use for the Identity provider.
            :param invocation_role: Provides the type of ``InvocationRole`` used to authenticate the user account.
            :param url: Provides the location of the service endpoint used to authenticate users.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-identityproviderdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_transfer as transfer
                
                identity_provider_details_property = transfer.CfnServer.IdentityProviderDetailsProperty(
                    directory_id="directoryId",
                    function="function",
                    invocation_role="invocationRole",
                    url="url"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if directory_id is not None:
                self._values["directory_id"] = directory_id
            if function is not None:
                self._values["function"] = function
            if invocation_role is not None:
                self._values["invocation_role"] = invocation_role
            if url is not None:
                self._values["url"] = url

        @builtins.property
        def directory_id(self) -> typing.Optional[builtins.str]:
            '''The identifier of the AWS Directory Service directory that you want to stop sharing.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-identityproviderdetails.html#cfn-transfer-server-identityproviderdetails-directoryid
            '''
            result = self._values.get("directory_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def function(self) -> typing.Optional[builtins.str]:
            '''The ARN for a lambda function to use for the Identity provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-identityproviderdetails.html#cfn-transfer-server-identityproviderdetails-function
            '''
            result = self._values.get("function")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def invocation_role(self) -> typing.Optional[builtins.str]:
            '''Provides the type of ``InvocationRole`` used to authenticate the user account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-identityproviderdetails.html#cfn-transfer-server-identityproviderdetails-invocationrole
            '''
            result = self._values.get("invocation_role")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def url(self) -> typing.Optional[builtins.str]:
            '''Provides the location of the service endpoint used to authenticate users.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-identityproviderdetails.html#cfn-transfer-server-identityproviderdetails-url
            '''
            result = self._values.get("url")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IdentityProviderDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_transfer.CfnServer.ProtocolDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "passive_ip": "passiveIp",
            "tls_session_resumption_mode": "tlsSessionResumptionMode",
        },
    )
    class ProtocolDetailsProperty:
        def __init__(
            self,
            *,
            passive_ip: typing.Optional[builtins.str] = None,
            tls_session_resumption_mode: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Protocol settings that are configured for your server.

            :param passive_ip: Indicates passive mode, for FTP and FTPS protocols. Enter a single dotted-quad IPv4 address, such as the external IP address of a firewall, router, or load balancer.
            :param tls_session_resumption_mode: A property used with Transfer servers that use the FTPS protocol. TLS Session Resumption provides a mechanism to resume or share a negotiated secret key between the control and data connection for an FTPS session. ``TlsSessionResumptionMode`` determines whether or not the server resumes recent, negotiated sessions through a unique session ID. This property is available during ``CreateServer`` and ``UpdateServer`` calls. If a ``TlsSessionResumptionMode`` value is not specified during CreateServer, it is set to ``ENFORCED`` by default. - ``DISABLED`` : the server does not process TLS session resumption client requests and creates a new TLS session for each request. - ``ENABLED`` : the server processes and accepts clients that are performing TLS session resumption. The server doesn't reject client data connections that do not perform the TLS session resumption client processing. - ``ENFORCED`` : the server processes and accepts clients that are performing TLS session resumption. The server rejects client data connections that do not perform the TLS session resumption client processing. Before you set the value to ``ENFORCED`` , test your clients. .. epigraph:: Not all FTPS clients perform TLS session resumption. So, if you choose to enforce TLS session resumption, you prevent any connections from FTPS clients that don't perform the protocol negotiation. To determine whether or not you can use the ``ENFORCED`` value, you need to test your clients.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-protocoldetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_transfer as transfer
                
                protocol_details_property = transfer.CfnServer.ProtocolDetailsProperty(
                    passive_ip="passiveIp",
                    tls_session_resumption_mode="tlsSessionResumptionMode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if passive_ip is not None:
                self._values["passive_ip"] = passive_ip
            if tls_session_resumption_mode is not None:
                self._values["tls_session_resumption_mode"] = tls_session_resumption_mode

        @builtins.property
        def passive_ip(self) -> typing.Optional[builtins.str]:
            '''Indicates passive mode, for FTP and FTPS protocols.

            Enter a single dotted-quad IPv4 address, such as the external IP address of a firewall, router, or load balancer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-protocoldetails.html#cfn-transfer-server-protocoldetails-passiveip
            '''
            result = self._values.get("passive_ip")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tls_session_resumption_mode(self) -> typing.Optional[builtins.str]:
            '''A property used with Transfer servers that use the FTPS protocol.

            TLS Session Resumption provides a mechanism to resume or share a negotiated secret key between the control and data connection for an FTPS session. ``TlsSessionResumptionMode`` determines whether or not the server resumes recent, negotiated sessions through a unique session ID. This property is available during ``CreateServer`` and ``UpdateServer`` calls. If a ``TlsSessionResumptionMode`` value is not specified during CreateServer, it is set to ``ENFORCED`` by default.

            - ``DISABLED`` : the server does not process TLS session resumption client requests and creates a new TLS session for each request.
            - ``ENABLED`` : the server processes and accepts clients that are performing TLS session resumption. The server doesn't reject client data connections that do not perform the TLS session resumption client processing.
            - ``ENFORCED`` : the server processes and accepts clients that are performing TLS session resumption. The server rejects client data connections that do not perform the TLS session resumption client processing. Before you set the value to ``ENFORCED`` , test your clients.

            .. epigraph::

               Not all FTPS clients perform TLS session resumption. So, if you choose to enforce TLS session resumption, you prevent any connections from FTPS clients that don't perform the protocol negotiation. To determine whether or not you can use the ``ENFORCED`` value, you need to test your clients.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-protocoldetails.html#cfn-transfer-server-protocoldetails-tlssessionresumptionmode
            '''
            result = self._values.get("tls_session_resumption_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ProtocolDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_transfer.CfnServer.WorkflowDetailProperty",
        jsii_struct_bases=[],
        name_mapping={"execution_role": "executionRole", "workflow_id": "workflowId"},
    )
    class WorkflowDetailProperty:
        def __init__(
            self,
            *,
            execution_role: builtins.str,
            workflow_id: builtins.str,
        ) -> None:
            '''Specifies the workflow ID for the workflow to assign and the execution role used for executing the workflow.

            :param execution_role: Includes the necessary permissions for S3, EFS, and Lambda operations that Transfer can assume, so that all workflow steps can operate on the required resources.
            :param workflow_id: A unique identifier for the workflow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-workflowdetail.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_transfer as transfer
                
                workflow_detail_property = transfer.CfnServer.WorkflowDetailProperty(
                    execution_role="executionRole",
                    workflow_id="workflowId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "execution_role": execution_role,
                "workflow_id": workflow_id,
            }

        @builtins.property
        def execution_role(self) -> builtins.str:
            '''Includes the necessary permissions for S3, EFS, and Lambda operations that Transfer can assume, so that all workflow steps can operate on the required resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-workflowdetail.html#cfn-transfer-server-workflowdetail-executionrole
            '''
            result = self._values.get("execution_role")
            assert result is not None, "Required property 'execution_role' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def workflow_id(self) -> builtins.str:
            '''A unique identifier for the workflow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-workflowdetail.html#cfn-transfer-server-workflowdetail-workflowid
            '''
            result = self._values.get("workflow_id")
            assert result is not None, "Required property 'workflow_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "WorkflowDetailProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_transfer.CfnServer.WorkflowDetailsProperty",
        jsii_struct_bases=[],
        name_mapping={"on_upload": "onUpload"},
    )
    class WorkflowDetailsProperty:
        def __init__(
            self,
            *,
            on_upload: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnServer.WorkflowDetailProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Container for the ``WorkflowDetail`` data type.

            It is used by actions that trigger a workflow to begin execution.

            :param on_upload: A trigger that starts a workflow: the workflow begins to execute after a file is uploaded.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-workflowdetails.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_transfer as transfer
                
                workflow_details_property = transfer.CfnServer.WorkflowDetailsProperty(
                    on_upload=[transfer.CfnServer.WorkflowDetailProperty(
                        execution_role="executionRole",
                        workflow_id="workflowId"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "on_upload": on_upload,
            }

        @builtins.property
        def on_upload(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnServer.WorkflowDetailProperty", _IResolvable_da3f097b]]]:
            '''A trigger that starts a workflow: the workflow begins to execute after a file is uploaded.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-server-workflowdetails.html#cfn-transfer-server-workflowdetails-onupload
            '''
            result = self._values.get("on_upload")
            assert result is not None, "Required property 'on_upload' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnServer.WorkflowDetailProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "WorkflowDetailsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_transfer.CfnServerProps",
    jsii_struct_bases=[],
    name_mapping={
        "certificate": "certificate",
        "domain": "domain",
        "endpoint_details": "endpointDetails",
        "endpoint_type": "endpointType",
        "identity_provider_details": "identityProviderDetails",
        "identity_provider_type": "identityProviderType",
        "logging_role": "loggingRole",
        "post_authentication_login_banner": "postAuthenticationLoginBanner",
        "pre_authentication_login_banner": "preAuthenticationLoginBanner",
        "protocol_details": "protocolDetails",
        "protocols": "protocols",
        "security_policy_name": "securityPolicyName",
        "tags": "tags",
        "workflow_details": "workflowDetails",
    },
)
class CfnServerProps:
    def __init__(
        self,
        *,
        certificate: typing.Optional[builtins.str] = None,
        domain: typing.Optional[builtins.str] = None,
        endpoint_details: typing.Optional[typing.Union[CfnServer.EndpointDetailsProperty, _IResolvable_da3f097b]] = None,
        endpoint_type: typing.Optional[builtins.str] = None,
        identity_provider_details: typing.Optional[typing.Union[CfnServer.IdentityProviderDetailsProperty, _IResolvable_da3f097b]] = None,
        identity_provider_type: typing.Optional[builtins.str] = None,
        logging_role: typing.Optional[builtins.str] = None,
        post_authentication_login_banner: typing.Optional[builtins.str] = None,
        pre_authentication_login_banner: typing.Optional[builtins.str] = None,
        protocol_details: typing.Optional[typing.Union[CfnServer.ProtocolDetailsProperty, _IResolvable_da3f097b]] = None,
        protocols: typing.Optional[typing.Sequence[builtins.str]] = None,
        security_policy_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        workflow_details: typing.Optional[typing.Union[CfnServer.WorkflowDetailsProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnServer``.

        :param certificate: The Amazon Resource Name (ARN) of the AWS Certificate Manager (ACM) certificate. Required when ``Protocols`` is set to ``FTPS`` . To request a new public certificate, see `Request a public certificate <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html>`_ in the *AWS Certificate Manager User Guide* . To import an existing certificate into ACM, see `Importing certificates into ACM <https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html>`_ in the *AWS Certificate Manager User Guide* . To request a private certificate to use FTPS through private IP addresses, see `Request a private certificate <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-private.html>`_ in the *AWS Certificate Manager User Guide* . Certificates with the following cryptographic algorithms and key sizes are supported: - 2048-bit RSA (RSA_2048) - 4096-bit RSA (RSA_4096) - Elliptic Prime Curve 256 bit (EC_prime256v1) - Elliptic Prime Curve 384 bit (EC_secp384r1) - Elliptic Prime Curve 521 bit (EC_secp521r1) .. epigraph:: The certificate must be a valid SSL/TLS X.509 version 3 certificate with FQDN or IP address specified and information about the issuer.
        :param domain: Specifies the domain of the storage system that is used for file transfers.
        :param endpoint_details: The virtual private cloud (VPC) endpoint settings that are configured for your server. When you host your endpoint within your VPC, you can make it accessible only to resources within your VPC, or you can attach Elastic IP addresses and make it accessible to clients over the internet. Your VPC's default security groups are automatically assigned to your endpoint.
        :param endpoint_type: The type of endpoint that you want your server to use. You can choose to make your server's endpoint publicly accessible (PUBLIC) or host it inside your VPC. With an endpoint that is hosted in a VPC, you can restrict access to your server and resources only within your VPC or choose to make it internet facing by attaching Elastic IP addresses directly to it.
        :param identity_provider_details: Required when ``IdentityProviderType`` is set to ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` . Accepts an array containing all of the information required to use a directory in ``AWS_DIRECTORY_SERVICE`` or invoke a customer-supplied authentication API, including the API Gateway URL. Not required when ``IdentityProviderType`` is set to ``SERVICE_MANAGED`` .
        :param identity_provider_type: Specifies the mode of authentication for a server. The default value is ``SERVICE_MANAGED`` , which allows you to store and access user credentials within the AWS Transfer Family service. Use ``AWS_DIRECTORY_SERVICE`` to provide access to Active Directory groups in AWS Managed Active Directory or Microsoft Active Directory in your on-premises environment or in AWS using AD Connectors. This option also requires you to provide a Directory ID using the ``IdentityProviderDetails`` parameter. Use the ``API_GATEWAY`` value to integrate with an identity provider of your choosing. The ``API_GATEWAY`` setting requires you to provide an API Gateway endpoint URL to call for authentication using the ``IdentityProviderDetails`` parameter. Use the ``AWS_LAMBDA`` value to directly use a Lambda function as your identity provider. If you choose this value, you must specify the ARN for the lambda function in the ``Function`` parameter for the ``IdentityProviderDetails`` data type.
        :param logging_role: Specifies the Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows a server to turn on Amazon CloudWatch logging for Amazon S3 or Amazon EFS events. When set, user activity can be viewed in your CloudWatch logs.
        :param post_authentication_login_banner: Specify a string to display when users connect to a server. This string is displayed after the user authenticates. .. epigraph:: The SFTP protocol does not support post-authentication display banners.
        :param pre_authentication_login_banner: Specify a string to display when users connect to a server. This string is displayed before the user authenticates. For example, the following banner displays details about using the system. ``This system is for the use of authorized users only. Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.``
        :param protocol_details: The protocol settings that are configured for your server. Use the ``PassiveIp`` parameter to indicate passive mode (for FTP and FTPS protocols). Enter a single dotted-quad IPv4 address, such as the external IP address of a firewall, router, or load balancer. Use the ``TlsSessionResumptionMode`` parameter to determine whether or not your Transfer server resumes recent, negotiated sessions through a unique session ID.
        :param protocols: Specifies the file transfer protocol or protocols over which your file transfer protocol client can connect to your server's endpoint. The available protocols are: - ``SFTP`` (Secure Shell (SSH) File Transfer Protocol): File transfer over SSH - ``FTPS`` (File Transfer Protocol Secure): File transfer with TLS encryption - ``FTP`` (File Transfer Protocol): Unencrypted file transfer .. epigraph:: If you select ``FTPS`` , you must choose a certificate stored in AWS Certificate Manager (ACM) which is used to identify your server when clients connect to it over FTPS. If ``Protocol`` includes either ``FTP`` or ``FTPS`` , then the ``EndpointType`` must be ``VPC`` and the ``IdentityProviderType`` must be ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` . If ``Protocol`` includes ``FTP`` , then ``AddressAllocationIds`` cannot be associated. If ``Protocol`` is set only to ``SFTP`` , the ``EndpointType`` can be set to ``PUBLIC`` and the ``IdentityProviderType`` can be set to ``SERVICE_MANAGED`` .
        :param security_policy_name: Specifies the name of the security policy that is attached to the server.
        :param tags: Key-value pairs that can be used to group and search for servers.
        :param workflow_details: Specifies the workflow ID for the workflow to assign and the execution role used for executing the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_transfer as transfer
            
            cfn_server_props = transfer.CfnServerProps(
                certificate="certificate",
                domain="domain",
                endpoint_details=transfer.CfnServer.EndpointDetailsProperty(
                    address_allocation_ids=["addressAllocationIds"],
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"],
                    vpc_endpoint_id="vpcEndpointId",
                    vpc_id="vpcId"
                ),
                endpoint_type="endpointType",
                identity_provider_details=transfer.CfnServer.IdentityProviderDetailsProperty(
                    directory_id="directoryId",
                    function="function",
                    invocation_role="invocationRole",
                    url="url"
                ),
                identity_provider_type="identityProviderType",
                logging_role="loggingRole",
                post_authentication_login_banner="postAuthenticationLoginBanner",
                pre_authentication_login_banner="preAuthenticationLoginBanner",
                protocol_details=transfer.CfnServer.ProtocolDetailsProperty(
                    passive_ip="passiveIp",
                    tls_session_resumption_mode="tlsSessionResumptionMode"
                ),
                protocols=["protocols"],
                security_policy_name="securityPolicyName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                workflow_details=transfer.CfnServer.WorkflowDetailsProperty(
                    on_upload=[transfer.CfnServer.WorkflowDetailProperty(
                        execution_role="executionRole",
                        workflow_id="workflowId"
                    )]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if certificate is not None:
            self._values["certificate"] = certificate
        if domain is not None:
            self._values["domain"] = domain
        if endpoint_details is not None:
            self._values["endpoint_details"] = endpoint_details
        if endpoint_type is not None:
            self._values["endpoint_type"] = endpoint_type
        if identity_provider_details is not None:
            self._values["identity_provider_details"] = identity_provider_details
        if identity_provider_type is not None:
            self._values["identity_provider_type"] = identity_provider_type
        if logging_role is not None:
            self._values["logging_role"] = logging_role
        if post_authentication_login_banner is not None:
            self._values["post_authentication_login_banner"] = post_authentication_login_banner
        if pre_authentication_login_banner is not None:
            self._values["pre_authentication_login_banner"] = pre_authentication_login_banner
        if protocol_details is not None:
            self._values["protocol_details"] = protocol_details
        if protocols is not None:
            self._values["protocols"] = protocols
        if security_policy_name is not None:
            self._values["security_policy_name"] = security_policy_name
        if tags is not None:
            self._values["tags"] = tags
        if workflow_details is not None:
            self._values["workflow_details"] = workflow_details

    @builtins.property
    def certificate(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the AWS Certificate Manager (ACM) certificate.

        Required when ``Protocols`` is set to ``FTPS`` .

        To request a new public certificate, see `Request a public certificate <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html>`_ in the *AWS Certificate Manager User Guide* .

        To import an existing certificate into ACM, see `Importing certificates into ACM <https://docs.aws.amazon.com/acm/latest/userguide/import-certificate.html>`_ in the *AWS Certificate Manager User Guide* .

        To request a private certificate to use FTPS through private IP addresses, see `Request a private certificate <https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-private.html>`_ in the *AWS Certificate Manager User Guide* .

        Certificates with the following cryptographic algorithms and key sizes are supported:

        - 2048-bit RSA (RSA_2048)
        - 4096-bit RSA (RSA_4096)
        - Elliptic Prime Curve 256 bit (EC_prime256v1)
        - Elliptic Prime Curve 384 bit (EC_secp384r1)
        - Elliptic Prime Curve 521 bit (EC_secp521r1)

        .. epigraph::

           The certificate must be a valid SSL/TLS X.509 version 3 certificate with FQDN or IP address specified and information about the issuer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-certificate
        '''
        result = self._values.get("certificate")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def domain(self) -> typing.Optional[builtins.str]:
        '''Specifies the domain of the storage system that is used for file transfers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-domain
        '''
        result = self._values.get("domain")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def endpoint_details(
        self,
    ) -> typing.Optional[typing.Union[CfnServer.EndpointDetailsProperty, _IResolvable_da3f097b]]:
        '''The virtual private cloud (VPC) endpoint settings that are configured for your server.

        When you host your endpoint within your VPC, you can make it accessible only to resources within your VPC, or you can attach Elastic IP addresses and make it accessible to clients over the internet. Your VPC's default security groups are automatically assigned to your endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-endpointdetails
        '''
        result = self._values.get("endpoint_details")
        return typing.cast(typing.Optional[typing.Union[CfnServer.EndpointDetailsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def endpoint_type(self) -> typing.Optional[builtins.str]:
        '''The type of endpoint that you want your server to use.

        You can choose to make your server's endpoint publicly accessible (PUBLIC) or host it inside your VPC. With an endpoint that is hosted in a VPC, you can restrict access to your server and resources only within your VPC or choose to make it internet facing by attaching Elastic IP addresses directly to it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-endpointtype
        '''
        result = self._values.get("endpoint_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def identity_provider_details(
        self,
    ) -> typing.Optional[typing.Union[CfnServer.IdentityProviderDetailsProperty, _IResolvable_da3f097b]]:
        '''Required when ``IdentityProviderType`` is set to ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` .

        Accepts an array containing all of the information required to use a directory in ``AWS_DIRECTORY_SERVICE`` or invoke a customer-supplied authentication API, including the API Gateway URL. Not required when ``IdentityProviderType`` is set to ``SERVICE_MANAGED`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-identityproviderdetails
        '''
        result = self._values.get("identity_provider_details")
        return typing.cast(typing.Optional[typing.Union[CfnServer.IdentityProviderDetailsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def identity_provider_type(self) -> typing.Optional[builtins.str]:
        '''Specifies the mode of authentication for a server.

        The default value is ``SERVICE_MANAGED`` , which allows you to store and access user credentials within the AWS Transfer Family service.

        Use ``AWS_DIRECTORY_SERVICE`` to provide access to Active Directory groups in AWS Managed Active Directory or Microsoft Active Directory in your on-premises environment or in AWS using AD Connectors. This option also requires you to provide a Directory ID using the ``IdentityProviderDetails`` parameter.

        Use the ``API_GATEWAY`` value to integrate with an identity provider of your choosing. The ``API_GATEWAY`` setting requires you to provide an API Gateway endpoint URL to call for authentication using the ``IdentityProviderDetails`` parameter.

        Use the ``AWS_LAMBDA`` value to directly use a Lambda function as your identity provider. If you choose this value, you must specify the ARN for the lambda function in the ``Function`` parameter for the ``IdentityProviderDetails`` data type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-identityprovidertype
        '''
        result = self._values.get("identity_provider_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def logging_role(self) -> typing.Optional[builtins.str]:
        '''Specifies the Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows a server to turn on Amazon CloudWatch logging for Amazon S3 or Amazon EFS events.

        When set, user activity can be viewed in your CloudWatch logs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-loggingrole
        '''
        result = self._values.get("logging_role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def post_authentication_login_banner(self) -> typing.Optional[builtins.str]:
        '''Specify a string to display when users connect to a server. This string is displayed after the user authenticates.

        .. epigraph::

           The SFTP protocol does not support post-authentication display banners.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-postauthenticationloginbanner
        '''
        result = self._values.get("post_authentication_login_banner")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def pre_authentication_login_banner(self) -> typing.Optional[builtins.str]:
        '''Specify a string to display when users connect to a server.

        This string is displayed before the user authenticates. For example, the following banner displays details about using the system.

        ``This system is for the use of authorized users only. Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-preauthenticationloginbanner
        '''
        result = self._values.get("pre_authentication_login_banner")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def protocol_details(
        self,
    ) -> typing.Optional[typing.Union[CfnServer.ProtocolDetailsProperty, _IResolvable_da3f097b]]:
        '''The protocol settings that are configured for your server.

        Use the ``PassiveIp`` parameter to indicate passive mode (for FTP and FTPS protocols). Enter a single dotted-quad IPv4 address, such as the external IP address of a firewall, router, or load balancer.

        Use the ``TlsSessionResumptionMode`` parameter to determine whether or not your Transfer server resumes recent, negotiated sessions through a unique session ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-protocoldetails
        '''
        result = self._values.get("protocol_details")
        return typing.cast(typing.Optional[typing.Union[CfnServer.ProtocolDetailsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def protocols(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specifies the file transfer protocol or protocols over which your file transfer protocol client can connect to your server's endpoint.

        The available protocols are:

        - ``SFTP`` (Secure Shell (SSH) File Transfer Protocol): File transfer over SSH
        - ``FTPS`` (File Transfer Protocol Secure): File transfer with TLS encryption
        - ``FTP`` (File Transfer Protocol): Unencrypted file transfer

        .. epigraph::

           If you select ``FTPS`` , you must choose a certificate stored in AWS Certificate Manager (ACM) which is used to identify your server when clients connect to it over FTPS.

           If ``Protocol`` includes either ``FTP`` or ``FTPS`` , then the ``EndpointType`` must be ``VPC`` and the ``IdentityProviderType`` must be ``AWS_DIRECTORY_SERVICE`` or ``API_GATEWAY`` .

           If ``Protocol`` includes ``FTP`` , then ``AddressAllocationIds`` cannot be associated.

           If ``Protocol`` is set only to ``SFTP`` , the ``EndpointType`` can be set to ``PUBLIC`` and the ``IdentityProviderType`` can be set to ``SERVICE_MANAGED`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-protocols
        '''
        result = self._values.get("protocols")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def security_policy_name(self) -> typing.Optional[builtins.str]:
        '''Specifies the name of the security policy that is attached to the server.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-securitypolicyname
        '''
        result = self._values.get("security_policy_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Key-value pairs that can be used to group and search for servers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def workflow_details(
        self,
    ) -> typing.Optional[typing.Union[CfnServer.WorkflowDetailsProperty, _IResolvable_da3f097b]]:
        '''Specifies the workflow ID for the workflow to assign and the execution role used for executing the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-workflowdetails
        '''
        result = self._values.get("workflow_details")
        return typing.cast(typing.Optional[typing.Union[CfnServer.WorkflowDetailsProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnServerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUser(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_transfer.CfnUser",
):
    '''A CloudFormation ``AWS::Transfer::User``.

    The ``AWS::Transfer::User`` resource creates a user and associates them with an existing server. You can only create and associate users with servers that have the ``IdentityProviderType`` set to ``SERVICE_MANAGED`` . Using parameters for ``CreateUser`` , you can specify the user name, set the home directory, store the user's public key, and assign the user's AWS Identity and Access Management (IAM) role. You can also optionally add a session policy, and assign metadata with tags that can be used to group and search for users.

    :cloudformationResource: AWS::Transfer::User
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_transfer as transfer
        
        cfn_user = transfer.CfnUser(self, "MyCfnUser",
            role="role",
            server_id="serverId",
            user_name="userName",
        
            # the properties below are optional
            home_directory="homeDirectory",
            home_directory_mappings=[transfer.CfnUser.HomeDirectoryMapEntryProperty(
                entry="entry",
                target="target"
            )],
            home_directory_type="homeDirectoryType",
            policy="policy",
            posix_profile=transfer.CfnUser.PosixProfileProperty(
                gid=123,
                uid=123,
        
                # the properties below are optional
                secondary_gids=[123]
            ),
            ssh_public_keys=["sshPublicKeys"],
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
        role: builtins.str,
        server_id: builtins.str,
        user_name: builtins.str,
        home_directory: typing.Optional[builtins.str] = None,
        home_directory_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnUser.HomeDirectoryMapEntryProperty", _IResolvable_da3f097b]]]] = None,
        home_directory_type: typing.Optional[builtins.str] = None,
        policy: typing.Optional[builtins.str] = None,
        posix_profile: typing.Optional[typing.Union["CfnUser.PosixProfileProperty", _IResolvable_da3f097b]] = None,
        ssh_public_keys: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Transfer::User``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param role: Specifies the Amazon Resource Name (ARN) of the IAM role that controls your users' access to your Amazon S3 bucket or EFS file system. The policies attached to this role determine the level of access that you want to provide your users when transferring files into and out of your Amazon S3 bucket or EFS file system. The IAM role should also contain a trust relationship that allows the server to access your resources when servicing your users' transfer requests.
        :param server_id: A system-assigned unique identifier for a server instance. This is the specific server that you added your user to.
        :param user_name: A unique string that identifies a user and is associated with a ``ServerId`` . This user name must be a minimum of 3 and a maximum of 100 characters long. The following are valid characters: a-z, A-Z, 0-9, underscore '_', hyphen '-', period '.', and at sign '@'. The user name can't start with a hyphen, period, or at sign.
        :param home_directory: The landing directory (folder) for a user when they log in to the server using the client. A ``HomeDirectory`` example is ``/bucket_name/home/mydirectory`` .
        :param home_directory_mappings: Logical directory mappings that specify what Amazon S3 paths and keys should be visible to your user and how you want to make them visible. You will need to specify the " ``Entry`` " and " ``Target`` " pair, where ``Entry`` shows how the path is made visible and ``Target`` is the actual Amazon S3 path. If you only specify a target, it will be displayed as is. You will need to also make sure that your IAM role provides access to paths in ``Target`` . The following is an example. ``'[ { "Entry": "/", "Target": "/bucket3/customized-reports/" } ]'`` In most cases, you can use this value instead of the session policy to lock your user down to the designated home directory ("chroot"). To do this, you can set ``Entry`` to '/' and set ``Target`` to the HomeDirectory parameter value. .. epigraph:: If the target of a logical directory entry does not exist in Amazon S3, the entry will be ignored. As a workaround, you can use the Amazon S3 API to create 0 byte objects as place holders for your directory. If using the CLI, use the ``s3api`` call instead of ``s3`` so you can use the put-object operation. For example, you use the following: ``AWS s3api put-object --bucket bucketname --key path/to/folder/`` . Make sure that the end of the key name ends in a '/' for it to be considered a folder.
        :param home_directory_type: The type of landing directory (folder) you want your users' home directory to be when they log into the server. If you set it to ``PATH`` , the user will see the absolute Amazon S3 bucket or EFS paths as is in their file transfer protocol clients. If you set it ``LOGICAL`` , you need to provide mappings in the ``HomeDirectoryMappings`` for how you want to make Amazon S3 or EFS paths visible to your users.
        :param policy: A session policy for your user so you can use the same IAM role across multiple users. This policy restricts user access to portions of their Amazon S3 bucket. Variables that you can use inside this policy include ``${Transfer:UserName}`` , ``${Transfer:HomeDirectory}`` , and ``${Transfer:HomeBucket}`` . .. epigraph:: For session policies, AWS Transfer Family stores the policy as a JSON blob, instead of the Amazon Resource Name (ARN) of the policy. You save the policy as a JSON blob and pass it in the ``Policy`` argument. For an example of a session policy, see `Example session policy <https://docs.aws.amazon.com/transfer/latest/userguide/session-policy.html>`_ . For more information, see `AssumeRole <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html>`_ in the *AWS Security Token Service API Reference* .
        :param posix_profile: Specifies the full POSIX identity, including user ID ( ``Uid`` ), group ID ( ``Gid`` ), and any secondary groups IDs ( ``SecondaryGids`` ), that controls your users' access to your Amazon Elastic File System (Amazon EFS) file systems. The POSIX permissions that are set on files and directories in your file system determine the level of access your users get when transferring files into and out of your Amazon EFS file systems.
        :param ssh_public_keys: Specifies the public key portion of the Secure Shell (SSH) keys stored for the described user.
        :param tags: Key-value pairs that can be used to group and search for users. Tags are metadata attached to users for any purpose.
        '''
        props = CfnUserProps(
            role=role,
            server_id=server_id,
            user_name=user_name,
            home_directory=home_directory,
            home_directory_mappings=home_directory_mappings,
            home_directory_type=home_directory_type,
            policy=policy,
            posix_profile=posix_profile,
            ssh_public_keys=ssh_public_keys,
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
        '''The Amazon Resource Name associated with the user, in the form ``arn:aws:transfer:region: *account-id* :user/ *server-id* / *username*`` .

        An example of a user ARN is: ``arn:aws:transfer:us-east-1:123456789012:user/user1`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrServerId")
    def attr_server_id(self) -> builtins.str:
        '''The ID of the server to which the user is attached.

        An example ``ServerId`` is ``s-01234567890abcdef`` .

        :cloudformationAttribute: ServerId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrServerId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrUserName")
    def attr_user_name(self) -> builtins.str:
        '''A unique string that identifies a user account associated with a server.

        An example ``UserName`` is ``transfer-user-1`` .

        :cloudformationAttribute: UserName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrUserName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Key-value pairs that can be used to group and search for users.

        Tags are metadata attached to users for any purpose.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> builtins.str:
        '''Specifies the Amazon Resource Name (ARN) of the IAM role that controls your users' access to your Amazon S3 bucket or EFS file system.

        The policies attached to this role determine the level of access that you want to provide your users when transferring files into and out of your Amazon S3 bucket or EFS file system. The IAM role should also contain a trust relationship that allows the server to access your resources when servicing your users' transfer requests.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-role
        '''
        return typing.cast(builtins.str, jsii.get(self, "role"))

    @role.setter
    def role(self, value: builtins.str) -> None:
        jsii.set(self, "role", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serverId")
    def server_id(self) -> builtins.str:
        '''A system-assigned unique identifier for a server instance.

        This is the specific server that you added your user to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-serverid
        '''
        return typing.cast(builtins.str, jsii.get(self, "serverId"))

    @server_id.setter
    def server_id(self, value: builtins.str) -> None:
        jsii.set(self, "serverId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> builtins.str:
        '''A unique string that identifies a user and is associated with a ``ServerId`` .

        This user name must be a minimum of 3 and a maximum of 100 characters long. The following are valid characters: a-z, A-Z, 0-9, underscore '_', hyphen '-', period '.', and at sign '@'. The user name can't start with a hyphen, period, or at sign.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-username
        '''
        return typing.cast(builtins.str, jsii.get(self, "userName"))

    @user_name.setter
    def user_name(self, value: builtins.str) -> None:
        jsii.set(self, "userName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="homeDirectory")
    def home_directory(self) -> typing.Optional[builtins.str]:
        '''The landing directory (folder) for a user when they log in to the server using the client.

        A ``HomeDirectory`` example is ``/bucket_name/home/mydirectory`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-homedirectory
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "homeDirectory"))

    @home_directory.setter
    def home_directory(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "homeDirectory", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="homeDirectoryMappings")
    def home_directory_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUser.HomeDirectoryMapEntryProperty", _IResolvable_da3f097b]]]]:
        '''Logical directory mappings that specify what Amazon S3 paths and keys should be visible to your user and how you want to make them visible.

        You will need to specify the " ``Entry`` " and " ``Target`` " pair, where ``Entry`` shows how the path is made visible and ``Target`` is the actual Amazon S3 path. If you only specify a target, it will be displayed as is. You will need to also make sure that your IAM role provides access to paths in ``Target`` . The following is an example.

        ``'[ { "Entry": "/", "Target": "/bucket3/customized-reports/" } ]'``

        In most cases, you can use this value instead of the session policy to lock your user down to the designated home directory ("chroot"). To do this, you can set ``Entry`` to '/' and set ``Target`` to the HomeDirectory parameter value.
        .. epigraph::

           If the target of a logical directory entry does not exist in Amazon S3, the entry will be ignored. As a workaround, you can use the Amazon S3 API to create 0 byte objects as place holders for your directory. If using the CLI, use the ``s3api`` call instead of ``s3`` so you can use the put-object operation. For example, you use the following: ``AWS s3api put-object --bucket bucketname --key path/to/folder/`` . Make sure that the end of the key name ends in a '/' for it to be considered a folder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-homedirectorymappings
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUser.HomeDirectoryMapEntryProperty", _IResolvable_da3f097b]]]], jsii.get(self, "homeDirectoryMappings"))

    @home_directory_mappings.setter
    def home_directory_mappings(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUser.HomeDirectoryMapEntryProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "homeDirectoryMappings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="homeDirectoryType")
    def home_directory_type(self) -> typing.Optional[builtins.str]:
        '''The type of landing directory (folder) you want your users' home directory to be when they log into the server.

        If you set it to ``PATH`` , the user will see the absolute Amazon S3 bucket or EFS paths as is in their file transfer protocol clients. If you set it ``LOGICAL`` , you need to provide mappings in the ``HomeDirectoryMappings`` for how you want to make Amazon S3 or EFS paths visible to your users.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-homedirectorytype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "homeDirectoryType"))

    @home_directory_type.setter
    def home_directory_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "homeDirectoryType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    def policy(self) -> typing.Optional[builtins.str]:
        '''A session policy for your user so you can use the same IAM role across multiple users.

        This policy restricts user access to portions of their Amazon S3 bucket. Variables that you can use inside this policy include ``${Transfer:UserName}`` , ``${Transfer:HomeDirectory}`` , and ``${Transfer:HomeBucket}`` .
        .. epigraph::

           For session policies, AWS Transfer Family stores the policy as a JSON blob, instead of the Amazon Resource Name (ARN) of the policy. You save the policy as a JSON blob and pass it in the ``Policy`` argument.

           For an example of a session policy, see `Example session policy <https://docs.aws.amazon.com/transfer/latest/userguide/session-policy.html>`_ .

           For more information, see `AssumeRole <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html>`_ in the *AWS Security Token Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-policy
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "policy"))

    @policy.setter
    def policy(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "policy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="posixProfile")
    def posix_profile(
        self,
    ) -> typing.Optional[typing.Union["CfnUser.PosixProfileProperty", _IResolvable_da3f097b]]:
        '''Specifies the full POSIX identity, including user ID ( ``Uid`` ), group ID ( ``Gid`` ), and any secondary groups IDs ( ``SecondaryGids`` ), that controls your users' access to your Amazon Elastic File System (Amazon EFS) file systems.

        The POSIX permissions that are set on files and directories in your file system determine the level of access your users get when transferring files into and out of your Amazon EFS file systems.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-posixprofile
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUser.PosixProfileProperty", _IResolvable_da3f097b]], jsii.get(self, "posixProfile"))

    @posix_profile.setter
    def posix_profile(
        self,
        value: typing.Optional[typing.Union["CfnUser.PosixProfileProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "posixProfile", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sshPublicKeys")
    def ssh_public_keys(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specifies the public key portion of the Secure Shell (SSH) keys stored for the described user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-sshpublickeys
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "sshPublicKeys"))

    @ssh_public_keys.setter
    def ssh_public_keys(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "sshPublicKeys", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_transfer.CfnUser.HomeDirectoryMapEntryProperty",
        jsii_struct_bases=[],
        name_mapping={"entry": "entry", "target": "target"},
    )
    class HomeDirectoryMapEntryProperty:
        def __init__(self, *, entry: builtins.str, target: builtins.str) -> None:
            '''Represents an object that contains entries and targets for ``HomeDirectoryMappings`` .

            :param entry: Represents an entry for ``HomeDirectoryMappings`` .
            :param target: Represents the map target that is used in a ``HomeDirectorymapEntry`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-user-homedirectorymapentry.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_transfer as transfer
                
                home_directory_map_entry_property = transfer.CfnUser.HomeDirectoryMapEntryProperty(
                    entry="entry",
                    target="target"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "entry": entry,
                "target": target,
            }

        @builtins.property
        def entry(self) -> builtins.str:
            '''Represents an entry for ``HomeDirectoryMappings`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-user-homedirectorymapentry.html#cfn-transfer-user-homedirectorymapentry-entry
            '''
            result = self._values.get("entry")
            assert result is not None, "Required property 'entry' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def target(self) -> builtins.str:
            '''Represents the map target that is used in a ``HomeDirectorymapEntry`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-user-homedirectorymapentry.html#cfn-transfer-user-homedirectorymapentry-target
            '''
            result = self._values.get("target")
            assert result is not None, "Required property 'target' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HomeDirectoryMapEntryProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_transfer.CfnUser.PosixProfileProperty",
        jsii_struct_bases=[],
        name_mapping={"gid": "gid", "uid": "uid", "secondary_gids": "secondaryGids"},
    )
    class PosixProfileProperty:
        def __init__(
            self,
            *,
            gid: jsii.Number,
            uid: jsii.Number,
            secondary_gids: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[jsii.Number]]] = None,
        ) -> None:
            '''The full POSIX identity, including user ID ( ``Uid`` ), group ID ( ``Gid`` ), and any secondary groups IDs ( ``SecondaryGids`` ), that controls your users' access to your Amazon EFS file systems.

            The POSIX permissions that are set on files and directories in your file system determine the level of access your users get when transferring files into and out of your Amazon EFS file systems.

            :param gid: The POSIX group ID used for all EFS operations by this user.
            :param uid: The POSIX user ID used for all EFS operations by this user.
            :param secondary_gids: The secondary POSIX group IDs used for all EFS operations by this user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-user-posixprofile.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_transfer as transfer
                
                posix_profile_property = transfer.CfnUser.PosixProfileProperty(
                    gid=123,
                    uid=123,
                
                    # the properties below are optional
                    secondary_gids=[123]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "gid": gid,
                "uid": uid,
            }
            if secondary_gids is not None:
                self._values["secondary_gids"] = secondary_gids

        @builtins.property
        def gid(self) -> jsii.Number:
            '''The POSIX group ID used for all EFS operations by this user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-user-posixprofile.html#cfn-transfer-user-posixprofile-gid
            '''
            result = self._values.get("gid")
            assert result is not None, "Required property 'gid' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def uid(self) -> jsii.Number:
            '''The POSIX user ID used for all EFS operations by this user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-user-posixprofile.html#cfn-transfer-user-posixprofile-uid
            '''
            result = self._values.get("uid")
            assert result is not None, "Required property 'uid' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def secondary_gids(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]]]:
            '''The secondary POSIX group IDs used for all EFS operations by this user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-user-posixprofile.html#cfn-transfer-user-posixprofile-secondarygids
            '''
            result = self._values.get("secondary_gids")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[jsii.Number]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PosixProfileProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_transfer.CfnUserProps",
    jsii_struct_bases=[],
    name_mapping={
        "role": "role",
        "server_id": "serverId",
        "user_name": "userName",
        "home_directory": "homeDirectory",
        "home_directory_mappings": "homeDirectoryMappings",
        "home_directory_type": "homeDirectoryType",
        "policy": "policy",
        "posix_profile": "posixProfile",
        "ssh_public_keys": "sshPublicKeys",
        "tags": "tags",
    },
)
class CfnUserProps:
    def __init__(
        self,
        *,
        role: builtins.str,
        server_id: builtins.str,
        user_name: builtins.str,
        home_directory: typing.Optional[builtins.str] = None,
        home_directory_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnUser.HomeDirectoryMapEntryProperty, _IResolvable_da3f097b]]]] = None,
        home_directory_type: typing.Optional[builtins.str] = None,
        policy: typing.Optional[builtins.str] = None,
        posix_profile: typing.Optional[typing.Union[CfnUser.PosixProfileProperty, _IResolvable_da3f097b]] = None,
        ssh_public_keys: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUser``.

        :param role: Specifies the Amazon Resource Name (ARN) of the IAM role that controls your users' access to your Amazon S3 bucket or EFS file system. The policies attached to this role determine the level of access that you want to provide your users when transferring files into and out of your Amazon S3 bucket or EFS file system. The IAM role should also contain a trust relationship that allows the server to access your resources when servicing your users' transfer requests.
        :param server_id: A system-assigned unique identifier for a server instance. This is the specific server that you added your user to.
        :param user_name: A unique string that identifies a user and is associated with a ``ServerId`` . This user name must be a minimum of 3 and a maximum of 100 characters long. The following are valid characters: a-z, A-Z, 0-9, underscore '_', hyphen '-', period '.', and at sign '@'. The user name can't start with a hyphen, period, or at sign.
        :param home_directory: The landing directory (folder) for a user when they log in to the server using the client. A ``HomeDirectory`` example is ``/bucket_name/home/mydirectory`` .
        :param home_directory_mappings: Logical directory mappings that specify what Amazon S3 paths and keys should be visible to your user and how you want to make them visible. You will need to specify the " ``Entry`` " and " ``Target`` " pair, where ``Entry`` shows how the path is made visible and ``Target`` is the actual Amazon S3 path. If you only specify a target, it will be displayed as is. You will need to also make sure that your IAM role provides access to paths in ``Target`` . The following is an example. ``'[ { "Entry": "/", "Target": "/bucket3/customized-reports/" } ]'`` In most cases, you can use this value instead of the session policy to lock your user down to the designated home directory ("chroot"). To do this, you can set ``Entry`` to '/' and set ``Target`` to the HomeDirectory parameter value. .. epigraph:: If the target of a logical directory entry does not exist in Amazon S3, the entry will be ignored. As a workaround, you can use the Amazon S3 API to create 0 byte objects as place holders for your directory. If using the CLI, use the ``s3api`` call instead of ``s3`` so you can use the put-object operation. For example, you use the following: ``AWS s3api put-object --bucket bucketname --key path/to/folder/`` . Make sure that the end of the key name ends in a '/' for it to be considered a folder.
        :param home_directory_type: The type of landing directory (folder) you want your users' home directory to be when they log into the server. If you set it to ``PATH`` , the user will see the absolute Amazon S3 bucket or EFS paths as is in their file transfer protocol clients. If you set it ``LOGICAL`` , you need to provide mappings in the ``HomeDirectoryMappings`` for how you want to make Amazon S3 or EFS paths visible to your users.
        :param policy: A session policy for your user so you can use the same IAM role across multiple users. This policy restricts user access to portions of their Amazon S3 bucket. Variables that you can use inside this policy include ``${Transfer:UserName}`` , ``${Transfer:HomeDirectory}`` , and ``${Transfer:HomeBucket}`` . .. epigraph:: For session policies, AWS Transfer Family stores the policy as a JSON blob, instead of the Amazon Resource Name (ARN) of the policy. You save the policy as a JSON blob and pass it in the ``Policy`` argument. For an example of a session policy, see `Example session policy <https://docs.aws.amazon.com/transfer/latest/userguide/session-policy.html>`_ . For more information, see `AssumeRole <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html>`_ in the *AWS Security Token Service API Reference* .
        :param posix_profile: Specifies the full POSIX identity, including user ID ( ``Uid`` ), group ID ( ``Gid`` ), and any secondary groups IDs ( ``SecondaryGids`` ), that controls your users' access to your Amazon Elastic File System (Amazon EFS) file systems. The POSIX permissions that are set on files and directories in your file system determine the level of access your users get when transferring files into and out of your Amazon EFS file systems.
        :param ssh_public_keys: Specifies the public key portion of the Secure Shell (SSH) keys stored for the described user.
        :param tags: Key-value pairs that can be used to group and search for users. Tags are metadata attached to users for any purpose.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_transfer as transfer
            
            cfn_user_props = transfer.CfnUserProps(
                role="role",
                server_id="serverId",
                user_name="userName",
            
                # the properties below are optional
                home_directory="homeDirectory",
                home_directory_mappings=[transfer.CfnUser.HomeDirectoryMapEntryProperty(
                    entry="entry",
                    target="target"
                )],
                home_directory_type="homeDirectoryType",
                policy="policy",
                posix_profile=transfer.CfnUser.PosixProfileProperty(
                    gid=123,
                    uid=123,
            
                    # the properties below are optional
                    secondary_gids=[123]
                ),
                ssh_public_keys=["sshPublicKeys"],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "role": role,
            "server_id": server_id,
            "user_name": user_name,
        }
        if home_directory is not None:
            self._values["home_directory"] = home_directory
        if home_directory_mappings is not None:
            self._values["home_directory_mappings"] = home_directory_mappings
        if home_directory_type is not None:
            self._values["home_directory_type"] = home_directory_type
        if policy is not None:
            self._values["policy"] = policy
        if posix_profile is not None:
            self._values["posix_profile"] = posix_profile
        if ssh_public_keys is not None:
            self._values["ssh_public_keys"] = ssh_public_keys
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def role(self) -> builtins.str:
        '''Specifies the Amazon Resource Name (ARN) of the IAM role that controls your users' access to your Amazon S3 bucket or EFS file system.

        The policies attached to this role determine the level of access that you want to provide your users when transferring files into and out of your Amazon S3 bucket or EFS file system. The IAM role should also contain a trust relationship that allows the server to access your resources when servicing your users' transfer requests.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-role
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def server_id(self) -> builtins.str:
        '''A system-assigned unique identifier for a server instance.

        This is the specific server that you added your user to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-serverid
        '''
        result = self._values.get("server_id")
        assert result is not None, "Required property 'server_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_name(self) -> builtins.str:
        '''A unique string that identifies a user and is associated with a ``ServerId`` .

        This user name must be a minimum of 3 and a maximum of 100 characters long. The following are valid characters: a-z, A-Z, 0-9, underscore '_', hyphen '-', period '.', and at sign '@'. The user name can't start with a hyphen, period, or at sign.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-username
        '''
        result = self._values.get("user_name")
        assert result is not None, "Required property 'user_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def home_directory(self) -> typing.Optional[builtins.str]:
        '''The landing directory (folder) for a user when they log in to the server using the client.

        A ``HomeDirectory`` example is ``/bucket_name/home/mydirectory`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-homedirectory
        '''
        result = self._values.get("home_directory")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def home_directory_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUser.HomeDirectoryMapEntryProperty, _IResolvable_da3f097b]]]]:
        '''Logical directory mappings that specify what Amazon S3 paths and keys should be visible to your user and how you want to make them visible.

        You will need to specify the " ``Entry`` " and " ``Target`` " pair, where ``Entry`` shows how the path is made visible and ``Target`` is the actual Amazon S3 path. If you only specify a target, it will be displayed as is. You will need to also make sure that your IAM role provides access to paths in ``Target`` . The following is an example.

        ``'[ { "Entry": "/", "Target": "/bucket3/customized-reports/" } ]'``

        In most cases, you can use this value instead of the session policy to lock your user down to the designated home directory ("chroot"). To do this, you can set ``Entry`` to '/' and set ``Target`` to the HomeDirectory parameter value.
        .. epigraph::

           If the target of a logical directory entry does not exist in Amazon S3, the entry will be ignored. As a workaround, you can use the Amazon S3 API to create 0 byte objects as place holders for your directory. If using the CLI, use the ``s3api`` call instead of ``s3`` so you can use the put-object operation. For example, you use the following: ``AWS s3api put-object --bucket bucketname --key path/to/folder/`` . Make sure that the end of the key name ends in a '/' for it to be considered a folder.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-homedirectorymappings
        '''
        result = self._values.get("home_directory_mappings")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUser.HomeDirectoryMapEntryProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def home_directory_type(self) -> typing.Optional[builtins.str]:
        '''The type of landing directory (folder) you want your users' home directory to be when they log into the server.

        If you set it to ``PATH`` , the user will see the absolute Amazon S3 bucket or EFS paths as is in their file transfer protocol clients. If you set it ``LOGICAL`` , you need to provide mappings in the ``HomeDirectoryMappings`` for how you want to make Amazon S3 or EFS paths visible to your users.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-homedirectorytype
        '''
        result = self._values.get("home_directory_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def policy(self) -> typing.Optional[builtins.str]:
        '''A session policy for your user so you can use the same IAM role across multiple users.

        This policy restricts user access to portions of their Amazon S3 bucket. Variables that you can use inside this policy include ``${Transfer:UserName}`` , ``${Transfer:HomeDirectory}`` , and ``${Transfer:HomeBucket}`` .
        .. epigraph::

           For session policies, AWS Transfer Family stores the policy as a JSON blob, instead of the Amazon Resource Name (ARN) of the policy. You save the policy as a JSON blob and pass it in the ``Policy`` argument.

           For an example of a session policy, see `Example session policy <https://docs.aws.amazon.com/transfer/latest/userguide/session-policy.html>`_ .

           For more information, see `AssumeRole <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html>`_ in the *AWS Security Token Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-policy
        '''
        result = self._values.get("policy")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def posix_profile(
        self,
    ) -> typing.Optional[typing.Union[CfnUser.PosixProfileProperty, _IResolvable_da3f097b]]:
        '''Specifies the full POSIX identity, including user ID ( ``Uid`` ), group ID ( ``Gid`` ), and any secondary groups IDs ( ``SecondaryGids`` ), that controls your users' access to your Amazon Elastic File System (Amazon EFS) file systems.

        The POSIX permissions that are set on files and directories in your file system determine the level of access your users get when transferring files into and out of your Amazon EFS file systems.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-posixprofile
        '''
        result = self._values.get("posix_profile")
        return typing.cast(typing.Optional[typing.Union[CfnUser.PosixProfileProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def ssh_public_keys(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specifies the public key portion of the Secure Shell (SSH) keys stored for the described user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-sshpublickeys
        '''
        result = self._values.get("ssh_public_keys")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Key-value pairs that can be used to group and search for users.

        Tags are metadata attached to users for any purpose.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-user.html#cfn-transfer-user-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnWorkflow(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_transfer.CfnWorkflow",
):
    '''A CloudFormation ``AWS::Transfer::Workflow``.

    Allows you to create a workflow with specified steps and step details the workflow invokes after file transfer completes. After creating a workflow, you can associate the workflow created with any transfer servers by specifying the ``workflow-details`` field in ``CreateServer`` and ``UpdateServer`` operations.

    :cloudformationResource: AWS::Transfer::Workflow
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_transfer as transfer
        
        # copy_step_details: Any
        # custom_step_details: Any
        # delete_step_details: Any
        # tag_step_details: Any
        
        cfn_workflow = transfer.CfnWorkflow(self, "MyCfnWorkflow",
            steps=[transfer.CfnWorkflow.WorkflowStepProperty(
                copy_step_details=copy_step_details,
                custom_step_details=custom_step_details,
                delete_step_details=delete_step_details,
                tag_step_details=tag_step_details,
                type="type"
            )],
        
            # the properties below are optional
            description="description",
            on_exception_steps=[transfer.CfnWorkflow.WorkflowStepProperty(
                copy_step_details=copy_step_details,
                custom_step_details=custom_step_details,
                delete_step_details=delete_step_details,
                tag_step_details=tag_step_details,
                type="type"
            )],
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
        steps: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWorkflow.WorkflowStepProperty", _IResolvable_da3f097b]]],
        description: typing.Optional[builtins.str] = None,
        on_exception_steps: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnWorkflow.WorkflowStepProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Transfer::Workflow``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param steps: Specifies the details for the steps that are in the specified workflow.
        :param description: Specifies the text description for the workflow.
        :param on_exception_steps: Specifies the steps (actions) to take if errors are encountered during execution of the workflow.
        :param tags: Key-value pairs that can be used to group and search for workflows. Tags are metadata attached to workflows for any purpose.
        '''
        props = CfnWorkflowProps(
            steps=steps,
            description=description,
            on_exception_steps=on_exception_steps,
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
        '''
        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrWorkflowId")
    def attr_workflow_id(self) -> builtins.str:
        '''A unique identifier for a workflow.

        :cloudformationAttribute: WorkflowId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrWorkflowId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Key-value pairs that can be used to group and search for workflows.

        Tags are metadata attached to workflows for any purpose.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html#cfn-transfer-workflow-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="steps")
    def steps(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWorkflow.WorkflowStepProperty", _IResolvable_da3f097b]]]:
        '''Specifies the details for the steps that are in the specified workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html#cfn-transfer-workflow-steps
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWorkflow.WorkflowStepProperty", _IResolvable_da3f097b]]], jsii.get(self, "steps"))

    @steps.setter
    def steps(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWorkflow.WorkflowStepProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "steps", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''Specifies the text description for the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html#cfn-transfer-workflow-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="onExceptionSteps")
    def on_exception_steps(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWorkflow.WorkflowStepProperty", _IResolvable_da3f097b]]]]:
        '''Specifies the steps (actions) to take if errors are encountered during execution of the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html#cfn-transfer-workflow-onexceptionsteps
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWorkflow.WorkflowStepProperty", _IResolvable_da3f097b]]]], jsii.get(self, "onExceptionSteps"))

    @on_exception_steps.setter
    def on_exception_steps(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnWorkflow.WorkflowStepProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "onExceptionSteps", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_transfer.CfnWorkflow.WorkflowStepProperty",
        jsii_struct_bases=[],
        name_mapping={
            "copy_step_details": "copyStepDetails",
            "custom_step_details": "customStepDetails",
            "delete_step_details": "deleteStepDetails",
            "tag_step_details": "tagStepDetails",
            "type": "type",
        },
    )
    class WorkflowStepProperty:
        def __init__(
            self,
            *,
            copy_step_details: typing.Any = None,
            custom_step_details: typing.Any = None,
            delete_step_details: typing.Any = None,
            tag_step_details: typing.Any = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The basic building block of a workflow.

            :param copy_step_details: Details for a step that performs a file copy. Consists of the following values: - A description - An S3 location for the destination of the file copy. - A flag that indicates whether or not to overwrite an existing file of the same name. The default is ``FALSE`` .
            :param custom_step_details: Details for a step that invokes a lambda function. Consists of the lambda function name, target, and timeout (in seconds).
            :param delete_step_details: Details for a step that deletes the file.
            :param tag_step_details: Details for a step that creates one or more tags. You specify one or more tags: each tag contains a key/value pair.
            :param type: Currently, the following step types are supported. - *Copy* : copy the file to another location - *Custom* : custom step with a lambda target - *Delete* : delete the file - *Tag* : add a tag to the file

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-workflow-workflowstep.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_transfer as transfer
                
                # copy_step_details: Any
                # custom_step_details: Any
                # delete_step_details: Any
                # tag_step_details: Any
                
                workflow_step_property = transfer.CfnWorkflow.WorkflowStepProperty(
                    copy_step_details=copy_step_details,
                    custom_step_details=custom_step_details,
                    delete_step_details=delete_step_details,
                    tag_step_details=tag_step_details,
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if copy_step_details is not None:
                self._values["copy_step_details"] = copy_step_details
            if custom_step_details is not None:
                self._values["custom_step_details"] = custom_step_details
            if delete_step_details is not None:
                self._values["delete_step_details"] = delete_step_details
            if tag_step_details is not None:
                self._values["tag_step_details"] = tag_step_details
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def copy_step_details(self) -> typing.Any:
            '''Details for a step that performs a file copy.

            Consists of the following values:

            - A description
            - An S3 location for the destination of the file copy.
            - A flag that indicates whether or not to overwrite an existing file of the same name. The default is ``FALSE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-workflow-workflowstep.html#cfn-transfer-workflow-workflowstep-copystepdetails
            '''
            result = self._values.get("copy_step_details")
            return typing.cast(typing.Any, result)

        @builtins.property
        def custom_step_details(self) -> typing.Any:
            '''Details for a step that invokes a lambda function.

            Consists of the lambda function name, target, and timeout (in seconds).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-workflow-workflowstep.html#cfn-transfer-workflow-workflowstep-customstepdetails
            '''
            result = self._values.get("custom_step_details")
            return typing.cast(typing.Any, result)

        @builtins.property
        def delete_step_details(self) -> typing.Any:
            '''Details for a step that deletes the file.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-workflow-workflowstep.html#cfn-transfer-workflow-workflowstep-deletestepdetails
            '''
            result = self._values.get("delete_step_details")
            return typing.cast(typing.Any, result)

        @builtins.property
        def tag_step_details(self) -> typing.Any:
            '''Details for a step that creates one or more tags.

            You specify one or more tags: each tag contains a key/value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-workflow-workflowstep.html#cfn-transfer-workflow-workflowstep-tagstepdetails
            '''
            result = self._values.get("tag_step_details")
            return typing.cast(typing.Any, result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''Currently, the following step types are supported.

            - *Copy* : copy the file to another location
            - *Custom* : custom step with a lambda target
            - *Delete* : delete the file
            - *Tag* : add a tag to the file

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-transfer-workflow-workflowstep.html#cfn-transfer-workflow-workflowstep-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "WorkflowStepProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_transfer.CfnWorkflowProps",
    jsii_struct_bases=[],
    name_mapping={
        "steps": "steps",
        "description": "description",
        "on_exception_steps": "onExceptionSteps",
        "tags": "tags",
    },
)
class CfnWorkflowProps:
    def __init__(
        self,
        *,
        steps: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnWorkflow.WorkflowStepProperty, _IResolvable_da3f097b]]],
        description: typing.Optional[builtins.str] = None,
        on_exception_steps: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnWorkflow.WorkflowStepProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnWorkflow``.

        :param steps: Specifies the details for the steps that are in the specified workflow.
        :param description: Specifies the text description for the workflow.
        :param on_exception_steps: Specifies the steps (actions) to take if errors are encountered during execution of the workflow.
        :param tags: Key-value pairs that can be used to group and search for workflows. Tags are metadata attached to workflows for any purpose.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_transfer as transfer
            
            # copy_step_details: Any
            # custom_step_details: Any
            # delete_step_details: Any
            # tag_step_details: Any
            
            cfn_workflow_props = transfer.CfnWorkflowProps(
                steps=[transfer.CfnWorkflow.WorkflowStepProperty(
                    copy_step_details=copy_step_details,
                    custom_step_details=custom_step_details,
                    delete_step_details=delete_step_details,
                    tag_step_details=tag_step_details,
                    type="type"
                )],
            
                # the properties below are optional
                description="description",
                on_exception_steps=[transfer.CfnWorkflow.WorkflowStepProperty(
                    copy_step_details=copy_step_details,
                    custom_step_details=custom_step_details,
                    delete_step_details=delete_step_details,
                    tag_step_details=tag_step_details,
                    type="type"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "steps": steps,
        }
        if description is not None:
            self._values["description"] = description
        if on_exception_steps is not None:
            self._values["on_exception_steps"] = on_exception_steps
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def steps(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnWorkflow.WorkflowStepProperty, _IResolvable_da3f097b]]]:
        '''Specifies the details for the steps that are in the specified workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html#cfn-transfer-workflow-steps
        '''
        result = self._values.get("steps")
        assert result is not None, "Required property 'steps' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnWorkflow.WorkflowStepProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''Specifies the text description for the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html#cfn-transfer-workflow-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def on_exception_steps(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnWorkflow.WorkflowStepProperty, _IResolvable_da3f097b]]]]:
        '''Specifies the steps (actions) to take if errors are encountered during execution of the workflow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html#cfn-transfer-workflow-onexceptionsteps
        '''
        result = self._values.get("on_exception_steps")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnWorkflow.WorkflowStepProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Key-value pairs that can be used to group and search for workflows.

        Tags are metadata attached to workflows for any purpose.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-workflow.html#cfn-transfer-workflow-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnWorkflowProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnServer",
    "CfnServerProps",
    "CfnUser",
    "CfnUserProps",
    "CfnWorkflow",
    "CfnWorkflowProps",
]

publication.publish()
