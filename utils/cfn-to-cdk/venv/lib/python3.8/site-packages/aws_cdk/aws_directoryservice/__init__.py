'''
# AWS Directory Service Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_directoryservice as directoryservice
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-directoryservice-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::DirectoryService](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_DirectoryService.html).

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
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnMicrosoftAD(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_directoryservice.CfnMicrosoftAD",
):
    '''A CloudFormation ``AWS::DirectoryService::MicrosoftAD``.

    The ``AWS::DirectoryService::MicrosoftAD`` resource specifies a Microsoft Active Directory in AWS so that your directory users and groups can access the AWS Management Console and AWS applications using their existing credentials. For more information, see `AWS Managed Microsoft AD <https://docs.aws.amazon.com/directoryservice/latest/admin-guide/directory_microsoft_ad.html>`_ in the *AWS Directory Service Admin Guide* .

    :cloudformationResource: AWS::DirectoryService::MicrosoftAD
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_directoryservice as directoryservice
        
        cfn_microsoft_aD = directoryservice.CfnMicrosoftAD(self, "MyCfnMicrosoftAD",
            name="name",
            password="password",
            vpc_settings=directoryservice.CfnMicrosoftAD.VpcSettingsProperty(
                subnet_ids=["subnetIds"],
                vpc_id="vpcId"
            ),
        
            # the properties below are optional
            create_alias=False,
            edition="edition",
            enable_sso=False,
            short_name="shortName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        password: builtins.str,
        vpc_settings: typing.Union["CfnMicrosoftAD.VpcSettingsProperty", _IResolvable_da3f097b],
        create_alias: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        edition: typing.Optional[builtins.str] = None,
        enable_sso: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        short_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::DirectoryService::MicrosoftAD``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The fully qualified domain name for the AWS Managed Microsoft AD directory, such as ``corp.example.com`` . This name will resolve inside your VPC only. It does not need to be publicly resolvable.
        :param password: The password for the default administrative user named ``Admin`` . If you need to change the password for the administrator account, see the `ResetUserPassword <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ResetUserPassword.html>`_ API call in the *AWS Directory Service API Reference* .
        :param vpc_settings: Specifies the VPC settings of the Microsoft AD directory server in AWS .
        :param create_alias: Specifies an alias for a directory and assigns the alias to the directory. The alias is used to construct the access URL for the directory, such as ``http://<alias>.awsapps.com`` . By default, AWS CloudFormation does not create an alias. .. epigraph:: After an alias has been created, it cannot be deleted or reused, so this operation should only be used when absolutely necessary.
        :param edition: AWS Managed Microsoft AD is available in two editions: ``Standard`` and ``Enterprise`` . ``Enterprise`` is the default.
        :param enable_sso: Whether to enable single sign-on for a Microsoft Active Directory in AWS . Single sign-on allows users in your directory to access certain AWS services from a computer joined to the directory without having to enter their credentials separately. If you don't specify a value, AWS CloudFormation disables single sign-on by default.
        :param short_name: The NetBIOS name for your domain, such as ``CORP`` . If you don't specify a NetBIOS name, it will default to the first part of your directory DNS. For example, ``CORP`` for the directory DNS ``corp.example.com`` .
        '''
        props = CfnMicrosoftADProps(
            name=name,
            password=password,
            vpc_settings=vpc_settings,
            create_alias=create_alias,
            edition=edition,
            enable_sso=enable_sso,
            short_name=short_name,
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
    @jsii.member(jsii_name="attrAlias")
    def attr_alias(self) -> builtins.str:
        '''The alias for a directory.

        For example: ``d-12373a053a`` or ``alias4-mydirectory-12345abcgmzsk`` (if you have the ``CreateAlias`` property set to true).

        :cloudformationAttribute: Alias
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAlias"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDnsIpAddresses")
    def attr_dns_ip_addresses(self) -> typing.List[builtins.str]:
        '''The IP addresses of the DNS servers for the directory, such as ``[ "192.0.2.1", "192.0.2.2" ]`` .

        :cloudformationAttribute: DnsIpAddresses
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrDnsIpAddresses"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The fully qualified domain name for the AWS Managed Microsoft AD directory, such as ``corp.example.com`` . This name will resolve inside your VPC only. It does not need to be publicly resolvable.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="password")
    def password(self) -> builtins.str:
        '''The password for the default administrative user named ``Admin`` .

        If you need to change the password for the administrator account, see the `ResetUserPassword <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ResetUserPassword.html>`_ API call in the *AWS Directory Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-password
        '''
        return typing.cast(builtins.str, jsii.get(self, "password"))

    @password.setter
    def password(self, value: builtins.str) -> None:
        jsii.set(self, "password", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcSettings")
    def vpc_settings(
        self,
    ) -> typing.Union["CfnMicrosoftAD.VpcSettingsProperty", _IResolvable_da3f097b]:
        '''Specifies the VPC settings of the Microsoft AD directory server in AWS .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-vpcsettings
        '''
        return typing.cast(typing.Union["CfnMicrosoftAD.VpcSettingsProperty", _IResolvable_da3f097b], jsii.get(self, "vpcSettings"))

    @vpc_settings.setter
    def vpc_settings(
        self,
        value: typing.Union["CfnMicrosoftAD.VpcSettingsProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "vpcSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="createAlias")
    def create_alias(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies an alias for a directory and assigns the alias to the directory.

        The alias is used to construct the access URL for the directory, such as ``http://<alias>.awsapps.com`` . By default, AWS CloudFormation does not create an alias.
        .. epigraph::

           After an alias has been created, it cannot be deleted or reused, so this operation should only be used when absolutely necessary.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-createalias
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "createAlias"))

    @create_alias.setter
    def create_alias(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "createAlias", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="edition")
    def edition(self) -> typing.Optional[builtins.str]:
        '''AWS Managed Microsoft AD is available in two editions: ``Standard`` and ``Enterprise`` .

        ``Enterprise`` is the default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-edition
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "edition"))

    @edition.setter
    def edition(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "edition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableSso")
    def enable_sso(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Whether to enable single sign-on for a Microsoft Active Directory in AWS .

        Single sign-on allows users in your directory to access certain AWS services from a computer joined to the directory without having to enter their credentials separately. If you don't specify a value, AWS CloudFormation disables single sign-on by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-enablesso
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableSso"))

    @enable_sso.setter
    def enable_sso(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableSso", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="shortName")
    def short_name(self) -> typing.Optional[builtins.str]:
        '''The NetBIOS name for your domain, such as ``CORP`` .

        If you don't specify a NetBIOS name, it will default to the first part of your directory DNS. For example, ``CORP`` for the directory DNS ``corp.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-shortname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "shortName"))

    @short_name.setter
    def short_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "shortName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_directoryservice.CfnMicrosoftAD.VpcSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={"subnet_ids": "subnetIds", "vpc_id": "vpcId"},
    )
    class VpcSettingsProperty:
        def __init__(
            self,
            *,
            subnet_ids: typing.Sequence[builtins.str],
            vpc_id: builtins.str,
        ) -> None:
            '''Contains VPC information for the `CreateDirectory <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CreateDirectory.html>`_ or `CreateMicrosoftAD <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CreateMicrosoftAD.html>`_ operation.

            :param subnet_ids: The identifiers of the subnets for the directory servers. The two subnets must be in different Availability Zones. AWS Directory Service specifies a directory server and a DNS server in each of these subnets.
            :param vpc_id: The identifier of the VPC in which to create the directory.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-directoryservice-microsoftad-vpcsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_directoryservice as directoryservice
                
                vpc_settings_property = directoryservice.CfnMicrosoftAD.VpcSettingsProperty(
                    subnet_ids=["subnetIds"],
                    vpc_id="vpcId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "subnet_ids": subnet_ids,
                "vpc_id": vpc_id,
            }

        @builtins.property
        def subnet_ids(self) -> typing.List[builtins.str]:
            '''The identifiers of the subnets for the directory servers.

            The two subnets must be in different Availability Zones. AWS Directory Service specifies a directory server and a DNS server in each of these subnets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-directoryservice-microsoftad-vpcsettings.html#cfn-directoryservice-microsoftad-vpcsettings-subnetids
            '''
            result = self._values.get("subnet_ids")
            assert result is not None, "Required property 'subnet_ids' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def vpc_id(self) -> builtins.str:
            '''The identifier of the VPC in which to create the directory.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-directoryservice-microsoftad-vpcsettings.html#cfn-directoryservice-microsoftad-vpcsettings-vpcid
            '''
            result = self._values.get("vpc_id")
            assert result is not None, "Required property 'vpc_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VpcSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_directoryservice.CfnMicrosoftADProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "password": "password",
        "vpc_settings": "vpcSettings",
        "create_alias": "createAlias",
        "edition": "edition",
        "enable_sso": "enableSso",
        "short_name": "shortName",
    },
)
class CfnMicrosoftADProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        password: builtins.str,
        vpc_settings: typing.Union[CfnMicrosoftAD.VpcSettingsProperty, _IResolvable_da3f097b],
        create_alias: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        edition: typing.Optional[builtins.str] = None,
        enable_sso: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        short_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnMicrosoftAD``.

        :param name: The fully qualified domain name for the AWS Managed Microsoft AD directory, such as ``corp.example.com`` . This name will resolve inside your VPC only. It does not need to be publicly resolvable.
        :param password: The password for the default administrative user named ``Admin`` . If you need to change the password for the administrator account, see the `ResetUserPassword <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ResetUserPassword.html>`_ API call in the *AWS Directory Service API Reference* .
        :param vpc_settings: Specifies the VPC settings of the Microsoft AD directory server in AWS .
        :param create_alias: Specifies an alias for a directory and assigns the alias to the directory. The alias is used to construct the access URL for the directory, such as ``http://<alias>.awsapps.com`` . By default, AWS CloudFormation does not create an alias. .. epigraph:: After an alias has been created, it cannot be deleted or reused, so this operation should only be used when absolutely necessary.
        :param edition: AWS Managed Microsoft AD is available in two editions: ``Standard`` and ``Enterprise`` . ``Enterprise`` is the default.
        :param enable_sso: Whether to enable single sign-on for a Microsoft Active Directory in AWS . Single sign-on allows users in your directory to access certain AWS services from a computer joined to the directory without having to enter their credentials separately. If you don't specify a value, AWS CloudFormation disables single sign-on by default.
        :param short_name: The NetBIOS name for your domain, such as ``CORP`` . If you don't specify a NetBIOS name, it will default to the first part of your directory DNS. For example, ``CORP`` for the directory DNS ``corp.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_directoryservice as directoryservice
            
            cfn_microsoft_aDProps = directoryservice.CfnMicrosoftADProps(
                name="name",
                password="password",
                vpc_settings=directoryservice.CfnMicrosoftAD.VpcSettingsProperty(
                    subnet_ids=["subnetIds"],
                    vpc_id="vpcId"
                ),
            
                # the properties below are optional
                create_alias=False,
                edition="edition",
                enable_sso=False,
                short_name="shortName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "password": password,
            "vpc_settings": vpc_settings,
        }
        if create_alias is not None:
            self._values["create_alias"] = create_alias
        if edition is not None:
            self._values["edition"] = edition
        if enable_sso is not None:
            self._values["enable_sso"] = enable_sso
        if short_name is not None:
            self._values["short_name"] = short_name

    @builtins.property
    def name(self) -> builtins.str:
        '''The fully qualified domain name for the AWS Managed Microsoft AD directory, such as ``corp.example.com`` . This name will resolve inside your VPC only. It does not need to be publicly resolvable.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def password(self) -> builtins.str:
        '''The password for the default administrative user named ``Admin`` .

        If you need to change the password for the administrator account, see the `ResetUserPassword <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ResetUserPassword.html>`_ API call in the *AWS Directory Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-password
        '''
        result = self._values.get("password")
        assert result is not None, "Required property 'password' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def vpc_settings(
        self,
    ) -> typing.Union[CfnMicrosoftAD.VpcSettingsProperty, _IResolvable_da3f097b]:
        '''Specifies the VPC settings of the Microsoft AD directory server in AWS .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-vpcsettings
        '''
        result = self._values.get("vpc_settings")
        assert result is not None, "Required property 'vpc_settings' is missing"
        return typing.cast(typing.Union[CfnMicrosoftAD.VpcSettingsProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def create_alias(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies an alias for a directory and assigns the alias to the directory.

        The alias is used to construct the access URL for the directory, such as ``http://<alias>.awsapps.com`` . By default, AWS CloudFormation does not create an alias.
        .. epigraph::

           After an alias has been created, it cannot be deleted or reused, so this operation should only be used when absolutely necessary.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-createalias
        '''
        result = self._values.get("create_alias")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def edition(self) -> typing.Optional[builtins.str]:
        '''AWS Managed Microsoft AD is available in two editions: ``Standard`` and ``Enterprise`` .

        ``Enterprise`` is the default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-edition
        '''
        result = self._values.get("edition")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_sso(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Whether to enable single sign-on for a Microsoft Active Directory in AWS .

        Single sign-on allows users in your directory to access certain AWS services from a computer joined to the directory without having to enter their credentials separately. If you don't specify a value, AWS CloudFormation disables single sign-on by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-enablesso
        '''
        result = self._values.get("enable_sso")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def short_name(self) -> typing.Optional[builtins.str]:
        '''The NetBIOS name for your domain, such as ``CORP`` .

        If you don't specify a NetBIOS name, it will default to the first part of your directory DNS. For example, ``CORP`` for the directory DNS ``corp.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html#cfn-directoryservice-microsoftad-shortname
        '''
        result = self._values.get("short_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnMicrosoftADProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSimpleAD(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_directoryservice.CfnSimpleAD",
):
    '''A CloudFormation ``AWS::DirectoryService::SimpleAD``.

    The ``AWS::DirectoryService::SimpleAD`` resource specifies an AWS Directory Service Simple Active Directory ( Simple AD ) in AWS so that your directory users and groups can access the AWS Management Console and AWS applications using their existing credentials. Simple AD is a Microsoft Active Directory–compatible directory. For more information, see `Simple Active Directory <https://docs.aws.amazon.com/directoryservice/latest/admin-guide/directory_simple_ad.html>`_ in the *AWS Directory Service Admin Guide* .

    :cloudformationResource: AWS::DirectoryService::SimpleAD
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_directoryservice as directoryservice
        
        cfn_simple_aD = directoryservice.CfnSimpleAD(self, "MyCfnSimpleAD",
            name="name",
            password="password",
            size="size",
            vpc_settings=directoryservice.CfnSimpleAD.VpcSettingsProperty(
                subnet_ids=["subnetIds"],
                vpc_id="vpcId"
            ),
        
            # the properties below are optional
            create_alias=False,
            description="description",
            enable_sso=False,
            short_name="shortName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        password: builtins.str,
        size: builtins.str,
        vpc_settings: typing.Union["CfnSimpleAD.VpcSettingsProperty", _IResolvable_da3f097b],
        create_alias: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        enable_sso: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        short_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::DirectoryService::SimpleAD``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The fully qualified name for the directory, such as ``corp.example.com`` .
        :param password: The password for the directory administrator. The directory creation process creates a directory administrator account with the user name ``Administrator`` and this password. If you need to change the password for the administrator account, see the `ResetUserPassword <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ResetUserPassword.html>`_ API call in the *AWS Directory Service API Reference* .
        :param size: The size of the directory. For valid values, see `CreateDirectory <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CreateDirectory.html>`_ in the *AWS Directory Service API Reference* .
        :param vpc_settings: A `DirectoryVpcSettings <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DirectoryVpcSettings.html>`_ object that contains additional information for the operation.
        :param create_alias: If set to ``true`` , specifies an alias for a directory and assigns the alias to the directory. The alias is used to construct the access URL for the directory, such as ``http://<alias>.awsapps.com`` . By default, this property is set to ``false`` . .. epigraph:: After an alias has been created, it cannot be deleted or reused, so this operation should only be used when absolutely necessary.
        :param description: A description for the directory.
        :param enable_sso: Whether to enable single sign-on for a directory. If you don't specify a value, AWS CloudFormation disables single sign-on by default.
        :param short_name: The NetBIOS name of the directory, such as ``CORP`` .
        '''
        props = CfnSimpleADProps(
            name=name,
            password=password,
            size=size,
            vpc_settings=vpc_settings,
            create_alias=create_alias,
            description=description,
            enable_sso=enable_sso,
            short_name=short_name,
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
    @jsii.member(jsii_name="attrAlias")
    def attr_alias(self) -> builtins.str:
        '''The alias for a directory.

        For example: ``d-12373a053a`` or ``alias4-mydirectory-12345abcgmzsk`` (if you have the ``CreateAlias`` property set to true).

        :cloudformationAttribute: Alias
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAlias"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDnsIpAddresses")
    def attr_dns_ip_addresses(self) -> typing.List[builtins.str]:
        '''The IP addresses of the DNS servers for the directory, such as ``[ "172.31.3.154", "172.31.63.203" ]`` .

        :cloudformationAttribute: DnsIpAddresses
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrDnsIpAddresses"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The fully qualified name for the directory, such as ``corp.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="password")
    def password(self) -> builtins.str:
        '''The password for the directory administrator.

        The directory creation process creates a directory administrator account with the user name ``Administrator`` and this password.

        If you need to change the password for the administrator account, see the `ResetUserPassword <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ResetUserPassword.html>`_ API call in the *AWS Directory Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-password
        '''
        return typing.cast(builtins.str, jsii.get(self, "password"))

    @password.setter
    def password(self, value: builtins.str) -> None:
        jsii.set(self, "password", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="size")
    def size(self) -> builtins.str:
        '''The size of the directory.

        For valid values, see `CreateDirectory <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CreateDirectory.html>`_ in the *AWS Directory Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-size
        '''
        return typing.cast(builtins.str, jsii.get(self, "size"))

    @size.setter
    def size(self, value: builtins.str) -> None:
        jsii.set(self, "size", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcSettings")
    def vpc_settings(
        self,
    ) -> typing.Union["CfnSimpleAD.VpcSettingsProperty", _IResolvable_da3f097b]:
        '''A `DirectoryVpcSettings <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DirectoryVpcSettings.html>`_ object that contains additional information for the operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-vpcsettings
        '''
        return typing.cast(typing.Union["CfnSimpleAD.VpcSettingsProperty", _IResolvable_da3f097b], jsii.get(self, "vpcSettings"))

    @vpc_settings.setter
    def vpc_settings(
        self,
        value: typing.Union["CfnSimpleAD.VpcSettingsProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "vpcSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="createAlias")
    def create_alias(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If set to ``true`` , specifies an alias for a directory and assigns the alias to the directory.

        The alias is used to construct the access URL for the directory, such as ``http://<alias>.awsapps.com`` . By default, this property is set to ``false`` .
        .. epigraph::

           After an alias has been created, it cannot be deleted or reused, so this operation should only be used when absolutely necessary.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-createalias
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "createAlias"))

    @create_alias.setter
    def create_alias(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "createAlias", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the directory.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableSso")
    def enable_sso(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Whether to enable single sign-on for a directory.

        If you don't specify a value, AWS CloudFormation disables single sign-on by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-enablesso
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableSso"))

    @enable_sso.setter
    def enable_sso(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableSso", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="shortName")
    def short_name(self) -> typing.Optional[builtins.str]:
        '''The NetBIOS name of the directory, such as ``CORP`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-shortname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "shortName"))

    @short_name.setter
    def short_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "shortName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_directoryservice.CfnSimpleAD.VpcSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={"subnet_ids": "subnetIds", "vpc_id": "vpcId"},
    )
    class VpcSettingsProperty:
        def __init__(
            self,
            *,
            subnet_ids: typing.Sequence[builtins.str],
            vpc_id: builtins.str,
        ) -> None:
            '''Contains VPC information for the `CreateDirectory <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CreateDirectory.html>`_ or `CreateMicrosoftAD <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CreateMicrosoftAD.html>`_ operation.

            :param subnet_ids: The identifiers of the subnets for the directory servers. The two subnets must be in different Availability Zones. AWS Directory Service specifies a directory server and a DNS server in each of these subnets.
            :param vpc_id: The identifier of the VPC in which to create the directory.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-directoryservice-simplead-vpcsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_directoryservice as directoryservice
                
                vpc_settings_property = directoryservice.CfnSimpleAD.VpcSettingsProperty(
                    subnet_ids=["subnetIds"],
                    vpc_id="vpcId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "subnet_ids": subnet_ids,
                "vpc_id": vpc_id,
            }

        @builtins.property
        def subnet_ids(self) -> typing.List[builtins.str]:
            '''The identifiers of the subnets for the directory servers.

            The two subnets must be in different Availability Zones. AWS Directory Service specifies a directory server and a DNS server in each of these subnets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-directoryservice-simplead-vpcsettings.html#cfn-directoryservice-simplead-vpcsettings-subnetids
            '''
            result = self._values.get("subnet_ids")
            assert result is not None, "Required property 'subnet_ids' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def vpc_id(self) -> builtins.str:
            '''The identifier of the VPC in which to create the directory.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-directoryservice-simplead-vpcsettings.html#cfn-directoryservice-simplead-vpcsettings-vpcid
            '''
            result = self._values.get("vpc_id")
            assert result is not None, "Required property 'vpc_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VpcSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_directoryservice.CfnSimpleADProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "password": "password",
        "size": "size",
        "vpc_settings": "vpcSettings",
        "create_alias": "createAlias",
        "description": "description",
        "enable_sso": "enableSso",
        "short_name": "shortName",
    },
)
class CfnSimpleADProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        password: builtins.str,
        size: builtins.str,
        vpc_settings: typing.Union[CfnSimpleAD.VpcSettingsProperty, _IResolvable_da3f097b],
        create_alias: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        enable_sso: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        short_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnSimpleAD``.

        :param name: The fully qualified name for the directory, such as ``corp.example.com`` .
        :param password: The password for the directory administrator. The directory creation process creates a directory administrator account with the user name ``Administrator`` and this password. If you need to change the password for the administrator account, see the `ResetUserPassword <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ResetUserPassword.html>`_ API call in the *AWS Directory Service API Reference* .
        :param size: The size of the directory. For valid values, see `CreateDirectory <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CreateDirectory.html>`_ in the *AWS Directory Service API Reference* .
        :param vpc_settings: A `DirectoryVpcSettings <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DirectoryVpcSettings.html>`_ object that contains additional information for the operation.
        :param create_alias: If set to ``true`` , specifies an alias for a directory and assigns the alias to the directory. The alias is used to construct the access URL for the directory, such as ``http://<alias>.awsapps.com`` . By default, this property is set to ``false`` . .. epigraph:: After an alias has been created, it cannot be deleted or reused, so this operation should only be used when absolutely necessary.
        :param description: A description for the directory.
        :param enable_sso: Whether to enable single sign-on for a directory. If you don't specify a value, AWS CloudFormation disables single sign-on by default.
        :param short_name: The NetBIOS name of the directory, such as ``CORP`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_directoryservice as directoryservice
            
            cfn_simple_aDProps = directoryservice.CfnSimpleADProps(
                name="name",
                password="password",
                size="size",
                vpc_settings=directoryservice.CfnSimpleAD.VpcSettingsProperty(
                    subnet_ids=["subnetIds"],
                    vpc_id="vpcId"
                ),
            
                # the properties below are optional
                create_alias=False,
                description="description",
                enable_sso=False,
                short_name="shortName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "password": password,
            "size": size,
            "vpc_settings": vpc_settings,
        }
        if create_alias is not None:
            self._values["create_alias"] = create_alias
        if description is not None:
            self._values["description"] = description
        if enable_sso is not None:
            self._values["enable_sso"] = enable_sso
        if short_name is not None:
            self._values["short_name"] = short_name

    @builtins.property
    def name(self) -> builtins.str:
        '''The fully qualified name for the directory, such as ``corp.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def password(self) -> builtins.str:
        '''The password for the directory administrator.

        The directory creation process creates a directory administrator account with the user name ``Administrator`` and this password.

        If you need to change the password for the administrator account, see the `ResetUserPassword <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_ResetUserPassword.html>`_ API call in the *AWS Directory Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-password
        '''
        result = self._values.get("password")
        assert result is not None, "Required property 'password' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def size(self) -> builtins.str:
        '''The size of the directory.

        For valid values, see `CreateDirectory <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_CreateDirectory.html>`_ in the *AWS Directory Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-size
        '''
        result = self._values.get("size")
        assert result is not None, "Required property 'size' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def vpc_settings(
        self,
    ) -> typing.Union[CfnSimpleAD.VpcSettingsProperty, _IResolvable_da3f097b]:
        '''A `DirectoryVpcSettings <https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DirectoryVpcSettings.html>`_ object that contains additional information for the operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-vpcsettings
        '''
        result = self._values.get("vpc_settings")
        assert result is not None, "Required property 'vpc_settings' is missing"
        return typing.cast(typing.Union[CfnSimpleAD.VpcSettingsProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def create_alias(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''If set to ``true`` , specifies an alias for a directory and assigns the alias to the directory.

        The alias is used to construct the access URL for the directory, such as ``http://<alias>.awsapps.com`` . By default, this property is set to ``false`` .
        .. epigraph::

           After an alias has been created, it cannot be deleted or reused, so this operation should only be used when absolutely necessary.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-createalias
        '''
        result = self._values.get("create_alias")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the directory.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_sso(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Whether to enable single sign-on for a directory.

        If you don't specify a value, AWS CloudFormation disables single sign-on by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-enablesso
        '''
        result = self._values.get("enable_sso")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def short_name(self) -> typing.Optional[builtins.str]:
        '''The NetBIOS name of the directory, such as ``CORP`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html#cfn-directoryservice-simplead-shortname
        '''
        result = self._values.get("short_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSimpleADProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnMicrosoftAD",
    "CfnMicrosoftADProps",
    "CfnSimpleAD",
    "CfnSimpleADProps",
]

publication.publish()
