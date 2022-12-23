'''
# AWS::FinSpace Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_finspace as finspace
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-finspace-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::FinSpace](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_FinSpace.html).

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
class CfnEnvironment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_finspace.CfnEnvironment",
):
    '''A CloudFormation ``AWS::FinSpace::Environment``.

    The ``AWS::FinSpace::Environment`` resource represents an Amazon FinSpace environment.

    :cloudformationResource: AWS::FinSpace::Environment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_finspace as finspace
        
        # attribute_map: Any
        
        cfn_environment = finspace.CfnEnvironment(self, "MyCfnEnvironment",
            name="name",
        
            # the properties below are optional
            data_bundles=["dataBundles"],
            description="description",
            federation_mode="federationMode",
            federation_parameters=finspace.CfnEnvironment.FederationParametersProperty(
                application_call_back_url="applicationCallBackUrl",
                attribute_map=attribute_map,
                federation_provider_name="federationProviderName",
                federation_urn="federationUrn",
                saml_metadata_document="samlMetadataDocument",
                saml_metadata_url="samlMetadataUrl"
            ),
            kms_key_id="kmsKeyId",
            superuser_parameters=finspace.CfnEnvironment.SuperuserParametersProperty(
                email_address="emailAddress",
                first_name="firstName",
                last_name="lastName"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        data_bundles: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        federation_mode: typing.Optional[builtins.str] = None,
        federation_parameters: typing.Optional[typing.Union["CfnEnvironment.FederationParametersProperty", _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        superuser_parameters: typing.Optional[typing.Union["CfnEnvironment.SuperuserParametersProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::FinSpace::Environment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the FinSpace environment.
        :param data_bundles: The list of Amazon Resource Names (ARN) of the data bundles to install. Currently supported data bundle ARNs:. - ``arn:aws:finspace:${Region}::data-bundle/capital-markets-sample`` - Contains sample Capital Markets datasets, categories and controlled vocabularies. - ``arn:aws:finspace:${Region}::data-bundle/taq`` (default) - Contains trades and quotes data in addition to sample Capital Markets data.
        :param description: The description of the FinSpace environment.
        :param federation_mode: The authentication mode for the environment.
        :param federation_parameters: Configuration information when authentication mode is FEDERATED.
        :param kms_key_id: The KMS key id used to encrypt in the FinSpace environment.
        :param superuser_parameters: Configuration information for the superuser.
        '''
        props = CfnEnvironmentProps(
            name=name,
            data_bundles=data_bundles,
            description=description,
            federation_mode=federation_mode,
            federation_parameters=federation_parameters,
            kms_key_id=kms_key_id,
            superuser_parameters=superuser_parameters,
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
    @jsii.member(jsii_name="attrAwsAccountId")
    def attr_aws_account_id(self) -> builtins.str:
        '''The ID of the AWS account in which the FinSpace environment is created.

        :cloudformationAttribute: AwsAccountId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAwsAccountId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDedicatedServiceAccountId")
    def attr_dedicated_service_account_id(self) -> builtins.str:
        '''The AWS account ID of the dedicated service account associated with your FinSpace environment.

        :cloudformationAttribute: DedicatedServiceAccountId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDedicatedServiceAccountId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEnvironmentArn")
    def attr_environment_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of your FinSpace environment.

        :cloudformationAttribute: EnvironmentArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEnvironmentArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEnvironmentId")
    def attr_environment_id(self) -> builtins.str:
        '''The identifier of the FinSpace environment.

        :cloudformationAttribute: EnvironmentId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEnvironmentId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEnvironmentUrl")
    def attr_environment_url(self) -> builtins.str:
        '''The sign-in url for the web application of your FinSpace environment.

        :cloudformationAttribute: EnvironmentUrl
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEnvironmentUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSageMakerStudioDomainUrl")
    def attr_sage_maker_studio_domain_url(self) -> builtins.str:
        '''The url of the integrated FinSpace notebook environment in your web application.

        :cloudformationAttribute: SageMakerStudioDomainUrl
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSageMakerStudioDomainUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatus")
    def attr_status(self) -> builtins.str:
        '''The current status of creation of the FinSpace environment.

        :cloudformationAttribute: Status
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the FinSpace environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataBundles")
    def data_bundles(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of Amazon Resource Names (ARN) of the data bundles to install. Currently supported data bundle ARNs:.

        - ``arn:aws:finspace:${Region}::data-bundle/capital-markets-sample`` - Contains sample Capital Markets datasets, categories and controlled vocabularies.
        - ``arn:aws:finspace:${Region}::data-bundle/taq`` (default) - Contains trades and quotes data in addition to sample Capital Markets data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-databundles
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "dataBundles"))

    @data_bundles.setter
    def data_bundles(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "dataBundles", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the FinSpace environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="federationMode")
    def federation_mode(self) -> typing.Optional[builtins.str]:
        '''The authentication mode for the environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-federationmode
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "federationMode"))

    @federation_mode.setter
    def federation_mode(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "federationMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="federationParameters")
    def federation_parameters(
        self,
    ) -> typing.Optional[typing.Union["CfnEnvironment.FederationParametersProperty", _IResolvable_da3f097b]]:
        '''Configuration information when authentication mode is FEDERATED.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-federationparameters
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEnvironment.FederationParametersProperty", _IResolvable_da3f097b]], jsii.get(self, "federationParameters"))

    @federation_parameters.setter
    def federation_parameters(
        self,
        value: typing.Optional[typing.Union["CfnEnvironment.FederationParametersProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "federationParameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The KMS key id used to encrypt in the FinSpace environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="superuserParameters")
    def superuser_parameters(
        self,
    ) -> typing.Optional[typing.Union["CfnEnvironment.SuperuserParametersProperty", _IResolvable_da3f097b]]:
        '''Configuration information for the superuser.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-superuserparameters
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEnvironment.SuperuserParametersProperty", _IResolvable_da3f097b]], jsii.get(self, "superuserParameters"))

    @superuser_parameters.setter
    def superuser_parameters(
        self,
        value: typing.Optional[typing.Union["CfnEnvironment.SuperuserParametersProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "superuserParameters", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_finspace.CfnEnvironment.FederationParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "application_call_back_url": "applicationCallBackUrl",
            "attribute_map": "attributeMap",
            "federation_provider_name": "federationProviderName",
            "federation_urn": "federationUrn",
            "saml_metadata_document": "samlMetadataDocument",
            "saml_metadata_url": "samlMetadataUrl",
        },
    )
    class FederationParametersProperty:
        def __init__(
            self,
            *,
            application_call_back_url: typing.Optional[builtins.str] = None,
            attribute_map: typing.Any = None,
            federation_provider_name: typing.Optional[builtins.str] = None,
            federation_urn: typing.Optional[builtins.str] = None,
            saml_metadata_document: typing.Optional[builtins.str] = None,
            saml_metadata_url: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Configuration information when authentication mode is FEDERATED.

            :param application_call_back_url: The redirect or sign-in URL that should be entered into the SAML 2.0 compliant identity provider configuration (IdP).
            :param attribute_map: SAML attribute name and value. The name must always be ``Email`` and the value should be set to the attribute definition in which user email is set. For example, name would be ``Email`` and value ``http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`` . Please check your SAML 2.0 compliant identity provider (IdP) documentation for details.
            :param federation_provider_name: Name of the identity provider (IdP).
            :param federation_urn: The Uniform Resource Name (URN). Also referred as Service Provider URN or Audience URI or Service Provider Entity ID.
            :param saml_metadata_document: SAML 2.0 Metadata document from identity provider (IdP).
            :param saml_metadata_url: Provide the metadata URL from your SAML 2.0 compliant identity provider (IdP).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-federationparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_finspace as finspace
                
                # attribute_map: Any
                
                federation_parameters_property = finspace.CfnEnvironment.FederationParametersProperty(
                    application_call_back_url="applicationCallBackUrl",
                    attribute_map=attribute_map,
                    federation_provider_name="federationProviderName",
                    federation_urn="federationUrn",
                    saml_metadata_document="samlMetadataDocument",
                    saml_metadata_url="samlMetadataUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if application_call_back_url is not None:
                self._values["application_call_back_url"] = application_call_back_url
            if attribute_map is not None:
                self._values["attribute_map"] = attribute_map
            if federation_provider_name is not None:
                self._values["federation_provider_name"] = federation_provider_name
            if federation_urn is not None:
                self._values["federation_urn"] = federation_urn
            if saml_metadata_document is not None:
                self._values["saml_metadata_document"] = saml_metadata_document
            if saml_metadata_url is not None:
                self._values["saml_metadata_url"] = saml_metadata_url

        @builtins.property
        def application_call_back_url(self) -> typing.Optional[builtins.str]:
            '''The redirect or sign-in URL that should be entered into the SAML 2.0 compliant identity provider configuration (IdP).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-federationparameters.html#cfn-finspace-environment-federationparameters-applicationcallbackurl
            '''
            result = self._values.get("application_call_back_url")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def attribute_map(self) -> typing.Any:
            '''SAML attribute name and value.

            The name must always be ``Email`` and the value should be set to the attribute definition in which user email is set. For example, name would be ``Email`` and value ``http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`` . Please check your SAML 2.0 compliant identity provider (IdP) documentation for details.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-federationparameters.html#cfn-finspace-environment-federationparameters-attributemap
            '''
            result = self._values.get("attribute_map")
            return typing.cast(typing.Any, result)

        @builtins.property
        def federation_provider_name(self) -> typing.Optional[builtins.str]:
            '''Name of the identity provider (IdP).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-federationparameters.html#cfn-finspace-environment-federationparameters-federationprovidername
            '''
            result = self._values.get("federation_provider_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def federation_urn(self) -> typing.Optional[builtins.str]:
            '''The Uniform Resource Name (URN).

            Also referred as Service Provider URN or Audience URI or Service Provider Entity ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-federationparameters.html#cfn-finspace-environment-federationparameters-federationurn
            '''
            result = self._values.get("federation_urn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def saml_metadata_document(self) -> typing.Optional[builtins.str]:
            '''SAML 2.0 Metadata document from identity provider (IdP).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-federationparameters.html#cfn-finspace-environment-federationparameters-samlmetadatadocument
            '''
            result = self._values.get("saml_metadata_document")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def saml_metadata_url(self) -> typing.Optional[builtins.str]:
            '''Provide the metadata URL from your SAML 2.0 compliant identity provider (IdP).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-federationparameters.html#cfn-finspace-environment-federationparameters-samlmetadataurl
            '''
            result = self._values.get("saml_metadata_url")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FederationParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_finspace.CfnEnvironment.SuperuserParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "email_address": "emailAddress",
            "first_name": "firstName",
            "last_name": "lastName",
        },
    )
    class SuperuserParametersProperty:
        def __init__(
            self,
            *,
            email_address: typing.Optional[builtins.str] = None,
            first_name: typing.Optional[builtins.str] = None,
            last_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Configuration information for the superuser.

            :param email_address: The email address of the superuser.
            :param first_name: The first name of the superuser.
            :param last_name: The last name of the superuser.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-superuserparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_finspace as finspace
                
                superuser_parameters_property = finspace.CfnEnvironment.SuperuserParametersProperty(
                    email_address="emailAddress",
                    first_name="firstName",
                    last_name="lastName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if email_address is not None:
                self._values["email_address"] = email_address
            if first_name is not None:
                self._values["first_name"] = first_name
            if last_name is not None:
                self._values["last_name"] = last_name

        @builtins.property
        def email_address(self) -> typing.Optional[builtins.str]:
            '''The email address of the superuser.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-superuserparameters.html#cfn-finspace-environment-superuserparameters-emailaddress
            '''
            result = self._values.get("email_address")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def first_name(self) -> typing.Optional[builtins.str]:
            '''The first name of the superuser.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-superuserparameters.html#cfn-finspace-environment-superuserparameters-firstname
            '''
            result = self._values.get("first_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def last_name(self) -> typing.Optional[builtins.str]:
            '''The last name of the superuser.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-finspace-environment-superuserparameters.html#cfn-finspace-environment-superuserparameters-lastname
            '''
            result = self._values.get("last_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SuperuserParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_finspace.CfnEnvironmentProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "data_bundles": "dataBundles",
        "description": "description",
        "federation_mode": "federationMode",
        "federation_parameters": "federationParameters",
        "kms_key_id": "kmsKeyId",
        "superuser_parameters": "superuserParameters",
    },
)
class CfnEnvironmentProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        data_bundles: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        federation_mode: typing.Optional[builtins.str] = None,
        federation_parameters: typing.Optional[typing.Union[CfnEnvironment.FederationParametersProperty, _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        superuser_parameters: typing.Optional[typing.Union[CfnEnvironment.SuperuserParametersProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnEnvironment``.

        :param name: The name of the FinSpace environment.
        :param data_bundles: The list of Amazon Resource Names (ARN) of the data bundles to install. Currently supported data bundle ARNs:. - ``arn:aws:finspace:${Region}::data-bundle/capital-markets-sample`` - Contains sample Capital Markets datasets, categories and controlled vocabularies. - ``arn:aws:finspace:${Region}::data-bundle/taq`` (default) - Contains trades and quotes data in addition to sample Capital Markets data.
        :param description: The description of the FinSpace environment.
        :param federation_mode: The authentication mode for the environment.
        :param federation_parameters: Configuration information when authentication mode is FEDERATED.
        :param kms_key_id: The KMS key id used to encrypt in the FinSpace environment.
        :param superuser_parameters: Configuration information for the superuser.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_finspace as finspace
            
            # attribute_map: Any
            
            cfn_environment_props = finspace.CfnEnvironmentProps(
                name="name",
            
                # the properties below are optional
                data_bundles=["dataBundles"],
                description="description",
                federation_mode="federationMode",
                federation_parameters=finspace.CfnEnvironment.FederationParametersProperty(
                    application_call_back_url="applicationCallBackUrl",
                    attribute_map=attribute_map,
                    federation_provider_name="federationProviderName",
                    federation_urn="federationUrn",
                    saml_metadata_document="samlMetadataDocument",
                    saml_metadata_url="samlMetadataUrl"
                ),
                kms_key_id="kmsKeyId",
                superuser_parameters=finspace.CfnEnvironment.SuperuserParametersProperty(
                    email_address="emailAddress",
                    first_name="firstName",
                    last_name="lastName"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if data_bundles is not None:
            self._values["data_bundles"] = data_bundles
        if description is not None:
            self._values["description"] = description
        if federation_mode is not None:
            self._values["federation_mode"] = federation_mode
        if federation_parameters is not None:
            self._values["federation_parameters"] = federation_parameters
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if superuser_parameters is not None:
            self._values["superuser_parameters"] = superuser_parameters

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the FinSpace environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def data_bundles(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of Amazon Resource Names (ARN) of the data bundles to install. Currently supported data bundle ARNs:.

        - ``arn:aws:finspace:${Region}::data-bundle/capital-markets-sample`` - Contains sample Capital Markets datasets, categories and controlled vocabularies.
        - ``arn:aws:finspace:${Region}::data-bundle/taq`` (default) - Contains trades and quotes data in addition to sample Capital Markets data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-databundles
        '''
        result = self._values.get("data_bundles")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the FinSpace environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def federation_mode(self) -> typing.Optional[builtins.str]:
        '''The authentication mode for the environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-federationmode
        '''
        result = self._values.get("federation_mode")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def federation_parameters(
        self,
    ) -> typing.Optional[typing.Union[CfnEnvironment.FederationParametersProperty, _IResolvable_da3f097b]]:
        '''Configuration information when authentication mode is FEDERATED.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-federationparameters
        '''
        result = self._values.get("federation_parameters")
        return typing.cast(typing.Optional[typing.Union[CfnEnvironment.FederationParametersProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The KMS key id used to encrypt in the FinSpace environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def superuser_parameters(
        self,
    ) -> typing.Optional[typing.Union[CfnEnvironment.SuperuserParametersProperty, _IResolvable_da3f097b]]:
        '''Configuration information for the superuser.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-finspace-environment.html#cfn-finspace-environment-superuserparameters
        '''
        result = self._values.get("superuser_parameters")
        return typing.cast(typing.Optional[typing.Union[CfnEnvironment.SuperuserParametersProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnEnvironmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnEnvironment",
    "CfnEnvironmentProps",
]

publication.publish()
