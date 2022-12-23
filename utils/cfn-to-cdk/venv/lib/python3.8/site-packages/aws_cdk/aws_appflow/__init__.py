'''
# AWS::AppFlow Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_appflow as appflow
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-appflow-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::AppFlow](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_AppFlow.html).

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
class CfnConnectorProfile(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile",
):
    '''A CloudFormation ``AWS::AppFlow::ConnectorProfile``.

    The ``AWS::AppFlow::ConnectorProfile`` resource is an Amazon AppFlow resource type that specifies the configuration profile for an instance of a connector. This includes the provided name, credentials ARN, connection-mode, and so on. The fields that are common to all types of connector profiles are explicitly specified under the ``Properties`` field. The rest of the connector-specific properties are specified under ``Properties/ConnectorProfileConfig`` .
    .. epigraph::

       If you want to use AWS CloudFormation to create a connector profile for connectors that implement OAuth (such as Salesforce, Slack, Zendesk, and Google Analytics), you must fetch the access and refresh tokens. You can do this by implementing your own UI for OAuth, or by retrieving the tokens from elsewhere. Alternatively, you can use the Amazon AppFlow console to create the connector profile, and then use that connector profile in the flow creation CloudFormation template.

    :cloudformationResource: AWS::AppFlow::ConnectorProfile
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appflow as appflow
        
        # basic_auth_credentials: Any
        # o_auth_credentials: Any
        
        cfn_connector_profile = appflow.CfnConnectorProfile(self, "MyCfnConnectorProfile",
            connection_mode="connectionMode",
            connector_profile_name="connectorProfileName",
            connector_type="connectorType",
        
            # the properties below are optional
            connector_profile_config=appflow.CfnConnectorProfile.ConnectorProfileConfigProperty(
                connector_profile_credentials=appflow.CfnConnectorProfile.ConnectorProfileCredentialsProperty(
                    amplitude=appflow.CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty(
                        api_key="apiKey",
                        secret_key="secretKey"
                    ),
                    datadog=appflow.CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty(
                        api_key="apiKey",
                        application_key="applicationKey"
                    ),
                    dynatrace=appflow.CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty(
                        api_token="apiToken"
                    ),
                    google_analytics=appflow.CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty(
                        client_id="clientId",
                        client_secret="clientSecret",
        
                        # the properties below are optional
                        access_token="accessToken",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        ),
                        refresh_token="refreshToken"
                    ),
                    infor_nexus=appflow.CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty(
                        access_key_id="accessKeyId",
                        datakey="datakey",
                        secret_access_key="secretAccessKey",
                        user_id="userId"
                    ),
                    marketo=appflow.CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty(
                        client_id="clientId",
                        client_secret="clientSecret",
        
                        # the properties below are optional
                        access_token="accessToken",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        )
                    ),
                    redshift=appflow.CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty(
                        password="password",
                        username="username"
                    ),
                    salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty(
                        access_token="accessToken",
                        client_credentials_arn="clientCredentialsArn",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        ),
                        refresh_token="refreshToken"
                    ),
                    sapo_data=appflow.CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty(
                        basic_auth_credentials=basic_auth_credentials,
                        o_auth_credentials=o_auth_credentials
                    ),
                    service_now=appflow.CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty(
                        password="password",
                        username="username"
                    ),
                    singular=appflow.CfnConnectorProfile.SingularConnectorProfileCredentialsProperty(
                        api_key="apiKey"
                    ),
                    slack=appflow.CfnConnectorProfile.SlackConnectorProfileCredentialsProperty(
                        client_id="clientId",
                        client_secret="clientSecret",
        
                        # the properties below are optional
                        access_token="accessToken",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        )
                    ),
                    snowflake=appflow.CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty(
                        password="password",
                        username="username"
                    ),
                    trendmicro=appflow.CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty(
                        api_secret_key="apiSecretKey"
                    ),
                    veeva=appflow.CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty(
                        password="password",
                        username="username"
                    ),
                    zendesk=appflow.CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty(
                        client_id="clientId",
                        client_secret="clientSecret",
        
                        # the properties below are optional
                        access_token="accessToken",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        )
                    )
                ),
        
                # the properties below are optional
                connector_profile_properties=appflow.CfnConnectorProfile.ConnectorProfilePropertiesProperty(
                    datadog=appflow.CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    dynatrace=appflow.CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    infor_nexus=appflow.CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    marketo=appflow.CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    redshift=appflow.CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty(
                        bucket_name="bucketName",
                        database_url="databaseUrl",
                        role_arn="roleArn",
        
                        # the properties below are optional
                        bucket_prefix="bucketPrefix"
                    ),
                    salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl",
                        is_sandbox_environment=False
                    ),
                    sapo_data=appflow.CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty(
                        application_host_url="applicationHostUrl",
                        application_service_path="applicationServicePath",
                        client_number="clientNumber",
                        logon_language="logonLanguage",
                        o_auth_properties=appflow.CfnConnectorProfile.OAuthPropertiesProperty(
                            auth_code_url="authCodeUrl",
                            o_auth_scopes=["oAuthScopes"],
                            token_url="tokenUrl"
                        ),
                        port_number=123,
                        private_link_service_name="privateLinkServiceName"
                    ),
                    service_now=appflow.CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    slack=appflow.CfnConnectorProfile.SlackConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    snowflake=appflow.CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty(
                        bucket_name="bucketName",
                        stage="stage",
                        warehouse="warehouse",
        
                        # the properties below are optional
                        account_name="accountName",
                        bucket_prefix="bucketPrefix",
                        private_link_service_name="privateLinkServiceName",
                        region="region"
                    ),
                    veeva=appflow.CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    zendesk=appflow.CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    )
                )
            ),
            kms_arn="kmsArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        connection_mode: builtins.str,
        connector_profile_name: builtins.str,
        connector_type: builtins.str,
        connector_profile_config: typing.Optional[typing.Union["CfnConnectorProfile.ConnectorProfileConfigProperty", _IResolvable_da3f097b]] = None,
        kms_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::AppFlow::ConnectorProfile``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param connection_mode: Indicates the connection mode and if it is public or private.
        :param connector_profile_name: The name of the connector profile. The name is unique for each ``ConnectorProfile`` in the AWS account .
        :param connector_type: The type of connector, such as Salesforce, Amplitude, and so on.
        :param connector_profile_config: Defines the connector-specific configuration and credentials.
        :param kms_arn: The ARN (Amazon Resource Name) of the Key Management Service (KMS) key you provide for encryption. This is required if you do not want to use the Amazon AppFlow-managed KMS key. If you don't provide anything here, Amazon AppFlow uses the Amazon AppFlow-managed KMS key.
        '''
        props = CfnConnectorProfileProps(
            connection_mode=connection_mode,
            connector_profile_name=connector_profile_name,
            connector_type=connector_type,
            connector_profile_config=connector_profile_config,
            kms_arn=kms_arn,
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
    @jsii.member(jsii_name="attrConnectorProfileArn")
    def attr_connector_profile_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the connector profile.

        :cloudformationAttribute: ConnectorProfileArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrConnectorProfileArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCredentialsArn")
    def attr_credentials_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the connector profile credentials.

        :cloudformationAttribute: CredentialsArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCredentialsArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionMode")
    def connection_mode(self) -> builtins.str:
        '''Indicates the connection mode and if it is public or private.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-connectionmode
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectionMode"))

    @connection_mode.setter
    def connection_mode(self, value: builtins.str) -> None:
        jsii.set(self, "connectionMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectorProfileName")
    def connector_profile_name(self) -> builtins.str:
        '''The name of the connector profile.

        The name is unique for each ``ConnectorProfile`` in the AWS account .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-connectorprofilename
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectorProfileName"))

    @connector_profile_name.setter
    def connector_profile_name(self, value: builtins.str) -> None:
        jsii.set(self, "connectorProfileName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectorType")
    def connector_type(self) -> builtins.str:
        '''The type of connector, such as Salesforce, Amplitude, and so on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-connectortype
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectorType"))

    @connector_type.setter
    def connector_type(self, value: builtins.str) -> None:
        jsii.set(self, "connectorType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectorProfileConfig")
    def connector_profile_config(
        self,
    ) -> typing.Optional[typing.Union["CfnConnectorProfile.ConnectorProfileConfigProperty", _IResolvable_da3f097b]]:
        '''Defines the connector-specific configuration and credentials.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-connectorprofileconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ConnectorProfileConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "connectorProfileConfig"))

    @connector_profile_config.setter
    def connector_profile_config(
        self,
        value: typing.Optional[typing.Union["CfnConnectorProfile.ConnectorProfileConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "connectorProfileConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsArn")
    def kms_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN (Amazon Resource Name) of the Key Management Service (KMS) key you provide for encryption.

        This is required if you do not want to use the Amazon AppFlow-managed KMS key. If you don't provide anything here, Amazon AppFlow uses the Amazon AppFlow-managed KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-kmsarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsArn"))

    @kms_arn.setter
    def kms_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsArn", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"api_key": "apiKey", "secret_key": "secretKey"},
    )
    class AmplitudeConnectorProfileCredentialsProperty:
        def __init__(self, *, api_key: builtins.str, secret_key: builtins.str) -> None:
            '''The ``AmplitudeConnectorProfileCredentials`` property type specifies the connector-specific credentials required when using Amplitude.

            :param api_key: A unique alphanumeric identifier used to authenticate a user, developer, or calling program to your API.
            :param secret_key: The Secret Access Key portion of the credentials.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-amplitudeconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                amplitude_connector_profile_credentials_property = appflow.CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty(
                    api_key="apiKey",
                    secret_key="secretKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "api_key": api_key,
                "secret_key": secret_key,
            }

        @builtins.property
        def api_key(self) -> builtins.str:
            '''A unique alphanumeric identifier used to authenticate a user, developer, or calling program to your API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-amplitudeconnectorprofilecredentials.html#cfn-appflow-connectorprofile-amplitudeconnectorprofilecredentials-apikey
            '''
            result = self._values.get("api_key")
            assert result is not None, "Required property 'api_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def secret_key(self) -> builtins.str:
            '''The Secret Access Key portion of the credentials.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-amplitudeconnectorprofilecredentials.html#cfn-appflow-connectorprofile-amplitudeconnectorprofilecredentials-secretkey
            '''
            result = self._values.get("secret_key")
            assert result is not None, "Required property 'secret_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AmplitudeConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"auth_code": "authCode", "redirect_uri": "redirectUri"},
    )
    class ConnectorOAuthRequestProperty:
        def __init__(
            self,
            *,
            auth_code: typing.Optional[builtins.str] = None,
            redirect_uri: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``ConnectorOAuthRequest`` property type specifies the select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :param auth_code: The code provided by the connector when it has been authenticated via the connected app.
            :param redirect_uri: The URL to which the authentication server redirects the browser after authorization has been granted.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectoroauthrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                connector_oAuth_request_property = appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                    auth_code="authCode",
                    redirect_uri="redirectUri"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if auth_code is not None:
                self._values["auth_code"] = auth_code
            if redirect_uri is not None:
                self._values["redirect_uri"] = redirect_uri

        @builtins.property
        def auth_code(self) -> typing.Optional[builtins.str]:
            '''The code provided by the connector when it has been authenticated via the connected app.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectoroauthrequest.html#cfn-appflow-connectorprofile-connectoroauthrequest-authcode
            '''
            result = self._values.get("auth_code")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def redirect_uri(self) -> typing.Optional[builtins.str]:
            '''The URL to which the authentication server redirects the browser after authorization has been granted.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectoroauthrequest.html#cfn-appflow-connectorprofile-connectoroauthrequest-redirecturi
            '''
            result = self._values.get("redirect_uri")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorOAuthRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.ConnectorProfileConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connector_profile_credentials": "connectorProfileCredentials",
            "connector_profile_properties": "connectorProfileProperties",
        },
    )
    class ConnectorProfileConfigProperty:
        def __init__(
            self,
            *,
            connector_profile_credentials: typing.Union["CfnConnectorProfile.ConnectorProfileCredentialsProperty", _IResolvable_da3f097b],
            connector_profile_properties: typing.Optional[typing.Union["CfnConnectorProfile.ConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Defines the connector-specific configuration and credentials for the connector profile.

            :param connector_profile_credentials: The connector-specific credentials required by each connector.
            :param connector_profile_properties: The connector-specific properties of the profile configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                # basic_auth_credentials: Any
                # o_auth_credentials: Any
                
                connector_profile_config_property = appflow.CfnConnectorProfile.ConnectorProfileConfigProperty(
                    connector_profile_credentials=appflow.CfnConnectorProfile.ConnectorProfileCredentialsProperty(
                        amplitude=appflow.CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty(
                            api_key="apiKey",
                            secret_key="secretKey"
                        ),
                        datadog=appflow.CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty(
                            api_key="apiKey",
                            application_key="applicationKey"
                        ),
                        dynatrace=appflow.CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty(
                            api_token="apiToken"
                        ),
                        google_analytics=appflow.CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty(
                            client_id="clientId",
                            client_secret="clientSecret",
                
                            # the properties below are optional
                            access_token="accessToken",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            ),
                            refresh_token="refreshToken"
                        ),
                        infor_nexus=appflow.CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty(
                            access_key_id="accessKeyId",
                            datakey="datakey",
                            secret_access_key="secretAccessKey",
                            user_id="userId"
                        ),
                        marketo=appflow.CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty(
                            client_id="clientId",
                            client_secret="clientSecret",
                
                            # the properties below are optional
                            access_token="accessToken",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            )
                        ),
                        redshift=appflow.CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty(
                            password="password",
                            username="username"
                        ),
                        salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty(
                            access_token="accessToken",
                            client_credentials_arn="clientCredentialsArn",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            ),
                            refresh_token="refreshToken"
                        ),
                        sapo_data=appflow.CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty(
                            basic_auth_credentials=basic_auth_credentials,
                            o_auth_credentials=o_auth_credentials
                        ),
                        service_now=appflow.CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty(
                            password="password",
                            username="username"
                        ),
                        singular=appflow.CfnConnectorProfile.SingularConnectorProfileCredentialsProperty(
                            api_key="apiKey"
                        ),
                        slack=appflow.CfnConnectorProfile.SlackConnectorProfileCredentialsProperty(
                            client_id="clientId",
                            client_secret="clientSecret",
                
                            # the properties below are optional
                            access_token="accessToken",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            )
                        ),
                        snowflake=appflow.CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty(
                            password="password",
                            username="username"
                        ),
                        trendmicro=appflow.CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty(
                            api_secret_key="apiSecretKey"
                        ),
                        veeva=appflow.CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty(
                            password="password",
                            username="username"
                        ),
                        zendesk=appflow.CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty(
                            client_id="clientId",
                            client_secret="clientSecret",
                
                            # the properties below are optional
                            access_token="accessToken",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            )
                        )
                    ),
                
                    # the properties below are optional
                    connector_profile_properties=appflow.CfnConnectorProfile.ConnectorProfilePropertiesProperty(
                        datadog=appflow.CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        dynatrace=appflow.CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        infor_nexus=appflow.CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        marketo=appflow.CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        redshift=appflow.CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty(
                            bucket_name="bucketName",
                            database_url="databaseUrl",
                            role_arn="roleArn",
                
                            # the properties below are optional
                            bucket_prefix="bucketPrefix"
                        ),
                        salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl",
                            is_sandbox_environment=False
                        ),
                        sapo_data=appflow.CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty(
                            application_host_url="applicationHostUrl",
                            application_service_path="applicationServicePath",
                            client_number="clientNumber",
                            logon_language="logonLanguage",
                            o_auth_properties=appflow.CfnConnectorProfile.OAuthPropertiesProperty(
                                auth_code_url="authCodeUrl",
                                o_auth_scopes=["oAuthScopes"],
                                token_url="tokenUrl"
                            ),
                            port_number=123,
                            private_link_service_name="privateLinkServiceName"
                        ),
                        service_now=appflow.CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        slack=appflow.CfnConnectorProfile.SlackConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        snowflake=appflow.CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty(
                            bucket_name="bucketName",
                            stage="stage",
                            warehouse="warehouse",
                
                            # the properties below are optional
                            account_name="accountName",
                            bucket_prefix="bucketPrefix",
                            private_link_service_name="privateLinkServiceName",
                            region="region"
                        ),
                        veeva=appflow.CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        zendesk=appflow.CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connector_profile_credentials": connector_profile_credentials,
            }
            if connector_profile_properties is not None:
                self._values["connector_profile_properties"] = connector_profile_properties

        @builtins.property
        def connector_profile_credentials(
            self,
        ) -> typing.Union["CfnConnectorProfile.ConnectorProfileCredentialsProperty", _IResolvable_da3f097b]:
            '''The connector-specific credentials required by each connector.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileconfig.html#cfn-appflow-connectorprofile-connectorprofileconfig-connectorprofilecredentials
            '''
            result = self._values.get("connector_profile_credentials")
            assert result is not None, "Required property 'connector_profile_credentials' is missing"
            return typing.cast(typing.Union["CfnConnectorProfile.ConnectorProfileCredentialsProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def connector_profile_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties of the profile configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileconfig.html#cfn-appflow-connectorprofile-connectorprofileconfig-connectorprofileproperties
            '''
            result = self._values.get("connector_profile_properties")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorProfileConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.ConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "amplitude": "amplitude",
            "datadog": "datadog",
            "dynatrace": "dynatrace",
            "google_analytics": "googleAnalytics",
            "infor_nexus": "inforNexus",
            "marketo": "marketo",
            "redshift": "redshift",
            "salesforce": "salesforce",
            "sapo_data": "sapoData",
            "service_now": "serviceNow",
            "singular": "singular",
            "slack": "slack",
            "snowflake": "snowflake",
            "trendmicro": "trendmicro",
            "veeva": "veeva",
            "zendesk": "zendesk",
        },
    )
    class ConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            amplitude: typing.Optional[typing.Union["CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            datadog: typing.Optional[typing.Union["CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            dynatrace: typing.Optional[typing.Union["CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            google_analytics: typing.Optional[typing.Union["CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            infor_nexus: typing.Optional[typing.Union["CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            marketo: typing.Optional[typing.Union["CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            redshift: typing.Optional[typing.Union["CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            salesforce: typing.Optional[typing.Union["CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            sapo_data: typing.Optional[typing.Union["CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            service_now: typing.Optional[typing.Union["CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            singular: typing.Optional[typing.Union["CfnConnectorProfile.SingularConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            slack: typing.Optional[typing.Union["CfnConnectorProfile.SlackConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            snowflake: typing.Optional[typing.Union["CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            trendmicro: typing.Optional[typing.Union["CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            veeva: typing.Optional[typing.Union["CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
            zendesk: typing.Optional[typing.Union["CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``ConnectorProfileCredentials`` property type specifies the connector-specific credentials required by a given connector.

            :param amplitude: The connector-specific credentials required when using Amplitude.
            :param datadog: The connector-specific credentials required when using Datadog.
            :param dynatrace: The connector-specific credentials required when using Dynatrace.
            :param google_analytics: The connector-specific credentials required when using Google Analytics.
            :param infor_nexus: The connector-specific credentials required when using Infor Nexus.
            :param marketo: The connector-specific credentials required when using Marketo.
            :param redshift: The connector-specific credentials required when using Amazon Redshift.
            :param salesforce: The connector-specific credentials required when using Salesforce.
            :param sapo_data: ``CfnConnectorProfile.ConnectorProfileCredentialsProperty.SAPOData``.
            :param service_now: The connector-specific credentials required when using ServiceNow.
            :param singular: The connector-specific credentials required when using Singular.
            :param slack: The connector-specific credentials required when using Slack.
            :param snowflake: The connector-specific credentials required when using Snowflake.
            :param trendmicro: The connector-specific credentials required when using Trend Micro.
            :param veeva: The connector-specific credentials required when using Veeva.
            :param zendesk: The connector-specific credentials required when using Zendesk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                # basic_auth_credentials: Any
                # o_auth_credentials: Any
                
                connector_profile_credentials_property = appflow.CfnConnectorProfile.ConnectorProfileCredentialsProperty(
                    amplitude=appflow.CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty(
                        api_key="apiKey",
                        secret_key="secretKey"
                    ),
                    datadog=appflow.CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty(
                        api_key="apiKey",
                        application_key="applicationKey"
                    ),
                    dynatrace=appflow.CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty(
                        api_token="apiToken"
                    ),
                    google_analytics=appflow.CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty(
                        client_id="clientId",
                        client_secret="clientSecret",
                
                        # the properties below are optional
                        access_token="accessToken",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        ),
                        refresh_token="refreshToken"
                    ),
                    infor_nexus=appflow.CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty(
                        access_key_id="accessKeyId",
                        datakey="datakey",
                        secret_access_key="secretAccessKey",
                        user_id="userId"
                    ),
                    marketo=appflow.CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty(
                        client_id="clientId",
                        client_secret="clientSecret",
                
                        # the properties below are optional
                        access_token="accessToken",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        )
                    ),
                    redshift=appflow.CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty(
                        password="password",
                        username="username"
                    ),
                    salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty(
                        access_token="accessToken",
                        client_credentials_arn="clientCredentialsArn",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        ),
                        refresh_token="refreshToken"
                    ),
                    sapo_data=appflow.CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty(
                        basic_auth_credentials=basic_auth_credentials,
                        o_auth_credentials=o_auth_credentials
                    ),
                    service_now=appflow.CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty(
                        password="password",
                        username="username"
                    ),
                    singular=appflow.CfnConnectorProfile.SingularConnectorProfileCredentialsProperty(
                        api_key="apiKey"
                    ),
                    slack=appflow.CfnConnectorProfile.SlackConnectorProfileCredentialsProperty(
                        client_id="clientId",
                        client_secret="clientSecret",
                
                        # the properties below are optional
                        access_token="accessToken",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        )
                    ),
                    snowflake=appflow.CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty(
                        password="password",
                        username="username"
                    ),
                    trendmicro=appflow.CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty(
                        api_secret_key="apiSecretKey"
                    ),
                    veeva=appflow.CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty(
                        password="password",
                        username="username"
                    ),
                    zendesk=appflow.CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty(
                        client_id="clientId",
                        client_secret="clientSecret",
                
                        # the properties below are optional
                        access_token="accessToken",
                        connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                            auth_code="authCode",
                            redirect_uri="redirectUri"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if amplitude is not None:
                self._values["amplitude"] = amplitude
            if datadog is not None:
                self._values["datadog"] = datadog
            if dynatrace is not None:
                self._values["dynatrace"] = dynatrace
            if google_analytics is not None:
                self._values["google_analytics"] = google_analytics
            if infor_nexus is not None:
                self._values["infor_nexus"] = infor_nexus
            if marketo is not None:
                self._values["marketo"] = marketo
            if redshift is not None:
                self._values["redshift"] = redshift
            if salesforce is not None:
                self._values["salesforce"] = salesforce
            if sapo_data is not None:
                self._values["sapo_data"] = sapo_data
            if service_now is not None:
                self._values["service_now"] = service_now
            if singular is not None:
                self._values["singular"] = singular
            if slack is not None:
                self._values["slack"] = slack
            if snowflake is not None:
                self._values["snowflake"] = snowflake
            if trendmicro is not None:
                self._values["trendmicro"] = trendmicro
            if veeva is not None:
                self._values["veeva"] = veeva
            if zendesk is not None:
                self._values["zendesk"] = zendesk

        @builtins.property
        def amplitude(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Amplitude.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-amplitude
            '''
            result = self._values.get("amplitude")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def datadog(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Datadog.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-datadog
            '''
            result = self._values.get("datadog")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def dynatrace(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Dynatrace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-dynatrace
            '''
            result = self._values.get("dynatrace")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def google_analytics(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Google Analytics.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-googleanalytics
            '''
            result = self._values.get("google_analytics")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def infor_nexus(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Infor Nexus.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-infornexus
            '''
            result = self._values.get("infor_nexus")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def marketo(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Marketo.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-marketo
            '''
            result = self._values.get("marketo")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def redshift(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Amazon Redshift.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-redshift
            '''
            result = self._values.get("redshift")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def salesforce(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Salesforce.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-salesforce
            '''
            result = self._values.get("salesforce")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sapo_data(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''``CfnConnectorProfile.ConnectorProfileCredentialsProperty.SAPOData``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-sapodata
            '''
            result = self._values.get("sapo_data")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def service_now(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using ServiceNow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-servicenow
            '''
            result = self._values.get("service_now")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def singular(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SingularConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Singular.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-singular
            '''
            result = self._values.get("singular")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SingularConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def slack(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SlackConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-slack
            '''
            result = self._values.get("slack")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SlackConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def snowflake(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Snowflake.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-snowflake
            '''
            result = self._values.get("snowflake")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def trendmicro(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Trend Micro.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-trendmicro
            '''
            result = self._values.get("trendmicro")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def veeva(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Veeva.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-veeva
            '''
            result = self._values.get("veeva")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def zendesk(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty", _IResolvable_da3f097b]]:
            '''The connector-specific credentials required when using Zendesk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofilecredentials.html#cfn-appflow-connectorprofile-connectorprofilecredentials-zendesk
            '''
            result = self._values.get("zendesk")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.ConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "datadog": "datadog",
            "dynatrace": "dynatrace",
            "infor_nexus": "inforNexus",
            "marketo": "marketo",
            "redshift": "redshift",
            "salesforce": "salesforce",
            "sapo_data": "sapoData",
            "service_now": "serviceNow",
            "slack": "slack",
            "snowflake": "snowflake",
            "veeva": "veeva",
            "zendesk": "zendesk",
        },
    )
    class ConnectorProfilePropertiesProperty:
        def __init__(
            self,
            *,
            datadog: typing.Optional[typing.Union["CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            dynatrace: typing.Optional[typing.Union["CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            infor_nexus: typing.Optional[typing.Union["CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            marketo: typing.Optional[typing.Union["CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            redshift: typing.Optional[typing.Union["CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            salesforce: typing.Optional[typing.Union["CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            sapo_data: typing.Optional[typing.Union["CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            service_now: typing.Optional[typing.Union["CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            slack: typing.Optional[typing.Union["CfnConnectorProfile.SlackConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            snowflake: typing.Optional[typing.Union["CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            veeva: typing.Optional[typing.Union["CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
            zendesk: typing.Optional[typing.Union["CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``ConnectorProfileProperties`` property type specifies the connector-specific profile properties required by each connector.

            :param datadog: The connector-specific properties required by Datadog.
            :param dynatrace: The connector-specific properties required by Dynatrace.
            :param infor_nexus: The connector-specific properties required by Infor Nexus.
            :param marketo: The connector-specific properties required by Marketo.
            :param redshift: The connector-specific properties required by Amazon Redshift.
            :param salesforce: The connector-specific properties required by Salesforce.
            :param sapo_data: ``CfnConnectorProfile.ConnectorProfilePropertiesProperty.SAPOData``.
            :param service_now: The connector-specific properties required by serviceNow.
            :param slack: The connector-specific properties required by Slack.
            :param snowflake: The connector-specific properties required by Snowflake.
            :param veeva: The connector-specific properties required by Veeva.
            :param zendesk: The connector-specific properties required by Zendesk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                connector_profile_properties_property = appflow.CfnConnectorProfile.ConnectorProfilePropertiesProperty(
                    datadog=appflow.CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    dynatrace=appflow.CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    infor_nexus=appflow.CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    marketo=appflow.CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    redshift=appflow.CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty(
                        bucket_name="bucketName",
                        database_url="databaseUrl",
                        role_arn="roleArn",
                
                        # the properties below are optional
                        bucket_prefix="bucketPrefix"
                    ),
                    salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl",
                        is_sandbox_environment=False
                    ),
                    sapo_data=appflow.CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty(
                        application_host_url="applicationHostUrl",
                        application_service_path="applicationServicePath",
                        client_number="clientNumber",
                        logon_language="logonLanguage",
                        o_auth_properties=appflow.CfnConnectorProfile.OAuthPropertiesProperty(
                            auth_code_url="authCodeUrl",
                            o_auth_scopes=["oAuthScopes"],
                            token_url="tokenUrl"
                        ),
                        port_number=123,
                        private_link_service_name="privateLinkServiceName"
                    ),
                    service_now=appflow.CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    slack=appflow.CfnConnectorProfile.SlackConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    snowflake=appflow.CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty(
                        bucket_name="bucketName",
                        stage="stage",
                        warehouse="warehouse",
                
                        # the properties below are optional
                        account_name="accountName",
                        bucket_prefix="bucketPrefix",
                        private_link_service_name="privateLinkServiceName",
                        region="region"
                    ),
                    veeva=appflow.CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    ),
                    zendesk=appflow.CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty(
                        instance_url="instanceUrl"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if datadog is not None:
                self._values["datadog"] = datadog
            if dynatrace is not None:
                self._values["dynatrace"] = dynatrace
            if infor_nexus is not None:
                self._values["infor_nexus"] = infor_nexus
            if marketo is not None:
                self._values["marketo"] = marketo
            if redshift is not None:
                self._values["redshift"] = redshift
            if salesforce is not None:
                self._values["salesforce"] = salesforce
            if sapo_data is not None:
                self._values["sapo_data"] = sapo_data
            if service_now is not None:
                self._values["service_now"] = service_now
            if slack is not None:
                self._values["slack"] = slack
            if snowflake is not None:
                self._values["snowflake"] = snowflake
            if veeva is not None:
                self._values["veeva"] = veeva
            if zendesk is not None:
                self._values["zendesk"] = zendesk

        @builtins.property
        def datadog(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Datadog.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-datadog
            '''
            result = self._values.get("datadog")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def dynatrace(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Dynatrace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-dynatrace
            '''
            result = self._values.get("dynatrace")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def infor_nexus(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Infor Nexus.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-infornexus
            '''
            result = self._values.get("infor_nexus")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def marketo(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Marketo.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-marketo
            '''
            result = self._values.get("marketo")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def redshift(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Amazon Redshift.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-redshift
            '''
            result = self._values.get("redshift")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def salesforce(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Salesforce.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-salesforce
            '''
            result = self._values.get("salesforce")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sapo_data(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnConnectorProfile.ConnectorProfilePropertiesProperty.SAPOData``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-sapodata
            '''
            result = self._values.get("sapo_data")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def service_now(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by serviceNow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-servicenow
            '''
            result = self._values.get("service_now")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def slack(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SlackConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-slack
            '''
            result = self._values.get("slack")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SlackConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def snowflake(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Snowflake.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-snowflake
            '''
            result = self._values.get("snowflake")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def veeva(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Veeva.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-veeva
            '''
            result = self._values.get("veeva")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def zendesk(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty", _IResolvable_da3f097b]]:
            '''The connector-specific properties required by Zendesk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-connectorprofileproperties.html#cfn-appflow-connectorprofile-connectorprofileproperties-zendesk
            '''
            result = self._values.get("zendesk")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"api_key": "apiKey", "application_key": "applicationKey"},
    )
    class DatadogConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            api_key: builtins.str,
            application_key: builtins.str,
        ) -> None:
            '''The ``DatadogConnectorProfileCredentials`` property type specifies the connector-specific credentials required by Datadog.

            :param api_key: A unique alphanumeric identifier used to authenticate a user, developer, or calling program to your API.
            :param application_key: Application keys, in conjunction with your API key, give you full access to Datadog’s programmatic API. Application keys are associated with the user account that created them. The application key is used to log all requests made to the API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-datadogconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                datadog_connector_profile_credentials_property = appflow.CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty(
                    api_key="apiKey",
                    application_key="applicationKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "api_key": api_key,
                "application_key": application_key,
            }

        @builtins.property
        def api_key(self) -> builtins.str:
            '''A unique alphanumeric identifier used to authenticate a user, developer, or calling program to your API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-datadogconnectorprofilecredentials.html#cfn-appflow-connectorprofile-datadogconnectorprofilecredentials-apikey
            '''
            result = self._values.get("api_key")
            assert result is not None, "Required property 'api_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def application_key(self) -> builtins.str:
            '''Application keys, in conjunction with your API key, give you full access to Datadog’s programmatic API.

            Application keys are associated with the user account that created them. The application key is used to log all requests made to the API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-datadogconnectorprofilecredentials.html#cfn-appflow-connectorprofile-datadogconnectorprofilecredentials-applicationkey
            '''
            result = self._values.get("application_key")
            assert result is not None, "Required property 'application_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatadogConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"instance_url": "instanceUrl"},
    )
    class DatadogConnectorProfilePropertiesProperty:
        def __init__(self, *, instance_url: builtins.str) -> None:
            '''The ``DatadogConnectorProfileProperties`` property type specifies the connector-specific profile properties required by Datadog.

            :param instance_url: The location of the Datadog resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-datadogconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                datadog_connector_profile_properties_property = appflow.CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_url": instance_url,
            }

        @builtins.property
        def instance_url(self) -> builtins.str:
            '''The location of the Datadog resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-datadogconnectorprofileproperties.html#cfn-appflow-connectorprofile-datadogconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            assert result is not None, "Required property 'instance_url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatadogConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"api_token": "apiToken"},
    )
    class DynatraceConnectorProfileCredentialsProperty:
        def __init__(self, *, api_token: builtins.str) -> None:
            '''The ``DynatraceConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required by Dynatrace.

            :param api_token: The API tokens used by Dynatrace API to authenticate various API calls.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-dynatraceconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                dynatrace_connector_profile_credentials_property = appflow.CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty(
                    api_token="apiToken"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "api_token": api_token,
            }

        @builtins.property
        def api_token(self) -> builtins.str:
            '''The API tokens used by Dynatrace API to authenticate various API calls.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-dynatraceconnectorprofilecredentials.html#cfn-appflow-connectorprofile-dynatraceconnectorprofilecredentials-apitoken
            '''
            result = self._values.get("api_token")
            assert result is not None, "Required property 'api_token' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DynatraceConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"instance_url": "instanceUrl"},
    )
    class DynatraceConnectorProfilePropertiesProperty:
        def __init__(self, *, instance_url: builtins.str) -> None:
            '''The ``DynatraceConnectorProfileProperties`` property type specifies the connector-specific profile properties required by Dynatrace.

            :param instance_url: The location of the Dynatrace resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-dynatraceconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                dynatrace_connector_profile_properties_property = appflow.CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_url": instance_url,
            }

        @builtins.property
        def instance_url(self) -> builtins.str:
            '''The location of the Dynatrace resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-dynatraceconnectorprofileproperties.html#cfn-appflow-connectorprofile-dynatraceconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            assert result is not None, "Required property 'instance_url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DynatraceConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "client_id": "clientId",
            "client_secret": "clientSecret",
            "access_token": "accessToken",
            "connector_o_auth_request": "connectorOAuthRequest",
            "refresh_token": "refreshToken",
        },
    )
    class GoogleAnalyticsConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            client_id: builtins.str,
            client_secret: builtins.str,
            access_token: typing.Optional[builtins.str] = None,
            connector_o_auth_request: typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]] = None,
            refresh_token: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``GoogleAnalyticsConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required by Google Analytics.

            :param client_id: The identifier for the desired client.
            :param client_secret: The client secret used by the OAuth client to authenticate to the authorization server.
            :param access_token: The credentials used to access protected Google Analytics resources.
            :param connector_o_auth_request: Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.
            :param refresh_token: The credentials used to acquire new access tokens. This is required only for OAuth2 access tokens, and is not required for OAuth1 access tokens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                google_analytics_connector_profile_credentials_property = appflow.CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty(
                    client_id="clientId",
                    client_secret="clientSecret",
                
                    # the properties below are optional
                    access_token="accessToken",
                    connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                        auth_code="authCode",
                        redirect_uri="redirectUri"
                    ),
                    refresh_token="refreshToken"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "client_id": client_id,
                "client_secret": client_secret,
            }
            if access_token is not None:
                self._values["access_token"] = access_token
            if connector_o_auth_request is not None:
                self._values["connector_o_auth_request"] = connector_o_auth_request
            if refresh_token is not None:
                self._values["refresh_token"] = refresh_token

        @builtins.property
        def client_id(self) -> builtins.str:
            '''The identifier for the desired client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials.html#cfn-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials-clientid
            '''
            result = self._values.get("client_id")
            assert result is not None, "Required property 'client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_secret(self) -> builtins.str:
            '''The client secret used by the OAuth client to authenticate to the authorization server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials.html#cfn-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials-clientsecret
            '''
            result = self._values.get("client_secret")
            assert result is not None, "Required property 'client_secret' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def access_token(self) -> typing.Optional[builtins.str]:
            '''The credentials used to access protected Google Analytics resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials.html#cfn-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials-accesstoken
            '''
            result = self._values.get("access_token")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def connector_o_auth_request(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]]:
            '''Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials.html#cfn-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials-connectoroauthrequest
            '''
            result = self._values.get("connector_o_auth_request")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def refresh_token(self) -> typing.Optional[builtins.str]:
            '''The credentials used to acquire new access tokens.

            This is required only for OAuth2 access tokens, and is not required for OAuth1 access tokens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials.html#cfn-appflow-connectorprofile-googleanalyticsconnectorprofilecredentials-refreshtoken
            '''
            result = self._values.get("refresh_token")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GoogleAnalyticsConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "access_key_id": "accessKeyId",
            "datakey": "datakey",
            "secret_access_key": "secretAccessKey",
            "user_id": "userId",
        },
    )
    class InforNexusConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            access_key_id: builtins.str,
            datakey: builtins.str,
            secret_access_key: builtins.str,
            user_id: builtins.str,
        ) -> None:
            '''The ``InforNexusConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required by Infor Nexus.

            :param access_key_id: The Access Key portion of the credentials.
            :param datakey: The encryption keys used to encrypt data.
            :param secret_access_key: The secret key used to sign requests.
            :param user_id: The identifier for the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-infornexusconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                infor_nexus_connector_profile_credentials_property = appflow.CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty(
                    access_key_id="accessKeyId",
                    datakey="datakey",
                    secret_access_key="secretAccessKey",
                    user_id="userId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "access_key_id": access_key_id,
                "datakey": datakey,
                "secret_access_key": secret_access_key,
                "user_id": user_id,
            }

        @builtins.property
        def access_key_id(self) -> builtins.str:
            '''The Access Key portion of the credentials.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-infornexusconnectorprofilecredentials.html#cfn-appflow-connectorprofile-infornexusconnectorprofilecredentials-accesskeyid
            '''
            result = self._values.get("access_key_id")
            assert result is not None, "Required property 'access_key_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def datakey(self) -> builtins.str:
            '''The encryption keys used to encrypt data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-infornexusconnectorprofilecredentials.html#cfn-appflow-connectorprofile-infornexusconnectorprofilecredentials-datakey
            '''
            result = self._values.get("datakey")
            assert result is not None, "Required property 'datakey' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def secret_access_key(self) -> builtins.str:
            '''The secret key used to sign requests.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-infornexusconnectorprofilecredentials.html#cfn-appflow-connectorprofile-infornexusconnectorprofilecredentials-secretaccesskey
            '''
            result = self._values.get("secret_access_key")
            assert result is not None, "Required property 'secret_access_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_id(self) -> builtins.str:
            '''The identifier for the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-infornexusconnectorprofilecredentials.html#cfn-appflow-connectorprofile-infornexusconnectorprofilecredentials-userid
            '''
            result = self._values.get("user_id")
            assert result is not None, "Required property 'user_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InforNexusConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"instance_url": "instanceUrl"},
    )
    class InforNexusConnectorProfilePropertiesProperty:
        def __init__(self, *, instance_url: builtins.str) -> None:
            '''The ``InforNexusConnectorProfileProperties`` property type specifies the connector-specific profile properties required by Infor Nexus.

            :param instance_url: The location of the Infor Nexus resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-infornexusconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                infor_nexus_connector_profile_properties_property = appflow.CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_url": instance_url,
            }

        @builtins.property
        def instance_url(self) -> builtins.str:
            '''The location of the Infor Nexus resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-infornexusconnectorprofileproperties.html#cfn-appflow-connectorprofile-infornexusconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            assert result is not None, "Required property 'instance_url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InforNexusConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "client_id": "clientId",
            "client_secret": "clientSecret",
            "access_token": "accessToken",
            "connector_o_auth_request": "connectorOAuthRequest",
        },
    )
    class MarketoConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            client_id: builtins.str,
            client_secret: builtins.str,
            access_token: typing.Optional[builtins.str] = None,
            connector_o_auth_request: typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``MarketoConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required by Marketo.

            :param client_id: The identifier for the desired client.
            :param client_secret: The client secret used by the OAuth client to authenticate to the authorization server.
            :param access_token: The credentials used to access protected Marketo resources.
            :param connector_o_auth_request: Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-marketoconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                marketo_connector_profile_credentials_property = appflow.CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty(
                    client_id="clientId",
                    client_secret="clientSecret",
                
                    # the properties below are optional
                    access_token="accessToken",
                    connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                        auth_code="authCode",
                        redirect_uri="redirectUri"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "client_id": client_id,
                "client_secret": client_secret,
            }
            if access_token is not None:
                self._values["access_token"] = access_token
            if connector_o_auth_request is not None:
                self._values["connector_o_auth_request"] = connector_o_auth_request

        @builtins.property
        def client_id(self) -> builtins.str:
            '''The identifier for the desired client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-marketoconnectorprofilecredentials.html#cfn-appflow-connectorprofile-marketoconnectorprofilecredentials-clientid
            '''
            result = self._values.get("client_id")
            assert result is not None, "Required property 'client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_secret(self) -> builtins.str:
            '''The client secret used by the OAuth client to authenticate to the authorization server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-marketoconnectorprofilecredentials.html#cfn-appflow-connectorprofile-marketoconnectorprofilecredentials-clientsecret
            '''
            result = self._values.get("client_secret")
            assert result is not None, "Required property 'client_secret' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def access_token(self) -> typing.Optional[builtins.str]:
            '''The credentials used to access protected Marketo resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-marketoconnectorprofilecredentials.html#cfn-appflow-connectorprofile-marketoconnectorprofilecredentials-accesstoken
            '''
            result = self._values.get("access_token")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def connector_o_auth_request(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]]:
            '''Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-marketoconnectorprofilecredentials.html#cfn-appflow-connectorprofile-marketoconnectorprofilecredentials-connectoroauthrequest
            '''
            result = self._values.get("connector_o_auth_request")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MarketoConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"instance_url": "instanceUrl"},
    )
    class MarketoConnectorProfilePropertiesProperty:
        def __init__(self, *, instance_url: builtins.str) -> None:
            '''The ``MarketoConnectorProfileProperties`` property type specifies the connector-specific profile properties required when using Marketo.

            :param instance_url: The location of the Marketo resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-marketoconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                marketo_connector_profile_properties_property = appflow.CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_url": instance_url,
            }

        @builtins.property
        def instance_url(self) -> builtins.str:
            '''The location of the Marketo resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-marketoconnectorprofileproperties.html#cfn-appflow-connectorprofile-marketoconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            assert result is not None, "Required property 'instance_url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MarketoConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.OAuthPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "auth_code_url": "authCodeUrl",
            "o_auth_scopes": "oAuthScopes",
            "token_url": "tokenUrl",
        },
    )
    class OAuthPropertiesProperty:
        def __init__(
            self,
            *,
            auth_code_url: typing.Optional[builtins.str] = None,
            o_auth_scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
            token_url: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param auth_code_url: ``CfnConnectorProfile.OAuthPropertiesProperty.AuthCodeUrl``.
            :param o_auth_scopes: ``CfnConnectorProfile.OAuthPropertiesProperty.OAuthScopes``.
            :param token_url: ``CfnConnectorProfile.OAuthPropertiesProperty.TokenUrl``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-oauthproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                o_auth_properties_property = appflow.CfnConnectorProfile.OAuthPropertiesProperty(
                    auth_code_url="authCodeUrl",
                    o_auth_scopes=["oAuthScopes"],
                    token_url="tokenUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if auth_code_url is not None:
                self._values["auth_code_url"] = auth_code_url
            if o_auth_scopes is not None:
                self._values["o_auth_scopes"] = o_auth_scopes
            if token_url is not None:
                self._values["token_url"] = token_url

        @builtins.property
        def auth_code_url(self) -> typing.Optional[builtins.str]:
            '''``CfnConnectorProfile.OAuthPropertiesProperty.AuthCodeUrl``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-oauthproperties.html#cfn-appflow-connectorprofile-oauthproperties-authcodeurl
            '''
            result = self._values.get("auth_code_url")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def o_auth_scopes(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnConnectorProfile.OAuthPropertiesProperty.OAuthScopes``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-oauthproperties.html#cfn-appflow-connectorprofile-oauthproperties-oauthscopes
            '''
            result = self._values.get("o_auth_scopes")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def token_url(self) -> typing.Optional[builtins.str]:
            '''``CfnConnectorProfile.OAuthPropertiesProperty.TokenUrl``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-oauthproperties.html#cfn-appflow-connectorprofile-oauthproperties-tokenurl
            '''
            result = self._values.get("token_url")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OAuthPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"password": "password", "username": "username"},
    )
    class RedshiftConnectorProfileCredentialsProperty:
        def __init__(self, *, password: builtins.str, username: builtins.str) -> None:
            '''The ``RedshiftConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using Amazon Redshift.

            :param password: The password that corresponds to the user name.
            :param username: The name of the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-redshiftconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                redshift_connector_profile_credentials_property = appflow.CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty(
                    password="password",
                    username="username"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
                "username": username,
            }

        @builtins.property
        def password(self) -> builtins.str:
            '''The password that corresponds to the user name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-redshiftconnectorprofilecredentials.html#cfn-appflow-connectorprofile-redshiftconnectorprofilecredentials-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def username(self) -> builtins.str:
            '''The name of the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-redshiftconnectorprofilecredentials.html#cfn-appflow-connectorprofile-redshiftconnectorprofilecredentials-username
            '''
            result = self._values.get("username")
            assert result is not None, "Required property 'username' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedshiftConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_name": "bucketName",
            "database_url": "databaseUrl",
            "role_arn": "roleArn",
            "bucket_prefix": "bucketPrefix",
        },
    )
    class RedshiftConnectorProfilePropertiesProperty:
        def __init__(
            self,
            *,
            bucket_name: builtins.str,
            database_url: builtins.str,
            role_arn: builtins.str,
            bucket_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``RedshiftConnectorProfileProperties`` property type specifies the connector-specific profile properties when using Amazon Redshift.

            :param bucket_name: A name for the associated Amazon S3 bucket.
            :param database_url: The JDBC URL of the Amazon Redshift cluster.
            :param role_arn: The Amazon Resource Name (ARN) of the IAM role.
            :param bucket_prefix: The object key for the destination bucket in which Amazon AppFlow places the files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-redshiftconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                redshift_connector_profile_properties_property = appflow.CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty(
                    bucket_name="bucketName",
                    database_url="databaseUrl",
                    role_arn="roleArn",
                
                    # the properties below are optional
                    bucket_prefix="bucketPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_name": bucket_name,
                "database_url": database_url,
                "role_arn": role_arn,
            }
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix

        @builtins.property
        def bucket_name(self) -> builtins.str:
            '''A name for the associated Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-redshiftconnectorprofileproperties.html#cfn-appflow-connectorprofile-redshiftconnectorprofileproperties-bucketname
            '''
            result = self._values.get("bucket_name")
            assert result is not None, "Required property 'bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def database_url(self) -> builtins.str:
            '''The JDBC URL of the Amazon Redshift cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-redshiftconnectorprofileproperties.html#cfn-appflow-connectorprofile-redshiftconnectorprofileproperties-databaseurl
            '''
            result = self._values.get("database_url")
            assert result is not None, "Required property 'database_url' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the IAM role.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-redshiftconnectorprofileproperties.html#cfn-appflow-connectorprofile-redshiftconnectorprofileproperties-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''The object key for the destination bucket in which Amazon AppFlow places the files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-redshiftconnectorprofileproperties.html#cfn-appflow-connectorprofile-redshiftconnectorprofileproperties-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedshiftConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "basic_auth_credentials": "basicAuthCredentials",
            "o_auth_credentials": "oAuthCredentials",
        },
    )
    class SAPODataConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            basic_auth_credentials: typing.Any = None,
            o_auth_credentials: typing.Any = None,
        ) -> None:
            '''
            :param basic_auth_credentials: ``CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty.BasicAuthCredentials``.
            :param o_auth_credentials: ``CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty.OAuthCredentials``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                # basic_auth_credentials: Any
                # o_auth_credentials: Any
                
                s_aPOData_connector_profile_credentials_property = appflow.CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty(
                    basic_auth_credentials=basic_auth_credentials,
                    o_auth_credentials=o_auth_credentials
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if basic_auth_credentials is not None:
                self._values["basic_auth_credentials"] = basic_auth_credentials
            if o_auth_credentials is not None:
                self._values["o_auth_credentials"] = o_auth_credentials

        @builtins.property
        def basic_auth_credentials(self) -> typing.Any:
            '''``CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty.BasicAuthCredentials``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofilecredentials.html#cfn-appflow-connectorprofile-sapodataconnectorprofilecredentials-basicauthcredentials
            '''
            result = self._values.get("basic_auth_credentials")
            return typing.cast(typing.Any, result)

        @builtins.property
        def o_auth_credentials(self) -> typing.Any:
            '''``CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty.OAuthCredentials``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofilecredentials.html#cfn-appflow-connectorprofile-sapodataconnectorprofilecredentials-oauthcredentials
            '''
            result = self._values.get("o_auth_credentials")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SAPODataConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "application_host_url": "applicationHostUrl",
            "application_service_path": "applicationServicePath",
            "client_number": "clientNumber",
            "logon_language": "logonLanguage",
            "o_auth_properties": "oAuthProperties",
            "port_number": "portNumber",
            "private_link_service_name": "privateLinkServiceName",
        },
    )
    class SAPODataConnectorProfilePropertiesProperty:
        def __init__(
            self,
            *,
            application_host_url: typing.Optional[builtins.str] = None,
            application_service_path: typing.Optional[builtins.str] = None,
            client_number: typing.Optional[builtins.str] = None,
            logon_language: typing.Optional[builtins.str] = None,
            o_auth_properties: typing.Optional[typing.Union["CfnConnectorProfile.OAuthPropertiesProperty", _IResolvable_da3f097b]] = None,
            port_number: typing.Optional[jsii.Number] = None,
            private_link_service_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param application_host_url: ``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.ApplicationHostUrl``.
            :param application_service_path: ``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.ApplicationServicePath``.
            :param client_number: ``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.ClientNumber``.
            :param logon_language: ``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.LogonLanguage``.
            :param o_auth_properties: ``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.OAuthProperties``.
            :param port_number: ``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.PortNumber``.
            :param private_link_service_name: ``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.PrivateLinkServiceName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                s_aPOData_connector_profile_properties_property = appflow.CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty(
                    application_host_url="applicationHostUrl",
                    application_service_path="applicationServicePath",
                    client_number="clientNumber",
                    logon_language="logonLanguage",
                    o_auth_properties=appflow.CfnConnectorProfile.OAuthPropertiesProperty(
                        auth_code_url="authCodeUrl",
                        o_auth_scopes=["oAuthScopes"],
                        token_url="tokenUrl"
                    ),
                    port_number=123,
                    private_link_service_name="privateLinkServiceName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if application_host_url is not None:
                self._values["application_host_url"] = application_host_url
            if application_service_path is not None:
                self._values["application_service_path"] = application_service_path
            if client_number is not None:
                self._values["client_number"] = client_number
            if logon_language is not None:
                self._values["logon_language"] = logon_language
            if o_auth_properties is not None:
                self._values["o_auth_properties"] = o_auth_properties
            if port_number is not None:
                self._values["port_number"] = port_number
            if private_link_service_name is not None:
                self._values["private_link_service_name"] = private_link_service_name

        @builtins.property
        def application_host_url(self) -> typing.Optional[builtins.str]:
            '''``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.ApplicationHostUrl``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofileproperties.html#cfn-appflow-connectorprofile-sapodataconnectorprofileproperties-applicationhosturl
            '''
            result = self._values.get("application_host_url")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def application_service_path(self) -> typing.Optional[builtins.str]:
            '''``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.ApplicationServicePath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofileproperties.html#cfn-appflow-connectorprofile-sapodataconnectorprofileproperties-applicationservicepath
            '''
            result = self._values.get("application_service_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def client_number(self) -> typing.Optional[builtins.str]:
            '''``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.ClientNumber``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofileproperties.html#cfn-appflow-connectorprofile-sapodataconnectorprofileproperties-clientnumber
            '''
            result = self._values.get("client_number")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def logon_language(self) -> typing.Optional[builtins.str]:
            '''``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.LogonLanguage``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofileproperties.html#cfn-appflow-connectorprofile-sapodataconnectorprofileproperties-logonlanguage
            '''
            result = self._values.get("logon_language")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def o_auth_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.OAuthPropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.OAuthProperties``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofileproperties.html#cfn-appflow-connectorprofile-sapodataconnectorprofileproperties-oauthproperties
            '''
            result = self._values.get("o_auth_properties")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.OAuthPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def port_number(self) -> typing.Optional[jsii.Number]:
            '''``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.PortNumber``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofileproperties.html#cfn-appflow-connectorprofile-sapodataconnectorprofileproperties-portnumber
            '''
            result = self._values.get("port_number")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def private_link_service_name(self) -> typing.Optional[builtins.str]:
            '''``CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty.PrivateLinkServiceName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-sapodataconnectorprofileproperties.html#cfn-appflow-connectorprofile-sapodataconnectorprofileproperties-privatelinkservicename
            '''
            result = self._values.get("private_link_service_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SAPODataConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "access_token": "accessToken",
            "client_credentials_arn": "clientCredentialsArn",
            "connector_o_auth_request": "connectorOAuthRequest",
            "refresh_token": "refreshToken",
        },
    )
    class SalesforceConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            access_token: typing.Optional[builtins.str] = None,
            client_credentials_arn: typing.Optional[builtins.str] = None,
            connector_o_auth_request: typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]] = None,
            refresh_token: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``SalesforceConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using Salesforce.

            :param access_token: The credentials used to access protected Salesforce resources.
            :param client_credentials_arn: The secret manager ARN, which contains the client ID and client secret of the connected app.
            :param connector_o_auth_request: Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.
            :param refresh_token: The credentials used to acquire new access tokens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                salesforce_connector_profile_credentials_property = appflow.CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty(
                    access_token="accessToken",
                    client_credentials_arn="clientCredentialsArn",
                    connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                        auth_code="authCode",
                        redirect_uri="redirectUri"
                    ),
                    refresh_token="refreshToken"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if access_token is not None:
                self._values["access_token"] = access_token
            if client_credentials_arn is not None:
                self._values["client_credentials_arn"] = client_credentials_arn
            if connector_o_auth_request is not None:
                self._values["connector_o_auth_request"] = connector_o_auth_request
            if refresh_token is not None:
                self._values["refresh_token"] = refresh_token

        @builtins.property
        def access_token(self) -> typing.Optional[builtins.str]:
            '''The credentials used to access protected Salesforce resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofilecredentials.html#cfn-appflow-connectorprofile-salesforceconnectorprofilecredentials-accesstoken
            '''
            result = self._values.get("access_token")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def client_credentials_arn(self) -> typing.Optional[builtins.str]:
            '''The secret manager ARN, which contains the client ID and client secret of the connected app.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofilecredentials.html#cfn-appflow-connectorprofile-salesforceconnectorprofilecredentials-clientcredentialsarn
            '''
            result = self._values.get("client_credentials_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def connector_o_auth_request(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]]:
            '''Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofilecredentials.html#cfn-appflow-connectorprofile-salesforceconnectorprofilecredentials-connectoroauthrequest
            '''
            result = self._values.get("connector_o_auth_request")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def refresh_token(self) -> typing.Optional[builtins.str]:
            '''The credentials used to acquire new access tokens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofilecredentials.html#cfn-appflow-connectorprofile-salesforceconnectorprofilecredentials-refreshtoken
            '''
            result = self._values.get("refresh_token")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SalesforceConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "instance_url": "instanceUrl",
            "is_sandbox_environment": "isSandboxEnvironment",
        },
    )
    class SalesforceConnectorProfilePropertiesProperty:
        def __init__(
            self,
            *,
            instance_url: typing.Optional[builtins.str] = None,
            is_sandbox_environment: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``SalesforceConnectorProfileProperties`` property type specifies the connector-specific profile properties required when using Salesforce.

            :param instance_url: The location of the Salesforce resource.
            :param is_sandbox_environment: Indicates whether the connector profile applies to a sandbox or production environment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                salesforce_connector_profile_properties_property = appflow.CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl",
                    is_sandbox_environment=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if instance_url is not None:
                self._values["instance_url"] = instance_url
            if is_sandbox_environment is not None:
                self._values["is_sandbox_environment"] = is_sandbox_environment

        @builtins.property
        def instance_url(self) -> typing.Optional[builtins.str]:
            '''The location of the Salesforce resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofileproperties.html#cfn-appflow-connectorprofile-salesforceconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def is_sandbox_environment(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the connector profile applies to a sandbox or production environment.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-salesforceconnectorprofileproperties.html#cfn-appflow-connectorprofile-salesforceconnectorprofileproperties-issandboxenvironment
            '''
            result = self._values.get("is_sandbox_environment")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SalesforceConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"password": "password", "username": "username"},
    )
    class ServiceNowConnectorProfileCredentialsProperty:
        def __init__(self, *, password: builtins.str, username: builtins.str) -> None:
            '''The ``ServiceNowConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using ServiceNow.

            :param password: The password that corresponds to the user name.
            :param username: The name of the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-servicenowconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                service_now_connector_profile_credentials_property = appflow.CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty(
                    password="password",
                    username="username"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
                "username": username,
            }

        @builtins.property
        def password(self) -> builtins.str:
            '''The password that corresponds to the user name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-servicenowconnectorprofilecredentials.html#cfn-appflow-connectorprofile-servicenowconnectorprofilecredentials-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def username(self) -> builtins.str:
            '''The name of the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-servicenowconnectorprofilecredentials.html#cfn-appflow-connectorprofile-servicenowconnectorprofilecredentials-username
            '''
            result = self._values.get("username")
            assert result is not None, "Required property 'username' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServiceNowConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"instance_url": "instanceUrl"},
    )
    class ServiceNowConnectorProfilePropertiesProperty:
        def __init__(self, *, instance_url: builtins.str) -> None:
            '''The ``ServiceNowConnectorProfileProperties`` property type specifies the connector-specific profile properties required when using ServiceNow.

            :param instance_url: The location of the ServiceNow resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-servicenowconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                service_now_connector_profile_properties_property = appflow.CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_url": instance_url,
            }

        @builtins.property
        def instance_url(self) -> builtins.str:
            '''The location of the ServiceNow resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-servicenowconnectorprofileproperties.html#cfn-appflow-connectorprofile-servicenowconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            assert result is not None, "Required property 'instance_url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServiceNowConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SingularConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"api_key": "apiKey"},
    )
    class SingularConnectorProfileCredentialsProperty:
        def __init__(self, *, api_key: builtins.str) -> None:
            '''The ``SingularConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using Singular.

            :param api_key: A unique alphanumeric identifier used to authenticate a user, developer, or calling program to your API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-singularconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                singular_connector_profile_credentials_property = appflow.CfnConnectorProfile.SingularConnectorProfileCredentialsProperty(
                    api_key="apiKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "api_key": api_key,
            }

        @builtins.property
        def api_key(self) -> builtins.str:
            '''A unique alphanumeric identifier used to authenticate a user, developer, or calling program to your API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-singularconnectorprofilecredentials.html#cfn-appflow-connectorprofile-singularconnectorprofilecredentials-apikey
            '''
            result = self._values.get("api_key")
            assert result is not None, "Required property 'api_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SingularConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SlackConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "client_id": "clientId",
            "client_secret": "clientSecret",
            "access_token": "accessToken",
            "connector_o_auth_request": "connectorOAuthRequest",
        },
    )
    class SlackConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            client_id: builtins.str,
            client_secret: builtins.str,
            access_token: typing.Optional[builtins.str] = None,
            connector_o_auth_request: typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``SlackConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using Slack.

            :param client_id: The identifier for the client.
            :param client_secret: The client secret used by the OAuth client to authenticate to the authorization server.
            :param access_token: The credentials used to access protected Slack resources.
            :param connector_o_auth_request: Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-slackconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                slack_connector_profile_credentials_property = appflow.CfnConnectorProfile.SlackConnectorProfileCredentialsProperty(
                    client_id="clientId",
                    client_secret="clientSecret",
                
                    # the properties below are optional
                    access_token="accessToken",
                    connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                        auth_code="authCode",
                        redirect_uri="redirectUri"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "client_id": client_id,
                "client_secret": client_secret,
            }
            if access_token is not None:
                self._values["access_token"] = access_token
            if connector_o_auth_request is not None:
                self._values["connector_o_auth_request"] = connector_o_auth_request

        @builtins.property
        def client_id(self) -> builtins.str:
            '''The identifier for the client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-slackconnectorprofilecredentials.html#cfn-appflow-connectorprofile-slackconnectorprofilecredentials-clientid
            '''
            result = self._values.get("client_id")
            assert result is not None, "Required property 'client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_secret(self) -> builtins.str:
            '''The client secret used by the OAuth client to authenticate to the authorization server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-slackconnectorprofilecredentials.html#cfn-appflow-connectorprofile-slackconnectorprofilecredentials-clientsecret
            '''
            result = self._values.get("client_secret")
            assert result is not None, "Required property 'client_secret' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def access_token(self) -> typing.Optional[builtins.str]:
            '''The credentials used to access protected Slack resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-slackconnectorprofilecredentials.html#cfn-appflow-connectorprofile-slackconnectorprofilecredentials-accesstoken
            '''
            result = self._values.get("access_token")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def connector_o_auth_request(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]]:
            '''Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-slackconnectorprofilecredentials.html#cfn-appflow-connectorprofile-slackconnectorprofilecredentials-connectoroauthrequest
            '''
            result = self._values.get("connector_o_auth_request")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlackConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SlackConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"instance_url": "instanceUrl"},
    )
    class SlackConnectorProfilePropertiesProperty:
        def __init__(self, *, instance_url: builtins.str) -> None:
            '''The ``SlackConnectorProfileProperties`` property type specifies the connector-specific profile properties required when using Slack.

            :param instance_url: The location of the Slack resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-slackconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                slack_connector_profile_properties_property = appflow.CfnConnectorProfile.SlackConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_url": instance_url,
            }

        @builtins.property
        def instance_url(self) -> builtins.str:
            '''The location of the Slack resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-slackconnectorprofileproperties.html#cfn-appflow-connectorprofile-slackconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            assert result is not None, "Required property 'instance_url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlackConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"password": "password", "username": "username"},
    )
    class SnowflakeConnectorProfileCredentialsProperty:
        def __init__(self, *, password: builtins.str, username: builtins.str) -> None:
            '''The ``SnowflakeConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using Snowflake.

            :param password: The password that corresponds to the user name.
            :param username: The name of the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                snowflake_connector_profile_credentials_property = appflow.CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty(
                    password="password",
                    username="username"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
                "username": username,
            }

        @builtins.property
        def password(self) -> builtins.str:
            '''The password that corresponds to the user name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofilecredentials.html#cfn-appflow-connectorprofile-snowflakeconnectorprofilecredentials-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def username(self) -> builtins.str:
            '''The name of the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofilecredentials.html#cfn-appflow-connectorprofile-snowflakeconnectorprofilecredentials-username
            '''
            result = self._values.get("username")
            assert result is not None, "Required property 'username' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SnowflakeConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_name": "bucketName",
            "stage": "stage",
            "warehouse": "warehouse",
            "account_name": "accountName",
            "bucket_prefix": "bucketPrefix",
            "private_link_service_name": "privateLinkServiceName",
            "region": "region",
        },
    )
    class SnowflakeConnectorProfilePropertiesProperty:
        def __init__(
            self,
            *,
            bucket_name: builtins.str,
            stage: builtins.str,
            warehouse: builtins.str,
            account_name: typing.Optional[builtins.str] = None,
            bucket_prefix: typing.Optional[builtins.str] = None,
            private_link_service_name: typing.Optional[builtins.str] = None,
            region: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``SnowflakeConnectorProfileProperties`` property type specifies the connector-specific profile properties required when using Snowflake.

            :param bucket_name: The name of the Amazon S3 bucket associated with Snowflake.
            :param stage: The name of the Amazon S3 stage that was created while setting up an Amazon S3 stage in the Snowflake account. This is written in the following format: < Database>< Schema>.
            :param warehouse: The name of the Snowflake warehouse.
            :param account_name: The name of the account.
            :param bucket_prefix: The bucket path that refers to the Amazon S3 bucket associated with Snowflake.
            :param private_link_service_name: The Snowflake Private Link service name to be used for private data transfers.
            :param region: The AWS Region of the Snowflake account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                snowflake_connector_profile_properties_property = appflow.CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty(
                    bucket_name="bucketName",
                    stage="stage",
                    warehouse="warehouse",
                
                    # the properties below are optional
                    account_name="accountName",
                    bucket_prefix="bucketPrefix",
                    private_link_service_name="privateLinkServiceName",
                    region="region"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_name": bucket_name,
                "stage": stage,
                "warehouse": warehouse,
            }
            if account_name is not None:
                self._values["account_name"] = account_name
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix
            if private_link_service_name is not None:
                self._values["private_link_service_name"] = private_link_service_name
            if region is not None:
                self._values["region"] = region

        @builtins.property
        def bucket_name(self) -> builtins.str:
            '''The name of the Amazon S3 bucket associated with Snowflake.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofileproperties.html#cfn-appflow-connectorprofile-snowflakeconnectorprofileproperties-bucketname
            '''
            result = self._values.get("bucket_name")
            assert result is not None, "Required property 'bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def stage(self) -> builtins.str:
            '''The name of the Amazon S3 stage that was created while setting up an Amazon S3 stage in the Snowflake account.

            This is written in the following format: < Database>< Schema>.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofileproperties.html#cfn-appflow-connectorprofile-snowflakeconnectorprofileproperties-stage
            '''
            result = self._values.get("stage")
            assert result is not None, "Required property 'stage' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def warehouse(self) -> builtins.str:
            '''The name of the Snowflake warehouse.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofileproperties.html#cfn-appflow-connectorprofile-snowflakeconnectorprofileproperties-warehouse
            '''
            result = self._values.get("warehouse")
            assert result is not None, "Required property 'warehouse' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def account_name(self) -> typing.Optional[builtins.str]:
            '''The name of the account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofileproperties.html#cfn-appflow-connectorprofile-snowflakeconnectorprofileproperties-accountname
            '''
            result = self._values.get("account_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''The bucket path that refers to the Amazon S3 bucket associated with Snowflake.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofileproperties.html#cfn-appflow-connectorprofile-snowflakeconnectorprofileproperties-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def private_link_service_name(self) -> typing.Optional[builtins.str]:
            '''The Snowflake Private Link service name to be used for private data transfers.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofileproperties.html#cfn-appflow-connectorprofile-snowflakeconnectorprofileproperties-privatelinkservicename
            '''
            result = self._values.get("private_link_service_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def region(self) -> typing.Optional[builtins.str]:
            '''The AWS Region of the Snowflake account.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-snowflakeconnectorprofileproperties.html#cfn-appflow-connectorprofile-snowflakeconnectorprofileproperties-region
            '''
            result = self._values.get("region")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SnowflakeConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"api_secret_key": "apiSecretKey"},
    )
    class TrendmicroConnectorProfileCredentialsProperty:
        def __init__(self, *, api_secret_key: builtins.str) -> None:
            '''The ``TrendmicroConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using Trend Micro.

            :param api_secret_key: The Secret Access Key portion of the credentials.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-trendmicroconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                trendmicro_connector_profile_credentials_property = appflow.CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty(
                    api_secret_key="apiSecretKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "api_secret_key": api_secret_key,
            }

        @builtins.property
        def api_secret_key(self) -> builtins.str:
            '''The Secret Access Key portion of the credentials.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-trendmicroconnectorprofilecredentials.html#cfn-appflow-connectorprofile-trendmicroconnectorprofilecredentials-apisecretkey
            '''
            result = self._values.get("api_secret_key")
            assert result is not None, "Required property 'api_secret_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TrendmicroConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={"password": "password", "username": "username"},
    )
    class VeevaConnectorProfileCredentialsProperty:
        def __init__(self, *, password: builtins.str, username: builtins.str) -> None:
            '''The ``VeevaConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using Veeva.

            :param password: The password that corresponds to the user name.
            :param username: The name of the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-veevaconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                veeva_connector_profile_credentials_property = appflow.CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty(
                    password="password",
                    username="username"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
                "username": username,
            }

        @builtins.property
        def password(self) -> builtins.str:
            '''The password that corresponds to the user name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-veevaconnectorprofilecredentials.html#cfn-appflow-connectorprofile-veevaconnectorprofilecredentials-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def username(self) -> builtins.str:
            '''The name of the user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-veevaconnectorprofilecredentials.html#cfn-appflow-connectorprofile-veevaconnectorprofilecredentials-username
            '''
            result = self._values.get("username")
            assert result is not None, "Required property 'username' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VeevaConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"instance_url": "instanceUrl"},
    )
    class VeevaConnectorProfilePropertiesProperty:
        def __init__(self, *, instance_url: builtins.str) -> None:
            '''The ``VeevaConnectorProfileProperties`` property type specifies the connector-specific profile properties required when using Veeva.

            :param instance_url: The location of the Veeva resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-veevaconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                veeva_connector_profile_properties_property = appflow.CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_url": instance_url,
            }

        @builtins.property
        def instance_url(self) -> builtins.str:
            '''The location of the Veeva resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-veevaconnectorprofileproperties.html#cfn-appflow-connectorprofile-veevaconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            assert result is not None, "Required property 'instance_url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VeevaConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "client_id": "clientId",
            "client_secret": "clientSecret",
            "access_token": "accessToken",
            "connector_o_auth_request": "connectorOAuthRequest",
        },
    )
    class ZendeskConnectorProfileCredentialsProperty:
        def __init__(
            self,
            *,
            client_id: builtins.str,
            client_secret: builtins.str,
            access_token: typing.Optional[builtins.str] = None,
            connector_o_auth_request: typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``ZendeskConnectorProfileCredentials`` property type specifies the connector-specific profile credentials required when using Zendesk.

            :param client_id: The identifier for the desired client.
            :param client_secret: The client secret used by the OAuth client to authenticate to the authorization server.
            :param access_token: The credentials used to access protected Zendesk resources.
            :param connector_o_auth_request: Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-zendeskconnectorprofilecredentials.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                zendesk_connector_profile_credentials_property = appflow.CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty(
                    client_id="clientId",
                    client_secret="clientSecret",
                
                    # the properties below are optional
                    access_token="accessToken",
                    connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                        auth_code="authCode",
                        redirect_uri="redirectUri"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "client_id": client_id,
                "client_secret": client_secret,
            }
            if access_token is not None:
                self._values["access_token"] = access_token
            if connector_o_auth_request is not None:
                self._values["connector_o_auth_request"] = connector_o_auth_request

        @builtins.property
        def client_id(self) -> builtins.str:
            '''The identifier for the desired client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-zendeskconnectorprofilecredentials.html#cfn-appflow-connectorprofile-zendeskconnectorprofilecredentials-clientid
            '''
            result = self._values.get("client_id")
            assert result is not None, "Required property 'client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_secret(self) -> builtins.str:
            '''The client secret used by the OAuth client to authenticate to the authorization server.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-zendeskconnectorprofilecredentials.html#cfn-appflow-connectorprofile-zendeskconnectorprofilecredentials-clientsecret
            '''
            result = self._values.get("client_secret")
            assert result is not None, "Required property 'client_secret' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def access_token(self) -> typing.Optional[builtins.str]:
            '''The credentials used to access protected Zendesk resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-zendeskconnectorprofilecredentials.html#cfn-appflow-connectorprofile-zendeskconnectorprofilecredentials-accesstoken
            '''
            result = self._values.get("access_token")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def connector_o_auth_request(
            self,
        ) -> typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]]:
            '''Used by select connectors for which the OAuth workflow is supported, such as Salesforce, Google Analytics, Marketo, Zendesk, and Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-zendeskconnectorprofilecredentials.html#cfn-appflow-connectorprofile-zendeskconnectorprofilecredentials-connectoroauthrequest
            '''
            result = self._values.get("connector_o_auth_request")
            return typing.cast(typing.Optional[typing.Union["CfnConnectorProfile.ConnectorOAuthRequestProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ZendeskConnectorProfileCredentialsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"instance_url": "instanceUrl"},
    )
    class ZendeskConnectorProfilePropertiesProperty:
        def __init__(self, *, instance_url: builtins.str) -> None:
            '''The ``ZendeskConnectorProfileProperties`` property type specifies the connector-specific profile properties required when using Zendesk.

            :param instance_url: The location of the Zendesk resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-zendeskconnectorprofileproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                zendesk_connector_profile_properties_property = appflow.CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty(
                    instance_url="instanceUrl"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "instance_url": instance_url,
            }

        @builtins.property
        def instance_url(self) -> builtins.str:
            '''The location of the Zendesk resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-connectorprofile-zendeskconnectorprofileproperties.html#cfn-appflow-connectorprofile-zendeskconnectorprofileproperties-instanceurl
            '''
            result = self._values.get("instance_url")
            assert result is not None, "Required property 'instance_url' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ZendeskConnectorProfilePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appflow.CfnConnectorProfileProps",
    jsii_struct_bases=[],
    name_mapping={
        "connection_mode": "connectionMode",
        "connector_profile_name": "connectorProfileName",
        "connector_type": "connectorType",
        "connector_profile_config": "connectorProfileConfig",
        "kms_arn": "kmsArn",
    },
)
class CfnConnectorProfileProps:
    def __init__(
        self,
        *,
        connection_mode: builtins.str,
        connector_profile_name: builtins.str,
        connector_type: builtins.str,
        connector_profile_config: typing.Optional[typing.Union[CfnConnectorProfile.ConnectorProfileConfigProperty, _IResolvable_da3f097b]] = None,
        kms_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnConnectorProfile``.

        :param connection_mode: Indicates the connection mode and if it is public or private.
        :param connector_profile_name: The name of the connector profile. The name is unique for each ``ConnectorProfile`` in the AWS account .
        :param connector_type: The type of connector, such as Salesforce, Amplitude, and so on.
        :param connector_profile_config: Defines the connector-specific configuration and credentials.
        :param kms_arn: The ARN (Amazon Resource Name) of the Key Management Service (KMS) key you provide for encryption. This is required if you do not want to use the Amazon AppFlow-managed KMS key. If you don't provide anything here, Amazon AppFlow uses the Amazon AppFlow-managed KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appflow as appflow
            
            # basic_auth_credentials: Any
            # o_auth_credentials: Any
            
            cfn_connector_profile_props = appflow.CfnConnectorProfileProps(
                connection_mode="connectionMode",
                connector_profile_name="connectorProfileName",
                connector_type="connectorType",
            
                # the properties below are optional
                connector_profile_config=appflow.CfnConnectorProfile.ConnectorProfileConfigProperty(
                    connector_profile_credentials=appflow.CfnConnectorProfile.ConnectorProfileCredentialsProperty(
                        amplitude=appflow.CfnConnectorProfile.AmplitudeConnectorProfileCredentialsProperty(
                            api_key="apiKey",
                            secret_key="secretKey"
                        ),
                        datadog=appflow.CfnConnectorProfile.DatadogConnectorProfileCredentialsProperty(
                            api_key="apiKey",
                            application_key="applicationKey"
                        ),
                        dynatrace=appflow.CfnConnectorProfile.DynatraceConnectorProfileCredentialsProperty(
                            api_token="apiToken"
                        ),
                        google_analytics=appflow.CfnConnectorProfile.GoogleAnalyticsConnectorProfileCredentialsProperty(
                            client_id="clientId",
                            client_secret="clientSecret",
            
                            # the properties below are optional
                            access_token="accessToken",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            ),
                            refresh_token="refreshToken"
                        ),
                        infor_nexus=appflow.CfnConnectorProfile.InforNexusConnectorProfileCredentialsProperty(
                            access_key_id="accessKeyId",
                            datakey="datakey",
                            secret_access_key="secretAccessKey",
                            user_id="userId"
                        ),
                        marketo=appflow.CfnConnectorProfile.MarketoConnectorProfileCredentialsProperty(
                            client_id="clientId",
                            client_secret="clientSecret",
            
                            # the properties below are optional
                            access_token="accessToken",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            )
                        ),
                        redshift=appflow.CfnConnectorProfile.RedshiftConnectorProfileCredentialsProperty(
                            password="password",
                            username="username"
                        ),
                        salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfileCredentialsProperty(
                            access_token="accessToken",
                            client_credentials_arn="clientCredentialsArn",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            ),
                            refresh_token="refreshToken"
                        ),
                        sapo_data=appflow.CfnConnectorProfile.SAPODataConnectorProfileCredentialsProperty(
                            basic_auth_credentials=basic_auth_credentials,
                            o_auth_credentials=o_auth_credentials
                        ),
                        service_now=appflow.CfnConnectorProfile.ServiceNowConnectorProfileCredentialsProperty(
                            password="password",
                            username="username"
                        ),
                        singular=appflow.CfnConnectorProfile.SingularConnectorProfileCredentialsProperty(
                            api_key="apiKey"
                        ),
                        slack=appflow.CfnConnectorProfile.SlackConnectorProfileCredentialsProperty(
                            client_id="clientId",
                            client_secret="clientSecret",
            
                            # the properties below are optional
                            access_token="accessToken",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            )
                        ),
                        snowflake=appflow.CfnConnectorProfile.SnowflakeConnectorProfileCredentialsProperty(
                            password="password",
                            username="username"
                        ),
                        trendmicro=appflow.CfnConnectorProfile.TrendmicroConnectorProfileCredentialsProperty(
                            api_secret_key="apiSecretKey"
                        ),
                        veeva=appflow.CfnConnectorProfile.VeevaConnectorProfileCredentialsProperty(
                            password="password",
                            username="username"
                        ),
                        zendesk=appflow.CfnConnectorProfile.ZendeskConnectorProfileCredentialsProperty(
                            client_id="clientId",
                            client_secret="clientSecret",
            
                            # the properties below are optional
                            access_token="accessToken",
                            connector_oAuth_request=appflow.CfnConnectorProfile.ConnectorOAuthRequestProperty(
                                auth_code="authCode",
                                redirect_uri="redirectUri"
                            )
                        )
                    ),
            
                    # the properties below are optional
                    connector_profile_properties=appflow.CfnConnectorProfile.ConnectorProfilePropertiesProperty(
                        datadog=appflow.CfnConnectorProfile.DatadogConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        dynatrace=appflow.CfnConnectorProfile.DynatraceConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        infor_nexus=appflow.CfnConnectorProfile.InforNexusConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        marketo=appflow.CfnConnectorProfile.MarketoConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        redshift=appflow.CfnConnectorProfile.RedshiftConnectorProfilePropertiesProperty(
                            bucket_name="bucketName",
                            database_url="databaseUrl",
                            role_arn="roleArn",
            
                            # the properties below are optional
                            bucket_prefix="bucketPrefix"
                        ),
                        salesforce=appflow.CfnConnectorProfile.SalesforceConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl",
                            is_sandbox_environment=False
                        ),
                        sapo_data=appflow.CfnConnectorProfile.SAPODataConnectorProfilePropertiesProperty(
                            application_host_url="applicationHostUrl",
                            application_service_path="applicationServicePath",
                            client_number="clientNumber",
                            logon_language="logonLanguage",
                            o_auth_properties=appflow.CfnConnectorProfile.OAuthPropertiesProperty(
                                auth_code_url="authCodeUrl",
                                o_auth_scopes=["oAuthScopes"],
                                token_url="tokenUrl"
                            ),
                            port_number=123,
                            private_link_service_name="privateLinkServiceName"
                        ),
                        service_now=appflow.CfnConnectorProfile.ServiceNowConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        slack=appflow.CfnConnectorProfile.SlackConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        snowflake=appflow.CfnConnectorProfile.SnowflakeConnectorProfilePropertiesProperty(
                            bucket_name="bucketName",
                            stage="stage",
                            warehouse="warehouse",
            
                            # the properties below are optional
                            account_name="accountName",
                            bucket_prefix="bucketPrefix",
                            private_link_service_name="privateLinkServiceName",
                            region="region"
                        ),
                        veeva=appflow.CfnConnectorProfile.VeevaConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        ),
                        zendesk=appflow.CfnConnectorProfile.ZendeskConnectorProfilePropertiesProperty(
                            instance_url="instanceUrl"
                        )
                    )
                ),
                kms_arn="kmsArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "connection_mode": connection_mode,
            "connector_profile_name": connector_profile_name,
            "connector_type": connector_type,
        }
        if connector_profile_config is not None:
            self._values["connector_profile_config"] = connector_profile_config
        if kms_arn is not None:
            self._values["kms_arn"] = kms_arn

    @builtins.property
    def connection_mode(self) -> builtins.str:
        '''Indicates the connection mode and if it is public or private.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-connectionmode
        '''
        result = self._values.get("connection_mode")
        assert result is not None, "Required property 'connection_mode' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def connector_profile_name(self) -> builtins.str:
        '''The name of the connector profile.

        The name is unique for each ``ConnectorProfile`` in the AWS account .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-connectorprofilename
        '''
        result = self._values.get("connector_profile_name")
        assert result is not None, "Required property 'connector_profile_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def connector_type(self) -> builtins.str:
        '''The type of connector, such as Salesforce, Amplitude, and so on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-connectortype
        '''
        result = self._values.get("connector_type")
        assert result is not None, "Required property 'connector_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def connector_profile_config(
        self,
    ) -> typing.Optional[typing.Union[CfnConnectorProfile.ConnectorProfileConfigProperty, _IResolvable_da3f097b]]:
        '''Defines the connector-specific configuration and credentials.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-connectorprofileconfig
        '''
        result = self._values.get("connector_profile_config")
        return typing.cast(typing.Optional[typing.Union[CfnConnectorProfile.ConnectorProfileConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def kms_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN (Amazon Resource Name) of the Key Management Service (KMS) key you provide for encryption.

        This is required if you do not want to use the Amazon AppFlow-managed KMS key. If you don't provide anything here, Amazon AppFlow uses the Amazon AppFlow-managed KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-connectorprofile.html#cfn-appflow-connectorprofile-kmsarn
        '''
        result = self._values.get("kms_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnConnectorProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnFlow(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_appflow.CfnFlow",
):
    '''A CloudFormation ``AWS::AppFlow::Flow``.

    The ``AWS::AppFlow::Flow`` resource is an Amazon AppFlow resource type that specifies a new flow.
    .. epigraph::

       If you want to use AWS CloudFormation to create a connector profile for connectors that implement OAuth (such as Salesforce, Slack, Zendesk, and Google Analytics), you must fetch the access and refresh tokens. You can do this by implementing your own UI for OAuth, or by retrieving the tokens from elsewhere. Alternatively, you can use the Amazon AppFlow console to create the connector profile, and then use that connector profile in the flow creation CloudFormation template.

    :cloudformationResource: AWS::AppFlow::Flow
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_appflow as appflow
        
        cfn_flow = appflow.CfnFlow(self, "MyCfnFlow",
            destination_flow_config_list=[appflow.CfnFlow.DestinationFlowConfigProperty(
                connector_type="connectorType",
                destination_connector_properties=appflow.CfnFlow.DestinationConnectorPropertiesProperty(
                    event_bridge=appflow.CfnFlow.EventBridgeDestinationPropertiesProperty(
                        object="object",
        
                        # the properties below are optional
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        )
                    ),
                    lookout_metrics=appflow.CfnFlow.LookoutMetricsDestinationPropertiesProperty(
                        object="object"
                    ),
                    redshift=appflow.CfnFlow.RedshiftDestinationPropertiesProperty(
                        intermediate_bucket_name="intermediateBucketName",
                        object="object",
        
                        # the properties below are optional
                        bucket_prefix="bucketPrefix",
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        )
                    ),
                    s3=appflow.CfnFlow.S3DestinationPropertiesProperty(
                        bucket_name="bucketName",
        
                        # the properties below are optional
                        bucket_prefix="bucketPrefix",
                        s3_output_format_config=appflow.CfnFlow.S3OutputFormatConfigProperty(
                            aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                                aggregation_type="aggregationType"
                            ),
                            file_type="fileType",
                            prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                                prefix_format="prefixFormat",
                                prefix_type="prefixType"
                            )
                        )
                    ),
                    salesforce=appflow.CfnFlow.SalesforceDestinationPropertiesProperty(
                        object="object",
        
                        # the properties below are optional
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        ),
                        id_field_names=["idFieldNames"],
                        write_operation_type="writeOperationType"
                    ),
                    sapo_data=appflow.CfnFlow.SAPODataDestinationPropertiesProperty(
                        object_path="objectPath",
        
                        # the properties below are optional
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        ),
                        id_field_names=["idFieldNames"],
                        success_response_handling_config=appflow.CfnFlow.SuccessResponseHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix"
                        ),
                        write_operation_type="writeOperationType"
                    ),
                    snowflake=appflow.CfnFlow.SnowflakeDestinationPropertiesProperty(
                        intermediate_bucket_name="intermediateBucketName",
                        object="object",
        
                        # the properties below are optional
                        bucket_prefix="bucketPrefix",
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        )
                    ),
                    upsolver=appflow.CfnFlow.UpsolverDestinationPropertiesProperty(
                        bucket_name="bucketName",
                        s3_output_format_config=appflow.CfnFlow.UpsolverS3OutputFormatConfigProperty(
                            prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                                prefix_format="prefixFormat",
                                prefix_type="prefixType"
                            ),
        
                            # the properties below are optional
                            aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                                aggregation_type="aggregationType"
                            ),
                            file_type="fileType"
                        ),
        
                        # the properties below are optional
                        bucket_prefix="bucketPrefix"
                    ),
                    zendesk=appflow.CfnFlow.ZendeskDestinationPropertiesProperty(
                        object="object",
        
                        # the properties below are optional
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        ),
                        id_field_names=["idFieldNames"],
                        write_operation_type="writeOperationType"
                    )
                ),
        
                # the properties below are optional
                connector_profile_name="connectorProfileName"
            )],
            flow_name="flowName",
            source_flow_config=appflow.CfnFlow.SourceFlowConfigProperty(
                connector_type="connectorType",
                source_connector_properties=appflow.CfnFlow.SourceConnectorPropertiesProperty(
                    amplitude=appflow.CfnFlow.AmplitudeSourcePropertiesProperty(
                        object="object"
                    ),
                    datadog=appflow.CfnFlow.DatadogSourcePropertiesProperty(
                        object="object"
                    ),
                    dynatrace=appflow.CfnFlow.DynatraceSourcePropertiesProperty(
                        object="object"
                    ),
                    google_analytics=appflow.CfnFlow.GoogleAnalyticsSourcePropertiesProperty(
                        object="object"
                    ),
                    infor_nexus=appflow.CfnFlow.InforNexusSourcePropertiesProperty(
                        object="object"
                    ),
                    marketo=appflow.CfnFlow.MarketoSourcePropertiesProperty(
                        object="object"
                    ),
                    s3=appflow.CfnFlow.S3SourcePropertiesProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix",
        
                        # the properties below are optional
                        s3_input_format_config=appflow.CfnFlow.S3InputFormatConfigProperty(
                            s3_input_file_type="s3InputFileType"
                        )
                    ),
                    salesforce=appflow.CfnFlow.SalesforceSourcePropertiesProperty(
                        object="object",
        
                        # the properties below are optional
                        enable_dynamic_field_update=False,
                        include_deleted_records=False
                    ),
                    sapo_data=appflow.CfnFlow.SAPODataSourcePropertiesProperty(
                        object_path="objectPath"
                    ),
                    service_now=appflow.CfnFlow.ServiceNowSourcePropertiesProperty(
                        object="object"
                    ),
                    singular=appflow.CfnFlow.SingularSourcePropertiesProperty(
                        object="object"
                    ),
                    slack=appflow.CfnFlow.SlackSourcePropertiesProperty(
                        object="object"
                    ),
                    trendmicro=appflow.CfnFlow.TrendmicroSourcePropertiesProperty(
                        object="object"
                    ),
                    veeva=appflow.CfnFlow.VeevaSourcePropertiesProperty(
                        object="object",
        
                        # the properties below are optional
                        document_type="documentType",
                        include_all_versions=False,
                        include_renditions=False,
                        include_source_files=False
                    ),
                    zendesk=appflow.CfnFlow.ZendeskSourcePropertiesProperty(
                        object="object"
                    )
                ),
        
                # the properties below are optional
                connector_profile_name="connectorProfileName",
                incremental_pull_config=appflow.CfnFlow.IncrementalPullConfigProperty(
                    datetime_type_field_name="datetimeTypeFieldName"
                )
            ),
            tasks=[appflow.CfnFlow.TaskProperty(
                source_fields=["sourceFields"],
                task_type="taskType",
        
                # the properties below are optional
                connector_operator=appflow.CfnFlow.ConnectorOperatorProperty(
                    amplitude="amplitude",
                    datadog="datadog",
                    dynatrace="dynatrace",
                    google_analytics="googleAnalytics",
                    infor_nexus="inforNexus",
                    marketo="marketo",
                    s3="s3",
                    salesforce="salesforce",
                    sapo_data="sapoData",
                    service_now="serviceNow",
                    singular="singular",
                    slack="slack",
                    trendmicro="trendmicro",
                    veeva="veeva",
                    zendesk="zendesk"
                ),
                destination_field="destinationField",
                task_properties=[appflow.CfnFlow.TaskPropertiesObjectProperty(
                    key="key",
                    value="value"
                )]
            )],
            trigger_config=appflow.CfnFlow.TriggerConfigProperty(
                trigger_type="triggerType",
        
                # the properties below are optional
                trigger_properties=appflow.CfnFlow.ScheduledTriggerPropertiesProperty(
                    schedule_expression="scheduleExpression",
        
                    # the properties below are optional
                    data_pull_mode="dataPullMode",
                    schedule_end_time=123,
                    schedule_offset=123,
                    schedule_start_time=123,
                    time_zone="timeZone"
                )
            ),
        
            # the properties below are optional
            description="description",
            kms_arn="kmsArn",
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
        destination_flow_config_list: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFlow.DestinationFlowConfigProperty", _IResolvable_da3f097b]]],
        flow_name: builtins.str,
        source_flow_config: typing.Union["CfnFlow.SourceFlowConfigProperty", _IResolvable_da3f097b],
        tasks: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFlow.TaskProperty", _IResolvable_da3f097b]]],
        trigger_config: typing.Union["CfnFlow.TriggerConfigProperty", _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        kms_arn: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::AppFlow::Flow``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param destination_flow_config_list: The configuration that controls how Amazon AppFlow places data in the destination connector.
        :param flow_name: The specified name of the flow. Spaces are not allowed. Use underscores (_) or hyphens (-) only.
        :param source_flow_config: Contains information about the configuration of the source connector used in the flow.
        :param tasks: A list of tasks that Amazon AppFlow performs while transferring the data in the flow run.
        :param trigger_config: The trigger settings that determine how and when Amazon AppFlow runs the specified flow.
        :param description: A user-entered description of the flow.
        :param kms_arn: The ARN (Amazon Resource Name) of the Key Management Service (KMS) key you provide for encryption. This is required if you do not want to use the Amazon AppFlow-managed KMS key. If you don't provide anything here, Amazon AppFlow uses the Amazon AppFlow-managed KMS key.
        :param tags: The tags used to organize, track, or control access for your flow.
        '''
        props = CfnFlowProps(
            destination_flow_config_list=destination_flow_config_list,
            flow_name=flow_name,
            source_flow_config=source_flow_config,
            tasks=tasks,
            trigger_config=trigger_config,
            description=description,
            kms_arn=kms_arn,
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
    @jsii.member(jsii_name="attrFlowArn")
    def attr_flow_arn(self) -> builtins.str:
        '''The flow's Amazon Resource Name (ARN).

        :cloudformationAttribute: FlowArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrFlowArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags used to organize, track, or control access for your flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="destinationFlowConfigList")
    def destination_flow_config_list(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFlow.DestinationFlowConfigProperty", _IResolvable_da3f097b]]]:
        '''The configuration that controls how Amazon AppFlow places data in the destination connector.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-destinationflowconfiglist
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFlow.DestinationFlowConfigProperty", _IResolvable_da3f097b]]], jsii.get(self, "destinationFlowConfigList"))

    @destination_flow_config_list.setter
    def destination_flow_config_list(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFlow.DestinationFlowConfigProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "destinationFlowConfigList", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="flowName")
    def flow_name(self) -> builtins.str:
        '''The specified name of the flow.

        Spaces are not allowed. Use underscores (_) or hyphens (-) only.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-flowname
        '''
        return typing.cast(builtins.str, jsii.get(self, "flowName"))

    @flow_name.setter
    def flow_name(self, value: builtins.str) -> None:
        jsii.set(self, "flowName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceFlowConfig")
    def source_flow_config(
        self,
    ) -> typing.Union["CfnFlow.SourceFlowConfigProperty", _IResolvable_da3f097b]:
        '''Contains information about the configuration of the source connector used in the flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-sourceflowconfig
        '''
        return typing.cast(typing.Union["CfnFlow.SourceFlowConfigProperty", _IResolvable_da3f097b], jsii.get(self, "sourceFlowConfig"))

    @source_flow_config.setter
    def source_flow_config(
        self,
        value: typing.Union["CfnFlow.SourceFlowConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "sourceFlowConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tasks")
    def tasks(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFlow.TaskProperty", _IResolvable_da3f097b]]]:
        '''A list of tasks that Amazon AppFlow performs while transferring the data in the flow run.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-tasks
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFlow.TaskProperty", _IResolvable_da3f097b]]], jsii.get(self, "tasks"))

    @tasks.setter
    def tasks(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFlow.TaskProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "tasks", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="triggerConfig")
    def trigger_config(
        self,
    ) -> typing.Union["CfnFlow.TriggerConfigProperty", _IResolvable_da3f097b]:
        '''The trigger settings that determine how and when Amazon AppFlow runs the specified flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-triggerconfig
        '''
        return typing.cast(typing.Union["CfnFlow.TriggerConfigProperty", _IResolvable_da3f097b], jsii.get(self, "triggerConfig"))

    @trigger_config.setter
    def trigger_config(
        self,
        value: typing.Union["CfnFlow.TriggerConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "triggerConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A user-entered description of the flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsArn")
    def kms_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN (Amazon Resource Name) of the Key Management Service (KMS) key you provide for encryption.

        This is required if you do not want to use the Amazon AppFlow-managed KMS key. If you don't provide anything here, Amazon AppFlow uses the Amazon AppFlow-managed KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-kmsarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsArn"))

    @kms_arn.setter
    def kms_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsArn", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.AggregationConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"aggregation_type": "aggregationType"},
    )
    class AggregationConfigProperty:
        def __init__(
            self,
            *,
            aggregation_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The aggregation settings that you can use to customize the output format of your flow data.

            :param aggregation_type: Specifies whether Amazon AppFlow aggregates the flow records into a single file, or leave them unaggregated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-aggregationconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                aggregation_config_property = appflow.CfnFlow.AggregationConfigProperty(
                    aggregation_type="aggregationType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if aggregation_type is not None:
                self._values["aggregation_type"] = aggregation_type

        @builtins.property
        def aggregation_type(self) -> typing.Optional[builtins.str]:
            '''Specifies whether Amazon AppFlow aggregates the flow records into a single file, or leave them unaggregated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-aggregationconfig.html#cfn-appflow-flow-aggregationconfig-aggregationtype
            '''
            result = self._values.get("aggregation_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AggregationConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.AmplitudeSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class AmplitudeSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when Amplitude is being used as a source.

            :param object: The object specified in the Amplitude flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-amplitudesourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                amplitude_source_properties_property = appflow.CfnFlow.AmplitudeSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Amplitude flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-amplitudesourceproperties.html#cfn-appflow-flow-amplitudesourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AmplitudeSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.ConnectorOperatorProperty",
        jsii_struct_bases=[],
        name_mapping={
            "amplitude": "amplitude",
            "datadog": "datadog",
            "dynatrace": "dynatrace",
            "google_analytics": "googleAnalytics",
            "infor_nexus": "inforNexus",
            "marketo": "marketo",
            "s3": "s3",
            "salesforce": "salesforce",
            "sapo_data": "sapoData",
            "service_now": "serviceNow",
            "singular": "singular",
            "slack": "slack",
            "trendmicro": "trendmicro",
            "veeva": "veeva",
            "zendesk": "zendesk",
        },
    )
    class ConnectorOperatorProperty:
        def __init__(
            self,
            *,
            amplitude: typing.Optional[builtins.str] = None,
            datadog: typing.Optional[builtins.str] = None,
            dynatrace: typing.Optional[builtins.str] = None,
            google_analytics: typing.Optional[builtins.str] = None,
            infor_nexus: typing.Optional[builtins.str] = None,
            marketo: typing.Optional[builtins.str] = None,
            s3: typing.Optional[builtins.str] = None,
            salesforce: typing.Optional[builtins.str] = None,
            sapo_data: typing.Optional[builtins.str] = None,
            service_now: typing.Optional[builtins.str] = None,
            singular: typing.Optional[builtins.str] = None,
            slack: typing.Optional[builtins.str] = None,
            trendmicro: typing.Optional[builtins.str] = None,
            veeva: typing.Optional[builtins.str] = None,
            zendesk: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The operation to be performed on the provided source fields.

            :param amplitude: The operation to be performed on the provided Amplitude source fields.
            :param datadog: The operation to be performed on the provided Datadog source fields.
            :param dynatrace: The operation to be performed on the provided Dynatrace source fields.
            :param google_analytics: The operation to be performed on the provided Google Analytics source fields.
            :param infor_nexus: The operation to be performed on the provided Infor Nexus source fields.
            :param marketo: The operation to be performed on the provided Marketo source fields.
            :param s3: The operation to be performed on the provided Amazon S3 source fields.
            :param salesforce: The operation to be performed on the provided Salesforce source fields.
            :param sapo_data: ``CfnFlow.ConnectorOperatorProperty.SAPOData``.
            :param service_now: The operation to be performed on the provided ServiceNow source fields.
            :param singular: The operation to be performed on the provided Singular source fields.
            :param slack: The operation to be performed on the provided Slack source fields.
            :param trendmicro: The operation to be performed on the provided Trend Micro source fields.
            :param veeva: The operation to be performed on the provided Veeva source fields.
            :param zendesk: The operation to be performed on the provided Zendesk source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                connector_operator_property = appflow.CfnFlow.ConnectorOperatorProperty(
                    amplitude="amplitude",
                    datadog="datadog",
                    dynatrace="dynatrace",
                    google_analytics="googleAnalytics",
                    infor_nexus="inforNexus",
                    marketo="marketo",
                    s3="s3",
                    salesforce="salesforce",
                    sapo_data="sapoData",
                    service_now="serviceNow",
                    singular="singular",
                    slack="slack",
                    trendmicro="trendmicro",
                    veeva="veeva",
                    zendesk="zendesk"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if amplitude is not None:
                self._values["amplitude"] = amplitude
            if datadog is not None:
                self._values["datadog"] = datadog
            if dynatrace is not None:
                self._values["dynatrace"] = dynatrace
            if google_analytics is not None:
                self._values["google_analytics"] = google_analytics
            if infor_nexus is not None:
                self._values["infor_nexus"] = infor_nexus
            if marketo is not None:
                self._values["marketo"] = marketo
            if s3 is not None:
                self._values["s3"] = s3
            if salesforce is not None:
                self._values["salesforce"] = salesforce
            if sapo_data is not None:
                self._values["sapo_data"] = sapo_data
            if service_now is not None:
                self._values["service_now"] = service_now
            if singular is not None:
                self._values["singular"] = singular
            if slack is not None:
                self._values["slack"] = slack
            if trendmicro is not None:
                self._values["trendmicro"] = trendmicro
            if veeva is not None:
                self._values["veeva"] = veeva
            if zendesk is not None:
                self._values["zendesk"] = zendesk

        @builtins.property
        def amplitude(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Amplitude source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-amplitude
            '''
            result = self._values.get("amplitude")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def datadog(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Datadog source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-datadog
            '''
            result = self._values.get("datadog")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dynatrace(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Dynatrace source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-dynatrace
            '''
            result = self._values.get("dynatrace")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def google_analytics(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Google Analytics source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-googleanalytics
            '''
            result = self._values.get("google_analytics")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def infor_nexus(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Infor Nexus source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-infornexus
            '''
            result = self._values.get("infor_nexus")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def marketo(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Marketo source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-marketo
            '''
            result = self._values.get("marketo")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Amazon S3 source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-s3
            '''
            result = self._values.get("s3")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def salesforce(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Salesforce source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-salesforce
            '''
            result = self._values.get("salesforce")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sapo_data(self) -> typing.Optional[builtins.str]:
            '''``CfnFlow.ConnectorOperatorProperty.SAPOData``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-sapodata
            '''
            result = self._values.get("sapo_data")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def service_now(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided ServiceNow source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-servicenow
            '''
            result = self._values.get("service_now")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def singular(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Singular source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-singular
            '''
            result = self._values.get("singular")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def slack(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Slack source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-slack
            '''
            result = self._values.get("slack")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def trendmicro(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Trend Micro source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-trendmicro
            '''
            result = self._values.get("trendmicro")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def veeva(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Veeva source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-veeva
            '''
            result = self._values.get("veeva")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def zendesk(self) -> typing.Optional[builtins.str]:
            '''The operation to be performed on the provided Zendesk source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-connectoroperator.html#cfn-appflow-flow-connectoroperator-zendesk
            '''
            result = self._values.get("zendesk")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorOperatorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.DatadogSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class DatadogSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when Datadog is being used as a source.

            :param object: The object specified in the Datadog flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-datadogsourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                datadog_source_properties_property = appflow.CfnFlow.DatadogSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Datadog flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-datadogsourceproperties.html#cfn-appflow-flow-datadogsourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatadogSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.DestinationConnectorPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "event_bridge": "eventBridge",
            "lookout_metrics": "lookoutMetrics",
            "redshift": "redshift",
            "s3": "s3",
            "salesforce": "salesforce",
            "sapo_data": "sapoData",
            "snowflake": "snowflake",
            "upsolver": "upsolver",
            "zendesk": "zendesk",
        },
    )
    class DestinationConnectorPropertiesProperty:
        def __init__(
            self,
            *,
            event_bridge: typing.Optional[typing.Union["CfnFlow.EventBridgeDestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
            lookout_metrics: typing.Optional[typing.Union["CfnFlow.LookoutMetricsDestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
            redshift: typing.Optional[typing.Union["CfnFlow.RedshiftDestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
            s3: typing.Optional[typing.Union["CfnFlow.S3DestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
            salesforce: typing.Optional[typing.Union["CfnFlow.SalesforceDestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
            sapo_data: typing.Optional[typing.Union["CfnFlow.SAPODataDestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
            snowflake: typing.Optional[typing.Union["CfnFlow.SnowflakeDestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
            upsolver: typing.Optional[typing.Union["CfnFlow.UpsolverDestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
            zendesk: typing.Optional[typing.Union["CfnFlow.ZendeskDestinationPropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''This stores the information that is required to query a particular connector.

            :param event_bridge: The properties required to query Amazon EventBridge.
            :param lookout_metrics: The properties required to query Amazon Lookout for Metrics.
            :param redshift: The properties required to query Amazon Redshift.
            :param s3: The properties required to query Amazon S3.
            :param salesforce: The properties required to query Salesforce.
            :param sapo_data: The properties required to query SAPOData.
            :param snowflake: The properties required to query Snowflake.
            :param upsolver: The properties required to query Upsolver.
            :param zendesk: ``CfnFlow.DestinationConnectorPropertiesProperty.Zendesk``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                destination_connector_properties_property = appflow.CfnFlow.DestinationConnectorPropertiesProperty(
                    event_bridge=appflow.CfnFlow.EventBridgeDestinationPropertiesProperty(
                        object="object",
                
                        # the properties below are optional
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        )
                    ),
                    lookout_metrics=appflow.CfnFlow.LookoutMetricsDestinationPropertiesProperty(
                        object="object"
                    ),
                    redshift=appflow.CfnFlow.RedshiftDestinationPropertiesProperty(
                        intermediate_bucket_name="intermediateBucketName",
                        object="object",
                
                        # the properties below are optional
                        bucket_prefix="bucketPrefix",
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        )
                    ),
                    s3=appflow.CfnFlow.S3DestinationPropertiesProperty(
                        bucket_name="bucketName",
                
                        # the properties below are optional
                        bucket_prefix="bucketPrefix",
                        s3_output_format_config=appflow.CfnFlow.S3OutputFormatConfigProperty(
                            aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                                aggregation_type="aggregationType"
                            ),
                            file_type="fileType",
                            prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                                prefix_format="prefixFormat",
                                prefix_type="prefixType"
                            )
                        )
                    ),
                    salesforce=appflow.CfnFlow.SalesforceDestinationPropertiesProperty(
                        object="object",
                
                        # the properties below are optional
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        ),
                        id_field_names=["idFieldNames"],
                        write_operation_type="writeOperationType"
                    ),
                    sapo_data=appflow.CfnFlow.SAPODataDestinationPropertiesProperty(
                        object_path="objectPath",
                
                        # the properties below are optional
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        ),
                        id_field_names=["idFieldNames"],
                        success_response_handling_config=appflow.CfnFlow.SuccessResponseHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix"
                        ),
                        write_operation_type="writeOperationType"
                    ),
                    snowflake=appflow.CfnFlow.SnowflakeDestinationPropertiesProperty(
                        intermediate_bucket_name="intermediateBucketName",
                        object="object",
                
                        # the properties below are optional
                        bucket_prefix="bucketPrefix",
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        )
                    ),
                    upsolver=appflow.CfnFlow.UpsolverDestinationPropertiesProperty(
                        bucket_name="bucketName",
                        s3_output_format_config=appflow.CfnFlow.UpsolverS3OutputFormatConfigProperty(
                            prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                                prefix_format="prefixFormat",
                                prefix_type="prefixType"
                            ),
                
                            # the properties below are optional
                            aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                                aggregation_type="aggregationType"
                            ),
                            file_type="fileType"
                        ),
                
                        # the properties below are optional
                        bucket_prefix="bucketPrefix"
                    ),
                    zendesk=appflow.CfnFlow.ZendeskDestinationPropertiesProperty(
                        object="object",
                
                        # the properties below are optional
                        error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                            fail_on_first_error=False
                        ),
                        id_field_names=["idFieldNames"],
                        write_operation_type="writeOperationType"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if event_bridge is not None:
                self._values["event_bridge"] = event_bridge
            if lookout_metrics is not None:
                self._values["lookout_metrics"] = lookout_metrics
            if redshift is not None:
                self._values["redshift"] = redshift
            if s3 is not None:
                self._values["s3"] = s3
            if salesforce is not None:
                self._values["salesforce"] = salesforce
            if sapo_data is not None:
                self._values["sapo_data"] = sapo_data
            if snowflake is not None:
                self._values["snowflake"] = snowflake
            if upsolver is not None:
                self._values["upsolver"] = upsolver
            if zendesk is not None:
                self._values["zendesk"] = zendesk

        @builtins.property
        def event_bridge(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.EventBridgeDestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''The properties required to query Amazon EventBridge.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-eventbridge
            '''
            result = self._values.get("event_bridge")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.EventBridgeDestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def lookout_metrics(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.LookoutMetricsDestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''The properties required to query Amazon Lookout for Metrics.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-lookoutmetrics
            '''
            result = self._values.get("lookout_metrics")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.LookoutMetricsDestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def redshift(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.RedshiftDestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''The properties required to query Amazon Redshift.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-redshift
            '''
            result = self._values.get("redshift")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.RedshiftDestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.S3DestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''The properties required to query Amazon S3.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-s3
            '''
            result = self._values.get("s3")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.S3DestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def salesforce(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.SalesforceDestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''The properties required to query Salesforce.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-salesforce
            '''
            result = self._values.get("salesforce")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.SalesforceDestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sapo_data(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.SAPODataDestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''The properties required to query SAPOData.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-sapodata
            '''
            result = self._values.get("sapo_data")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.SAPODataDestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def snowflake(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.SnowflakeDestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''The properties required to query Snowflake.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-snowflake
            '''
            result = self._values.get("snowflake")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.SnowflakeDestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def upsolver(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.UpsolverDestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''The properties required to query Upsolver.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-upsolver
            '''
            result = self._values.get("upsolver")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.UpsolverDestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def zendesk(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ZendeskDestinationPropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnFlow.DestinationConnectorPropertiesProperty.Zendesk``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationconnectorproperties.html#cfn-appflow-flow-destinationconnectorproperties-zendesk
            '''
            result = self._values.get("zendesk")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ZendeskDestinationPropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DestinationConnectorPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.DestinationFlowConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connector_type": "connectorType",
            "destination_connector_properties": "destinationConnectorProperties",
            "connector_profile_name": "connectorProfileName",
        },
    )
    class DestinationFlowConfigProperty:
        def __init__(
            self,
            *,
            connector_type: builtins.str,
            destination_connector_properties: typing.Union["CfnFlow.DestinationConnectorPropertiesProperty", _IResolvable_da3f097b],
            connector_profile_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``DestinationFlowConfig`` property type specifies information about the configuration of destination connectors present in the flow.

            :param connector_type: The type of destination connector, such as Sales force, Amazon S3, and so on. *Allowed Values* : ``EventBridge | Redshift | S3 | Salesforce | Snowflake``
            :param destination_connector_properties: This stores the information that is required to query a particular connector.
            :param connector_profile_name: The name of the connector profile. This name must be unique for each connector profile in the AWS account .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationflowconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                destination_flow_config_property = appflow.CfnFlow.DestinationFlowConfigProperty(
                    connector_type="connectorType",
                    destination_connector_properties=appflow.CfnFlow.DestinationConnectorPropertiesProperty(
                        event_bridge=appflow.CfnFlow.EventBridgeDestinationPropertiesProperty(
                            object="object",
                
                            # the properties below are optional
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            )
                        ),
                        lookout_metrics=appflow.CfnFlow.LookoutMetricsDestinationPropertiesProperty(
                            object="object"
                        ),
                        redshift=appflow.CfnFlow.RedshiftDestinationPropertiesProperty(
                            intermediate_bucket_name="intermediateBucketName",
                            object="object",
                
                            # the properties below are optional
                            bucket_prefix="bucketPrefix",
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            )
                        ),
                        s3=appflow.CfnFlow.S3DestinationPropertiesProperty(
                            bucket_name="bucketName",
                
                            # the properties below are optional
                            bucket_prefix="bucketPrefix",
                            s3_output_format_config=appflow.CfnFlow.S3OutputFormatConfigProperty(
                                aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                                    aggregation_type="aggregationType"
                                ),
                                file_type="fileType",
                                prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                                    prefix_format="prefixFormat",
                                    prefix_type="prefixType"
                                )
                            )
                        ),
                        salesforce=appflow.CfnFlow.SalesforceDestinationPropertiesProperty(
                            object="object",
                
                            # the properties below are optional
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            ),
                            id_field_names=["idFieldNames"],
                            write_operation_type="writeOperationType"
                        ),
                        sapo_data=appflow.CfnFlow.SAPODataDestinationPropertiesProperty(
                            object_path="objectPath",
                
                            # the properties below are optional
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            ),
                            id_field_names=["idFieldNames"],
                            success_response_handling_config=appflow.CfnFlow.SuccessResponseHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix"
                            ),
                            write_operation_type="writeOperationType"
                        ),
                        snowflake=appflow.CfnFlow.SnowflakeDestinationPropertiesProperty(
                            intermediate_bucket_name="intermediateBucketName",
                            object="object",
                
                            # the properties below are optional
                            bucket_prefix="bucketPrefix",
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            )
                        ),
                        upsolver=appflow.CfnFlow.UpsolverDestinationPropertiesProperty(
                            bucket_name="bucketName",
                            s3_output_format_config=appflow.CfnFlow.UpsolverS3OutputFormatConfigProperty(
                                prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                                    prefix_format="prefixFormat",
                                    prefix_type="prefixType"
                                ),
                
                                # the properties below are optional
                                aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                                    aggregation_type="aggregationType"
                                ),
                                file_type="fileType"
                            ),
                
                            # the properties below are optional
                            bucket_prefix="bucketPrefix"
                        ),
                        zendesk=appflow.CfnFlow.ZendeskDestinationPropertiesProperty(
                            object="object",
                
                            # the properties below are optional
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            ),
                            id_field_names=["idFieldNames"],
                            write_operation_type="writeOperationType"
                        )
                    ),
                
                    # the properties below are optional
                    connector_profile_name="connectorProfileName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connector_type": connector_type,
                "destination_connector_properties": destination_connector_properties,
            }
            if connector_profile_name is not None:
                self._values["connector_profile_name"] = connector_profile_name

        @builtins.property
        def connector_type(self) -> builtins.str:
            '''The type of destination connector, such as Sales force, Amazon S3, and so on.

            *Allowed Values* : ``EventBridge | Redshift | S3 | Salesforce | Snowflake``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationflowconfig.html#cfn-appflow-flow-destinationflowconfig-connectortype
            '''
            result = self._values.get("connector_type")
            assert result is not None, "Required property 'connector_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def destination_connector_properties(
            self,
        ) -> typing.Union["CfnFlow.DestinationConnectorPropertiesProperty", _IResolvable_da3f097b]:
            '''This stores the information that is required to query a particular connector.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationflowconfig.html#cfn-appflow-flow-destinationflowconfig-destinationconnectorproperties
            '''
            result = self._values.get("destination_connector_properties")
            assert result is not None, "Required property 'destination_connector_properties' is missing"
            return typing.cast(typing.Union["CfnFlow.DestinationConnectorPropertiesProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def connector_profile_name(self) -> typing.Optional[builtins.str]:
            '''The name of the connector profile.

            This name must be unique for each connector profile in the AWS account .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-destinationflowconfig.html#cfn-appflow-flow-destinationflowconfig-connectorprofilename
            '''
            result = self._values.get("connector_profile_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DestinationFlowConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.DynatraceSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class DynatraceSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when Dynatrace is being used as a source.

            :param object: The object specified in the Dynatrace flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-dynatracesourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                dynatrace_source_properties_property = appflow.CfnFlow.DynatraceSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Dynatrace flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-dynatracesourceproperties.html#cfn-appflow-flow-dynatracesourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DynatraceSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.ErrorHandlingConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_name": "bucketName",
            "bucket_prefix": "bucketPrefix",
            "fail_on_first_error": "failOnFirstError",
        },
    )
    class ErrorHandlingConfigProperty:
        def __init__(
            self,
            *,
            bucket_name: typing.Optional[builtins.str] = None,
            bucket_prefix: typing.Optional[builtins.str] = None,
            fail_on_first_error: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The settings that determine how Amazon AppFlow handles an error when placing data in the destination.

            For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. ``ErrorHandlingConfig`` is a part of the destination connector details.

            :param bucket_name: Specifies the name of the Amazon S3 bucket.
            :param bucket_prefix: Specifies the Amazon S3 bucket prefix.
            :param fail_on_first_error: Specifies if the flow should fail after the first instance of a failure when attempting to place data in the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-errorhandlingconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                error_handling_config_property = appflow.CfnFlow.ErrorHandlingConfigProperty(
                    bucket_name="bucketName",
                    bucket_prefix="bucketPrefix",
                    fail_on_first_error=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if bucket_name is not None:
                self._values["bucket_name"] = bucket_name
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix
            if fail_on_first_error is not None:
                self._values["fail_on_first_error"] = fail_on_first_error

        @builtins.property
        def bucket_name(self) -> typing.Optional[builtins.str]:
            '''Specifies the name of the Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-errorhandlingconfig.html#cfn-appflow-flow-errorhandlingconfig-bucketname
            '''
            result = self._values.get("bucket_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''Specifies the Amazon S3 bucket prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-errorhandlingconfig.html#cfn-appflow-flow-errorhandlingconfig-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def fail_on_first_error(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies if the flow should fail after the first instance of a failure when attempting to place data in the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-errorhandlingconfig.html#cfn-appflow-flow-errorhandlingconfig-failonfirsterror
            '''
            result = self._values.get("fail_on_first_error")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ErrorHandlingConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.EventBridgeDestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "object": "object",
            "error_handling_config": "errorHandlingConfig",
        },
    )
    class EventBridgeDestinationPropertiesProperty:
        def __init__(
            self,
            *,
            object: builtins.str,
            error_handling_config: typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The properties that are applied when Amazon EventBridge is being used as a destination.

            :param object: The object specified in the Amazon EventBridge flow destination.
            :param error_handling_config: The object specified in the Amplitude flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-eventbridgedestinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                event_bridge_destination_properties_property = appflow.CfnFlow.EventBridgeDestinationPropertiesProperty(
                    object="object",
                
                    # the properties below are optional
                    error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix",
                        fail_on_first_error=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }
            if error_handling_config is not None:
                self._values["error_handling_config"] = error_handling_config

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Amazon EventBridge flow destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-eventbridgedestinationproperties.html#cfn-appflow-flow-eventbridgedestinationproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def error_handling_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]]:
            '''The object specified in the Amplitude flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-eventbridgedestinationproperties.html#cfn-appflow-flow-eventbridgedestinationproperties-errorhandlingconfig
            '''
            result = self._values.get("error_handling_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EventBridgeDestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.GoogleAnalyticsSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class GoogleAnalyticsSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when Google Analytics is being used as a source.

            :param object: The object specified in the Google Analytics flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-googleanalyticssourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                google_analytics_source_properties_property = appflow.CfnFlow.GoogleAnalyticsSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Google Analytics flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-googleanalyticssourceproperties.html#cfn-appflow-flow-googleanalyticssourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GoogleAnalyticsSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.IncrementalPullConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"datetime_type_field_name": "datetimeTypeFieldName"},
    )
    class IncrementalPullConfigProperty:
        def __init__(
            self,
            *,
            datetime_type_field_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the configuration used when importing incremental records from the source.

            :param datetime_type_field_name: A field that specifies the date time or timestamp field as the criteria to use when importing incremental records from the source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-incrementalpullconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                incremental_pull_config_property = appflow.CfnFlow.IncrementalPullConfigProperty(
                    datetime_type_field_name="datetimeTypeFieldName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if datetime_type_field_name is not None:
                self._values["datetime_type_field_name"] = datetime_type_field_name

        @builtins.property
        def datetime_type_field_name(self) -> typing.Optional[builtins.str]:
            '''A field that specifies the date time or timestamp field as the criteria to use when importing incremental records from the source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-incrementalpullconfig.html#cfn-appflow-flow-incrementalpullconfig-datetimetypefieldname
            '''
            result = self._values.get("datetime_type_field_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IncrementalPullConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.InforNexusSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class InforNexusSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when Infor Nexus is being used as a source.

            :param object: The object specified in the Infor Nexus flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-infornexussourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                infor_nexus_source_properties_property = appflow.CfnFlow.InforNexusSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Infor Nexus flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-infornexussourceproperties.html#cfn-appflow-flow-infornexussourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InforNexusSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.LookoutMetricsDestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class LookoutMetricsDestinationPropertiesProperty:
        def __init__(self, *, object: typing.Optional[builtins.str] = None) -> None:
            '''The properties that are applied when Amazon Lookout for Metrics is used as a destination.

            :param object: The object specified in the Amazon Lookout for Metrics flow destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-lookoutmetricsdestinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                lookout_metrics_destination_properties_property = appflow.CfnFlow.LookoutMetricsDestinationPropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if object is not None:
                self._values["object"] = object

        @builtins.property
        def object(self) -> typing.Optional[builtins.str]:
            '''The object specified in the Amazon Lookout for Metrics flow destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-lookoutmetricsdestinationproperties.html#cfn-appflow-flow-lookoutmetricsdestinationproperties-object
            '''
            result = self._values.get("object")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LookoutMetricsDestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.MarketoSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class MarketoSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when Marketo is being used as a source.

            :param object: The object specified in the Marketo flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-marketosourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                marketo_source_properties_property = appflow.CfnFlow.MarketoSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Marketo flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-marketosourceproperties.html#cfn-appflow-flow-marketosourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MarketoSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.PrefixConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"prefix_format": "prefixFormat", "prefix_type": "prefixType"},
    )
    class PrefixConfigProperty:
        def __init__(
            self,
            *,
            prefix_format: typing.Optional[builtins.str] = None,
            prefix_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Determines the prefix that Amazon AppFlow applies to the destination folder name.

            You can name your destination folders according to the flow frequency and date.

            :param prefix_format: Determines the level of granularity that's included in the prefix.
            :param prefix_type: Determines the format of the prefix, and whether it applies to the file name, file path, or both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-prefixconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                prefix_config_property = appflow.CfnFlow.PrefixConfigProperty(
                    prefix_format="prefixFormat",
                    prefix_type="prefixType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if prefix_format is not None:
                self._values["prefix_format"] = prefix_format
            if prefix_type is not None:
                self._values["prefix_type"] = prefix_type

        @builtins.property
        def prefix_format(self) -> typing.Optional[builtins.str]:
            '''Determines the level of granularity that's included in the prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-prefixconfig.html#cfn-appflow-flow-prefixconfig-prefixformat
            '''
            result = self._values.get("prefix_format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def prefix_type(self) -> typing.Optional[builtins.str]:
            '''Determines the format of the prefix, and whether it applies to the file name, file path, or both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-prefixconfig.html#cfn-appflow-flow-prefixconfig-prefixtype
            '''
            result = self._values.get("prefix_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PrefixConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.RedshiftDestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "intermediate_bucket_name": "intermediateBucketName",
            "object": "object",
            "bucket_prefix": "bucketPrefix",
            "error_handling_config": "errorHandlingConfig",
        },
    )
    class RedshiftDestinationPropertiesProperty:
        def __init__(
            self,
            *,
            intermediate_bucket_name: builtins.str,
            object: builtins.str,
            bucket_prefix: typing.Optional[builtins.str] = None,
            error_handling_config: typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The properties that are applied when Amazon Redshift is being used as a destination.

            :param intermediate_bucket_name: The intermediate bucket that Amazon AppFlow uses when moving data into Amazon Redshift.
            :param object: The object specified in the Amazon Redshift flow destination.
            :param bucket_prefix: The object key for the bucket in which Amazon AppFlow places the destination files.
            :param error_handling_config: The settings that determine how Amazon AppFlow handles an error when placing data in the Amazon Redshift destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. ``ErrorHandlingConfig`` is a part of the destination connector details.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-redshiftdestinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                redshift_destination_properties_property = appflow.CfnFlow.RedshiftDestinationPropertiesProperty(
                    intermediate_bucket_name="intermediateBucketName",
                    object="object",
                
                    # the properties below are optional
                    bucket_prefix="bucketPrefix",
                    error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix",
                        fail_on_first_error=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "intermediate_bucket_name": intermediate_bucket_name,
                "object": object,
            }
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix
            if error_handling_config is not None:
                self._values["error_handling_config"] = error_handling_config

        @builtins.property
        def intermediate_bucket_name(self) -> builtins.str:
            '''The intermediate bucket that Amazon AppFlow uses when moving data into Amazon Redshift.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-redshiftdestinationproperties.html#cfn-appflow-flow-redshiftdestinationproperties-intermediatebucketname
            '''
            result = self._values.get("intermediate_bucket_name")
            assert result is not None, "Required property 'intermediate_bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Amazon Redshift flow destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-redshiftdestinationproperties.html#cfn-appflow-flow-redshiftdestinationproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''The object key for the bucket in which Amazon AppFlow places the destination files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-redshiftdestinationproperties.html#cfn-appflow-flow-redshiftdestinationproperties-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def error_handling_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]]:
            '''The settings that determine how Amazon AppFlow handles an error when placing data in the Amazon Redshift destination.

            For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. ``ErrorHandlingConfig`` is a part of the destination connector details.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-redshiftdestinationproperties.html#cfn-appflow-flow-redshiftdestinationproperties-errorhandlingconfig
            '''
            result = self._values.get("error_handling_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedshiftDestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.S3DestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_name": "bucketName",
            "bucket_prefix": "bucketPrefix",
            "s3_output_format_config": "s3OutputFormatConfig",
        },
    )
    class S3DestinationPropertiesProperty:
        def __init__(
            self,
            *,
            bucket_name: builtins.str,
            bucket_prefix: typing.Optional[builtins.str] = None,
            s3_output_format_config: typing.Optional[typing.Union["CfnFlow.S3OutputFormatConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The properties that are applied when Amazon S3 is used as a destination.

            :param bucket_name: The Amazon S3 bucket name in which Amazon AppFlow places the transferred data.
            :param bucket_prefix: The object key for the destination bucket in which Amazon AppFlow places the files.
            :param s3_output_format_config: The configuration that determines how Amazon AppFlow should format the flow output data when Amazon S3 is used as the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3destinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                s3_destination_properties_property = appflow.CfnFlow.S3DestinationPropertiesProperty(
                    bucket_name="bucketName",
                
                    # the properties below are optional
                    bucket_prefix="bucketPrefix",
                    s3_output_format_config=appflow.CfnFlow.S3OutputFormatConfigProperty(
                        aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                            aggregation_type="aggregationType"
                        ),
                        file_type="fileType",
                        prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                            prefix_format="prefixFormat",
                            prefix_type="prefixType"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_name": bucket_name,
            }
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix
            if s3_output_format_config is not None:
                self._values["s3_output_format_config"] = s3_output_format_config

        @builtins.property
        def bucket_name(self) -> builtins.str:
            '''The Amazon S3 bucket name in which Amazon AppFlow places the transferred data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3destinationproperties.html#cfn-appflow-flow-s3destinationproperties-bucketname
            '''
            result = self._values.get("bucket_name")
            assert result is not None, "Required property 'bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''The object key for the destination bucket in which Amazon AppFlow places the files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3destinationproperties.html#cfn-appflow-flow-s3destinationproperties-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3_output_format_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.S3OutputFormatConfigProperty", _IResolvable_da3f097b]]:
            '''The configuration that determines how Amazon AppFlow should format the flow output data when Amazon S3 is used as the destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3destinationproperties.html#cfn-appflow-flow-s3destinationproperties-s3outputformatconfig
            '''
            result = self._values.get("s3_output_format_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.S3OutputFormatConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3DestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.S3InputFormatConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"s3_input_file_type": "s3InputFileType"},
    )
    class S3InputFormatConfigProperty:
        def __init__(
            self,
            *,
            s3_input_file_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param s3_input_file_type: ``CfnFlow.S3InputFormatConfigProperty.S3InputFileType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3inputformatconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                s3_input_format_config_property = appflow.CfnFlow.S3InputFormatConfigProperty(
                    s3_input_file_type="s3InputFileType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if s3_input_file_type is not None:
                self._values["s3_input_file_type"] = s3_input_file_type

        @builtins.property
        def s3_input_file_type(self) -> typing.Optional[builtins.str]:
            '''``CfnFlow.S3InputFormatConfigProperty.S3InputFileType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3inputformatconfig.html#cfn-appflow-flow-s3inputformatconfig-s3inputfiletype
            '''
            result = self._values.get("s3_input_file_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3InputFormatConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.S3OutputFormatConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "aggregation_config": "aggregationConfig",
            "file_type": "fileType",
            "prefix_config": "prefixConfig",
        },
    )
    class S3OutputFormatConfigProperty:
        def __init__(
            self,
            *,
            aggregation_config: typing.Optional[typing.Union["CfnFlow.AggregationConfigProperty", _IResolvable_da3f097b]] = None,
            file_type: typing.Optional[builtins.str] = None,
            prefix_config: typing.Optional[typing.Union["CfnFlow.PrefixConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The configuration that determines how Amazon AppFlow should format the flow output data when Amazon S3 is used as the destination.

            :param aggregation_config: The aggregation settings that you can use to customize the output format of your flow data.
            :param file_type: Indicates the file type that Amazon AppFlow places in the Amazon S3 bucket.
            :param prefix_config: Determines the prefix that Amazon AppFlow applies to the folder name in the Amazon S3 bucket. You can name folders according to the flow frequency and date.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3outputformatconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                s3_output_format_config_property = appflow.CfnFlow.S3OutputFormatConfigProperty(
                    aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                        aggregation_type="aggregationType"
                    ),
                    file_type="fileType",
                    prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                        prefix_format="prefixFormat",
                        prefix_type="prefixType"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if aggregation_config is not None:
                self._values["aggregation_config"] = aggregation_config
            if file_type is not None:
                self._values["file_type"] = file_type
            if prefix_config is not None:
                self._values["prefix_config"] = prefix_config

        @builtins.property
        def aggregation_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.AggregationConfigProperty", _IResolvable_da3f097b]]:
            '''The aggregation settings that you can use to customize the output format of your flow data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3outputformatconfig.html#cfn-appflow-flow-s3outputformatconfig-aggregationconfig
            '''
            result = self._values.get("aggregation_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.AggregationConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def file_type(self) -> typing.Optional[builtins.str]:
            '''Indicates the file type that Amazon AppFlow places in the Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3outputformatconfig.html#cfn-appflow-flow-s3outputformatconfig-filetype
            '''
            result = self._values.get("file_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def prefix_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.PrefixConfigProperty", _IResolvable_da3f097b]]:
            '''Determines the prefix that Amazon AppFlow applies to the folder name in the Amazon S3 bucket.

            You can name folders according to the flow frequency and date.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3outputformatconfig.html#cfn-appflow-flow-s3outputformatconfig-prefixconfig
            '''
            result = self._values.get("prefix_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.PrefixConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3OutputFormatConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.S3SourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_name": "bucketName",
            "bucket_prefix": "bucketPrefix",
            "s3_input_format_config": "s3InputFormatConfig",
        },
    )
    class S3SourcePropertiesProperty:
        def __init__(
            self,
            *,
            bucket_name: builtins.str,
            bucket_prefix: builtins.str,
            s3_input_format_config: typing.Optional[typing.Union["CfnFlow.S3InputFormatConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The properties that are applied when Amazon S3 is being used as the flow source.

            :param bucket_name: The Amazon S3 bucket name where the source files are stored.
            :param bucket_prefix: The object key for the Amazon S3 bucket in which the source files are stored.
            :param s3_input_format_config: ``CfnFlow.S3SourcePropertiesProperty.S3InputFormatConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3sourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                s3_source_properties_property = appflow.CfnFlow.S3SourcePropertiesProperty(
                    bucket_name="bucketName",
                    bucket_prefix="bucketPrefix",
                
                    # the properties below are optional
                    s3_input_format_config=appflow.CfnFlow.S3InputFormatConfigProperty(
                        s3_input_file_type="s3InputFileType"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_name": bucket_name,
                "bucket_prefix": bucket_prefix,
            }
            if s3_input_format_config is not None:
                self._values["s3_input_format_config"] = s3_input_format_config

        @builtins.property
        def bucket_name(self) -> builtins.str:
            '''The Amazon S3 bucket name where the source files are stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3sourceproperties.html#cfn-appflow-flow-s3sourceproperties-bucketname
            '''
            result = self._values.get("bucket_name")
            assert result is not None, "Required property 'bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bucket_prefix(self) -> builtins.str:
            '''The object key for the Amazon S3 bucket in which the source files are stored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3sourceproperties.html#cfn-appflow-flow-s3sourceproperties-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            assert result is not None, "Required property 'bucket_prefix' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_input_format_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.S3InputFormatConfigProperty", _IResolvable_da3f097b]]:
            '''``CfnFlow.S3SourcePropertiesProperty.S3InputFormatConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-s3sourceproperties.html#cfn-appflow-flow-s3sourceproperties-s3inputformatconfig
            '''
            result = self._values.get("s3_input_format_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.S3InputFormatConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3SourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SAPODataDestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "object_path": "objectPath",
            "error_handling_config": "errorHandlingConfig",
            "id_field_names": "idFieldNames",
            "success_response_handling_config": "successResponseHandlingConfig",
            "write_operation_type": "writeOperationType",
        },
    )
    class SAPODataDestinationPropertiesProperty:
        def __init__(
            self,
            *,
            object_path: builtins.str,
            error_handling_config: typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]] = None,
            id_field_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            success_response_handling_config: typing.Optional[typing.Union["CfnFlow.SuccessResponseHandlingConfigProperty", _IResolvable_da3f097b]] = None,
            write_operation_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The properties that are applied when using SAPOData as a flow destination.

            :param object_path: The object path specified in the SAPOData flow destination.
            :param error_handling_config: ``CfnFlow.SAPODataDestinationPropertiesProperty.ErrorHandlingConfig``.
            :param id_field_names: ``CfnFlow.SAPODataDestinationPropertiesProperty.IdFieldNames``.
            :param success_response_handling_config: Determines how Amazon AppFlow handles the success response that it gets from the connector after placing data. For example, this setting would determine where to write the response from a destination connector upon a successful insert operation.
            :param write_operation_type: ``CfnFlow.SAPODataDestinationPropertiesProperty.WriteOperationType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sapodatadestinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                s_aPOData_destination_properties_property = appflow.CfnFlow.SAPODataDestinationPropertiesProperty(
                    object_path="objectPath",
                
                    # the properties below are optional
                    error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix",
                        fail_on_first_error=False
                    ),
                    id_field_names=["idFieldNames"],
                    success_response_handling_config=appflow.CfnFlow.SuccessResponseHandlingConfigProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix"
                    ),
                    write_operation_type="writeOperationType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object_path": object_path,
            }
            if error_handling_config is not None:
                self._values["error_handling_config"] = error_handling_config
            if id_field_names is not None:
                self._values["id_field_names"] = id_field_names
            if success_response_handling_config is not None:
                self._values["success_response_handling_config"] = success_response_handling_config
            if write_operation_type is not None:
                self._values["write_operation_type"] = write_operation_type

        @builtins.property
        def object_path(self) -> builtins.str:
            '''The object path specified in the SAPOData flow destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sapodatadestinationproperties.html#cfn-appflow-flow-sapodatadestinationproperties-objectpath
            '''
            result = self._values.get("object_path")
            assert result is not None, "Required property 'object_path' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def error_handling_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]]:
            '''``CfnFlow.SAPODataDestinationPropertiesProperty.ErrorHandlingConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sapodatadestinationproperties.html#cfn-appflow-flow-sapodatadestinationproperties-errorhandlingconfig
            '''
            result = self._values.get("error_handling_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def id_field_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnFlow.SAPODataDestinationPropertiesProperty.IdFieldNames``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sapodatadestinationproperties.html#cfn-appflow-flow-sapodatadestinationproperties-idfieldnames
            '''
            result = self._values.get("id_field_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def success_response_handling_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.SuccessResponseHandlingConfigProperty", _IResolvable_da3f097b]]:
            '''Determines how Amazon AppFlow handles the success response that it gets from the connector after placing data.

            For example, this setting would determine where to write the response from a destination connector upon a successful insert operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sapodatadestinationproperties.html#cfn-appflow-flow-sapodatadestinationproperties-successresponsehandlingconfig
            '''
            result = self._values.get("success_response_handling_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.SuccessResponseHandlingConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def write_operation_type(self) -> typing.Optional[builtins.str]:
            '''``CfnFlow.SAPODataDestinationPropertiesProperty.WriteOperationType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sapodatadestinationproperties.html#cfn-appflow-flow-sapodatadestinationproperties-writeoperationtype
            '''
            result = self._values.get("write_operation_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SAPODataDestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SAPODataSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object_path": "objectPath"},
    )
    class SAPODataSourcePropertiesProperty:
        def __init__(self, *, object_path: builtins.str) -> None:
            '''
            :param object_path: ``CfnFlow.SAPODataSourcePropertiesProperty.ObjectPath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sapodatasourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                s_aPOData_source_properties_property = appflow.CfnFlow.SAPODataSourcePropertiesProperty(
                    object_path="objectPath"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object_path": object_path,
            }

        @builtins.property
        def object_path(self) -> builtins.str:
            '''``CfnFlow.SAPODataSourcePropertiesProperty.ObjectPath``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sapodatasourceproperties.html#cfn-appflow-flow-sapodatasourceproperties-objectpath
            '''
            result = self._values.get("object_path")
            assert result is not None, "Required property 'object_path' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SAPODataSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SalesforceDestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "object": "object",
            "error_handling_config": "errorHandlingConfig",
            "id_field_names": "idFieldNames",
            "write_operation_type": "writeOperationType",
        },
    )
    class SalesforceDestinationPropertiesProperty:
        def __init__(
            self,
            *,
            object: builtins.str,
            error_handling_config: typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]] = None,
            id_field_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            write_operation_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The properties that are applied when Salesforce is being used as a destination.

            :param object: The object specified in the Salesforce flow destination.
            :param error_handling_config: The settings that determine how Amazon AppFlow handles an error when placing data in the Salesforce destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. ``ErrorHandlingConfig`` is a part of the destination connector details.
            :param id_field_names: The name of the field that Amazon AppFlow uses as an ID when performing a write operation such as update or delete.
            :param write_operation_type: This specifies the type of write operation to be performed in Salesforce. When the value is ``UPSERT`` , then ``idFieldNames`` is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcedestinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                salesforce_destination_properties_property = appflow.CfnFlow.SalesforceDestinationPropertiesProperty(
                    object="object",
                
                    # the properties below are optional
                    error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix",
                        fail_on_first_error=False
                    ),
                    id_field_names=["idFieldNames"],
                    write_operation_type="writeOperationType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }
            if error_handling_config is not None:
                self._values["error_handling_config"] = error_handling_config
            if id_field_names is not None:
                self._values["id_field_names"] = id_field_names
            if write_operation_type is not None:
                self._values["write_operation_type"] = write_operation_type

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Salesforce flow destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcedestinationproperties.html#cfn-appflow-flow-salesforcedestinationproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def error_handling_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]]:
            '''The settings that determine how Amazon AppFlow handles an error when placing data in the Salesforce destination.

            For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. ``ErrorHandlingConfig`` is a part of the destination connector details.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcedestinationproperties.html#cfn-appflow-flow-salesforcedestinationproperties-errorhandlingconfig
            '''
            result = self._values.get("error_handling_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def id_field_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The name of the field that Amazon AppFlow uses as an ID when performing a write operation such as update or delete.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcedestinationproperties.html#cfn-appflow-flow-salesforcedestinationproperties-idfieldnames
            '''
            result = self._values.get("id_field_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def write_operation_type(self) -> typing.Optional[builtins.str]:
            '''This specifies the type of write operation to be performed in Salesforce.

            When the value is ``UPSERT`` , then ``idFieldNames`` is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcedestinationproperties.html#cfn-appflow-flow-salesforcedestinationproperties-writeoperationtype
            '''
            result = self._values.get("write_operation_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SalesforceDestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SalesforceSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "object": "object",
            "enable_dynamic_field_update": "enableDynamicFieldUpdate",
            "include_deleted_records": "includeDeletedRecords",
        },
    )
    class SalesforceSourcePropertiesProperty:
        def __init__(
            self,
            *,
            object: builtins.str,
            enable_dynamic_field_update: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_deleted_records: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The properties that are applied when Salesforce is being used as a source.

            :param object: The object specified in the Salesforce flow source.
            :param enable_dynamic_field_update: The flag that enables dynamic fetching of new (recently added) fields in the Salesforce objects while running a flow.
            :param include_deleted_records: Indicates whether Amazon AppFlow includes deleted files in the flow run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcesourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                salesforce_source_properties_property = appflow.CfnFlow.SalesforceSourcePropertiesProperty(
                    object="object",
                
                    # the properties below are optional
                    enable_dynamic_field_update=False,
                    include_deleted_records=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }
            if enable_dynamic_field_update is not None:
                self._values["enable_dynamic_field_update"] = enable_dynamic_field_update
            if include_deleted_records is not None:
                self._values["include_deleted_records"] = include_deleted_records

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Salesforce flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcesourceproperties.html#cfn-appflow-flow-salesforcesourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def enable_dynamic_field_update(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The flag that enables dynamic fetching of new (recently added) fields in the Salesforce objects while running a flow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcesourceproperties.html#cfn-appflow-flow-salesforcesourceproperties-enabledynamicfieldupdate
            '''
            result = self._values.get("enable_dynamic_field_update")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_deleted_records(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether Amazon AppFlow includes deleted files in the flow run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-salesforcesourceproperties.html#cfn-appflow-flow-salesforcesourceproperties-includedeletedrecords
            '''
            result = self._values.get("include_deleted_records")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SalesforceSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.ScheduledTriggerPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "schedule_expression": "scheduleExpression",
            "data_pull_mode": "dataPullMode",
            "schedule_end_time": "scheduleEndTime",
            "schedule_offset": "scheduleOffset",
            "schedule_start_time": "scheduleStartTime",
            "time_zone": "timeZone",
        },
    )
    class ScheduledTriggerPropertiesProperty:
        def __init__(
            self,
            *,
            schedule_expression: builtins.str,
            data_pull_mode: typing.Optional[builtins.str] = None,
            schedule_end_time: typing.Optional[jsii.Number] = None,
            schedule_offset: typing.Optional[jsii.Number] = None,
            schedule_start_time: typing.Optional[jsii.Number] = None,
            time_zone: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the configuration details of a schedule-triggered flow as defined by the user.

            Currently, these settings only apply to the ``Scheduled`` trigger type.

            :param schedule_expression: The scheduling expression that determines the rate at which the scheduled flow will run, for example: ``rate(5minutes)`` .
            :param data_pull_mode: Specifies whether a scheduled flow has an incremental data transfer or a complete data transfer for each flow run.
            :param schedule_end_time: Specifies the scheduled end time for a schedule-triggered flow.
            :param schedule_offset: Specifies the optional offset that is added to the time interval for a schedule-triggered flow.
            :param schedule_start_time: Specifies the scheduled start time for a schedule-triggered flow.
            :param time_zone: Specifies the time zone used when referring to the date and time of a scheduled-triggered flow, such as ``America/New_York`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-scheduledtriggerproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                scheduled_trigger_properties_property = appflow.CfnFlow.ScheduledTriggerPropertiesProperty(
                    schedule_expression="scheduleExpression",
                
                    # the properties below are optional
                    data_pull_mode="dataPullMode",
                    schedule_end_time=123,
                    schedule_offset=123,
                    schedule_start_time=123,
                    time_zone="timeZone"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "schedule_expression": schedule_expression,
            }
            if data_pull_mode is not None:
                self._values["data_pull_mode"] = data_pull_mode
            if schedule_end_time is not None:
                self._values["schedule_end_time"] = schedule_end_time
            if schedule_offset is not None:
                self._values["schedule_offset"] = schedule_offset
            if schedule_start_time is not None:
                self._values["schedule_start_time"] = schedule_start_time
            if time_zone is not None:
                self._values["time_zone"] = time_zone

        @builtins.property
        def schedule_expression(self) -> builtins.str:
            '''The scheduling expression that determines the rate at which the scheduled flow will run, for example: ``rate(5minutes)`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-scheduledtriggerproperties.html#cfn-appflow-flow-scheduledtriggerproperties-scheduleexpression
            '''
            result = self._values.get("schedule_expression")
            assert result is not None, "Required property 'schedule_expression' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def data_pull_mode(self) -> typing.Optional[builtins.str]:
            '''Specifies whether a scheduled flow has an incremental data transfer or a complete data transfer for each flow run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-scheduledtriggerproperties.html#cfn-appflow-flow-scheduledtriggerproperties-datapullmode
            '''
            result = self._values.get("data_pull_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schedule_end_time(self) -> typing.Optional[jsii.Number]:
            '''Specifies the scheduled end time for a schedule-triggered flow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-scheduledtriggerproperties.html#cfn-appflow-flow-scheduledtriggerproperties-scheduleendtime
            '''
            result = self._values.get("schedule_end_time")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def schedule_offset(self) -> typing.Optional[jsii.Number]:
            '''Specifies the optional offset that is added to the time interval for a schedule-triggered flow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-scheduledtriggerproperties.html#cfn-appflow-flow-scheduledtriggerproperties-scheduleoffset
            '''
            result = self._values.get("schedule_offset")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def schedule_start_time(self) -> typing.Optional[jsii.Number]:
            '''Specifies the scheduled start time for a schedule-triggered flow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-scheduledtriggerproperties.html#cfn-appflow-flow-scheduledtriggerproperties-schedulestarttime
            '''
            result = self._values.get("schedule_start_time")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def time_zone(self) -> typing.Optional[builtins.str]:
            '''Specifies the time zone used when referring to the date and time of a scheduled-triggered flow, such as ``America/New_York`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-scheduledtriggerproperties.html#cfn-appflow-flow-scheduledtriggerproperties-timezone
            '''
            result = self._values.get("time_zone")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScheduledTriggerPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.ServiceNowSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class ServiceNowSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when ServiceNow is being used as a source.

            :param object: The object specified in the ServiceNow flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-servicenowsourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                service_now_source_properties_property = appflow.CfnFlow.ServiceNowSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the ServiceNow flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-servicenowsourceproperties.html#cfn-appflow-flow-servicenowsourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServiceNowSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SingularSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class SingularSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when Singular is being used as a source.

            :param object: The object specified in the Singular flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-singularsourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                singular_source_properties_property = appflow.CfnFlow.SingularSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Singular flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-singularsourceproperties.html#cfn-appflow-flow-singularsourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SingularSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SlackSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class SlackSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when Slack is being used as a source.

            :param object: The object specified in the Slack flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-slacksourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                slack_source_properties_property = appflow.CfnFlow.SlackSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Slack flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-slacksourceproperties.html#cfn-appflow-flow-slacksourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SlackSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SnowflakeDestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "intermediate_bucket_name": "intermediateBucketName",
            "object": "object",
            "bucket_prefix": "bucketPrefix",
            "error_handling_config": "errorHandlingConfig",
        },
    )
    class SnowflakeDestinationPropertiesProperty:
        def __init__(
            self,
            *,
            intermediate_bucket_name: builtins.str,
            object: builtins.str,
            bucket_prefix: typing.Optional[builtins.str] = None,
            error_handling_config: typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The properties that are applied when Snowflake is being used as a destination.

            :param intermediate_bucket_name: The intermediate bucket that Amazon AppFlow uses when moving data into Snowflake.
            :param object: The object specified in the Snowflake flow destination.
            :param bucket_prefix: The object key for the destination bucket in which Amazon AppFlow places the files.
            :param error_handling_config: The settings that determine how Amazon AppFlow handles an error when placing data in the Snowflake destination. For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. ``ErrorHandlingConfig`` is a part of the destination connector details.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-snowflakedestinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                snowflake_destination_properties_property = appflow.CfnFlow.SnowflakeDestinationPropertiesProperty(
                    intermediate_bucket_name="intermediateBucketName",
                    object="object",
                
                    # the properties below are optional
                    bucket_prefix="bucketPrefix",
                    error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix",
                        fail_on_first_error=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "intermediate_bucket_name": intermediate_bucket_name,
                "object": object,
            }
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix
            if error_handling_config is not None:
                self._values["error_handling_config"] = error_handling_config

        @builtins.property
        def intermediate_bucket_name(self) -> builtins.str:
            '''The intermediate bucket that Amazon AppFlow uses when moving data into Snowflake.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-snowflakedestinationproperties.html#cfn-appflow-flow-snowflakedestinationproperties-intermediatebucketname
            '''
            result = self._values.get("intermediate_bucket_name")
            assert result is not None, "Required property 'intermediate_bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Snowflake flow destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-snowflakedestinationproperties.html#cfn-appflow-flow-snowflakedestinationproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''The object key for the destination bucket in which Amazon AppFlow places the files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-snowflakedestinationproperties.html#cfn-appflow-flow-snowflakedestinationproperties-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def error_handling_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]]:
            '''The settings that determine how Amazon AppFlow handles an error when placing data in the Snowflake destination.

            For example, this setting would determine if the flow should fail after one insertion error, or continue and attempt to insert every record regardless of the initial failure. ``ErrorHandlingConfig`` is a part of the destination connector details.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-snowflakedestinationproperties.html#cfn-appflow-flow-snowflakedestinationproperties-errorhandlingconfig
            '''
            result = self._values.get("error_handling_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SnowflakeDestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SourceConnectorPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "amplitude": "amplitude",
            "datadog": "datadog",
            "dynatrace": "dynatrace",
            "google_analytics": "googleAnalytics",
            "infor_nexus": "inforNexus",
            "marketo": "marketo",
            "s3": "s3",
            "salesforce": "salesforce",
            "sapo_data": "sapoData",
            "service_now": "serviceNow",
            "singular": "singular",
            "slack": "slack",
            "trendmicro": "trendmicro",
            "veeva": "veeva",
            "zendesk": "zendesk",
        },
    )
    class SourceConnectorPropertiesProperty:
        def __init__(
            self,
            *,
            amplitude: typing.Optional[typing.Union["CfnFlow.AmplitudeSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            datadog: typing.Optional[typing.Union["CfnFlow.DatadogSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            dynatrace: typing.Optional[typing.Union["CfnFlow.DynatraceSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            google_analytics: typing.Optional[typing.Union["CfnFlow.GoogleAnalyticsSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            infor_nexus: typing.Optional[typing.Union["CfnFlow.InforNexusSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            marketo: typing.Optional[typing.Union["CfnFlow.MarketoSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            s3: typing.Optional[typing.Union["CfnFlow.S3SourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            salesforce: typing.Optional[typing.Union["CfnFlow.SalesforceSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            sapo_data: typing.Optional[typing.Union["CfnFlow.SAPODataSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            service_now: typing.Optional[typing.Union["CfnFlow.ServiceNowSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            singular: typing.Optional[typing.Union["CfnFlow.SingularSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            slack: typing.Optional[typing.Union["CfnFlow.SlackSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            trendmicro: typing.Optional[typing.Union["CfnFlow.TrendmicroSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            veeva: typing.Optional[typing.Union["CfnFlow.VeevaSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            zendesk: typing.Optional[typing.Union["CfnFlow.ZendeskSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies the information that is required to query a particular connector.

            :param amplitude: Specifies the information that is required for querying Amplitude.
            :param datadog: Specifies the information that is required for querying Datadog.
            :param dynatrace: Specifies the information that is required for querying Dynatrace.
            :param google_analytics: Specifies the information that is required for querying Google Analytics.
            :param infor_nexus: Specifies the information that is required for querying Infor Nexus.
            :param marketo: Specifies the information that is required for querying Marketo.
            :param s3: Specifies the information that is required for querying Amazon S3.
            :param salesforce: Specifies the information that is required for querying Salesforce.
            :param sapo_data: ``CfnFlow.SourceConnectorPropertiesProperty.SAPOData``.
            :param service_now: Specifies the information that is required for querying ServiceNow.
            :param singular: Specifies the information that is required for querying Singular.
            :param slack: Specifies the information that is required for querying Slack.
            :param trendmicro: Specifies the information that is required for querying Trend Micro.
            :param veeva: Specifies the information that is required for querying Veeva.
            :param zendesk: Specifies the information that is required for querying Zendesk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                source_connector_properties_property = appflow.CfnFlow.SourceConnectorPropertiesProperty(
                    amplitude=appflow.CfnFlow.AmplitudeSourcePropertiesProperty(
                        object="object"
                    ),
                    datadog=appflow.CfnFlow.DatadogSourcePropertiesProperty(
                        object="object"
                    ),
                    dynatrace=appflow.CfnFlow.DynatraceSourcePropertiesProperty(
                        object="object"
                    ),
                    google_analytics=appflow.CfnFlow.GoogleAnalyticsSourcePropertiesProperty(
                        object="object"
                    ),
                    infor_nexus=appflow.CfnFlow.InforNexusSourcePropertiesProperty(
                        object="object"
                    ),
                    marketo=appflow.CfnFlow.MarketoSourcePropertiesProperty(
                        object="object"
                    ),
                    s3=appflow.CfnFlow.S3SourcePropertiesProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix",
                
                        # the properties below are optional
                        s3_input_format_config=appflow.CfnFlow.S3InputFormatConfigProperty(
                            s3_input_file_type="s3InputFileType"
                        )
                    ),
                    salesforce=appflow.CfnFlow.SalesforceSourcePropertiesProperty(
                        object="object",
                
                        # the properties below are optional
                        enable_dynamic_field_update=False,
                        include_deleted_records=False
                    ),
                    sapo_data=appflow.CfnFlow.SAPODataSourcePropertiesProperty(
                        object_path="objectPath"
                    ),
                    service_now=appflow.CfnFlow.ServiceNowSourcePropertiesProperty(
                        object="object"
                    ),
                    singular=appflow.CfnFlow.SingularSourcePropertiesProperty(
                        object="object"
                    ),
                    slack=appflow.CfnFlow.SlackSourcePropertiesProperty(
                        object="object"
                    ),
                    trendmicro=appflow.CfnFlow.TrendmicroSourcePropertiesProperty(
                        object="object"
                    ),
                    veeva=appflow.CfnFlow.VeevaSourcePropertiesProperty(
                        object="object",
                
                        # the properties below are optional
                        document_type="documentType",
                        include_all_versions=False,
                        include_renditions=False,
                        include_source_files=False
                    ),
                    zendesk=appflow.CfnFlow.ZendeskSourcePropertiesProperty(
                        object="object"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if amplitude is not None:
                self._values["amplitude"] = amplitude
            if datadog is not None:
                self._values["datadog"] = datadog
            if dynatrace is not None:
                self._values["dynatrace"] = dynatrace
            if google_analytics is not None:
                self._values["google_analytics"] = google_analytics
            if infor_nexus is not None:
                self._values["infor_nexus"] = infor_nexus
            if marketo is not None:
                self._values["marketo"] = marketo
            if s3 is not None:
                self._values["s3"] = s3
            if salesforce is not None:
                self._values["salesforce"] = salesforce
            if sapo_data is not None:
                self._values["sapo_data"] = sapo_data
            if service_now is not None:
                self._values["service_now"] = service_now
            if singular is not None:
                self._values["singular"] = singular
            if slack is not None:
                self._values["slack"] = slack
            if trendmicro is not None:
                self._values["trendmicro"] = trendmicro
            if veeva is not None:
                self._values["veeva"] = veeva
            if zendesk is not None:
                self._values["zendesk"] = zendesk

        @builtins.property
        def amplitude(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.AmplitudeSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Amplitude.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-amplitude
            '''
            result = self._values.get("amplitude")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.AmplitudeSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def datadog(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.DatadogSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Datadog.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-datadog
            '''
            result = self._values.get("datadog")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.DatadogSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def dynatrace(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.DynatraceSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Dynatrace.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-dynatrace
            '''
            result = self._values.get("dynatrace")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.DynatraceSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def google_analytics(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.GoogleAnalyticsSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Google Analytics.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-googleanalytics
            '''
            result = self._values.get("google_analytics")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.GoogleAnalyticsSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def infor_nexus(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.InforNexusSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Infor Nexus.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-infornexus
            '''
            result = self._values.get("infor_nexus")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.InforNexusSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def marketo(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.MarketoSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Marketo.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-marketo
            '''
            result = self._values.get("marketo")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.MarketoSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.S3SourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Amazon S3.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-s3
            '''
            result = self._values.get("s3")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.S3SourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def salesforce(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.SalesforceSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Salesforce.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-salesforce
            '''
            result = self._values.get("salesforce")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.SalesforceSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sapo_data(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.SAPODataSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnFlow.SourceConnectorPropertiesProperty.SAPOData``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-sapodata
            '''
            result = self._values.get("sapo_data")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.SAPODataSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def service_now(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ServiceNowSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying ServiceNow.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-servicenow
            '''
            result = self._values.get("service_now")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ServiceNowSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def singular(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.SingularSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Singular.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-singular
            '''
            result = self._values.get("singular")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.SingularSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def slack(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.SlackSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Slack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-slack
            '''
            result = self._values.get("slack")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.SlackSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def trendmicro(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.TrendmicroSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Trend Micro.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-trendmicro
            '''
            result = self._values.get("trendmicro")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.TrendmicroSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def veeva(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.VeevaSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Veeva.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-veeva
            '''
            result = self._values.get("veeva")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.VeevaSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def zendesk(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ZendeskSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the information that is required for querying Zendesk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceconnectorproperties.html#cfn-appflow-flow-sourceconnectorproperties-zendesk
            '''
            result = self._values.get("zendesk")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ZendeskSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceConnectorPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SourceFlowConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connector_type": "connectorType",
            "source_connector_properties": "sourceConnectorProperties",
            "connector_profile_name": "connectorProfileName",
            "incremental_pull_config": "incrementalPullConfig",
        },
    )
    class SourceFlowConfigProperty:
        def __init__(
            self,
            *,
            connector_type: builtins.str,
            source_connector_properties: typing.Union["CfnFlow.SourceConnectorPropertiesProperty", _IResolvable_da3f097b],
            connector_profile_name: typing.Optional[builtins.str] = None,
            incremental_pull_config: typing.Optional[typing.Union["CfnFlow.IncrementalPullConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Contains information about the configuration of the source connector used in the flow.

            :param connector_type: The type of source connector, such as Salesforce, Amplitude, and so on. *Allowed Values* : S3 | Amplitude | Datadog | Dynatrace | Googleanalytics | Infornexus | Salesforce | Servicenow | Singular | Slack | Trendmicro | Veeva | Zendesk
            :param source_connector_properties: Specifies the information that is required to query a particular source connector.
            :param connector_profile_name: The name of the connector profile. This name must be unique for each connector profile in the AWS account .
            :param incremental_pull_config: Defines the configuration for a scheduled incremental data pull. If a valid configuration is provided, the fields specified in the configuration are used when querying for the incremental data pull.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceflowconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                source_flow_config_property = appflow.CfnFlow.SourceFlowConfigProperty(
                    connector_type="connectorType",
                    source_connector_properties=appflow.CfnFlow.SourceConnectorPropertiesProperty(
                        amplitude=appflow.CfnFlow.AmplitudeSourcePropertiesProperty(
                            object="object"
                        ),
                        datadog=appflow.CfnFlow.DatadogSourcePropertiesProperty(
                            object="object"
                        ),
                        dynatrace=appflow.CfnFlow.DynatraceSourcePropertiesProperty(
                            object="object"
                        ),
                        google_analytics=appflow.CfnFlow.GoogleAnalyticsSourcePropertiesProperty(
                            object="object"
                        ),
                        infor_nexus=appflow.CfnFlow.InforNexusSourcePropertiesProperty(
                            object="object"
                        ),
                        marketo=appflow.CfnFlow.MarketoSourcePropertiesProperty(
                            object="object"
                        ),
                        s3=appflow.CfnFlow.S3SourcePropertiesProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
                
                            # the properties below are optional
                            s3_input_format_config=appflow.CfnFlow.S3InputFormatConfigProperty(
                                s3_input_file_type="s3InputFileType"
                            )
                        ),
                        salesforce=appflow.CfnFlow.SalesforceSourcePropertiesProperty(
                            object="object",
                
                            # the properties below are optional
                            enable_dynamic_field_update=False,
                            include_deleted_records=False
                        ),
                        sapo_data=appflow.CfnFlow.SAPODataSourcePropertiesProperty(
                            object_path="objectPath"
                        ),
                        service_now=appflow.CfnFlow.ServiceNowSourcePropertiesProperty(
                            object="object"
                        ),
                        singular=appflow.CfnFlow.SingularSourcePropertiesProperty(
                            object="object"
                        ),
                        slack=appflow.CfnFlow.SlackSourcePropertiesProperty(
                            object="object"
                        ),
                        trendmicro=appflow.CfnFlow.TrendmicroSourcePropertiesProperty(
                            object="object"
                        ),
                        veeva=appflow.CfnFlow.VeevaSourcePropertiesProperty(
                            object="object",
                
                            # the properties below are optional
                            document_type="documentType",
                            include_all_versions=False,
                            include_renditions=False,
                            include_source_files=False
                        ),
                        zendesk=appflow.CfnFlow.ZendeskSourcePropertiesProperty(
                            object="object"
                        )
                    ),
                
                    # the properties below are optional
                    connector_profile_name="connectorProfileName",
                    incremental_pull_config=appflow.CfnFlow.IncrementalPullConfigProperty(
                        datetime_type_field_name="datetimeTypeFieldName"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connector_type": connector_type,
                "source_connector_properties": source_connector_properties,
            }
            if connector_profile_name is not None:
                self._values["connector_profile_name"] = connector_profile_name
            if incremental_pull_config is not None:
                self._values["incremental_pull_config"] = incremental_pull_config

        @builtins.property
        def connector_type(self) -> builtins.str:
            '''The type of source connector, such as Salesforce, Amplitude, and so on.

            *Allowed Values* : S3 | Amplitude | Datadog | Dynatrace | Googleanalytics | Infornexus | Salesforce | Servicenow | Singular | Slack | Trendmicro | Veeva | Zendesk

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceflowconfig.html#cfn-appflow-flow-sourceflowconfig-connectortype
            '''
            result = self._values.get("connector_type")
            assert result is not None, "Required property 'connector_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source_connector_properties(
            self,
        ) -> typing.Union["CfnFlow.SourceConnectorPropertiesProperty", _IResolvable_da3f097b]:
            '''Specifies the information that is required to query a particular source connector.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceflowconfig.html#cfn-appflow-flow-sourceflowconfig-sourceconnectorproperties
            '''
            result = self._values.get("source_connector_properties")
            assert result is not None, "Required property 'source_connector_properties' is missing"
            return typing.cast(typing.Union["CfnFlow.SourceConnectorPropertiesProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def connector_profile_name(self) -> typing.Optional[builtins.str]:
            '''The name of the connector profile.

            This name must be unique for each connector profile in the AWS account .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceflowconfig.html#cfn-appflow-flow-sourceflowconfig-connectorprofilename
            '''
            result = self._values.get("connector_profile_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def incremental_pull_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.IncrementalPullConfigProperty", _IResolvable_da3f097b]]:
            '''Defines the configuration for a scheduled incremental data pull.

            If a valid configuration is provided, the fields specified in the configuration are used when querying for the incremental data pull.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-sourceflowconfig.html#cfn-appflow-flow-sourceflowconfig-incrementalpullconfig
            '''
            result = self._values.get("incremental_pull_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.IncrementalPullConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceFlowConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.SuccessResponseHandlingConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"bucket_name": "bucketName", "bucket_prefix": "bucketPrefix"},
    )
    class SuccessResponseHandlingConfigProperty:
        def __init__(
            self,
            *,
            bucket_name: typing.Optional[builtins.str] = None,
            bucket_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Determines how Amazon AppFlow handles the success response that it gets from the connector after placing data.

            For example, this setting would determine where to write the response from the destination connector upon a successful insert operation.

            :param bucket_name: The name of the Amazon S3 bucket.
            :param bucket_prefix: The Amazon S3 bucket prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-successresponsehandlingconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                success_response_handling_config_property = appflow.CfnFlow.SuccessResponseHandlingConfigProperty(
                    bucket_name="bucketName",
                    bucket_prefix="bucketPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if bucket_name is not None:
                self._values["bucket_name"] = bucket_name
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix

        @builtins.property
        def bucket_name(self) -> typing.Optional[builtins.str]:
            '''The name of the Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-successresponsehandlingconfig.html#cfn-appflow-flow-successresponsehandlingconfig-bucketname
            '''
            result = self._values.get("bucket_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''The Amazon S3 bucket prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-successresponsehandlingconfig.html#cfn-appflow-flow-successresponsehandlingconfig-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SuccessResponseHandlingConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.TaskPropertiesObjectProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class TaskPropertiesObjectProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''A map used to store task-related information.

            The execution service looks for particular information based on the ``TaskType`` .

            :param key: The task property key. *Allowed Values* : ``VALUE | VALUES | DATA_TYPE | UPPER_BOUND | LOWER_BOUND | SOURCE_DATA_TYPE | DESTINATION_DATA_TYPE | VALIDATION_ACTION | MASK_VALUE | MASK_LENGTH | TRUNCATE_LENGTH | MATH_OPERATION_FIELDS_ORDER | CONCAT_FORMAT | SUBFIELD_CATEGORY_MAP`` | ``EXCLUDE_SOURCE_FIELDS_LIST``
            :param value: The task property value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-taskpropertiesobject.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                task_properties_object_property = appflow.CfnFlow.TaskPropertiesObjectProperty(
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
            '''The task property key.

            *Allowed Values* : ``VALUE | VALUES | DATA_TYPE | UPPER_BOUND | LOWER_BOUND | SOURCE_DATA_TYPE | DESTINATION_DATA_TYPE | VALIDATION_ACTION | MASK_VALUE | MASK_LENGTH | TRUNCATE_LENGTH | MATH_OPERATION_FIELDS_ORDER | CONCAT_FORMAT | SUBFIELD_CATEGORY_MAP`` | ``EXCLUDE_SOURCE_FIELDS_LIST``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-taskpropertiesobject.html#cfn-appflow-flow-taskpropertiesobject-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The task property value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-taskpropertiesobject.html#cfn-appflow-flow-taskpropertiesobject-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TaskPropertiesObjectProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.TaskProperty",
        jsii_struct_bases=[],
        name_mapping={
            "source_fields": "sourceFields",
            "task_type": "taskType",
            "connector_operator": "connectorOperator",
            "destination_field": "destinationField",
            "task_properties": "taskProperties",
        },
    )
    class TaskProperty:
        def __init__(
            self,
            *,
            source_fields: typing.Sequence[builtins.str],
            task_type: builtins.str,
            connector_operator: typing.Optional[typing.Union["CfnFlow.ConnectorOperatorProperty", _IResolvable_da3f097b]] = None,
            destination_field: typing.Optional[builtins.str] = None,
            task_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFlow.TaskPropertiesObjectProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The ``Task`` property type specifies the class for modeling different type of tasks.

            Task implementation varies based on the ``TaskType`` .

            :param source_fields: The source fields to which a particular task is applied.
            :param task_type: Specifies the particular task implementation that Amazon AppFlow performs. *Allowed values* : ``Arithmetic`` | ``Filter`` | ``Map`` | ``Map_all`` | ``Mask`` | ``Merge`` | ``Truncate`` | ``Validate``
            :param connector_operator: The operation to be performed on the provided source fields.
            :param destination_field: A field in a destination connector, or a field value against which Amazon AppFlow validates a source field.
            :param task_properties: A map used to store task-related information. The execution service looks for particular information based on the ``TaskType`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-task.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                task_property = appflow.CfnFlow.TaskProperty(
                    source_fields=["sourceFields"],
                    task_type="taskType",
                
                    # the properties below are optional
                    connector_operator=appflow.CfnFlow.ConnectorOperatorProperty(
                        amplitude="amplitude",
                        datadog="datadog",
                        dynatrace="dynatrace",
                        google_analytics="googleAnalytics",
                        infor_nexus="inforNexus",
                        marketo="marketo",
                        s3="s3",
                        salesforce="salesforce",
                        sapo_data="sapoData",
                        service_now="serviceNow",
                        singular="singular",
                        slack="slack",
                        trendmicro="trendmicro",
                        veeva="veeva",
                        zendesk="zendesk"
                    ),
                    destination_field="destinationField",
                    task_properties=[appflow.CfnFlow.TaskPropertiesObjectProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source_fields": source_fields,
                "task_type": task_type,
            }
            if connector_operator is not None:
                self._values["connector_operator"] = connector_operator
            if destination_field is not None:
                self._values["destination_field"] = destination_field
            if task_properties is not None:
                self._values["task_properties"] = task_properties

        @builtins.property
        def source_fields(self) -> typing.List[builtins.str]:
            '''The source fields to which a particular task is applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-task.html#cfn-appflow-flow-task-sourcefields
            '''
            result = self._values.get("source_fields")
            assert result is not None, "Required property 'source_fields' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def task_type(self) -> builtins.str:
            '''Specifies the particular task implementation that Amazon AppFlow performs.

            *Allowed values* : ``Arithmetic`` | ``Filter`` | ``Map`` | ``Map_all`` | ``Mask`` | ``Merge`` | ``Truncate`` | ``Validate``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-task.html#cfn-appflow-flow-task-tasktype
            '''
            result = self._values.get("task_type")
            assert result is not None, "Required property 'task_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def connector_operator(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ConnectorOperatorProperty", _IResolvable_da3f097b]]:
            '''The operation to be performed on the provided source fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-task.html#cfn-appflow-flow-task-connectoroperator
            '''
            result = self._values.get("connector_operator")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ConnectorOperatorProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def destination_field(self) -> typing.Optional[builtins.str]:
            '''A field in a destination connector, or a field value against which Amazon AppFlow validates a source field.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-task.html#cfn-appflow-flow-task-destinationfield
            '''
            result = self._values.get("destination_field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def task_properties(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFlow.TaskPropertiesObjectProperty", _IResolvable_da3f097b]]]]:
            '''A map used to store task-related information.

            The execution service looks for particular information based on the ``TaskType`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-task.html#cfn-appflow-flow-task-taskproperties
            '''
            result = self._values.get("task_properties")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFlow.TaskPropertiesObjectProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TaskProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.TrendmicroSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class TrendmicroSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when using Trend Micro as a flow source.

            :param object: The object specified in the Trend Micro flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-trendmicrosourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                trendmicro_source_properties_property = appflow.CfnFlow.TrendmicroSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Trend Micro flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-trendmicrosourceproperties.html#cfn-appflow-flow-trendmicrosourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TrendmicroSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.TriggerConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "trigger_type": "triggerType",
            "trigger_properties": "triggerProperties",
        },
    )
    class TriggerConfigProperty:
        def __init__(
            self,
            *,
            trigger_type: builtins.str,
            trigger_properties: typing.Optional[typing.Union["CfnFlow.ScheduledTriggerPropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The trigger settings that determine how and when Amazon AppFlow runs the specified flow.

            :param trigger_type: Specifies the type of flow trigger. This can be ``OnDemand`` , ``Scheduled`` , or ``Event`` .
            :param trigger_properties: Specifies the configuration details of a schedule-triggered flow as defined by the user. Currently, these settings only apply to the ``Scheduled`` trigger type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-triggerconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                trigger_config_property = appflow.CfnFlow.TriggerConfigProperty(
                    trigger_type="triggerType",
                
                    # the properties below are optional
                    trigger_properties=appflow.CfnFlow.ScheduledTriggerPropertiesProperty(
                        schedule_expression="scheduleExpression",
                
                        # the properties below are optional
                        data_pull_mode="dataPullMode",
                        schedule_end_time=123,
                        schedule_offset=123,
                        schedule_start_time=123,
                        time_zone="timeZone"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "trigger_type": trigger_type,
            }
            if trigger_properties is not None:
                self._values["trigger_properties"] = trigger_properties

        @builtins.property
        def trigger_type(self) -> builtins.str:
            '''Specifies the type of flow trigger.

            This can be ``OnDemand`` , ``Scheduled`` , or ``Event`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-triggerconfig.html#cfn-appflow-flow-triggerconfig-triggertype
            '''
            result = self._values.get("trigger_type")
            assert result is not None, "Required property 'trigger_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def trigger_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ScheduledTriggerPropertiesProperty", _IResolvable_da3f097b]]:
            '''Specifies the configuration details of a schedule-triggered flow as defined by the user.

            Currently, these settings only apply to the ``Scheduled`` trigger type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-triggerconfig.html#cfn-appflow-flow-triggerconfig-triggerproperties
            '''
            result = self._values.get("trigger_properties")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ScheduledTriggerPropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TriggerConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.UpsolverDestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_name": "bucketName",
            "s3_output_format_config": "s3OutputFormatConfig",
            "bucket_prefix": "bucketPrefix",
        },
    )
    class UpsolverDestinationPropertiesProperty:
        def __init__(
            self,
            *,
            bucket_name: builtins.str,
            s3_output_format_config: typing.Union["CfnFlow.UpsolverS3OutputFormatConfigProperty", _IResolvable_da3f097b],
            bucket_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The properties that are applied when Upsolver is used as a destination.

            :param bucket_name: The Upsolver Amazon S3 bucket name in which Amazon AppFlow places the transferred data.
            :param s3_output_format_config: The configuration that determines how data is formatted when Upsolver is used as the flow destination.
            :param bucket_prefix: The object key for the destination Upsolver Amazon S3 bucket in which Amazon AppFlow places the files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-upsolverdestinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                upsolver_destination_properties_property = appflow.CfnFlow.UpsolverDestinationPropertiesProperty(
                    bucket_name="bucketName",
                    s3_output_format_config=appflow.CfnFlow.UpsolverS3OutputFormatConfigProperty(
                        prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                            prefix_format="prefixFormat",
                            prefix_type="prefixType"
                        ),
                
                        # the properties below are optional
                        aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                            aggregation_type="aggregationType"
                        ),
                        file_type="fileType"
                    ),
                
                    # the properties below are optional
                    bucket_prefix="bucketPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_name": bucket_name,
                "s3_output_format_config": s3_output_format_config,
            }
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix

        @builtins.property
        def bucket_name(self) -> builtins.str:
            '''The Upsolver Amazon S3 bucket name in which Amazon AppFlow places the transferred data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-upsolverdestinationproperties.html#cfn-appflow-flow-upsolverdestinationproperties-bucketname
            '''
            result = self._values.get("bucket_name")
            assert result is not None, "Required property 'bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_output_format_config(
            self,
        ) -> typing.Union["CfnFlow.UpsolverS3OutputFormatConfigProperty", _IResolvable_da3f097b]:
            '''The configuration that determines how data is formatted when Upsolver is used as the flow destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-upsolverdestinationproperties.html#cfn-appflow-flow-upsolverdestinationproperties-s3outputformatconfig
            '''
            result = self._values.get("s3_output_format_config")
            assert result is not None, "Required property 's3_output_format_config' is missing"
            return typing.cast(typing.Union["CfnFlow.UpsolverS3OutputFormatConfigProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''The object key for the destination Upsolver Amazon S3 bucket in which Amazon AppFlow places the files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-upsolverdestinationproperties.html#cfn-appflow-flow-upsolverdestinationproperties-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UpsolverDestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.UpsolverS3OutputFormatConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "prefix_config": "prefixConfig",
            "aggregation_config": "aggregationConfig",
            "file_type": "fileType",
        },
    )
    class UpsolverS3OutputFormatConfigProperty:
        def __init__(
            self,
            *,
            prefix_config: typing.Union["CfnFlow.PrefixConfigProperty", _IResolvable_da3f097b],
            aggregation_config: typing.Optional[typing.Union["CfnFlow.AggregationConfigProperty", _IResolvable_da3f097b]] = None,
            file_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration that determines how Amazon AppFlow formats the flow output data when Upsolver is used as the destination.

            :param prefix_config: Determines the prefix that Amazon AppFlow applies to the destination folder name. You can name your destination folders according to the flow frequency and date.
            :param aggregation_config: The aggregation settings that you can use to customize the output format of your flow data.
            :param file_type: Indicates the file type that Amazon AppFlow places in the Upsolver Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-upsolvers3outputformatconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                upsolver_s3_output_format_config_property = appflow.CfnFlow.UpsolverS3OutputFormatConfigProperty(
                    prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                        prefix_format="prefixFormat",
                        prefix_type="prefixType"
                    ),
                
                    # the properties below are optional
                    aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                        aggregation_type="aggregationType"
                    ),
                    file_type="fileType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "prefix_config": prefix_config,
            }
            if aggregation_config is not None:
                self._values["aggregation_config"] = aggregation_config
            if file_type is not None:
                self._values["file_type"] = file_type

        @builtins.property
        def prefix_config(
            self,
        ) -> typing.Union["CfnFlow.PrefixConfigProperty", _IResolvable_da3f097b]:
            '''Determines the prefix that Amazon AppFlow applies to the destination folder name.

            You can name your destination folders according to the flow frequency and date.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-upsolvers3outputformatconfig.html#cfn-appflow-flow-upsolvers3outputformatconfig-prefixconfig
            '''
            result = self._values.get("prefix_config")
            assert result is not None, "Required property 'prefix_config' is missing"
            return typing.cast(typing.Union["CfnFlow.PrefixConfigProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def aggregation_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.AggregationConfigProperty", _IResolvable_da3f097b]]:
            '''The aggregation settings that you can use to customize the output format of your flow data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-upsolvers3outputformatconfig.html#cfn-appflow-flow-upsolvers3outputformatconfig-aggregationconfig
            '''
            result = self._values.get("aggregation_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.AggregationConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def file_type(self) -> typing.Optional[builtins.str]:
            '''Indicates the file type that Amazon AppFlow places in the Upsolver Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-upsolvers3outputformatconfig.html#cfn-appflow-flow-upsolvers3outputformatconfig-filetype
            '''
            result = self._values.get("file_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UpsolverS3OutputFormatConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.VeevaSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "object": "object",
            "document_type": "documentType",
            "include_all_versions": "includeAllVersions",
            "include_renditions": "includeRenditions",
            "include_source_files": "includeSourceFiles",
        },
    )
    class VeevaSourcePropertiesProperty:
        def __init__(
            self,
            *,
            object: builtins.str,
            document_type: typing.Optional[builtins.str] = None,
            include_all_versions: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_renditions: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_source_files: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The properties that are applied when using Veeva as a flow source.

            :param object: The object specified in the Veeva flow source.
            :param document_type: ``CfnFlow.VeevaSourcePropertiesProperty.DocumentType``.
            :param include_all_versions: ``CfnFlow.VeevaSourcePropertiesProperty.IncludeAllVersions``.
            :param include_renditions: ``CfnFlow.VeevaSourcePropertiesProperty.IncludeRenditions``.
            :param include_source_files: ``CfnFlow.VeevaSourcePropertiesProperty.IncludeSourceFiles``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-veevasourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                veeva_source_properties_property = appflow.CfnFlow.VeevaSourcePropertiesProperty(
                    object="object",
                
                    # the properties below are optional
                    document_type="documentType",
                    include_all_versions=False,
                    include_renditions=False,
                    include_source_files=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }
            if document_type is not None:
                self._values["document_type"] = document_type
            if include_all_versions is not None:
                self._values["include_all_versions"] = include_all_versions
            if include_renditions is not None:
                self._values["include_renditions"] = include_renditions
            if include_source_files is not None:
                self._values["include_source_files"] = include_source_files

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Veeva flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-veevasourceproperties.html#cfn-appflow-flow-veevasourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def document_type(self) -> typing.Optional[builtins.str]:
            '''``CfnFlow.VeevaSourcePropertiesProperty.DocumentType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-veevasourceproperties.html#cfn-appflow-flow-veevasourceproperties-documenttype
            '''
            result = self._values.get("document_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def include_all_versions(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnFlow.VeevaSourcePropertiesProperty.IncludeAllVersions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-veevasourceproperties.html#cfn-appflow-flow-veevasourceproperties-includeallversions
            '''
            result = self._values.get("include_all_versions")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_renditions(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnFlow.VeevaSourcePropertiesProperty.IncludeRenditions``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-veevasourceproperties.html#cfn-appflow-flow-veevasourceproperties-includerenditions
            '''
            result = self._values.get("include_renditions")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_source_files(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnFlow.VeevaSourcePropertiesProperty.IncludeSourceFiles``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-veevasourceproperties.html#cfn-appflow-flow-veevasourceproperties-includesourcefiles
            '''
            result = self._values.get("include_source_files")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VeevaSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.ZendeskDestinationPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "object": "object",
            "error_handling_config": "errorHandlingConfig",
            "id_field_names": "idFieldNames",
            "write_operation_type": "writeOperationType",
        },
    )
    class ZendeskDestinationPropertiesProperty:
        def __init__(
            self,
            *,
            object: builtins.str,
            error_handling_config: typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]] = None,
            id_field_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            write_operation_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param object: ``CfnFlow.ZendeskDestinationPropertiesProperty.Object``.
            :param error_handling_config: ``CfnFlow.ZendeskDestinationPropertiesProperty.ErrorHandlingConfig``.
            :param id_field_names: ``CfnFlow.ZendeskDestinationPropertiesProperty.IdFieldNames``.
            :param write_operation_type: ``CfnFlow.ZendeskDestinationPropertiesProperty.WriteOperationType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-zendeskdestinationproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                zendesk_destination_properties_property = appflow.CfnFlow.ZendeskDestinationPropertiesProperty(
                    object="object",
                
                    # the properties below are optional
                    error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                        bucket_name="bucketName",
                        bucket_prefix="bucketPrefix",
                        fail_on_first_error=False
                    ),
                    id_field_names=["idFieldNames"],
                    write_operation_type="writeOperationType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }
            if error_handling_config is not None:
                self._values["error_handling_config"] = error_handling_config
            if id_field_names is not None:
                self._values["id_field_names"] = id_field_names
            if write_operation_type is not None:
                self._values["write_operation_type"] = write_operation_type

        @builtins.property
        def object(self) -> builtins.str:
            '''``CfnFlow.ZendeskDestinationPropertiesProperty.Object``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-zendeskdestinationproperties.html#cfn-appflow-flow-zendeskdestinationproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def error_handling_config(
            self,
        ) -> typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]]:
            '''``CfnFlow.ZendeskDestinationPropertiesProperty.ErrorHandlingConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-zendeskdestinationproperties.html#cfn-appflow-flow-zendeskdestinationproperties-errorhandlingconfig
            '''
            result = self._values.get("error_handling_config")
            return typing.cast(typing.Optional[typing.Union["CfnFlow.ErrorHandlingConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def id_field_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''``CfnFlow.ZendeskDestinationPropertiesProperty.IdFieldNames``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-zendeskdestinationproperties.html#cfn-appflow-flow-zendeskdestinationproperties-idfieldnames
            '''
            result = self._values.get("id_field_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def write_operation_type(self) -> typing.Optional[builtins.str]:
            '''``CfnFlow.ZendeskDestinationPropertiesProperty.WriteOperationType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-zendeskdestinationproperties.html#cfn-appflow-flow-zendeskdestinationproperties-writeoperationtype
            '''
            result = self._values.get("write_operation_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ZendeskDestinationPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_appflow.CfnFlow.ZendeskSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class ZendeskSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''The properties that are applied when using Zendesk as a flow source.

            :param object: The object specified in the Zendesk flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-zendesksourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_appflow as appflow
                
                zendesk_source_properties_property = appflow.CfnFlow.ZendeskSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''The object specified in the Zendesk flow source.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appflow-flow-zendesksourceproperties.html#cfn-appflow-flow-zendesksourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ZendeskSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_appflow.CfnFlowProps",
    jsii_struct_bases=[],
    name_mapping={
        "destination_flow_config_list": "destinationFlowConfigList",
        "flow_name": "flowName",
        "source_flow_config": "sourceFlowConfig",
        "tasks": "tasks",
        "trigger_config": "triggerConfig",
        "description": "description",
        "kms_arn": "kmsArn",
        "tags": "tags",
    },
)
class CfnFlowProps:
    def __init__(
        self,
        *,
        destination_flow_config_list: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnFlow.DestinationFlowConfigProperty, _IResolvable_da3f097b]]],
        flow_name: builtins.str,
        source_flow_config: typing.Union[CfnFlow.SourceFlowConfigProperty, _IResolvable_da3f097b],
        tasks: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnFlow.TaskProperty, _IResolvable_da3f097b]]],
        trigger_config: typing.Union[CfnFlow.TriggerConfigProperty, _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        kms_arn: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnFlow``.

        :param destination_flow_config_list: The configuration that controls how Amazon AppFlow places data in the destination connector.
        :param flow_name: The specified name of the flow. Spaces are not allowed. Use underscores (_) or hyphens (-) only.
        :param source_flow_config: Contains information about the configuration of the source connector used in the flow.
        :param tasks: A list of tasks that Amazon AppFlow performs while transferring the data in the flow run.
        :param trigger_config: The trigger settings that determine how and when Amazon AppFlow runs the specified flow.
        :param description: A user-entered description of the flow.
        :param kms_arn: The ARN (Amazon Resource Name) of the Key Management Service (KMS) key you provide for encryption. This is required if you do not want to use the Amazon AppFlow-managed KMS key. If you don't provide anything here, Amazon AppFlow uses the Amazon AppFlow-managed KMS key.
        :param tags: The tags used to organize, track, or control access for your flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_appflow as appflow
            
            cfn_flow_props = appflow.CfnFlowProps(
                destination_flow_config_list=[appflow.CfnFlow.DestinationFlowConfigProperty(
                    connector_type="connectorType",
                    destination_connector_properties=appflow.CfnFlow.DestinationConnectorPropertiesProperty(
                        event_bridge=appflow.CfnFlow.EventBridgeDestinationPropertiesProperty(
                            object="object",
            
                            # the properties below are optional
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            )
                        ),
                        lookout_metrics=appflow.CfnFlow.LookoutMetricsDestinationPropertiesProperty(
                            object="object"
                        ),
                        redshift=appflow.CfnFlow.RedshiftDestinationPropertiesProperty(
                            intermediate_bucket_name="intermediateBucketName",
                            object="object",
            
                            # the properties below are optional
                            bucket_prefix="bucketPrefix",
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            )
                        ),
                        s3=appflow.CfnFlow.S3DestinationPropertiesProperty(
                            bucket_name="bucketName",
            
                            # the properties below are optional
                            bucket_prefix="bucketPrefix",
                            s3_output_format_config=appflow.CfnFlow.S3OutputFormatConfigProperty(
                                aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                                    aggregation_type="aggregationType"
                                ),
                                file_type="fileType",
                                prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                                    prefix_format="prefixFormat",
                                    prefix_type="prefixType"
                                )
                            )
                        ),
                        salesforce=appflow.CfnFlow.SalesforceDestinationPropertiesProperty(
                            object="object",
            
                            # the properties below are optional
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            ),
                            id_field_names=["idFieldNames"],
                            write_operation_type="writeOperationType"
                        ),
                        sapo_data=appflow.CfnFlow.SAPODataDestinationPropertiesProperty(
                            object_path="objectPath",
            
                            # the properties below are optional
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            ),
                            id_field_names=["idFieldNames"],
                            success_response_handling_config=appflow.CfnFlow.SuccessResponseHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix"
                            ),
                            write_operation_type="writeOperationType"
                        ),
                        snowflake=appflow.CfnFlow.SnowflakeDestinationPropertiesProperty(
                            intermediate_bucket_name="intermediateBucketName",
                            object="object",
            
                            # the properties below are optional
                            bucket_prefix="bucketPrefix",
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            )
                        ),
                        upsolver=appflow.CfnFlow.UpsolverDestinationPropertiesProperty(
                            bucket_name="bucketName",
                            s3_output_format_config=appflow.CfnFlow.UpsolverS3OutputFormatConfigProperty(
                                prefix_config=appflow.CfnFlow.PrefixConfigProperty(
                                    prefix_format="prefixFormat",
                                    prefix_type="prefixType"
                                ),
            
                                # the properties below are optional
                                aggregation_config=appflow.CfnFlow.AggregationConfigProperty(
                                    aggregation_type="aggregationType"
                                ),
                                file_type="fileType"
                            ),
            
                            # the properties below are optional
                            bucket_prefix="bucketPrefix"
                        ),
                        zendesk=appflow.CfnFlow.ZendeskDestinationPropertiesProperty(
                            object="object",
            
                            # the properties below are optional
                            error_handling_config=appflow.CfnFlow.ErrorHandlingConfigProperty(
                                bucket_name="bucketName",
                                bucket_prefix="bucketPrefix",
                                fail_on_first_error=False
                            ),
                            id_field_names=["idFieldNames"],
                            write_operation_type="writeOperationType"
                        )
                    ),
            
                    # the properties below are optional
                    connector_profile_name="connectorProfileName"
                )],
                flow_name="flowName",
                source_flow_config=appflow.CfnFlow.SourceFlowConfigProperty(
                    connector_type="connectorType",
                    source_connector_properties=appflow.CfnFlow.SourceConnectorPropertiesProperty(
                        amplitude=appflow.CfnFlow.AmplitudeSourcePropertiesProperty(
                            object="object"
                        ),
                        datadog=appflow.CfnFlow.DatadogSourcePropertiesProperty(
                            object="object"
                        ),
                        dynatrace=appflow.CfnFlow.DynatraceSourcePropertiesProperty(
                            object="object"
                        ),
                        google_analytics=appflow.CfnFlow.GoogleAnalyticsSourcePropertiesProperty(
                            object="object"
                        ),
                        infor_nexus=appflow.CfnFlow.InforNexusSourcePropertiesProperty(
                            object="object"
                        ),
                        marketo=appflow.CfnFlow.MarketoSourcePropertiesProperty(
                            object="object"
                        ),
                        s3=appflow.CfnFlow.S3SourcePropertiesProperty(
                            bucket_name="bucketName",
                            bucket_prefix="bucketPrefix",
            
                            # the properties below are optional
                            s3_input_format_config=appflow.CfnFlow.S3InputFormatConfigProperty(
                                s3_input_file_type="s3InputFileType"
                            )
                        ),
                        salesforce=appflow.CfnFlow.SalesforceSourcePropertiesProperty(
                            object="object",
            
                            # the properties below are optional
                            enable_dynamic_field_update=False,
                            include_deleted_records=False
                        ),
                        sapo_data=appflow.CfnFlow.SAPODataSourcePropertiesProperty(
                            object_path="objectPath"
                        ),
                        service_now=appflow.CfnFlow.ServiceNowSourcePropertiesProperty(
                            object="object"
                        ),
                        singular=appflow.CfnFlow.SingularSourcePropertiesProperty(
                            object="object"
                        ),
                        slack=appflow.CfnFlow.SlackSourcePropertiesProperty(
                            object="object"
                        ),
                        trendmicro=appflow.CfnFlow.TrendmicroSourcePropertiesProperty(
                            object="object"
                        ),
                        veeva=appflow.CfnFlow.VeevaSourcePropertiesProperty(
                            object="object",
            
                            # the properties below are optional
                            document_type="documentType",
                            include_all_versions=False,
                            include_renditions=False,
                            include_source_files=False
                        ),
                        zendesk=appflow.CfnFlow.ZendeskSourcePropertiesProperty(
                            object="object"
                        )
                    ),
            
                    # the properties below are optional
                    connector_profile_name="connectorProfileName",
                    incremental_pull_config=appflow.CfnFlow.IncrementalPullConfigProperty(
                        datetime_type_field_name="datetimeTypeFieldName"
                    )
                ),
                tasks=[appflow.CfnFlow.TaskProperty(
                    source_fields=["sourceFields"],
                    task_type="taskType",
            
                    # the properties below are optional
                    connector_operator=appflow.CfnFlow.ConnectorOperatorProperty(
                        amplitude="amplitude",
                        datadog="datadog",
                        dynatrace="dynatrace",
                        google_analytics="googleAnalytics",
                        infor_nexus="inforNexus",
                        marketo="marketo",
                        s3="s3",
                        salesforce="salesforce",
                        sapo_data="sapoData",
                        service_now="serviceNow",
                        singular="singular",
                        slack="slack",
                        trendmicro="trendmicro",
                        veeva="veeva",
                        zendesk="zendesk"
                    ),
                    destination_field="destinationField",
                    task_properties=[appflow.CfnFlow.TaskPropertiesObjectProperty(
                        key="key",
                        value="value"
                    )]
                )],
                trigger_config=appflow.CfnFlow.TriggerConfigProperty(
                    trigger_type="triggerType",
            
                    # the properties below are optional
                    trigger_properties=appflow.CfnFlow.ScheduledTriggerPropertiesProperty(
                        schedule_expression="scheduleExpression",
            
                        # the properties below are optional
                        data_pull_mode="dataPullMode",
                        schedule_end_time=123,
                        schedule_offset=123,
                        schedule_start_time=123,
                        time_zone="timeZone"
                    )
                ),
            
                # the properties below are optional
                description="description",
                kms_arn="kmsArn",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "destination_flow_config_list": destination_flow_config_list,
            "flow_name": flow_name,
            "source_flow_config": source_flow_config,
            "tasks": tasks,
            "trigger_config": trigger_config,
        }
        if description is not None:
            self._values["description"] = description
        if kms_arn is not None:
            self._values["kms_arn"] = kms_arn
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def destination_flow_config_list(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFlow.DestinationFlowConfigProperty, _IResolvable_da3f097b]]]:
        '''The configuration that controls how Amazon AppFlow places data in the destination connector.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-destinationflowconfiglist
        '''
        result = self._values.get("destination_flow_config_list")
        assert result is not None, "Required property 'destination_flow_config_list' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFlow.DestinationFlowConfigProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def flow_name(self) -> builtins.str:
        '''The specified name of the flow.

        Spaces are not allowed. Use underscores (_) or hyphens (-) only.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-flowname
        '''
        result = self._values.get("flow_name")
        assert result is not None, "Required property 'flow_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def source_flow_config(
        self,
    ) -> typing.Union[CfnFlow.SourceFlowConfigProperty, _IResolvable_da3f097b]:
        '''Contains information about the configuration of the source connector used in the flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-sourceflowconfig
        '''
        result = self._values.get("source_flow_config")
        assert result is not None, "Required property 'source_flow_config' is missing"
        return typing.cast(typing.Union[CfnFlow.SourceFlowConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def tasks(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFlow.TaskProperty, _IResolvable_da3f097b]]]:
        '''A list of tasks that Amazon AppFlow performs while transferring the data in the flow run.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-tasks
        '''
        result = self._values.get("tasks")
        assert result is not None, "Required property 'tasks' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFlow.TaskProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def trigger_config(
        self,
    ) -> typing.Union[CfnFlow.TriggerConfigProperty, _IResolvable_da3f097b]:
        '''The trigger settings that determine how and when Amazon AppFlow runs the specified flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-triggerconfig
        '''
        result = self._values.get("trigger_config")
        assert result is not None, "Required property 'trigger_config' is missing"
        return typing.cast(typing.Union[CfnFlow.TriggerConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A user-entered description of the flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN (Amazon Resource Name) of the Key Management Service (KMS) key you provide for encryption.

        This is required if you do not want to use the Amazon AppFlow-managed KMS key. If you don't provide anything here, Amazon AppFlow uses the Amazon AppFlow-managed KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-kmsarn
        '''
        result = self._values.get("kms_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags used to organize, track, or control access for your flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appflow-flow.html#cfn-appflow-flow-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFlowProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnConnectorProfile",
    "CfnConnectorProfileProps",
    "CfnFlow",
    "CfnFlowProps",
]

publication.publish()
