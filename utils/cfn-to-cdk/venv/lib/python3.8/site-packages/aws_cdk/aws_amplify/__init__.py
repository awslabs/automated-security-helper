'''
# AWS Amplify Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_amplify as amplify
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-amplify-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Amplify](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Amplify.html).

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
class CfnApp(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_amplify.CfnApp",
):
    '''A CloudFormation ``AWS::Amplify::App``.

    The AWS::Amplify::App resource creates Apps in the Amplify Console. An App is a collection of branches.

    :cloudformationResource: AWS::Amplify::App
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_amplify as amplify
        
        cfn_app = amplify.CfnApp(self, "MyCfnApp",
            name="name",
        
            # the properties below are optional
            access_token="accessToken",
            auto_branch_creation_config=amplify.CfnApp.AutoBranchCreationConfigProperty(
                auto_branch_creation_patterns=["autoBranchCreationPatterns"],
                basic_auth_config=amplify.CfnApp.BasicAuthConfigProperty(
                    enable_basic_auth=False,
                    password="password",
                    username="username"
                ),
                build_spec="buildSpec",
                enable_auto_branch_creation=False,
                enable_auto_build=False,
                enable_performance_mode=False,
                enable_pull_request_preview=False,
                environment_variables=[amplify.CfnApp.EnvironmentVariableProperty(
                    name="name",
                    value="value"
                )],
                pull_request_environment_name="pullRequestEnvironmentName",
                stage="stage"
            ),
            basic_auth_config=amplify.CfnApp.BasicAuthConfigProperty(
                enable_basic_auth=False,
                password="password",
                username="username"
            ),
            build_spec="buildSpec",
            custom_headers="customHeaders",
            custom_rules=[amplify.CfnApp.CustomRuleProperty(
                source="source",
                target="target",
        
                # the properties below are optional
                condition="condition",
                status="status"
            )],
            description="description",
            enable_branch_auto_deletion=False,
            environment_variables=[amplify.CfnApp.EnvironmentVariableProperty(
                name="name",
                value="value"
            )],
            iam_service_role="iamServiceRole",
            oauth_token="oauthToken",
            repository="repository",
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
        access_token: typing.Optional[builtins.str] = None,
        auto_branch_creation_config: typing.Optional[typing.Union["CfnApp.AutoBranchCreationConfigProperty", _IResolvable_da3f097b]] = None,
        basic_auth_config: typing.Optional[typing.Union["CfnApp.BasicAuthConfigProperty", _IResolvable_da3f097b]] = None,
        build_spec: typing.Optional[builtins.str] = None,
        custom_headers: typing.Optional[builtins.str] = None,
        custom_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnApp.CustomRuleProperty", _IResolvable_da3f097b]]]] = None,
        description: typing.Optional[builtins.str] = None,
        enable_branch_auto_deletion: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        environment_variables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnApp.EnvironmentVariableProperty", _IResolvable_da3f097b]]]] = None,
        iam_service_role: typing.Optional[builtins.str] = None,
        oauth_token: typing.Optional[builtins.str] = None,
        repository: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Amplify::App``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name for an Amplify app. *Length Constraints:* Minimum length of 1. Maximum length of 255. *Pattern:* (?s).+
        :param access_token: Personal Access token for 3rd party source control system for an Amplify app, used to create webhook and read-only deploy key. Token is not stored. *Length Constraints:* Minimum length of 1. Maximum length of 255.
        :param auto_branch_creation_config: Sets the configuration for your automatic branch creation.
        :param basic_auth_config: The credentials for basic authorization for an Amplify app. You must base64-encode the authorization credentials and provide them in the format ``user:password`` .
        :param build_spec: The build specification (build spec) for an Amplify app. *Length Constraints:* Minimum length of 1. Maximum length of 25000. *Pattern:* (?s).+
        :param custom_headers: The custom HTTP headers for an Amplify app. *Length Constraints:* Minimum length of 0. Maximum length of 25000. *Pattern:* (?s).*
        :param custom_rules: The custom rewrite and redirect rules for an Amplify app.
        :param description: The description for an Amplify app. *Length Constraints:* Maximum length of 1000. *Pattern:* (?s).*
        :param enable_branch_auto_deletion: Automatically disconnect a branch in the Amplify Console when you delete a branch from your Git repository.
        :param environment_variables: The environment variables map for an Amplify app.
        :param iam_service_role: The AWS Identity and Access Management (IAM) service role for the Amazon Resource Name (ARN) of the Amplify app. *Length Constraints:* Minimum length of 0. Maximum length of 1000. *Pattern:* (?s).*
        :param oauth_token: The OAuth token for a third-party source control system for an Amplify app. The OAuth token is used to create a webhook and a read-only deploy key. The OAuth token is not stored. *Length Constraints:* Maximum length of 1000. *Pattern:* (?s).*
        :param repository: The repository for an Amplify app. *Pattern:* (?s).*
        :param tags: The tag for an Amplify app.
        '''
        props = CfnAppProps(
            name=name,
            access_token=access_token,
            auto_branch_creation_config=auto_branch_creation_config,
            basic_auth_config=basic_auth_config,
            build_spec=build_spec,
            custom_headers=custom_headers,
            custom_rules=custom_rules,
            description=description,
            enable_branch_auto_deletion=enable_branch_auto_deletion,
            environment_variables=environment_variables,
            iam_service_role=iam_service_role,
            oauth_token=oauth_token,
            repository=repository,
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
    @jsii.member(jsii_name="attrAppId")
    def attr_app_id(self) -> builtins.str:
        '''Unique Id for the Amplify App.

        :cloudformationAttribute: AppId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAppId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrAppName")
    def attr_app_name(self) -> builtins.str:
        '''Name for the Amplify App.

        :cloudformationAttribute: AppName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAppName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''ARN for the Amplify App.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDefaultDomain")
    def attr_default_domain(self) -> builtins.str:
        '''Default domain for the Amplify App.

        :cloudformationAttribute: DefaultDomain
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDefaultDomain"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tag for an Amplify app.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name for an Amplify app.

        *Length Constraints:* Minimum length of 1. Maximum length of 255.

        *Pattern:* (?s).+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessToken")
    def access_token(self) -> typing.Optional[builtins.str]:
        '''Personal Access token for 3rd party source control system for an Amplify app, used to create webhook and read-only deploy key.

        Token is not stored.

        *Length Constraints:* Minimum length of 1. Maximum length of 255.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-accesstoken
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "accessToken"))

    @access_token.setter
    def access_token(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "accessToken", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoBranchCreationConfig")
    def auto_branch_creation_config(
        self,
    ) -> typing.Optional[typing.Union["CfnApp.AutoBranchCreationConfigProperty", _IResolvable_da3f097b]]:
        '''Sets the configuration for your automatic branch creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-autobranchcreationconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnApp.AutoBranchCreationConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "autoBranchCreationConfig"))

    @auto_branch_creation_config.setter
    def auto_branch_creation_config(
        self,
        value: typing.Optional[typing.Union["CfnApp.AutoBranchCreationConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "autoBranchCreationConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="basicAuthConfig")
    def basic_auth_config(
        self,
    ) -> typing.Optional[typing.Union["CfnApp.BasicAuthConfigProperty", _IResolvable_da3f097b]]:
        '''The credentials for basic authorization for an Amplify app.

        You must base64-encode the authorization credentials and provide them in the format ``user:password`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-basicauthconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnApp.BasicAuthConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "basicAuthConfig"))

    @basic_auth_config.setter
    def basic_auth_config(
        self,
        value: typing.Optional[typing.Union["CfnApp.BasicAuthConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "basicAuthConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="buildSpec")
    def build_spec(self) -> typing.Optional[builtins.str]:
        '''The build specification (build spec) for an Amplify app.

        *Length Constraints:* Minimum length of 1. Maximum length of 25000.

        *Pattern:* (?s).+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-buildspec
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "buildSpec"))

    @build_spec.setter
    def build_spec(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "buildSpec", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="customHeaders")
    def custom_headers(self) -> typing.Optional[builtins.str]:
        '''The custom HTTP headers for an Amplify app.

        *Length Constraints:* Minimum length of 0. Maximum length of 25000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-customheaders
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "customHeaders"))

    @custom_headers.setter
    def custom_headers(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "customHeaders", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="customRules")
    def custom_rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnApp.CustomRuleProperty", _IResolvable_da3f097b]]]]:
        '''The custom rewrite and redirect rules for an Amplify app.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-customrules
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnApp.CustomRuleProperty", _IResolvable_da3f097b]]]], jsii.get(self, "customRules"))

    @custom_rules.setter
    def custom_rules(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnApp.CustomRuleProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "customRules", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description for an Amplify app.

        *Length Constraints:* Maximum length of 1000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableBranchAutoDeletion")
    def enable_branch_auto_deletion(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Automatically disconnect a branch in the Amplify Console when you delete a branch from your Git repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-enablebranchautodeletion
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableBranchAutoDeletion"))

    @enable_branch_auto_deletion.setter
    def enable_branch_auto_deletion(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableBranchAutoDeletion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="environmentVariables")
    def environment_variables(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnApp.EnvironmentVariableProperty", _IResolvable_da3f097b]]]]:
        '''The environment variables map for an Amplify app.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-environmentvariables
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnApp.EnvironmentVariableProperty", _IResolvable_da3f097b]]]], jsii.get(self, "environmentVariables"))

    @environment_variables.setter
    def environment_variables(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnApp.EnvironmentVariableProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "environmentVariables", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="iamServiceRole")
    def iam_service_role(self) -> typing.Optional[builtins.str]:
        '''The AWS Identity and Access Management (IAM) service role for the Amazon Resource Name (ARN) of the Amplify app.

        *Length Constraints:* Minimum length of 0. Maximum length of 1000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-iamservicerole
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "iamServiceRole"))

    @iam_service_role.setter
    def iam_service_role(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "iamServiceRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="oauthToken")
    def oauth_token(self) -> typing.Optional[builtins.str]:
        '''The OAuth token for a third-party source control system for an Amplify app.

        The OAuth token is used to create a webhook and a read-only deploy key. The OAuth token is not stored.

        *Length Constraints:* Maximum length of 1000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-oauthtoken
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "oauthToken"))

    @oauth_token.setter
    def oauth_token(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "oauthToken", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repository")
    def repository(self) -> typing.Optional[builtins.str]:
        '''The repository for an Amplify app.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-repository
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "repository"))

    @repository.setter
    def repository(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "repository", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplify.CfnApp.AutoBranchCreationConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "auto_branch_creation_patterns": "autoBranchCreationPatterns",
            "basic_auth_config": "basicAuthConfig",
            "build_spec": "buildSpec",
            "enable_auto_branch_creation": "enableAutoBranchCreation",
            "enable_auto_build": "enableAutoBuild",
            "enable_performance_mode": "enablePerformanceMode",
            "enable_pull_request_preview": "enablePullRequestPreview",
            "environment_variables": "environmentVariables",
            "pull_request_environment_name": "pullRequestEnvironmentName",
            "stage": "stage",
        },
    )
    class AutoBranchCreationConfigProperty:
        def __init__(
            self,
            *,
            auto_branch_creation_patterns: typing.Optional[typing.Sequence[builtins.str]] = None,
            basic_auth_config: typing.Optional[typing.Union["CfnApp.BasicAuthConfigProperty", _IResolvable_da3f097b]] = None,
            build_spec: typing.Optional[builtins.str] = None,
            enable_auto_branch_creation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            enable_auto_build: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            enable_performance_mode: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            enable_pull_request_preview: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            environment_variables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnApp.EnvironmentVariableProperty", _IResolvable_da3f097b]]]] = None,
            pull_request_environment_name: typing.Optional[builtins.str] = None,
            stage: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Use the AutoBranchCreationConfig property type to automatically create branches that match a certain pattern.

            :param auto_branch_creation_patterns: Automated branch creation glob patterns for the Amplify app.
            :param basic_auth_config: Sets password protection for your auto created branch.
            :param build_spec: The build specification (build spec) for the autocreated branch. *Length Constraints:* Minimum length of 1. Maximum length of 25000.
            :param enable_auto_branch_creation: Enables automated branch creation for the Amplify app.
            :param enable_auto_build: Enables auto building for the auto created branch.
            :param enable_performance_mode: Enables performance mode for the branch. Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.
            :param enable_pull_request_preview: Sets whether pull request previews are enabled for each branch that Amplify Console automatically creates for your app. Amplify Console creates previews by deploying your app to a unique URL whenever a pull request is opened for the branch. Development and QA teams can use this preview to test the pull request before it's merged into a production or integration branch. To provide backend support for your preview, the Amplify Console automatically provisions a temporary backend environment that it deletes when the pull request is closed. If you want to specify a dedicated backend environment for your previews, use the ``PullRequestEnvironmentName`` property. For more information, see `Web Previews <https://docs.aws.amazon.com/amplify/latest/userguide/pr-previews.html>`_ in the *AWS Amplify Console User Guide* .
            :param environment_variables: Environment variables for the auto created branch.
            :param pull_request_environment_name: If pull request previews are enabled, you can use this property to specify a dedicated backend environment for your previews. For example, you could specify an environment named ``prod`` , ``test`` , or ``dev`` that you initialized with the Amplify CLI. To enable pull request previews, set the ``EnablePullRequestPreview`` property to ``true`` . If you don't specify an environment, the Amplify Console provides backend support for each preview by automatically provisioning a temporary backend environment. Amplify Console deletes this environment when the pull request is closed. For more information about creating backend environments, see `Feature Branch Deployments and Team Workflows <https://docs.aws.amazon.com/amplify/latest/userguide/multi-environments.html>`_ in the *AWS Amplify Console User Guide* . *Length Constraints:* Maximum length of 20. *Pattern:* (?s).*
            :param stage: Stage for the auto created branch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplify as amplify
                
                auto_branch_creation_config_property = amplify.CfnApp.AutoBranchCreationConfigProperty(
                    auto_branch_creation_patterns=["autoBranchCreationPatterns"],
                    basic_auth_config=amplify.CfnApp.BasicAuthConfigProperty(
                        enable_basic_auth=False,
                        password="password",
                        username="username"
                    ),
                    build_spec="buildSpec",
                    enable_auto_branch_creation=False,
                    enable_auto_build=False,
                    enable_performance_mode=False,
                    enable_pull_request_preview=False,
                    environment_variables=[amplify.CfnApp.EnvironmentVariableProperty(
                        name="name",
                        value="value"
                    )],
                    pull_request_environment_name="pullRequestEnvironmentName",
                    stage="stage"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if auto_branch_creation_patterns is not None:
                self._values["auto_branch_creation_patterns"] = auto_branch_creation_patterns
            if basic_auth_config is not None:
                self._values["basic_auth_config"] = basic_auth_config
            if build_spec is not None:
                self._values["build_spec"] = build_spec
            if enable_auto_branch_creation is not None:
                self._values["enable_auto_branch_creation"] = enable_auto_branch_creation
            if enable_auto_build is not None:
                self._values["enable_auto_build"] = enable_auto_build
            if enable_performance_mode is not None:
                self._values["enable_performance_mode"] = enable_performance_mode
            if enable_pull_request_preview is not None:
                self._values["enable_pull_request_preview"] = enable_pull_request_preview
            if environment_variables is not None:
                self._values["environment_variables"] = environment_variables
            if pull_request_environment_name is not None:
                self._values["pull_request_environment_name"] = pull_request_environment_name
            if stage is not None:
                self._values["stage"] = stage

        @builtins.property
        def auto_branch_creation_patterns(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''Automated branch creation glob patterns for the Amplify app.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-autobranchcreationpatterns
            '''
            result = self._values.get("auto_branch_creation_patterns")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def basic_auth_config(
            self,
        ) -> typing.Optional[typing.Union["CfnApp.BasicAuthConfigProperty", _IResolvable_da3f097b]]:
            '''Sets password protection for your auto created branch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-basicauthconfig
            '''
            result = self._values.get("basic_auth_config")
            return typing.cast(typing.Optional[typing.Union["CfnApp.BasicAuthConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def build_spec(self) -> typing.Optional[builtins.str]:
            '''The build specification (build spec) for the autocreated branch.

            *Length Constraints:* Minimum length of 1. Maximum length of 25000.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-buildspec
            '''
            result = self._values.get("build_spec")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def enable_auto_branch_creation(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables automated branch creation for the Amplify app.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-enableautobranchcreation
            '''
            result = self._values.get("enable_auto_branch_creation")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def enable_auto_build(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables auto building for the auto created branch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-enableautobuild
            '''
            result = self._values.get("enable_auto_build")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def enable_performance_mode(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables performance mode for the branch.

            Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-enableperformancemode
            '''
            result = self._values.get("enable_performance_mode")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def enable_pull_request_preview(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Sets whether pull request previews are enabled for each branch that Amplify Console automatically creates for your app.

            Amplify Console creates previews by deploying your app to a unique URL whenever a pull request is opened for the branch. Development and QA teams can use this preview to test the pull request before it's merged into a production or integration branch.

            To provide backend support for your preview, the Amplify Console automatically provisions a temporary backend environment that it deletes when the pull request is closed. If you want to specify a dedicated backend environment for your previews, use the ``PullRequestEnvironmentName`` property.

            For more information, see `Web Previews <https://docs.aws.amazon.com/amplify/latest/userguide/pr-previews.html>`_ in the *AWS Amplify Console User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-enablepullrequestpreview
            '''
            result = self._values.get("enable_pull_request_preview")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def environment_variables(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnApp.EnvironmentVariableProperty", _IResolvable_da3f097b]]]]:
            '''Environment variables for the auto created branch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-environmentvariables
            '''
            result = self._values.get("environment_variables")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnApp.EnvironmentVariableProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def pull_request_environment_name(self) -> typing.Optional[builtins.str]:
            '''If pull request previews are enabled, you can use this property to specify a dedicated backend environment for your previews.

            For example, you could specify an environment named ``prod`` , ``test`` , or ``dev`` that you initialized with the Amplify CLI.

            To enable pull request previews, set the ``EnablePullRequestPreview`` property to ``true`` .

            If you don't specify an environment, the Amplify Console provides backend support for each preview by automatically provisioning a temporary backend environment. Amplify Console deletes this environment when the pull request is closed.

            For more information about creating backend environments, see `Feature Branch Deployments and Team Workflows <https://docs.aws.amazon.com/amplify/latest/userguide/multi-environments.html>`_ in the *AWS Amplify Console User Guide* .

            *Length Constraints:* Maximum length of 20.

            *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-pullrequestenvironmentname
            '''
            result = self._values.get("pull_request_environment_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def stage(self) -> typing.Optional[builtins.str]:
            '''Stage for the auto created branch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-autobranchcreationconfig.html#cfn-amplify-app-autobranchcreationconfig-stage
            '''
            result = self._values.get("stage")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AutoBranchCreationConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplify.CfnApp.BasicAuthConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "enable_basic_auth": "enableBasicAuth",
            "password": "password",
            "username": "username",
        },
    )
    class BasicAuthConfigProperty:
        def __init__(
            self,
            *,
            enable_basic_auth: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            password: typing.Optional[builtins.str] = None,
            username: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Use the BasicAuthConfig property type to set password protection at an app level to all your branches.

            :param enable_basic_auth: Enables basic authorization for the Amplify app's branches.
            :param password: The password for basic authorization. *Length Constraints:* Minimum length of 1. Maximum length of 255.
            :param username: The user name for basic authorization. *Length Constraints:* Minimum length of 1. Maximum length of 255.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-basicauthconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplify as amplify
                
                basic_auth_config_property = amplify.CfnApp.BasicAuthConfigProperty(
                    enable_basic_auth=False,
                    password="password",
                    username="username"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if enable_basic_auth is not None:
                self._values["enable_basic_auth"] = enable_basic_auth
            if password is not None:
                self._values["password"] = password
            if username is not None:
                self._values["username"] = username

        @builtins.property
        def enable_basic_auth(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables basic authorization for the Amplify app's branches.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-basicauthconfig.html#cfn-amplify-app-basicauthconfig-enablebasicauth
            '''
            result = self._values.get("enable_basic_auth")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def password(self) -> typing.Optional[builtins.str]:
            '''The password for basic authorization.

            *Length Constraints:* Minimum length of 1. Maximum length of 255.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-basicauthconfig.html#cfn-amplify-app-basicauthconfig-password
            '''
            result = self._values.get("password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def username(self) -> typing.Optional[builtins.str]:
            '''The user name for basic authorization.

            *Length Constraints:* Minimum length of 1. Maximum length of 255.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-basicauthconfig.html#cfn-amplify-app-basicauthconfig-username
            '''
            result = self._values.get("username")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BasicAuthConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplify.CfnApp.CustomRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "source": "source",
            "target": "target",
            "condition": "condition",
            "status": "status",
        },
    )
    class CustomRuleProperty:
        def __init__(
            self,
            *,
            source: builtins.str,
            target: builtins.str,
            condition: typing.Optional[builtins.str] = None,
            status: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The CustomRule property type allows you to specify redirects, rewrites, and reverse proxies.

            Redirects enable a web app to reroute navigation from one URL to another.

            :param source: The source pattern for a URL rewrite or redirect rule. *Length Constraints:* Minimum length of 1. Maximum length of 2048. *Pattern:* (?s).+
            :param target: The target pattern for a URL rewrite or redirect rule. *Length Constraints:* Minimum length of 1. Maximum length of 2048. *Pattern:* (?s).+
            :param condition: The condition for a URL rewrite or redirect rule, such as a country code. *Length Constraints:* Minimum length of 0. Maximum length of 2048. *Pattern:* (?s).*
            :param status: The status code for a URL rewrite or redirect rule. - **200** - Represents a 200 rewrite rule. - **301** - Represents a 301 (moved pemanently) redirect rule. This and all future requests should be directed to the target URL. - **302** - Represents a 302 temporary redirect rule. - **404** - Represents a 404 redirect rule. - **404-200** - Represents a 404 rewrite rule. *Length Constraints:* Minimum length of 3. Maximum length of 7. *Pattern:* .{3,7}

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-customrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplify as amplify
                
                custom_rule_property = amplify.CfnApp.CustomRuleProperty(
                    source="source",
                    target="target",
                
                    # the properties below are optional
                    condition="condition",
                    status="status"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source": source,
                "target": target,
            }
            if condition is not None:
                self._values["condition"] = condition
            if status is not None:
                self._values["status"] = status

        @builtins.property
        def source(self) -> builtins.str:
            '''The source pattern for a URL rewrite or redirect rule.

            *Length Constraints:* Minimum length of 1. Maximum length of 2048.

            *Pattern:* (?s).+

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-customrule.html#cfn-amplify-app-customrule-source
            '''
            result = self._values.get("source")
            assert result is not None, "Required property 'source' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def target(self) -> builtins.str:
            '''The target pattern for a URL rewrite or redirect rule.

            *Length Constraints:* Minimum length of 1. Maximum length of 2048.

            *Pattern:* (?s).+

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-customrule.html#cfn-amplify-app-customrule-target
            '''
            result = self._values.get("target")
            assert result is not None, "Required property 'target' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def condition(self) -> typing.Optional[builtins.str]:
            '''The condition for a URL rewrite or redirect rule, such as a country code.

            *Length Constraints:* Minimum length of 0. Maximum length of 2048.

            *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-customrule.html#cfn-amplify-app-customrule-condition
            '''
            result = self._values.get("condition")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def status(self) -> typing.Optional[builtins.str]:
            '''The status code for a URL rewrite or redirect rule.

            - **200** - Represents a 200 rewrite rule.
            - **301** - Represents a 301 (moved pemanently) redirect rule. This and all future requests should be directed to the target URL.
            - **302** - Represents a 302 temporary redirect rule.
            - **404** - Represents a 404 redirect rule.
            - **404-200** - Represents a 404 rewrite rule.

            *Length Constraints:* Minimum length of 3. Maximum length of 7.

            *Pattern:* .{3,7}

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-customrule.html#cfn-amplify-app-customrule-status
            '''
            result = self._values.get("status")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplify.CfnApp.EnvironmentVariableProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class EnvironmentVariableProperty:
        def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
            '''Environment variables are key-value pairs that are available at build time.

            Set environment variables for all branches in your app.

            :param name: The environment variable name. *Length Constraints:* Maximum length of 255. *Pattern:* (?s).*
            :param value: The environment variable value. *Length Constraints:* Maximum length of 5500. *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-environmentvariable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplify as amplify
                
                environment_variable_property = amplify.CfnApp.EnvironmentVariableProperty(
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
            '''The environment variable name.

            *Length Constraints:* Maximum length of 255.

            *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-environmentvariable.html#cfn-amplify-app-environmentvariable-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The environment variable value.

            *Length Constraints:* Maximum length of 5500.

            *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-environmentvariable.html#cfn-amplify-app-environmentvariable-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EnvironmentVariableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_amplify.CfnAppProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "access_token": "accessToken",
        "auto_branch_creation_config": "autoBranchCreationConfig",
        "basic_auth_config": "basicAuthConfig",
        "build_spec": "buildSpec",
        "custom_headers": "customHeaders",
        "custom_rules": "customRules",
        "description": "description",
        "enable_branch_auto_deletion": "enableBranchAutoDeletion",
        "environment_variables": "environmentVariables",
        "iam_service_role": "iamServiceRole",
        "oauth_token": "oauthToken",
        "repository": "repository",
        "tags": "tags",
    },
)
class CfnAppProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        access_token: typing.Optional[builtins.str] = None,
        auto_branch_creation_config: typing.Optional[typing.Union[CfnApp.AutoBranchCreationConfigProperty, _IResolvable_da3f097b]] = None,
        basic_auth_config: typing.Optional[typing.Union[CfnApp.BasicAuthConfigProperty, _IResolvable_da3f097b]] = None,
        build_spec: typing.Optional[builtins.str] = None,
        custom_headers: typing.Optional[builtins.str] = None,
        custom_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnApp.CustomRuleProperty, _IResolvable_da3f097b]]]] = None,
        description: typing.Optional[builtins.str] = None,
        enable_branch_auto_deletion: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        environment_variables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnApp.EnvironmentVariableProperty, _IResolvable_da3f097b]]]] = None,
        iam_service_role: typing.Optional[builtins.str] = None,
        oauth_token: typing.Optional[builtins.str] = None,
        repository: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnApp``.

        :param name: The name for an Amplify app. *Length Constraints:* Minimum length of 1. Maximum length of 255. *Pattern:* (?s).+
        :param access_token: Personal Access token for 3rd party source control system for an Amplify app, used to create webhook and read-only deploy key. Token is not stored. *Length Constraints:* Minimum length of 1. Maximum length of 255.
        :param auto_branch_creation_config: Sets the configuration for your automatic branch creation.
        :param basic_auth_config: The credentials for basic authorization for an Amplify app. You must base64-encode the authorization credentials and provide them in the format ``user:password`` .
        :param build_spec: The build specification (build spec) for an Amplify app. *Length Constraints:* Minimum length of 1. Maximum length of 25000. *Pattern:* (?s).+
        :param custom_headers: The custom HTTP headers for an Amplify app. *Length Constraints:* Minimum length of 0. Maximum length of 25000. *Pattern:* (?s).*
        :param custom_rules: The custom rewrite and redirect rules for an Amplify app.
        :param description: The description for an Amplify app. *Length Constraints:* Maximum length of 1000. *Pattern:* (?s).*
        :param enable_branch_auto_deletion: Automatically disconnect a branch in the Amplify Console when you delete a branch from your Git repository.
        :param environment_variables: The environment variables map for an Amplify app.
        :param iam_service_role: The AWS Identity and Access Management (IAM) service role for the Amazon Resource Name (ARN) of the Amplify app. *Length Constraints:* Minimum length of 0. Maximum length of 1000. *Pattern:* (?s).*
        :param oauth_token: The OAuth token for a third-party source control system for an Amplify app. The OAuth token is used to create a webhook and a read-only deploy key. The OAuth token is not stored. *Length Constraints:* Maximum length of 1000. *Pattern:* (?s).*
        :param repository: The repository for an Amplify app. *Pattern:* (?s).*
        :param tags: The tag for an Amplify app.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_amplify as amplify
            
            cfn_app_props = amplify.CfnAppProps(
                name="name",
            
                # the properties below are optional
                access_token="accessToken",
                auto_branch_creation_config=amplify.CfnApp.AutoBranchCreationConfigProperty(
                    auto_branch_creation_patterns=["autoBranchCreationPatterns"],
                    basic_auth_config=amplify.CfnApp.BasicAuthConfigProperty(
                        enable_basic_auth=False,
                        password="password",
                        username="username"
                    ),
                    build_spec="buildSpec",
                    enable_auto_branch_creation=False,
                    enable_auto_build=False,
                    enable_performance_mode=False,
                    enable_pull_request_preview=False,
                    environment_variables=[amplify.CfnApp.EnvironmentVariableProperty(
                        name="name",
                        value="value"
                    )],
                    pull_request_environment_name="pullRequestEnvironmentName",
                    stage="stage"
                ),
                basic_auth_config=amplify.CfnApp.BasicAuthConfigProperty(
                    enable_basic_auth=False,
                    password="password",
                    username="username"
                ),
                build_spec="buildSpec",
                custom_headers="customHeaders",
                custom_rules=[amplify.CfnApp.CustomRuleProperty(
                    source="source",
                    target="target",
            
                    # the properties below are optional
                    condition="condition",
                    status="status"
                )],
                description="description",
                enable_branch_auto_deletion=False,
                environment_variables=[amplify.CfnApp.EnvironmentVariableProperty(
                    name="name",
                    value="value"
                )],
                iam_service_role="iamServiceRole",
                oauth_token="oauthToken",
                repository="repository",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if access_token is not None:
            self._values["access_token"] = access_token
        if auto_branch_creation_config is not None:
            self._values["auto_branch_creation_config"] = auto_branch_creation_config
        if basic_auth_config is not None:
            self._values["basic_auth_config"] = basic_auth_config
        if build_spec is not None:
            self._values["build_spec"] = build_spec
        if custom_headers is not None:
            self._values["custom_headers"] = custom_headers
        if custom_rules is not None:
            self._values["custom_rules"] = custom_rules
        if description is not None:
            self._values["description"] = description
        if enable_branch_auto_deletion is not None:
            self._values["enable_branch_auto_deletion"] = enable_branch_auto_deletion
        if environment_variables is not None:
            self._values["environment_variables"] = environment_variables
        if iam_service_role is not None:
            self._values["iam_service_role"] = iam_service_role
        if oauth_token is not None:
            self._values["oauth_token"] = oauth_token
        if repository is not None:
            self._values["repository"] = repository
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name for an Amplify app.

        *Length Constraints:* Minimum length of 1. Maximum length of 255.

        *Pattern:* (?s).+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def access_token(self) -> typing.Optional[builtins.str]:
        '''Personal Access token for 3rd party source control system for an Amplify app, used to create webhook and read-only deploy key.

        Token is not stored.

        *Length Constraints:* Minimum length of 1. Maximum length of 255.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-accesstoken
        '''
        result = self._values.get("access_token")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def auto_branch_creation_config(
        self,
    ) -> typing.Optional[typing.Union[CfnApp.AutoBranchCreationConfigProperty, _IResolvable_da3f097b]]:
        '''Sets the configuration for your automatic branch creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-autobranchcreationconfig
        '''
        result = self._values.get("auto_branch_creation_config")
        return typing.cast(typing.Optional[typing.Union[CfnApp.AutoBranchCreationConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def basic_auth_config(
        self,
    ) -> typing.Optional[typing.Union[CfnApp.BasicAuthConfigProperty, _IResolvable_da3f097b]]:
        '''The credentials for basic authorization for an Amplify app.

        You must base64-encode the authorization credentials and provide them in the format ``user:password`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-basicauthconfig
        '''
        result = self._values.get("basic_auth_config")
        return typing.cast(typing.Optional[typing.Union[CfnApp.BasicAuthConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def build_spec(self) -> typing.Optional[builtins.str]:
        '''The build specification (build spec) for an Amplify app.

        *Length Constraints:* Minimum length of 1. Maximum length of 25000.

        *Pattern:* (?s).+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-buildspec
        '''
        result = self._values.get("build_spec")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def custom_headers(self) -> typing.Optional[builtins.str]:
        '''The custom HTTP headers for an Amplify app.

        *Length Constraints:* Minimum length of 0. Maximum length of 25000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-customheaders
        '''
        result = self._values.get("custom_headers")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def custom_rules(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnApp.CustomRuleProperty, _IResolvable_da3f097b]]]]:
        '''The custom rewrite and redirect rules for an Amplify app.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-customrules
        '''
        result = self._values.get("custom_rules")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnApp.CustomRuleProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description for an Amplify app.

        *Length Constraints:* Maximum length of 1000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_branch_auto_deletion(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Automatically disconnect a branch in the Amplify Console when you delete a branch from your Git repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-enablebranchautodeletion
        '''
        result = self._values.get("enable_branch_auto_deletion")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def environment_variables(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnApp.EnvironmentVariableProperty, _IResolvable_da3f097b]]]]:
        '''The environment variables map for an Amplify app.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-environmentvariables
        '''
        result = self._values.get("environment_variables")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnApp.EnvironmentVariableProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def iam_service_role(self) -> typing.Optional[builtins.str]:
        '''The AWS Identity and Access Management (IAM) service role for the Amazon Resource Name (ARN) of the Amplify app.

        *Length Constraints:* Minimum length of 0. Maximum length of 1000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-iamservicerole
        '''
        result = self._values.get("iam_service_role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def oauth_token(self) -> typing.Optional[builtins.str]:
        '''The OAuth token for a third-party source control system for an Amplify app.

        The OAuth token is used to create a webhook and a read-only deploy key. The OAuth token is not stored.

        *Length Constraints:* Maximum length of 1000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-oauthtoken
        '''
        result = self._values.get("oauth_token")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def repository(self) -> typing.Optional[builtins.str]:
        '''The repository for an Amplify app.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-repository
        '''
        result = self._values.get("repository")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tag for an Amplify app.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html#cfn-amplify-app-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAppProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnBranch(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_amplify.CfnBranch",
):
    '''A CloudFormation ``AWS::Amplify::Branch``.

    The AWS::Amplify::Branch resource creates a new branch within an app.

    :cloudformationResource: AWS::Amplify::Branch
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_amplify as amplify
        
        cfn_branch = amplify.CfnBranch(self, "MyCfnBranch",
            app_id="appId",
            branch_name="branchName",
        
            # the properties below are optional
            basic_auth_config=amplify.CfnBranch.BasicAuthConfigProperty(
                password="password",
                username="username",
        
                # the properties below are optional
                enable_basic_auth=False
            ),
            build_spec="buildSpec",
            description="description",
            enable_auto_build=False,
            enable_performance_mode=False,
            enable_pull_request_preview=False,
            environment_variables=[amplify.CfnBranch.EnvironmentVariableProperty(
                name="name",
                value="value"
            )],
            pull_request_environment_name="pullRequestEnvironmentName",
            stage="stage",
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
        app_id: builtins.str,
        branch_name: builtins.str,
        basic_auth_config: typing.Optional[typing.Union["CfnBranch.BasicAuthConfigProperty", _IResolvable_da3f097b]] = None,
        build_spec: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        enable_auto_build: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        enable_performance_mode: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        enable_pull_request_preview: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        environment_variables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBranch.EnvironmentVariableProperty", _IResolvable_da3f097b]]]] = None,
        pull_request_environment_name: typing.Optional[builtins.str] = None,
        stage: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Amplify::Branch``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param app_id: The unique ID for an Amplify app. *Length Constraints:* Minimum length of 1. Maximum length of 20. *Pattern:* d[a-z0-9]+
        :param branch_name: The name for the branch. *Length Constraints:* Minimum length of 1. Maximum length of 255. *Pattern:* (?s).+
        :param basic_auth_config: The basic authorization credentials for a branch of an Amplify app. You must base64-encode the authorization credentials and provide them in the format ``user:password`` .
        :param build_spec: The build specification (build spec) for the branch. *Length Constraints:* Minimum length of 1. Maximum length of 25000. *Pattern:* (?s).+
        :param description: The description for the branch that is part of an Amplify app. *Length Constraints:* Maximum length of 1000. *Pattern:* (?s).*
        :param enable_auto_build: Enables auto building for the branch.
        :param enable_performance_mode: Enables performance mode for the branch. Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.
        :param enable_pull_request_preview: Sets whether the Amplify Console creates a preview for each pull request that is made for this branch. If this property is enabled, the Amplify Console deploys your app to a unique preview URL after each pull request is opened. Development and QA teams can use this preview to test the pull request before it's merged into a production or integration branch. To provide backend support for your preview, the Amplify Console automatically provisions a temporary backend environment that it deletes when the pull request is closed. If you want to specify a dedicated backend environment for your previews, use the ``PullRequestEnvironmentName`` property. For more information, see `Web Previews <https://docs.aws.amazon.com/amplify/latest/userguide/pr-previews.html>`_ in the *AWS Amplify Console User Guide* .
        :param environment_variables: The environment variables for the branch.
        :param pull_request_environment_name: If pull request previews are enabled for this branch, you can use this property to specify a dedicated backend environment for your previews. For example, you could specify an environment named ``prod`` , ``test`` , or ``dev`` that you initialized with the Amplify CLI and mapped to this branch. To enable pull request previews, set the ``EnablePullRequestPreview`` property to ``true`` . If you don't specify an environment, the Amplify Console provides backend support for each preview by automatically provisioning a temporary backend environment. Amplify Console deletes this environment when the pull request is closed. For more information about creating backend environments, see `Feature Branch Deployments and Team Workflows <https://docs.aws.amazon.com/amplify/latest/userguide/multi-environments.html>`_ in the *AWS Amplify Console User Guide* . *Length Constraints:* Maximum length of 20. *Pattern:* (?s).*
        :param stage: Describes the current stage for the branch. *Valid Values:* PRODUCTION | BETA | DEVELOPMENT | EXPERIMENTAL | PULL_REQUEST
        :param tags: The tag for the branch.
        '''
        props = CfnBranchProps(
            app_id=app_id,
            branch_name=branch_name,
            basic_auth_config=basic_auth_config,
            build_spec=build_spec,
            description=description,
            enable_auto_build=enable_auto_build,
            enable_performance_mode=enable_performance_mode,
            enable_pull_request_preview=enable_pull_request_preview,
            environment_variables=environment_variables,
            pull_request_environment_name=pull_request_environment_name,
            stage=stage,
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
        '''ARN for a branch, part of an Amplify app.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrBranchName")
    def attr_branch_name(self) -> builtins.str:
        '''Name for a branch, part of an Amplify app.

        :cloudformationAttribute: BranchName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBranchName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tag for the branch.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="appId")
    def app_id(self) -> builtins.str:
        '''The unique ID for an Amplify app.

        *Length Constraints:* Minimum length of 1. Maximum length of 20.

        *Pattern:* d[a-z0-9]+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-appid
        '''
        return typing.cast(builtins.str, jsii.get(self, "appId"))

    @app_id.setter
    def app_id(self, value: builtins.str) -> None:
        jsii.set(self, "appId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="branchName")
    def branch_name(self) -> builtins.str:
        '''The name for the branch.

        *Length Constraints:* Minimum length of 1. Maximum length of 255.

        *Pattern:* (?s).+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-branchname
        '''
        return typing.cast(builtins.str, jsii.get(self, "branchName"))

    @branch_name.setter
    def branch_name(self, value: builtins.str) -> None:
        jsii.set(self, "branchName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="basicAuthConfig")
    def basic_auth_config(
        self,
    ) -> typing.Optional[typing.Union["CfnBranch.BasicAuthConfigProperty", _IResolvable_da3f097b]]:
        '''The basic authorization credentials for a branch of an Amplify app.

        You must base64-encode the authorization credentials and provide them in the format ``user:password`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-basicauthconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBranch.BasicAuthConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "basicAuthConfig"))

    @basic_auth_config.setter
    def basic_auth_config(
        self,
        value: typing.Optional[typing.Union["CfnBranch.BasicAuthConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "basicAuthConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="buildSpec")
    def build_spec(self) -> typing.Optional[builtins.str]:
        '''The build specification (build spec) for the branch.

        *Length Constraints:* Minimum length of 1. Maximum length of 25000.

        *Pattern:* (?s).+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-buildspec
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "buildSpec"))

    @build_spec.setter
    def build_spec(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "buildSpec", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description for the branch that is part of an Amplify app.

        *Length Constraints:* Maximum length of 1000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableAutoBuild")
    def enable_auto_build(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables auto building for the branch.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-enableautobuild
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableAutoBuild"))

    @enable_auto_build.setter
    def enable_auto_build(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableAutoBuild", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enablePerformanceMode")
    def enable_performance_mode(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables performance mode for the branch.

        Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-enableperformancemode
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enablePerformanceMode"))

    @enable_performance_mode.setter
    def enable_performance_mode(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enablePerformanceMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enablePullRequestPreview")
    def enable_pull_request_preview(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Sets whether the Amplify Console creates a preview for each pull request that is made for this branch.

        If this property is enabled, the Amplify Console deploys your app to a unique preview URL after each pull request is opened. Development and QA teams can use this preview to test the pull request before it's merged into a production or integration branch.

        To provide backend support for your preview, the Amplify Console automatically provisions a temporary backend environment that it deletes when the pull request is closed. If you want to specify a dedicated backend environment for your previews, use the ``PullRequestEnvironmentName`` property.

        For more information, see `Web Previews <https://docs.aws.amazon.com/amplify/latest/userguide/pr-previews.html>`_ in the *AWS Amplify Console User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-enablepullrequestpreview
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enablePullRequestPreview"))

    @enable_pull_request_preview.setter
    def enable_pull_request_preview(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enablePullRequestPreview", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="environmentVariables")
    def environment_variables(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBranch.EnvironmentVariableProperty", _IResolvable_da3f097b]]]]:
        '''The environment variables for the branch.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-environmentvariables
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBranch.EnvironmentVariableProperty", _IResolvable_da3f097b]]]], jsii.get(self, "environmentVariables"))

    @environment_variables.setter
    def environment_variables(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBranch.EnvironmentVariableProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "environmentVariables", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="pullRequestEnvironmentName")
    def pull_request_environment_name(self) -> typing.Optional[builtins.str]:
        '''If pull request previews are enabled for this branch, you can use this property to specify a dedicated backend environment for your previews.

        For example, you could specify an environment named ``prod`` , ``test`` , or ``dev`` that you initialized with the Amplify CLI and mapped to this branch.

        To enable pull request previews, set the ``EnablePullRequestPreview`` property to ``true`` .

        If you don't specify an environment, the Amplify Console provides backend support for each preview by automatically provisioning a temporary backend environment. Amplify Console deletes this environment when the pull request is closed.

        For more information about creating backend environments, see `Feature Branch Deployments and Team Workflows <https://docs.aws.amazon.com/amplify/latest/userguide/multi-environments.html>`_ in the *AWS Amplify Console User Guide* .

        *Length Constraints:* Maximum length of 20.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-pullrequestenvironmentname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "pullRequestEnvironmentName"))

    @pull_request_environment_name.setter
    def pull_request_environment_name(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "pullRequestEnvironmentName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="stage")
    def stage(self) -> typing.Optional[builtins.str]:
        '''Describes the current stage for the branch.

        *Valid Values:* PRODUCTION | BETA | DEVELOPMENT | EXPERIMENTAL | PULL_REQUEST

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-stage
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "stage"))

    @stage.setter
    def stage(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "stage", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplify.CfnBranch.BasicAuthConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "password": "password",
            "username": "username",
            "enable_basic_auth": "enableBasicAuth",
        },
    )
    class BasicAuthConfigProperty:
        def __init__(
            self,
            *,
            password: builtins.str,
            username: builtins.str,
            enable_basic_auth: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Use the BasicAuthConfig property type to set password protection for a specific branch.

            :param password: The password for basic authorization. *Length Constraints:* Minimum length of 1. Maximum length of 255.
            :param username: The user name for basic authorization. *Length Constraints:* Minimum length of 1. Maximum length of 255.
            :param enable_basic_auth: Enables basic authorization for the branch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-branch-basicauthconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplify as amplify
                
                basic_auth_config_property = amplify.CfnBranch.BasicAuthConfigProperty(
                    password="password",
                    username="username",
                
                    # the properties below are optional
                    enable_basic_auth=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
                "username": username,
            }
            if enable_basic_auth is not None:
                self._values["enable_basic_auth"] = enable_basic_auth

        @builtins.property
        def password(self) -> builtins.str:
            '''The password for basic authorization.

            *Length Constraints:* Minimum length of 1. Maximum length of 255.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-branch-basicauthconfig.html#cfn-amplify-branch-basicauthconfig-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def username(self) -> builtins.str:
            '''The user name for basic authorization.

            *Length Constraints:* Minimum length of 1. Maximum length of 255.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-branch-basicauthconfig.html#cfn-amplify-branch-basicauthconfig-username
            '''
            result = self._values.get("username")
            assert result is not None, "Required property 'username' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def enable_basic_auth(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables basic authorization for the branch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-branch-basicauthconfig.html#cfn-amplify-branch-basicauthconfig-enablebasicauth
            '''
            result = self._values.get("enable_basic_auth")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BasicAuthConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplify.CfnBranch.EnvironmentVariableProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class EnvironmentVariableProperty:
        def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
            '''The EnvironmentVariable property type sets environment variables for a specific branch.

            Environment variables are key-value pairs that are available at build time.

            :param name: The environment variable name. *Length Constraints:* Maximum length of 255. *Pattern:* (?s).*
            :param value: The environment variable value. *Length Constraints:* Maximum length of 5500. *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-branch-environmentvariable.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplify as amplify
                
                environment_variable_property = amplify.CfnBranch.EnvironmentVariableProperty(
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
            '''The environment variable name.

            *Length Constraints:* Maximum length of 255.

            *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-branch-environmentvariable.html#cfn-amplify-branch-environmentvariable-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The environment variable value.

            *Length Constraints:* Maximum length of 5500.

            *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-branch-environmentvariable.html#cfn-amplify-branch-environmentvariable-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EnvironmentVariableProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_amplify.CfnBranchProps",
    jsii_struct_bases=[],
    name_mapping={
        "app_id": "appId",
        "branch_name": "branchName",
        "basic_auth_config": "basicAuthConfig",
        "build_spec": "buildSpec",
        "description": "description",
        "enable_auto_build": "enableAutoBuild",
        "enable_performance_mode": "enablePerformanceMode",
        "enable_pull_request_preview": "enablePullRequestPreview",
        "environment_variables": "environmentVariables",
        "pull_request_environment_name": "pullRequestEnvironmentName",
        "stage": "stage",
        "tags": "tags",
    },
)
class CfnBranchProps:
    def __init__(
        self,
        *,
        app_id: builtins.str,
        branch_name: builtins.str,
        basic_auth_config: typing.Optional[typing.Union[CfnBranch.BasicAuthConfigProperty, _IResolvable_da3f097b]] = None,
        build_spec: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        enable_auto_build: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        enable_performance_mode: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        enable_pull_request_preview: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        environment_variables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBranch.EnvironmentVariableProperty, _IResolvable_da3f097b]]]] = None,
        pull_request_environment_name: typing.Optional[builtins.str] = None,
        stage: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnBranch``.

        :param app_id: The unique ID for an Amplify app. *Length Constraints:* Minimum length of 1. Maximum length of 20. *Pattern:* d[a-z0-9]+
        :param branch_name: The name for the branch. *Length Constraints:* Minimum length of 1. Maximum length of 255. *Pattern:* (?s).+
        :param basic_auth_config: The basic authorization credentials for a branch of an Amplify app. You must base64-encode the authorization credentials and provide them in the format ``user:password`` .
        :param build_spec: The build specification (build spec) for the branch. *Length Constraints:* Minimum length of 1. Maximum length of 25000. *Pattern:* (?s).+
        :param description: The description for the branch that is part of an Amplify app. *Length Constraints:* Maximum length of 1000. *Pattern:* (?s).*
        :param enable_auto_build: Enables auto building for the branch.
        :param enable_performance_mode: Enables performance mode for the branch. Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.
        :param enable_pull_request_preview: Sets whether the Amplify Console creates a preview for each pull request that is made for this branch. If this property is enabled, the Amplify Console deploys your app to a unique preview URL after each pull request is opened. Development and QA teams can use this preview to test the pull request before it's merged into a production or integration branch. To provide backend support for your preview, the Amplify Console automatically provisions a temporary backend environment that it deletes when the pull request is closed. If you want to specify a dedicated backend environment for your previews, use the ``PullRequestEnvironmentName`` property. For more information, see `Web Previews <https://docs.aws.amazon.com/amplify/latest/userguide/pr-previews.html>`_ in the *AWS Amplify Console User Guide* .
        :param environment_variables: The environment variables for the branch.
        :param pull_request_environment_name: If pull request previews are enabled for this branch, you can use this property to specify a dedicated backend environment for your previews. For example, you could specify an environment named ``prod`` , ``test`` , or ``dev`` that you initialized with the Amplify CLI and mapped to this branch. To enable pull request previews, set the ``EnablePullRequestPreview`` property to ``true`` . If you don't specify an environment, the Amplify Console provides backend support for each preview by automatically provisioning a temporary backend environment. Amplify Console deletes this environment when the pull request is closed. For more information about creating backend environments, see `Feature Branch Deployments and Team Workflows <https://docs.aws.amazon.com/amplify/latest/userguide/multi-environments.html>`_ in the *AWS Amplify Console User Guide* . *Length Constraints:* Maximum length of 20. *Pattern:* (?s).*
        :param stage: Describes the current stage for the branch. *Valid Values:* PRODUCTION | BETA | DEVELOPMENT | EXPERIMENTAL | PULL_REQUEST
        :param tags: The tag for the branch.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_amplify as amplify
            
            cfn_branch_props = amplify.CfnBranchProps(
                app_id="appId",
                branch_name="branchName",
            
                # the properties below are optional
                basic_auth_config=amplify.CfnBranch.BasicAuthConfigProperty(
                    password="password",
                    username="username",
            
                    # the properties below are optional
                    enable_basic_auth=False
                ),
                build_spec="buildSpec",
                description="description",
                enable_auto_build=False,
                enable_performance_mode=False,
                enable_pull_request_preview=False,
                environment_variables=[amplify.CfnBranch.EnvironmentVariableProperty(
                    name="name",
                    value="value"
                )],
                pull_request_environment_name="pullRequestEnvironmentName",
                stage="stage",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "app_id": app_id,
            "branch_name": branch_name,
        }
        if basic_auth_config is not None:
            self._values["basic_auth_config"] = basic_auth_config
        if build_spec is not None:
            self._values["build_spec"] = build_spec
        if description is not None:
            self._values["description"] = description
        if enable_auto_build is not None:
            self._values["enable_auto_build"] = enable_auto_build
        if enable_performance_mode is not None:
            self._values["enable_performance_mode"] = enable_performance_mode
        if enable_pull_request_preview is not None:
            self._values["enable_pull_request_preview"] = enable_pull_request_preview
        if environment_variables is not None:
            self._values["environment_variables"] = environment_variables
        if pull_request_environment_name is not None:
            self._values["pull_request_environment_name"] = pull_request_environment_name
        if stage is not None:
            self._values["stage"] = stage
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def app_id(self) -> builtins.str:
        '''The unique ID for an Amplify app.

        *Length Constraints:* Minimum length of 1. Maximum length of 20.

        *Pattern:* d[a-z0-9]+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-appid
        '''
        result = self._values.get("app_id")
        assert result is not None, "Required property 'app_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def branch_name(self) -> builtins.str:
        '''The name for the branch.

        *Length Constraints:* Minimum length of 1. Maximum length of 255.

        *Pattern:* (?s).+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-branchname
        '''
        result = self._values.get("branch_name")
        assert result is not None, "Required property 'branch_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def basic_auth_config(
        self,
    ) -> typing.Optional[typing.Union[CfnBranch.BasicAuthConfigProperty, _IResolvable_da3f097b]]:
        '''The basic authorization credentials for a branch of an Amplify app.

        You must base64-encode the authorization credentials and provide them in the format ``user:password`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-basicauthconfig
        '''
        result = self._values.get("basic_auth_config")
        return typing.cast(typing.Optional[typing.Union[CfnBranch.BasicAuthConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def build_spec(self) -> typing.Optional[builtins.str]:
        '''The build specification (build spec) for the branch.

        *Length Constraints:* Minimum length of 1. Maximum length of 25000.

        *Pattern:* (?s).+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-buildspec
        '''
        result = self._values.get("build_spec")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description for the branch that is part of an Amplify app.

        *Length Constraints:* Maximum length of 1000.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_auto_build(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables auto building for the branch.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-enableautobuild
        '''
        result = self._values.get("enable_auto_build")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def enable_performance_mode(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables performance mode for the branch.

        Performance mode optimizes for faster hosting performance by keeping content cached at the edge for a longer interval. When performance mode is enabled, hosting configuration or code changes can take up to 10 minutes to roll out.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-enableperformancemode
        '''
        result = self._values.get("enable_performance_mode")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def enable_pull_request_preview(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Sets whether the Amplify Console creates a preview for each pull request that is made for this branch.

        If this property is enabled, the Amplify Console deploys your app to a unique preview URL after each pull request is opened. Development and QA teams can use this preview to test the pull request before it's merged into a production or integration branch.

        To provide backend support for your preview, the Amplify Console automatically provisions a temporary backend environment that it deletes when the pull request is closed. If you want to specify a dedicated backend environment for your previews, use the ``PullRequestEnvironmentName`` property.

        For more information, see `Web Previews <https://docs.aws.amazon.com/amplify/latest/userguide/pr-previews.html>`_ in the *AWS Amplify Console User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-enablepullrequestpreview
        '''
        result = self._values.get("enable_pull_request_preview")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def environment_variables(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBranch.EnvironmentVariableProperty, _IResolvable_da3f097b]]]]:
        '''The environment variables for the branch.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-environmentvariables
        '''
        result = self._values.get("environment_variables")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBranch.EnvironmentVariableProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def pull_request_environment_name(self) -> typing.Optional[builtins.str]:
        '''If pull request previews are enabled for this branch, you can use this property to specify a dedicated backend environment for your previews.

        For example, you could specify an environment named ``prod`` , ``test`` , or ``dev`` that you initialized with the Amplify CLI and mapped to this branch.

        To enable pull request previews, set the ``EnablePullRequestPreview`` property to ``true`` .

        If you don't specify an environment, the Amplify Console provides backend support for each preview by automatically provisioning a temporary backend environment. Amplify Console deletes this environment when the pull request is closed.

        For more information about creating backend environments, see `Feature Branch Deployments and Team Workflows <https://docs.aws.amazon.com/amplify/latest/userguide/multi-environments.html>`_ in the *AWS Amplify Console User Guide* .

        *Length Constraints:* Maximum length of 20.

        *Pattern:* (?s).*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-pullrequestenvironmentname
        '''
        result = self._values.get("pull_request_environment_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def stage(self) -> typing.Optional[builtins.str]:
        '''Describes the current stage for the branch.

        *Valid Values:* PRODUCTION | BETA | DEVELOPMENT | EXPERIMENTAL | PULL_REQUEST

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-stage
        '''
        result = self._values.get("stage")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tag for the branch.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBranchProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDomain(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_amplify.CfnDomain",
):
    '''A CloudFormation ``AWS::Amplify::Domain``.

    The AWS::Amplify::Domain resource allows you to connect a custom domain to your app.

    :cloudformationResource: AWS::Amplify::Domain
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_amplify as amplify
        
        cfn_domain = amplify.CfnDomain(self, "MyCfnDomain",
            app_id="appId",
            domain_name="domainName",
            sub_domain_settings=[amplify.CfnDomain.SubDomainSettingProperty(
                branch_name="branchName",
                prefix="prefix"
            )],
        
            # the properties below are optional
            auto_sub_domain_creation_patterns=["autoSubDomainCreationPatterns"],
            auto_sub_domain_iam_role="autoSubDomainIamRole",
            enable_auto_sub_domain=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        app_id: builtins.str,
        domain_name: builtins.str,
        sub_domain_settings: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDomain.SubDomainSettingProperty", _IResolvable_da3f097b]]],
        auto_sub_domain_creation_patterns: typing.Optional[typing.Sequence[builtins.str]] = None,
        auto_sub_domain_iam_role: typing.Optional[builtins.str] = None,
        enable_auto_sub_domain: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Amplify::Domain``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param app_id: The unique ID for an Amplify app. *Length Constraints:* Minimum length of 1. Maximum length of 20. *Pattern:* d[a-z0-9]+
        :param domain_name: The domain name for the domain association. *Length Constraints:* Maximum length of 255. *Pattern:* ^(((?!-)[A-Za-z0-9-]{0,62}[A-Za-z0-9]).)+((?!-)[A-Za-z0-9-]{1,62}[A-Za-z0-9])(.)?$
        :param sub_domain_settings: The setting for the subdomain.
        :param auto_sub_domain_creation_patterns: Sets the branch patterns for automatic subdomain creation.
        :param auto_sub_domain_iam_role: The required AWS Identity and Access Management (IAM) service role for the Amazon Resource Name (ARN) for automatically creating subdomains. *Length Constraints:* Maximum length of 1000. *Pattern:* ^$|^arn:aws:iam::\\d{12}:role.+
        :param enable_auto_sub_domain: Enables the automated creation of subdomains for branches.
        '''
        props = CfnDomainProps(
            app_id=app_id,
            domain_name=domain_name,
            sub_domain_settings=sub_domain_settings,
            auto_sub_domain_creation_patterns=auto_sub_domain_creation_patterns,
            auto_sub_domain_iam_role=auto_sub_domain_iam_role,
            enable_auto_sub_domain=enable_auto_sub_domain,
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
        '''ARN for the Domain Association.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrAutoSubDomainCreationPatterns")
    def attr_auto_sub_domain_creation_patterns(self) -> typing.List[builtins.str]:
        '''Branch patterns for the automatically created subdomain.

        :cloudformationAttribute: AutoSubDomainCreationPatterns
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrAutoSubDomainCreationPatterns"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrAutoSubDomainIamRole")
    def attr_auto_sub_domain_iam_role(self) -> builtins.str:
        '''The IAM service role for the subdomain.

        :cloudformationAttribute: AutoSubDomainIAMRole
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAutoSubDomainIamRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCertificateRecord")
    def attr_certificate_record(self) -> builtins.str:
        '''DNS Record for certificate verification.

        :cloudformationAttribute: CertificateRecord
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCertificateRecord"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDomainName")
    def attr_domain_name(self) -> builtins.str:
        '''Name of the domain.

        :cloudformationAttribute: DomainName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDomainStatus")
    def attr_domain_status(self) -> builtins.str:
        '''Status for the Domain Association.

        :cloudformationAttribute: DomainStatus
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDomainStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEnableAutoSubDomain")
    def attr_enable_auto_sub_domain(self) -> _IResolvable_da3f097b:
        '''Specifies whether the automated creation of subdomains for branches is enabled.

        :cloudformationAttribute: EnableAutoSubDomain
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrEnableAutoSubDomain"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrStatusReason")
    def attr_status_reason(self) -> builtins.str:
        '''Reason for the current status of the domain.

        :cloudformationAttribute: StatusReason
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStatusReason"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="appId")
    def app_id(self) -> builtins.str:
        '''The unique ID for an Amplify app.

        *Length Constraints:* Minimum length of 1. Maximum length of 20.

        *Pattern:* d[a-z0-9]+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-appid
        '''
        return typing.cast(builtins.str, jsii.get(self, "appId"))

    @app_id.setter
    def app_id(self, value: builtins.str) -> None:
        jsii.set(self, "appId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The domain name for the domain association.

        *Length Constraints:* Maximum length of 255.

        *Pattern:* ^(((?!-)[A-Za-z0-9-]{0,62}[A-Za-z0-9]).)+((?!-)[A-Za-z0-9-]{1,62}[A-Za-z0-9])(.)?$

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-domainname
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

    @domain_name.setter
    def domain_name(self, value: builtins.str) -> None:
        jsii.set(self, "domainName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subDomainSettings")
    def sub_domain_settings(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDomain.SubDomainSettingProperty", _IResolvable_da3f097b]]]:
        '''The setting for the subdomain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-subdomainsettings
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDomain.SubDomainSettingProperty", _IResolvable_da3f097b]]], jsii.get(self, "subDomainSettings"))

    @sub_domain_settings.setter
    def sub_domain_settings(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDomain.SubDomainSettingProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "subDomainSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoSubDomainCreationPatterns")
    def auto_sub_domain_creation_patterns(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''Sets the branch patterns for automatic subdomain creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-autosubdomaincreationpatterns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "autoSubDomainCreationPatterns"))

    @auto_sub_domain_creation_patterns.setter
    def auto_sub_domain_creation_patterns(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "autoSubDomainCreationPatterns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoSubDomainIamRole")
    def auto_sub_domain_iam_role(self) -> typing.Optional[builtins.str]:
        '''The required AWS Identity and Access Management (IAM) service role for the Amazon Resource Name (ARN) for automatically creating subdomains.

        *Length Constraints:* Maximum length of 1000.

        *Pattern:* ^$|^arn:aws:iam::\\d{12}:role.+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-autosubdomainiamrole
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "autoSubDomainIamRole"))

    @auto_sub_domain_iam_role.setter
    def auto_sub_domain_iam_role(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "autoSubDomainIamRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableAutoSubDomain")
    def enable_auto_sub_domain(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables the automated creation of subdomains for branches.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-enableautosubdomain
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableAutoSubDomain"))

    @enable_auto_sub_domain.setter
    def enable_auto_sub_domain(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableAutoSubDomain", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_amplify.CfnDomain.SubDomainSettingProperty",
        jsii_struct_bases=[],
        name_mapping={"branch_name": "branchName", "prefix": "prefix"},
    )
    class SubDomainSettingProperty:
        def __init__(self, *, branch_name: builtins.str, prefix: builtins.str) -> None:
            '''The SubDomainSetting property type enables you to connect a subdomain (for example, example.exampledomain.com) to a specific branch.

            :param branch_name: The branch name setting for the subdomain. *Length Constraints:* Minimum length of 1. Maximum length of 255. *Pattern:* (?s).+
            :param prefix: The prefix setting for the subdomain. *Length Constraints:* Maximum length of 255. *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-domain-subdomainsetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_amplify as amplify
                
                sub_domain_setting_property = amplify.CfnDomain.SubDomainSettingProperty(
                    branch_name="branchName",
                    prefix="prefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "branch_name": branch_name,
                "prefix": prefix,
            }

        @builtins.property
        def branch_name(self) -> builtins.str:
            '''The branch name setting for the subdomain.

            *Length Constraints:* Minimum length of 1. Maximum length of 255.

            *Pattern:* (?s).+

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-domain-subdomainsetting.html#cfn-amplify-domain-subdomainsetting-branchname
            '''
            result = self._values.get("branch_name")
            assert result is not None, "Required property 'branch_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def prefix(self) -> builtins.str:
            '''The prefix setting for the subdomain.

            *Length Constraints:* Maximum length of 255.

            *Pattern:* (?s).*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-domain-subdomainsetting.html#cfn-amplify-domain-subdomainsetting-prefix
            '''
            result = self._values.get("prefix")
            assert result is not None, "Required property 'prefix' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SubDomainSettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_amplify.CfnDomainProps",
    jsii_struct_bases=[],
    name_mapping={
        "app_id": "appId",
        "domain_name": "domainName",
        "sub_domain_settings": "subDomainSettings",
        "auto_sub_domain_creation_patterns": "autoSubDomainCreationPatterns",
        "auto_sub_domain_iam_role": "autoSubDomainIamRole",
        "enable_auto_sub_domain": "enableAutoSubDomain",
    },
)
class CfnDomainProps:
    def __init__(
        self,
        *,
        app_id: builtins.str,
        domain_name: builtins.str,
        sub_domain_settings: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDomain.SubDomainSettingProperty, _IResolvable_da3f097b]]],
        auto_sub_domain_creation_patterns: typing.Optional[typing.Sequence[builtins.str]] = None,
        auto_sub_domain_iam_role: typing.Optional[builtins.str] = None,
        enable_auto_sub_domain: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDomain``.

        :param app_id: The unique ID for an Amplify app. *Length Constraints:* Minimum length of 1. Maximum length of 20. *Pattern:* d[a-z0-9]+
        :param domain_name: The domain name for the domain association. *Length Constraints:* Maximum length of 255. *Pattern:* ^(((?!-)[A-Za-z0-9-]{0,62}[A-Za-z0-9]).)+((?!-)[A-Za-z0-9-]{1,62}[A-Za-z0-9])(.)?$
        :param sub_domain_settings: The setting for the subdomain.
        :param auto_sub_domain_creation_patterns: Sets the branch patterns for automatic subdomain creation.
        :param auto_sub_domain_iam_role: The required AWS Identity and Access Management (IAM) service role for the Amazon Resource Name (ARN) for automatically creating subdomains. *Length Constraints:* Maximum length of 1000. *Pattern:* ^$|^arn:aws:iam::\\d{12}:role.+
        :param enable_auto_sub_domain: Enables the automated creation of subdomains for branches.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_amplify as amplify
            
            cfn_domain_props = amplify.CfnDomainProps(
                app_id="appId",
                domain_name="domainName",
                sub_domain_settings=[amplify.CfnDomain.SubDomainSettingProperty(
                    branch_name="branchName",
                    prefix="prefix"
                )],
            
                # the properties below are optional
                auto_sub_domain_creation_patterns=["autoSubDomainCreationPatterns"],
                auto_sub_domain_iam_role="autoSubDomainIamRole",
                enable_auto_sub_domain=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "app_id": app_id,
            "domain_name": domain_name,
            "sub_domain_settings": sub_domain_settings,
        }
        if auto_sub_domain_creation_patterns is not None:
            self._values["auto_sub_domain_creation_patterns"] = auto_sub_domain_creation_patterns
        if auto_sub_domain_iam_role is not None:
            self._values["auto_sub_domain_iam_role"] = auto_sub_domain_iam_role
        if enable_auto_sub_domain is not None:
            self._values["enable_auto_sub_domain"] = enable_auto_sub_domain

    @builtins.property
    def app_id(self) -> builtins.str:
        '''The unique ID for an Amplify app.

        *Length Constraints:* Minimum length of 1. Maximum length of 20.

        *Pattern:* d[a-z0-9]+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-appid
        '''
        result = self._values.get("app_id")
        assert result is not None, "Required property 'app_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The domain name for the domain association.

        *Length Constraints:* Maximum length of 255.

        *Pattern:* ^(((?!-)[A-Za-z0-9-]{0,62}[A-Za-z0-9]).)+((?!-)[A-Za-z0-9-]{1,62}[A-Za-z0-9])(.)?$

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-domainname
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def sub_domain_settings(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDomain.SubDomainSettingProperty, _IResolvable_da3f097b]]]:
        '''The setting for the subdomain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-subdomainsettings
        '''
        result = self._values.get("sub_domain_settings")
        assert result is not None, "Required property 'sub_domain_settings' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDomain.SubDomainSettingProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def auto_sub_domain_creation_patterns(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''Sets the branch patterns for automatic subdomain creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-autosubdomaincreationpatterns
        '''
        result = self._values.get("auto_sub_domain_creation_patterns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def auto_sub_domain_iam_role(self) -> typing.Optional[builtins.str]:
        '''The required AWS Identity and Access Management (IAM) service role for the Amazon Resource Name (ARN) for automatically creating subdomains.

        *Length Constraints:* Maximum length of 1000.

        *Pattern:* ^$|^arn:aws:iam::\\d{12}:role.+

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-autosubdomainiamrole
        '''
        result = self._values.get("auto_sub_domain_iam_role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_auto_sub_domain(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables the automated creation of subdomains for branches.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-domain.html#cfn-amplify-domain-enableautosubdomain
        '''
        result = self._values.get("enable_auto_sub_domain")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDomainProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnApp",
    "CfnAppProps",
    "CfnBranch",
    "CfnBranchProps",
    "CfnDomain",
    "CfnDomainProps",
]

publication.publish()
