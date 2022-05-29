'''
# AWS::CodeStar Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_codestar as codestar
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-codestar-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::CodeStar](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_CodeStar.html).

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
class CfnGitHubRepository(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_codestar.CfnGitHubRepository",
):
    '''A CloudFormation ``AWS::CodeStar::GitHubRepository``.

    The ``AWS::CodeStar::GitHubRepository`` resource creates a GitHub repository where users can store source code for use with AWS workflows. You must provide a location for the source code ZIP file in the AWS CloudFormation template, so the code can be uploaded to the created repository. You must have created a personal access token in GitHub to provide in the AWS CloudFormation template. AWS uses this token to connect to GitHub on your behalf. For more information about using a GitHub source repository with AWS CodeStar projects, see `AWS CodeStar Project Files and Resources <https://docs.aws.amazon.com/codestar/latest/userguide/templates.html#templates-whatis>`_ .

    :cloudformationResource: AWS::CodeStar::GitHubRepository
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_codestar as codestar
        
        cfn_git_hub_repository = codestar.CfnGitHubRepository(self, "MyCfnGitHubRepository",
            repository_name="repositoryName",
            repository_owner="repositoryOwner",
        
            # the properties below are optional
            code=codestar.CfnGitHubRepository.CodeProperty(
                s3=codestar.CfnGitHubRepository.S3Property(
                    bucket="bucket",
                    key="key",
        
                    # the properties below are optional
                    object_version="objectVersion"
                )
            ),
            connection_arn="connectionArn",
            enable_issues=False,
            is_private=False,
            repository_access_token="repositoryAccessToken",
            repository_description="repositoryDescription"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        repository_name: builtins.str,
        repository_owner: builtins.str,
        code: typing.Optional[typing.Union["CfnGitHubRepository.CodeProperty", _IResolvable_da3f097b]] = None,
        connection_arn: typing.Optional[builtins.str] = None,
        enable_issues: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        is_private: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        repository_access_token: typing.Optional[builtins.str] = None,
        repository_description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CodeStar::GitHubRepository``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param repository_name: The name of the repository you want to create in GitHub with AWS CloudFormation stack creation.
        :param repository_owner: The GitHub user name for the owner of the GitHub repository to be created. If this repository should be owned by a GitHub organization, provide its name.
        :param code: Information about code to be committed to a repository after it is created in an AWS CloudFormation stack.
        :param connection_arn: ``AWS::CodeStar::GitHubRepository.ConnectionArn``.
        :param enable_issues: Indicates whether to enable issues for the GitHub repository. You can use GitHub issues to track information and bugs for your repository.
        :param is_private: Indicates whether the GitHub repository is a private repository. If so, you choose who can see and commit to this repository.
        :param repository_access_token: The GitHub user's personal access token for the GitHub repository.
        :param repository_description: A comment or description about the new repository. This description is displayed in GitHub after the repository is created.
        '''
        props = CfnGitHubRepositoryProps(
            repository_name=repository_name,
            repository_owner=repository_owner,
            code=code,
            connection_arn=connection_arn,
            enable_issues=enable_issues,
            is_private=is_private,
            repository_access_token=repository_access_token,
            repository_description=repository_description,
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
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The name of the repository you want to create in GitHub with AWS CloudFormation stack creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-repositoryname
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryName"))

    @repository_name.setter
    def repository_name(self, value: builtins.str) -> None:
        jsii.set(self, "repositoryName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryOwner")
    def repository_owner(self) -> builtins.str:
        '''The GitHub user name for the owner of the GitHub repository to be created.

        If this repository should be owned by a GitHub organization, provide its name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-repositoryowner
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryOwner"))

    @repository_owner.setter
    def repository_owner(self, value: builtins.str) -> None:
        jsii.set(self, "repositoryOwner", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="code")
    def code(
        self,
    ) -> typing.Optional[typing.Union["CfnGitHubRepository.CodeProperty", _IResolvable_da3f097b]]:
        '''Information about code to be committed to a repository after it is created in an AWS CloudFormation stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-code
        '''
        return typing.cast(typing.Optional[typing.Union["CfnGitHubRepository.CodeProperty", _IResolvable_da3f097b]], jsii.get(self, "code"))

    @code.setter
    def code(
        self,
        value: typing.Optional[typing.Union["CfnGitHubRepository.CodeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "code", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionArn")
    def connection_arn(self) -> typing.Optional[builtins.str]:
        '''``AWS::CodeStar::GitHubRepository.ConnectionArn``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-connectionarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "connectionArn"))

    @connection_arn.setter
    def connection_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "connectionArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableIssues")
    def enable_issues(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether to enable issues for the GitHub repository.

        You can use GitHub issues to track information and bugs for your repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-enableissues
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableIssues"))

    @enable_issues.setter
    def enable_issues(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableIssues", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isPrivate")
    def is_private(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether the GitHub repository is a private repository.

        If so, you choose who can see and commit to this repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-isprivate
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "isPrivate"))

    @is_private.setter
    def is_private(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "isPrivate", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryAccessToken")
    def repository_access_token(self) -> typing.Optional[builtins.str]:
        '''The GitHub user's personal access token for the GitHub repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-repositoryaccesstoken
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "repositoryAccessToken"))

    @repository_access_token.setter
    def repository_access_token(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "repositoryAccessToken", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryDescription")
    def repository_description(self) -> typing.Optional[builtins.str]:
        '''A comment or description about the new repository.

        This description is displayed in GitHub after the repository is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-repositorydescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "repositoryDescription"))

    @repository_description.setter
    def repository_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "repositoryDescription", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_codestar.CfnGitHubRepository.CodeProperty",
        jsii_struct_bases=[],
        name_mapping={"s3": "s3"},
    )
    class CodeProperty:
        def __init__(
            self,
            *,
            s3: typing.Union["CfnGitHubRepository.S3Property", _IResolvable_da3f097b],
        ) -> None:
            '''The ``Code`` property type specifies information about code to be committed.

            ``Code`` is a property of the ``AWS::CodeStar::GitHubRepository`` resource.

            :param s3: Information about the Amazon S3 bucket that contains a ZIP file of code to be committed to the repository.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestar-githubrepository-code.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_codestar as codestar
                
                code_property = codestar.CfnGitHubRepository.CodeProperty(
                    s3=codestar.CfnGitHubRepository.S3Property(
                        bucket="bucket",
                        key="key",
                
                        # the properties below are optional
                        object_version="objectVersion"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "s3": s3,
            }

        @builtins.property
        def s3(
            self,
        ) -> typing.Union["CfnGitHubRepository.S3Property", _IResolvable_da3f097b]:
            '''Information about the Amazon S3 bucket that contains a ZIP file of code to be committed to the repository.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestar-githubrepository-code.html#cfn-codestar-githubrepository-code-s3
            '''
            result = self._values.get("s3")
            assert result is not None, "Required property 's3' is missing"
            return typing.cast(typing.Union["CfnGitHubRepository.S3Property", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CodeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_codestar.CfnGitHubRepository.S3Property",
        jsii_struct_bases=[],
        name_mapping={
            "bucket": "bucket",
            "key": "key",
            "object_version": "objectVersion",
        },
    )
    class S3Property:
        def __init__(
            self,
            *,
            bucket: builtins.str,
            key: builtins.str,
            object_version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``S3`` property type specifies information about the Amazon S3 bucket that contains the code to be committed to the new repository.

            ``S3`` is a property of the ``AWS::CodeStar::GitHubRepository`` resource.

            :param bucket: The name of the Amazon S3 bucket that contains the ZIP file with the content to be committed to the new repository.
            :param key: The S3 object key or file name for the ZIP file.
            :param object_version: The object version of the ZIP file, if versioning is enabled for the Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestar-githubrepository-s3.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_codestar as codestar
                
                s3_property = codestar.CfnGitHubRepository.S3Property(
                    bucket="bucket",
                    key="key",
                
                    # the properties below are optional
                    object_version="objectVersion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket": bucket,
                "key": key,
            }
            if object_version is not None:
                self._values["object_version"] = object_version

        @builtins.property
        def bucket(self) -> builtins.str:
            '''The name of the Amazon S3 bucket that contains the ZIP file with the content to be committed to the new repository.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestar-githubrepository-s3.html#cfn-codestar-githubrepository-s3-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key(self) -> builtins.str:
            '''The S3 object key or file name for the ZIP file.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestar-githubrepository-s3.html#cfn-codestar-githubrepository-s3-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def object_version(self) -> typing.Optional[builtins.str]:
            '''The object version of the ZIP file, if versioning is enabled for the Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codestar-githubrepository-s3.html#cfn-codestar-githubrepository-s3-objectversion
            '''
            result = self._values.get("object_version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3Property(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codestar.CfnGitHubRepositoryProps",
    jsii_struct_bases=[],
    name_mapping={
        "repository_name": "repositoryName",
        "repository_owner": "repositoryOwner",
        "code": "code",
        "connection_arn": "connectionArn",
        "enable_issues": "enableIssues",
        "is_private": "isPrivate",
        "repository_access_token": "repositoryAccessToken",
        "repository_description": "repositoryDescription",
    },
)
class CfnGitHubRepositoryProps:
    def __init__(
        self,
        *,
        repository_name: builtins.str,
        repository_owner: builtins.str,
        code: typing.Optional[typing.Union[CfnGitHubRepository.CodeProperty, _IResolvable_da3f097b]] = None,
        connection_arn: typing.Optional[builtins.str] = None,
        enable_issues: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        is_private: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        repository_access_token: typing.Optional[builtins.str] = None,
        repository_description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnGitHubRepository``.

        :param repository_name: The name of the repository you want to create in GitHub with AWS CloudFormation stack creation.
        :param repository_owner: The GitHub user name for the owner of the GitHub repository to be created. If this repository should be owned by a GitHub organization, provide its name.
        :param code: Information about code to be committed to a repository after it is created in an AWS CloudFormation stack.
        :param connection_arn: ``AWS::CodeStar::GitHubRepository.ConnectionArn``.
        :param enable_issues: Indicates whether to enable issues for the GitHub repository. You can use GitHub issues to track information and bugs for your repository.
        :param is_private: Indicates whether the GitHub repository is a private repository. If so, you choose who can see and commit to this repository.
        :param repository_access_token: The GitHub user's personal access token for the GitHub repository.
        :param repository_description: A comment or description about the new repository. This description is displayed in GitHub after the repository is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codestar as codestar
            
            cfn_git_hub_repository_props = codestar.CfnGitHubRepositoryProps(
                repository_name="repositoryName",
                repository_owner="repositoryOwner",
            
                # the properties below are optional
                code=codestar.CfnGitHubRepository.CodeProperty(
                    s3=codestar.CfnGitHubRepository.S3Property(
                        bucket="bucket",
                        key="key",
            
                        # the properties below are optional
                        object_version="objectVersion"
                    )
                ),
                connection_arn="connectionArn",
                enable_issues=False,
                is_private=False,
                repository_access_token="repositoryAccessToken",
                repository_description="repositoryDescription"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "repository_name": repository_name,
            "repository_owner": repository_owner,
        }
        if code is not None:
            self._values["code"] = code
        if connection_arn is not None:
            self._values["connection_arn"] = connection_arn
        if enable_issues is not None:
            self._values["enable_issues"] = enable_issues
        if is_private is not None:
            self._values["is_private"] = is_private
        if repository_access_token is not None:
            self._values["repository_access_token"] = repository_access_token
        if repository_description is not None:
            self._values["repository_description"] = repository_description

    @builtins.property
    def repository_name(self) -> builtins.str:
        '''The name of the repository you want to create in GitHub with AWS CloudFormation stack creation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-repositoryname
        '''
        result = self._values.get("repository_name")
        assert result is not None, "Required property 'repository_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def repository_owner(self) -> builtins.str:
        '''The GitHub user name for the owner of the GitHub repository to be created.

        If this repository should be owned by a GitHub organization, provide its name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-repositoryowner
        '''
        result = self._values.get("repository_owner")
        assert result is not None, "Required property 'repository_owner' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def code(
        self,
    ) -> typing.Optional[typing.Union[CfnGitHubRepository.CodeProperty, _IResolvable_da3f097b]]:
        '''Information about code to be committed to a repository after it is created in an AWS CloudFormation stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-code
        '''
        result = self._values.get("code")
        return typing.cast(typing.Optional[typing.Union[CfnGitHubRepository.CodeProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def connection_arn(self) -> typing.Optional[builtins.str]:
        '''``AWS::CodeStar::GitHubRepository.ConnectionArn``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-connectionarn
        '''
        result = self._values.get("connection_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_issues(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether to enable issues for the GitHub repository.

        You can use GitHub issues to track information and bugs for your repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-enableissues
        '''
        result = self._values.get("enable_issues")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def is_private(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether the GitHub repository is a private repository.

        If so, you choose who can see and commit to this repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-isprivate
        '''
        result = self._values.get("is_private")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def repository_access_token(self) -> typing.Optional[builtins.str]:
        '''The GitHub user's personal access token for the GitHub repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-repositoryaccesstoken
        '''
        result = self._values.get("repository_access_token")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def repository_description(self) -> typing.Optional[builtins.str]:
        '''A comment or description about the new repository.

        This description is displayed in GitHub after the repository is created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codestar-githubrepository.html#cfn-codestar-githubrepository-repositorydescription
        '''
        result = self._values.get("repository_description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnGitHubRepositoryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnGitHubRepository",
    "CfnGitHubRepositoryProps",
]

publication.publish()
