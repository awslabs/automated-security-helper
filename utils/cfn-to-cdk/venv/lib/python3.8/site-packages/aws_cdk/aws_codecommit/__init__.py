'''
# AWS CodeCommit Construct Library

AWS CodeCommit is a version control service that enables you to privately store and manage Git repositories in the AWS cloud.

For further information on CodeCommit,
see the [AWS CodeCommit documentation](https://docs.aws.amazon.com/codecommit).

To add a CodeCommit Repository to your stack:

```python
repo = codecommit.Repository(self, "Repository",
    repository_name="MyRepositoryName",
    description="Some description."
)
```

Use the `repositoryCloneUrlHttp`, `repositoryCloneUrlSsh` or `repositoryCloneUrlGrc`
property to clone your repository.

To add an Amazon SNS trigger to your repository:

```python
# repo: codecommit.Repository


# trigger is established for all repository actions on all branches by default.
repo.notify("arn:aws:sns:*:123456789012:my_topic")
```

## Add initial commit

It is possible to initialize the Repository via the `Code` class.
It provides methods for loading code from a directory, `.zip` file and from a pre-created CDK Asset.

Example:

```python
repo = codecommit.Repository(self, "Repository",
    repository_name="MyRepositoryName",
    code=codecommit.Code.from_directory(path.join(__dirname, "directory/"), "develop")
)
```

## Events

CodeCommit repositories emit Amazon CloudWatch events for certain activities.
Use the `repo.onXxx` methods to define rules that trigger on these events
and invoke targets as a result:

```python
import aws_cdk.aws_sns as sns
import aws_cdk.aws_events_targets as targets

# repo: codecommit.Repository
# project: codebuild.PipelineProject
# my_topic: sns.Topic


# starts a CodeBuild project when a commit is pushed to the "master" branch of the repo
repo.on_commit("CommitToMaster",
    target=targets.CodeBuildProject(project),
    branches=["master"]
)

# publishes a message to an Amazon SNS topic when a comment is made on a pull request
rule = repo.on_comment_on_pull_request("CommentOnPullRequest",
    target=targets.SnsTopic(my_topic)
)
```

## CodeStar Notifications

To define CodeStar Notification rules for Repositories, use one of the `notifyOnXxx()` methods.
They are very similar to `onXxx()` methods for CloudWatch events:

```python
import aws_cdk.aws_chatbot as chatbot

# repository: codecommit.Repository

target = chatbot.SlackChannelConfiguration(self, "MySlackChannel",
    slack_channel_configuration_name="YOUR_CHANNEL_NAME",
    slack_workspace_id="YOUR_SLACK_WORKSPACE_ID",
    slack_channel_id="YOUR_SLACK_CHANNEL_ID"
)
rule = repository.notify_on_pull_request_created("NotifyOnPullRequestCreated", target)
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
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_codestarnotifications import (
    DetailType as _DetailType_cf8135e7,
    INotificationRule as _INotificationRule_71939426,
    INotificationRuleSource as _INotificationRuleSource_10482823,
    INotificationRuleTarget as _INotificationRuleTarget_faa3b79b,
    NotificationRuleOptions as _NotificationRuleOptions_dff73281,
    NotificationRuleSourceConfig as _NotificationRuleSourceConfig_20189a3e,
)
from ..aws_events import (
    EventPattern as _EventPattern_fe557901,
    IRuleTarget as _IRuleTarget_7a91f454,
    OnEventOptions as _OnEventOptions_8711b8b3,
    Rule as _Rule_334ed2b5,
)
from ..aws_iam import Grant as _Grant_a7ae64f8, IGrantable as _IGrantable_71c4f5de
from ..aws_s3_assets import Asset as _Asset_ac2a7e61


@jsii.implements(_IInspectable_c2943556)
class CfnRepository(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_codecommit.CfnRepository",
):
    '''A CloudFormation ``AWS::CodeCommit::Repository``.

    Creates a new, empty repository.

    :cloudformationResource: AWS::CodeCommit::Repository
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_codecommit as codecommit
        
        cfn_repository = codecommit.CfnRepository(self, "MyCfnRepository",
            repository_name="repositoryName",
        
            # the properties below are optional
            code=codecommit.CfnRepository.CodeProperty(
                s3=codecommit.CfnRepository.S3Property(
                    bucket="bucket",
                    key="key",
        
                    # the properties below are optional
                    object_version="objectVersion"
                ),
        
                # the properties below are optional
                branch_name="branchName"
            ),
            repository_description="repositoryDescription",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            triggers=[codecommit.CfnRepository.RepositoryTriggerProperty(
                destination_arn="destinationArn",
                events=["events"],
                name="name",
        
                # the properties below are optional
                branches=["branches"],
                custom_data="customData"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        repository_name: builtins.str,
        code: typing.Optional[typing.Union["CfnRepository.CodeProperty", _IResolvable_da3f097b]] = None,
        repository_description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        triggers: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRepository.RepositoryTriggerProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::CodeCommit::Repository``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param repository_name: The name of the new repository to be created. .. epigraph:: The repository name must be unique across the calling AWS account . Repository names are limited to 100 alphanumeric, dash, and underscore characters, and cannot include certain characters. For more information about the limits on repository names, see `Quotas <https://docs.aws.amazon.com/codecommit/latest/userguide/limits.html>`_ in the *AWS CodeCommit User Guide* . The suffix .git is prohibited.
        :param code: Information about code to be committed to a repository after it is created in an AWS CloudFormation stack. Information about code is only used in resource creation. Updates to a stack will not reflect changes made to code properties after initial resource creation. .. epigraph:: You can only use this property to add code when creating a repository with a AWS CloudFormation template at creation time. This property cannot be used for updating code to an existing repository.
        :param repository_description: A comment or description about the new repository. .. epigraph:: The description field for a repository accepts all HTML characters and all valid Unicode characters. Applications that do not HTML-encode the description and display it in a webpage can expose users to potentially malicious code. Make sure that you HTML-encode the description field in any application that uses this API to display the repository description on a webpage.
        :param tags: One or more tag key-value pairs to use when tagging this repository.
        :param triggers: The JSON block of configuration information for each trigger.
        '''
        props = CfnRepositoryProps(
            repository_name=repository_name,
            code=code,
            repository_description=repository_description,
            tags=tags,
            triggers=triggers,
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
        '''When you pass the logical ID of this resource, the function returns the Amazon Resource Name (ARN) of the repository.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCloneUrlHttp")
    def attr_clone_url_http(self) -> builtins.str:
        '''When you pass the logical ID of this resource, the function returns the URL to use for cloning the repository over HTTPS.

        :cloudformationAttribute: CloneUrlHttp
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCloneUrlHttp"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCloneUrlSsh")
    def attr_clone_url_ssh(self) -> builtins.str:
        '''When you pass the logical ID of this resource, the function returns the URL to use for cloning the repository over SSH.

        :cloudformationAttribute: CloneUrlSsh
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCloneUrlSsh"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''When you pass the logical ID of this resource, the function returns the repository's name.

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''One or more tag key-value pairs to use when tagging this repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The name of the new repository to be created.

        .. epigraph::

           The repository name must be unique across the calling AWS account . Repository names are limited to 100 alphanumeric, dash, and underscore characters, and cannot include certain characters. For more information about the limits on repository names, see `Quotas <https://docs.aws.amazon.com/codecommit/latest/userguide/limits.html>`_ in the *AWS CodeCommit User Guide* . The suffix .git is prohibited.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-repositoryname
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryName"))

    @repository_name.setter
    def repository_name(self, value: builtins.str) -> None:
        jsii.set(self, "repositoryName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="code")
    def code(
        self,
    ) -> typing.Optional[typing.Union["CfnRepository.CodeProperty", _IResolvable_da3f097b]]:
        '''Information about code to be committed to a repository after it is created in an AWS CloudFormation stack.

        Information about code is only used in resource creation. Updates to a stack will not reflect changes made to code properties after initial resource creation.
        .. epigraph::

           You can only use this property to add code when creating a repository with a AWS CloudFormation template at creation time. This property cannot be used for updating code to an existing repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-code
        '''
        return typing.cast(typing.Optional[typing.Union["CfnRepository.CodeProperty", _IResolvable_da3f097b]], jsii.get(self, "code"))

    @code.setter
    def code(
        self,
        value: typing.Optional[typing.Union["CfnRepository.CodeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "code", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryDescription")
    def repository_description(self) -> typing.Optional[builtins.str]:
        '''A comment or description about the new repository.

        .. epigraph::

           The description field for a repository accepts all HTML characters and all valid Unicode characters. Applications that do not HTML-encode the description and display it in a webpage can expose users to potentially malicious code. Make sure that you HTML-encode the description field in any application that uses this API to display the repository description on a webpage.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-repositorydescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "repositoryDescription"))

    @repository_description.setter
    def repository_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "repositoryDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="triggers")
    def triggers(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRepository.RepositoryTriggerProperty", _IResolvable_da3f097b]]]]:
        '''The JSON block of configuration information for each trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-triggers
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRepository.RepositoryTriggerProperty", _IResolvable_da3f097b]]]], jsii.get(self, "triggers"))

    @triggers.setter
    def triggers(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRepository.RepositoryTriggerProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "triggers", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_codecommit.CfnRepository.CodeProperty",
        jsii_struct_bases=[],
        name_mapping={"s3": "s3", "branch_name": "branchName"},
    )
    class CodeProperty:
        def __init__(
            self,
            *,
            s3: typing.Union["CfnRepository.S3Property", _IResolvable_da3f097b],
            branch_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about code to be committed.

            :param s3: Information about the Amazon S3 bucket that contains a ZIP file of code to be committed to the repository. Changes to this property are ignored after initial resource creation.
            :param branch_name: Optional. Specifies a branch name to be used as the default branch when importing code into a repository on initial creation. If this property is not set, the name *main* will be used for the default branch for the repository. Changes to this property are ignored after initial resource creation. We recommend using this parameter to set the name to *main* to align with the default behavior of CodeCommit unless another name is needed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-code.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_codecommit as codecommit
                
                code_property = codecommit.CfnRepository.CodeProperty(
                    s3=codecommit.CfnRepository.S3Property(
                        bucket="bucket",
                        key="key",
                
                        # the properties below are optional
                        object_version="objectVersion"
                    ),
                
                    # the properties below are optional
                    branch_name="branchName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "s3": s3,
            }
            if branch_name is not None:
                self._values["branch_name"] = branch_name

        @builtins.property
        def s3(self) -> typing.Union["CfnRepository.S3Property", _IResolvable_da3f097b]:
            '''Information about the Amazon S3 bucket that contains a ZIP file of code to be committed to the repository.

            Changes to this property are ignored after initial resource creation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-code.html#cfn-codecommit-repository-code-s3
            '''
            result = self._values.get("s3")
            assert result is not None, "Required property 's3' is missing"
            return typing.cast(typing.Union["CfnRepository.S3Property", _IResolvable_da3f097b], result)

        @builtins.property
        def branch_name(self) -> typing.Optional[builtins.str]:
            '''Optional.

            Specifies a branch name to be used as the default branch when importing code into a repository on initial creation. If this property is not set, the name *main* will be used for the default branch for the repository. Changes to this property are ignored after initial resource creation. We recommend using this parameter to set the name to *main* to align with the default behavior of CodeCommit unless another name is needed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-code.html#cfn-codecommit-repository-code-branchname
            '''
            result = self._values.get("branch_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CodeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_codecommit.CfnRepository.RepositoryTriggerProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_arn": "destinationArn",
            "events": "events",
            "name": "name",
            "branches": "branches",
            "custom_data": "customData",
        },
    )
    class RepositoryTriggerProperty:
        def __init__(
            self,
            *,
            destination_arn: builtins.str,
            events: typing.Sequence[builtins.str],
            name: builtins.str,
            branches: typing.Optional[typing.Sequence[builtins.str]] = None,
            custom_data: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a trigger for a repository.

            .. epigraph::

               If you want to receive notifications about repository events, consider using notifications instead of triggers. For more information, see `Configuring notifications for repository events <https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-repository-email.html>`_ .

            :param destination_arn: The ARN of the resource that is the target for a trigger (for example, the ARN of a topic in Amazon SNS).
            :param events: The repository events that cause the trigger to run actions in another service, such as sending a notification through Amazon SNS. .. epigraph:: The valid value "all" cannot be used with any other values.
            :param name: The name of the trigger.
            :param branches: The branches to be included in the trigger configuration. If you specify an empty array, the trigger applies to all branches. .. epigraph:: Although no content is required in the array, you must include the array itself.
            :param custom_data: Any custom data associated with the trigger to be included in the information sent to the target of the trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-repositorytrigger.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_codecommit as codecommit
                
                repository_trigger_property = codecommit.CfnRepository.RepositoryTriggerProperty(
                    destination_arn="destinationArn",
                    events=["events"],
                    name="name",
                
                    # the properties below are optional
                    branches=["branches"],
                    custom_data="customData"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_arn": destination_arn,
                "events": events,
                "name": name,
            }
            if branches is not None:
                self._values["branches"] = branches
            if custom_data is not None:
                self._values["custom_data"] = custom_data

        @builtins.property
        def destination_arn(self) -> builtins.str:
            '''The ARN of the resource that is the target for a trigger (for example, the ARN of a topic in Amazon SNS).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-repositorytrigger.html#cfn-codecommit-repository-repositorytrigger-destinationarn
            '''
            result = self._values.get("destination_arn")
            assert result is not None, "Required property 'destination_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def events(self) -> typing.List[builtins.str]:
            '''The repository events that cause the trigger to run actions in another service, such as sending a notification through Amazon SNS.

            .. epigraph::

               The valid value "all" cannot be used with any other values.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-repositorytrigger.html#cfn-codecommit-repository-repositorytrigger-events
            '''
            result = self._values.get("events")
            assert result is not None, "Required property 'events' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-repositorytrigger.html#cfn-codecommit-repository-repositorytrigger-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def branches(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The branches to be included in the trigger configuration.

            If you specify an empty array, the trigger applies to all branches.
            .. epigraph::

               Although no content is required in the array, you must include the array itself.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-repositorytrigger.html#cfn-codecommit-repository-repositorytrigger-branches
            '''
            result = self._values.get("branches")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def custom_data(self) -> typing.Optional[builtins.str]:
            '''Any custom data associated with the trigger to be included in the information sent to the target of the trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-repositorytrigger.html#cfn-codecommit-repository-repositorytrigger-customdata
            '''
            result = self._values.get("custom_data")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RepositoryTriggerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_codecommit.CfnRepository.S3Property",
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
            '''Information about the Amazon S3 bucket that contains the code that will be committed to the new repository.

            Changes to this property are ignored after initial resource creation.

            :param bucket: The name of the Amazon S3 bucket that contains the ZIP file with the content that will be committed to the new repository. This can be specified using the name of the bucket in the AWS account . Changes to this property are ignored after initial resource creation.
            :param key: The key to use for accessing the Amazon S3 bucket. Changes to this property are ignored after initial resource creation. For more information, see `Creating object key names <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html>`_ and `Uploading objects <https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html>`_ in the Amazon S3 User Guide.
            :param object_version: The object version of the ZIP file, if versioning is enabled for the Amazon S3 bucket. Changes to this property are ignored after initial resource creation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-s3.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_codecommit as codecommit
                
                s3_property = codecommit.CfnRepository.S3Property(
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
            '''The name of the Amazon S3 bucket that contains the ZIP file with the content that will be committed to the new repository.

            This can be specified using the name of the bucket in the AWS account . Changes to this property are ignored after initial resource creation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-s3.html#cfn-codecommit-repository-s3-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def key(self) -> builtins.str:
            '''The key to use for accessing the Amazon S3 bucket.

            Changes to this property are ignored after initial resource creation. For more information, see `Creating object key names <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html>`_ and `Uploading objects <https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html>`_ in the Amazon S3 User Guide.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-s3.html#cfn-codecommit-repository-s3-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def object_version(self) -> typing.Optional[builtins.str]:
            '''The object version of the ZIP file, if versioning is enabled for the Amazon S3 bucket.

            Changes to this property are ignored after initial resource creation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codecommit-repository-s3.html#cfn-codecommit-repository-s3-objectversion
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
    jsii_type="aws-cdk-lib.aws_codecommit.CfnRepositoryProps",
    jsii_struct_bases=[],
    name_mapping={
        "repository_name": "repositoryName",
        "code": "code",
        "repository_description": "repositoryDescription",
        "tags": "tags",
        "triggers": "triggers",
    },
)
class CfnRepositoryProps:
    def __init__(
        self,
        *,
        repository_name: builtins.str,
        code: typing.Optional[typing.Union[CfnRepository.CodeProperty, _IResolvable_da3f097b]] = None,
        repository_description: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        triggers: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnRepository.RepositoryTriggerProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRepository``.

        :param repository_name: The name of the new repository to be created. .. epigraph:: The repository name must be unique across the calling AWS account . Repository names are limited to 100 alphanumeric, dash, and underscore characters, and cannot include certain characters. For more information about the limits on repository names, see `Quotas <https://docs.aws.amazon.com/codecommit/latest/userguide/limits.html>`_ in the *AWS CodeCommit User Guide* . The suffix .git is prohibited.
        :param code: Information about code to be committed to a repository after it is created in an AWS CloudFormation stack. Information about code is only used in resource creation. Updates to a stack will not reflect changes made to code properties after initial resource creation. .. epigraph:: You can only use this property to add code when creating a repository with a AWS CloudFormation template at creation time. This property cannot be used for updating code to an existing repository.
        :param repository_description: A comment or description about the new repository. .. epigraph:: The description field for a repository accepts all HTML characters and all valid Unicode characters. Applications that do not HTML-encode the description and display it in a webpage can expose users to potentially malicious code. Make sure that you HTML-encode the description field in any application that uses this API to display the repository description on a webpage.
        :param tags: One or more tag key-value pairs to use when tagging this repository.
        :param triggers: The JSON block of configuration information for each trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codecommit as codecommit
            
            cfn_repository_props = codecommit.CfnRepositoryProps(
                repository_name="repositoryName",
            
                # the properties below are optional
                code=codecommit.CfnRepository.CodeProperty(
                    s3=codecommit.CfnRepository.S3Property(
                        bucket="bucket",
                        key="key",
            
                        # the properties below are optional
                        object_version="objectVersion"
                    ),
            
                    # the properties below are optional
                    branch_name="branchName"
                ),
                repository_description="repositoryDescription",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                triggers=[codecommit.CfnRepository.RepositoryTriggerProperty(
                    destination_arn="destinationArn",
                    events=["events"],
                    name="name",
            
                    # the properties below are optional
                    branches=["branches"],
                    custom_data="customData"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "repository_name": repository_name,
        }
        if code is not None:
            self._values["code"] = code
        if repository_description is not None:
            self._values["repository_description"] = repository_description
        if tags is not None:
            self._values["tags"] = tags
        if triggers is not None:
            self._values["triggers"] = triggers

    @builtins.property
    def repository_name(self) -> builtins.str:
        '''The name of the new repository to be created.

        .. epigraph::

           The repository name must be unique across the calling AWS account . Repository names are limited to 100 alphanumeric, dash, and underscore characters, and cannot include certain characters. For more information about the limits on repository names, see `Quotas <https://docs.aws.amazon.com/codecommit/latest/userguide/limits.html>`_ in the *AWS CodeCommit User Guide* . The suffix .git is prohibited.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-repositoryname
        '''
        result = self._values.get("repository_name")
        assert result is not None, "Required property 'repository_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def code(
        self,
    ) -> typing.Optional[typing.Union[CfnRepository.CodeProperty, _IResolvable_da3f097b]]:
        '''Information about code to be committed to a repository after it is created in an AWS CloudFormation stack.

        Information about code is only used in resource creation. Updates to a stack will not reflect changes made to code properties after initial resource creation.
        .. epigraph::

           You can only use this property to add code when creating a repository with a AWS CloudFormation template at creation time. This property cannot be used for updating code to an existing repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-code
        '''
        result = self._values.get("code")
        return typing.cast(typing.Optional[typing.Union[CfnRepository.CodeProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def repository_description(self) -> typing.Optional[builtins.str]:
        '''A comment or description about the new repository.

        .. epigraph::

           The description field for a repository accepts all HTML characters and all valid Unicode characters. Applications that do not HTML-encode the description and display it in a webpage can expose users to potentially malicious code. Make sure that you HTML-encode the description field in any application that uses this API to display the repository description on a webpage.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-repositorydescription
        '''
        result = self._values.get("repository_description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''One or more tag key-value pairs to use when tagging this repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def triggers(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRepository.RepositoryTriggerProperty, _IResolvable_da3f097b]]]]:
        '''The JSON block of configuration information for each trigger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codecommit-repository.html#cfn-codecommit-repository-triggers
        '''
        result = self._values.get("triggers")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRepository.RepositoryTriggerProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRepositoryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Code(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_codecommit.Code",
):
    '''Represents the contents to initialize the repository with.

    :exampleMetadata: infused

    Example::

        repo = codecommit.Repository(self, "Repository",
            repository_name="MyRepositoryName",
            code=codecommit.Code.from_directory(path.join(__dirname, "directory/"), "develop")
        )
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="fromAsset") # type: ignore[misc]
    @builtins.classmethod
    def from_asset(
        cls,
        asset: _Asset_ac2a7e61,
        branch: typing.Optional[builtins.str] = None,
    ) -> "Code":
        '''Code from user-supplied asset.

        :param asset: pre-existing asset.
        :param branch: the name of the branch to create in the repository. Default is "main"
        '''
        return typing.cast("Code", jsii.sinvoke(cls, "fromAsset", [asset, branch]))

    @jsii.member(jsii_name="fromDirectory") # type: ignore[misc]
    @builtins.classmethod
    def from_directory(
        cls,
        directory_path: builtins.str,
        branch: typing.Optional[builtins.str] = None,
    ) -> "Code":
        '''Code from directory.

        :param directory_path: the path to the local directory containing the contents to initialize the repository with.
        :param branch: the name of the branch to create in the repository. Default is "main"
        '''
        return typing.cast("Code", jsii.sinvoke(cls, "fromDirectory", [directory_path, branch]))

    @jsii.member(jsii_name="fromZipFile") # type: ignore[misc]
    @builtins.classmethod
    def from_zip_file(
        cls,
        file_path: builtins.str,
        branch: typing.Optional[builtins.str] = None,
    ) -> "Code":
        '''Code from preexisting ZIP file.

        :param file_path: the path to the local ZIP file containing the contents to initialize the repository with.
        :param branch: the name of the branch to create in the repository. Default is "main"
        '''
        return typing.cast("Code", jsii.sinvoke(cls, "fromZipFile", [file_path, branch]))

    @jsii.member(jsii_name="bind") # type: ignore[misc]
    @abc.abstractmethod
    def bind(self, scope: constructs.Construct) -> "CodeConfig":
        '''This method is called after a repository is passed this instance of Code in its 'code' property.

        :param scope: the binding scope.
        '''
        ...


class _CodeProxy(Code):
    @jsii.member(jsii_name="bind")
    def bind(self, scope: constructs.Construct) -> "CodeConfig":
        '''This method is called after a repository is passed this instance of Code in its 'code' property.

        :param scope: the binding scope.
        '''
        return typing.cast("CodeConfig", jsii.invoke(self, "bind", [scope]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, Code).__jsii_proxy_class__ = lambda : _CodeProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codecommit.CodeConfig",
    jsii_struct_bases=[],
    name_mapping={"code": "code"},
)
class CodeConfig:
    def __init__(self, *, code: CfnRepository.CodeProperty) -> None:
        '''Represents the structure to pass into the underlying CfnRepository class.

        :param code: represents the underlying code structure.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codecommit as codecommit
            
            code_config = codecommit.CodeConfig(
                code=codecommit.CfnRepository.CodeProperty(
                    s3=codecommit.CfnRepository.S3Property(
                        bucket="bucket",
                        key="key",
            
                        # the properties below are optional
                        object_version="objectVersion"
                    ),
            
                    # the properties below are optional
                    branch_name="branchName"
                )
            )
        '''
        if isinstance(code, dict):
            code = CfnRepository.CodeProperty(**code)
        self._values: typing.Dict[str, typing.Any] = {
            "code": code,
        }

    @builtins.property
    def code(self) -> CfnRepository.CodeProperty:
        '''represents the underlying code structure.'''
        result = self._values.get("code")
        assert result is not None, "Required property 'code' is missing"
        return typing.cast(CfnRepository.CodeProperty, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CodeConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_codecommit.IRepository")
class IRepository(
    _IResource_c80c4260,
    _INotificationRuleSource_10482823,
    typing_extensions.Protocol,
):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryArn")
    def repository_arn(self) -> builtins.str:
        '''The ARN of this Repository.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlGrc")
    def repository_clone_url_grc(self) -> builtins.str:
        '''The HTTPS (GRC) clone URL.

        HTTPS (GRC) is the protocol to use with git-remote-codecommit (GRC).

        It is the recommended method for supporting connections made with federated
        access, identity providers, and temporary credentials.

        :see: https://docs.aws.amazon.com/codecommit/latest/userguide/setting-up-git-remote-codecommit.html
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlHttp")
    def repository_clone_url_http(self) -> builtins.str:
        '''The HTTP clone URL.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlSsh")
    def repository_clone_url_ssh(self) -> builtins.str:
        '''The SSH clone URL.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The human-visible name of this Repository.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the given principal identity permissions to perform the actions on this repository.

        :param grantee: -
        :param actions: -
        '''
        ...

    @jsii.member(jsii_name="grantPull")
    def grant_pull(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull this repository.

        :param grantee: -
        '''
        ...

    @jsii.member(jsii_name="grantPullPush")
    def grant_pull_push(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull and push this repository.

        :param grantee: -
        '''
        ...

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to read this repository.

        :param grantee: -
        '''
        ...

    @jsii.member(jsii_name="notifyOn")
    def notify_on(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        events: typing.Sequence["RepositoryNotificationEvents"],
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule triggered when the project events specified by you are emitted. Similar to ``onEvent`` API.

        You can also use the methods to define rules for the specific event emitted.
        eg: ``notifyOnPullRequstCreated``.

        :param id: -
        :param target: -
        :param events: A list of event types associated with this notification rule for CodeCommit repositories. For a complete list of event types and IDs, see Notification concepts in the Developer Tools Console User Guide.
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``

        :return: CodeStar Notifications rule associated with this repository.
        '''
        ...

    @jsii.member(jsii_name="notifyOnApprovalRuleOverridden")
    def notify_on_approval_rule_overridden(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when an approval rule is overridden.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        ...

    @jsii.member(jsii_name="notifyOnApprovalStatusChanged")
    def notify_on_approval_status_changed(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when an approval status is changed.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        ...

    @jsii.member(jsii_name="notifyOnBranchOrTagCreated")
    def notify_on_branch_or_tag_created(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a new branch or tag is created.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        ...

    @jsii.member(jsii_name="notifyOnBranchOrTagDeleted")
    def notify_on_branch_or_tag_deleted(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a branch or tag is deleted.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        ...

    @jsii.member(jsii_name="notifyOnPullRequestComment")
    def notify_on_pull_request_comment(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a comment is made on a pull request.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        ...

    @jsii.member(jsii_name="notifyOnPullRequestCreated")
    def notify_on_pull_request_created(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a pull request is created.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        ...

    @jsii.member(jsii_name="notifyOnPullRequestMerged")
    def notify_on_pull_request_merged(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a pull request is merged.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        ...

    @jsii.member(jsii_name="onCommentOnCommit")
    def on_comment_on_commit(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a comment is made on a commit.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onCommentOnPullRequest")
    def on_comment_on_pull_request(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a comment is made on a pull request.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onCommit")
    def on_commit(
        self,
        id: builtins.str,
        *,
        branches: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a commit is pushed to a branch.

        :param id: -
        :param branches: The branch to monitor. Default: - All branches
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onEvent")
    def on_event(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers for repository events.

        Use
        ``rule.addEventPattern(pattern)`` to specify a filter.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onPullRequestStateChange")
    def on_pull_request_state_change(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a pull request state is changed.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onReferenceCreated")
    def on_reference_created(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is created (i.e. a new branch/tag is created) to the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onReferenceDeleted")
    def on_reference_deleted(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is delete (i.e. a branch/tag is deleted) from the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onReferenceUpdated")
    def on_reference_updated(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is updated (i.e. a commit is pushed to an existing or new branch) from the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onStateChange")
    def on_state_change(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a "CodeCommit Repository State Change" event occurs.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...


class _IRepositoryProxy(
    jsii.proxy_for(_IResource_c80c4260), # type: ignore[misc]
    jsii.proxy_for(_INotificationRuleSource_10482823), # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_codecommit.IRepository"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryArn")
    def repository_arn(self) -> builtins.str:
        '''The ARN of this Repository.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlGrc")
    def repository_clone_url_grc(self) -> builtins.str:
        '''The HTTPS (GRC) clone URL.

        HTTPS (GRC) is the protocol to use with git-remote-codecommit (GRC).

        It is the recommended method for supporting connections made with federated
        access, identity providers, and temporary credentials.

        :see: https://docs.aws.amazon.com/codecommit/latest/userguide/setting-up-git-remote-codecommit.html
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryCloneUrlGrc"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlHttp")
    def repository_clone_url_http(self) -> builtins.str:
        '''The HTTP clone URL.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryCloneUrlHttp"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlSsh")
    def repository_clone_url_ssh(self) -> builtins.str:
        '''The SSH clone URL.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryCloneUrlSsh"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The human-visible name of this Repository.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryName"))

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the given principal identity permissions to perform the actions on this repository.

        :param grantee: -
        :param actions: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *actions]))

    @jsii.member(jsii_name="grantPull")
    def grant_pull(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPull", [grantee]))

    @jsii.member(jsii_name="grantPullPush")
    def grant_pull_push(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull and push this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPullPush", [grantee]))

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to read this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [grantee]))

    @jsii.member(jsii_name="notifyOn")
    def notify_on(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        events: typing.Sequence["RepositoryNotificationEvents"],
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule triggered when the project events specified by you are emitted. Similar to ``onEvent`` API.

        You can also use the methods to define rules for the specific event emitted.
        eg: ``notifyOnPullRequstCreated``.

        :param id: -
        :param target: -
        :param events: A list of event types associated with this notification rule for CodeCommit repositories. For a complete list of event types and IDs, see Notification concepts in the Developer Tools Console User Guide.
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``

        :return: CodeStar Notifications rule associated with this repository.
        '''
        options = RepositoryNotifyOnOptions(
            events=events,
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOn", [id, target, options]))

    @jsii.member(jsii_name="notifyOnApprovalRuleOverridden")
    def notify_on_approval_rule_overridden(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when an approval rule is overridden.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnApprovalRuleOverridden", [id, target, options]))

    @jsii.member(jsii_name="notifyOnApprovalStatusChanged")
    def notify_on_approval_status_changed(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when an approval status is changed.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnApprovalStatusChanged", [id, target, options]))

    @jsii.member(jsii_name="notifyOnBranchOrTagCreated")
    def notify_on_branch_or_tag_created(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a new branch or tag is created.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnBranchOrTagCreated", [id, target, options]))

    @jsii.member(jsii_name="notifyOnBranchOrTagDeleted")
    def notify_on_branch_or_tag_deleted(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a branch or tag is deleted.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnBranchOrTagDeleted", [id, target, options]))

    @jsii.member(jsii_name="notifyOnPullRequestComment")
    def notify_on_pull_request_comment(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a comment is made on a pull request.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnPullRequestComment", [id, target, options]))

    @jsii.member(jsii_name="notifyOnPullRequestCreated")
    def notify_on_pull_request_created(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a pull request is created.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnPullRequestCreated", [id, target, options]))

    @jsii.member(jsii_name="notifyOnPullRequestMerged")
    def notify_on_pull_request_merged(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a pull request is merged.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnPullRequestMerged", [id, target, options]))

    @jsii.member(jsii_name="onCommentOnCommit")
    def on_comment_on_commit(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a comment is made on a commit.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCommentOnCommit", [id, options]))

    @jsii.member(jsii_name="onCommentOnPullRequest")
    def on_comment_on_pull_request(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a comment is made on a pull request.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCommentOnPullRequest", [id, options]))

    @jsii.member(jsii_name="onCommit")
    def on_commit(
        self,
        id: builtins.str,
        *,
        branches: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a commit is pushed to a branch.

        :param id: -
        :param branches: The branch to monitor. Default: - All branches
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCommitOptions(
            branches=branches,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCommit", [id, options]))

    @jsii.member(jsii_name="onEvent")
    def on_event(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers for repository events.

        Use
        ``rule.addEventPattern(pattern)`` to specify a filter.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onEvent", [id, options]))

    @jsii.member(jsii_name="onPullRequestStateChange")
    def on_pull_request_state_change(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a pull request state is changed.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onPullRequestStateChange", [id, options]))

    @jsii.member(jsii_name="onReferenceCreated")
    def on_reference_created(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is created (i.e. a new branch/tag is created) to the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onReferenceCreated", [id, options]))

    @jsii.member(jsii_name="onReferenceDeleted")
    def on_reference_deleted(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is delete (i.e. a branch/tag is deleted) from the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onReferenceDeleted", [id, options]))

    @jsii.member(jsii_name="onReferenceUpdated")
    def on_reference_updated(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is updated (i.e. a commit is pushed to an existing or new branch) from the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onReferenceUpdated", [id, options]))

    @jsii.member(jsii_name="onStateChange")
    def on_state_change(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a "CodeCommit Repository State Change" event occurs.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onStateChange", [id, options]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IRepository).__jsii_proxy_class__ = lambda : _IRepositoryProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codecommit.OnCommitOptions",
    jsii_struct_bases=[_OnEventOptions_8711b8b3],
    name_mapping={
        "description": "description",
        "event_pattern": "eventPattern",
        "rule_name": "ruleName",
        "target": "target",
        "branches": "branches",
    },
)
class OnCommitOptions(_OnEventOptions_8711b8b3):
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
        branches: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Options for the onCommit() method.

        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        :param branches: The branch to monitor. Default: - All branches

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_codecommit as codecommit
            import aws_cdk.aws_events_targets as targets
            
            # repo: codecommit.Repository
            
            my_topic = sns.Topic(self, "Topic")
            
            repo.on_commit("OnCommit",
                target=targets.SnsTopic(my_topic)
            )
        '''
        if isinstance(event_pattern, dict):
            event_pattern = _EventPattern_fe557901(**event_pattern)
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if event_pattern is not None:
            self._values["event_pattern"] = event_pattern
        if rule_name is not None:
            self._values["rule_name"] = rule_name
        if target is not None:
            self._values["target"] = target
        if branches is not None:
            self._values["branches"] = branches

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the rule's purpose.

        :default: - No description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def event_pattern(self) -> typing.Optional[_EventPattern_fe557901]:
        '''Additional restrictions for the event to route to the specified target.

        The method that generates the rule probably imposes some type of event
        filtering. The filtering implied by what you pass here is added
        on top of that filtering.

        :default: - No additional filtering based on an event pattern.

        :see: https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html
        '''
        result = self._values.get("event_pattern")
        return typing.cast(typing.Optional[_EventPattern_fe557901], result)

    @builtins.property
    def rule_name(self) -> typing.Optional[builtins.str]:
        '''A name for the rule.

        :default: AWS CloudFormation generates a unique physical ID.
        '''
        result = self._values.get("rule_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def target(self) -> typing.Optional[_IRuleTarget_7a91f454]:
        '''The target to register for the event.

        :default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        result = self._values.get("target")
        return typing.cast(typing.Optional[_IRuleTarget_7a91f454], result)

    @builtins.property
    def branches(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The branch to monitor.

        :default: - All branches
        '''
        result = self._values.get("branches")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OnCommitOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ReferenceEvent(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_codecommit.ReferenceEvent",
):
    '''Fields of CloudWatch Events that change references.

    :see: https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/EventTypes.html#codebuild_event_type
    '''

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="commitId")
    def commit_id(cls) -> builtins.str:
        '''Commit id this reference now points to.'''
        return typing.cast(builtins.str, jsii.sget(cls, "commitId"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="eventType")
    def event_type(cls) -> builtins.str:
        '''The type of reference event.

        'referenceCreated', 'referenceUpdated' or 'referenceDeleted'
        '''
        return typing.cast(builtins.str, jsii.sget(cls, "eventType"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="referenceFullName")
    def reference_full_name(cls) -> builtins.str:
        '''Full reference name.

        For example, 'refs/tags/myTag'
        '''
        return typing.cast(builtins.str, jsii.sget(cls, "referenceFullName"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="referenceName")
    def reference_name(cls) -> builtins.str:
        '''Name of reference changed (branch or tag name).'''
        return typing.cast(builtins.str, jsii.sget(cls, "referenceName"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="referenceType")
    def reference_type(cls) -> builtins.str:
        '''Type of reference changed.

        'branch' or 'tag'
        '''
        return typing.cast(builtins.str, jsii.sget(cls, "referenceType"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="repositoryId")
    def repository_id(cls) -> builtins.str:
        '''Id of the CodeCommit repository.'''
        return typing.cast(builtins.str, jsii.sget(cls, "repositoryId"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(cls) -> builtins.str:
        '''Name of the CodeCommit repository.'''
        return typing.cast(builtins.str, jsii.sget(cls, "repositoryName"))


@jsii.implements(IRepository)
class Repository(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_codecommit.Repository",
):
    '''Provides a CodeCommit Repository.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        # project: codebuild.PipelineProject
        
        repository = codecommit.Repository(self, "MyRepository",
            repository_name="MyRepository"
        )
        project = codebuild.PipelineProject(self, "MyProject")
        
        source_output = codepipeline.Artifact()
        source_action = codepipeline_actions.CodeCommitSourceAction(
            action_name="CodeCommit",
            repository=repository,
            output=source_output
        )
        build_action = codepipeline_actions.CodeBuildAction(
            action_name="CodeBuild",
            project=project,
            input=source_output,
            outputs=[codepipeline.Artifact()],  # optional
            execute_batch_build=True,  # optional, defaults to false
            combine_batch_build_artifacts=True
        )
        
        codepipeline.Pipeline(self, "MyPipeline",
            stages=[codepipeline.StageProps(
                stage_name="Source",
                actions=[source_action]
            ), codepipeline.StageProps(
                stage_name="Build",
                actions=[build_action]
            )
            ]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        repository_name: builtins.str,
        code: typing.Optional[Code] = None,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param repository_name: Name of the repository. This property is required for all CodeCommit repositories.
        :param code: The contents with which to initialize the repository after it has been created. Default: - No initialization (create empty repo)
        :param description: A description of the repository. Use the description to identify the purpose of the repository. Default: - No description.
        '''
        props = RepositoryProps(
            repository_name=repository_name, code=code, description=description
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromRepositoryArn") # type: ignore[misc]
    @builtins.classmethod
    def from_repository_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        repository_arn: builtins.str,
    ) -> IRepository:
        '''Imports a codecommit repository.

        :param scope: -
        :param id: -
        :param repository_arn: (e.g. ``arn:aws:codecommit:us-east-1:123456789012:MyDemoRepo``).
        '''
        return typing.cast(IRepository, jsii.sinvoke(cls, "fromRepositoryArn", [scope, id, repository_arn]))

    @jsii.member(jsii_name="fromRepositoryName") # type: ignore[misc]
    @builtins.classmethod
    def from_repository_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        repository_name: builtins.str,
    ) -> IRepository:
        '''
        :param scope: -
        :param id: -
        :param repository_name: -
        '''
        return typing.cast(IRepository, jsii.sinvoke(cls, "fromRepositoryName", [scope, id, repository_name]))

    @jsii.member(jsii_name="bindAsNotificationRuleSource")
    def bind_as_notification_rule_source(
        self,
        _scope: constructs.Construct,
    ) -> _NotificationRuleSourceConfig_20189a3e:
        '''Returns a source configuration for notification rule.

        :param _scope: -
        '''
        return typing.cast(_NotificationRuleSourceConfig_20189a3e, jsii.invoke(self, "bindAsNotificationRuleSource", [_scope]))

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the given principal identity permissions to perform the actions on this repository.

        :param grantee: -
        :param actions: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *actions]))

    @jsii.member(jsii_name="grantPull")
    def grant_pull(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPull", [grantee]))

    @jsii.member(jsii_name="grantPullPush")
    def grant_pull_push(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull and push this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPullPush", [grantee]))

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to read this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [grantee]))

    @jsii.member(jsii_name="notifiyOnPullRequestMerged")
    def notifiy_on_pull_request_merged(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a pull request is merged.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifiyOnPullRequestMerged", [id, target, options]))

    @jsii.member(jsii_name="notify")
    def notify(
        self,
        arn: builtins.str,
        *,
        branches: typing.Optional[typing.Sequence[builtins.str]] = None,
        custom_data: typing.Optional[builtins.str] = None,
        events: typing.Optional[typing.Sequence["RepositoryEventTrigger"]] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> "Repository":
        '''Create a trigger to notify another service to run actions on repository events.

        :param arn: Arn of the resource that repository events will notify.
        :param branches: The names of the branches in the AWS CodeCommit repository that contain events that you want to include in the trigger. If you don't specify at least one branch, the trigger applies to all branches.
        :param custom_data: When an event is triggered, additional information that AWS CodeCommit includes when it sends information to the target.
        :param events: The repository events for which AWS CodeCommit sends information to the target, which you specified in the DestinationArn property.If you don't specify events, the trigger runs for all repository events.
        :param name: A name for the trigger.Triggers on a repository must have unique names.
        '''
        options = RepositoryTriggerOptions(
            branches=branches, custom_data=custom_data, events=events, name=name
        )

        return typing.cast("Repository", jsii.invoke(self, "notify", [arn, options]))

    @jsii.member(jsii_name="notifyOn")
    def notify_on(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        events: typing.Sequence["RepositoryNotificationEvents"],
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule triggered when the project events specified by you are emitted. Similar to ``onEvent`` API.

        You can also use the methods to define rules for the specific event emitted.
        eg: ``notifyOnPullRequstCreated``.

        :param id: -
        :param target: -
        :param events: A list of event types associated with this notification rule for CodeCommit repositories. For a complete list of event types and IDs, see Notification concepts in the Developer Tools Console User Guide.
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = RepositoryNotifyOnOptions(
            events=events,
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOn", [id, target, options]))

    @jsii.member(jsii_name="notifyOnApprovalRuleOverridden")
    def notify_on_approval_rule_overridden(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when an approval rule is overridden.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnApprovalRuleOverridden", [id, target, options]))

    @jsii.member(jsii_name="notifyOnApprovalStatusChanged")
    def notify_on_approval_status_changed(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when an approval status is changed.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnApprovalStatusChanged", [id, target, options]))

    @jsii.member(jsii_name="notifyOnBranchOrTagCreated")
    def notify_on_branch_or_tag_created(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a new branch or tag is created.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnBranchOrTagCreated", [id, target, options]))

    @jsii.member(jsii_name="notifyOnBranchOrTagDeleted")
    def notify_on_branch_or_tag_deleted(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a branch or tag is deleted.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnBranchOrTagDeleted", [id, target, options]))

    @jsii.member(jsii_name="notifyOnPullRequestComment")
    def notify_on_pull_request_comment(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a comment is made on a pull request.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnPullRequestComment", [id, target, options]))

    @jsii.member(jsii_name="notifyOnPullRequestCreated")
    def notify_on_pull_request_created(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a pull request is created.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnPullRequestCreated", [id, target, options]))

    @jsii.member(jsii_name="notifyOnPullRequestMerged")
    def notify_on_pull_request_merged(
        self,
        id: builtins.str,
        target: _INotificationRuleTarget_faa3b79b,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
    ) -> _INotificationRule_71939426:
        '''Defines a CodeStar Notification rule which triggers when a pull request is merged.

        :param id: -
        :param target: -
        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        '''
        options = _NotificationRuleOptions_dff73281(
            detail_type=detail_type,
            enabled=enabled,
            notification_rule_name=notification_rule_name,
        )

        return typing.cast(_INotificationRule_71939426, jsii.invoke(self, "notifyOnPullRequestMerged", [id, target, options]))

    @jsii.member(jsii_name="onCommentOnCommit")
    def on_comment_on_commit(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a comment is made on a commit.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCommentOnCommit", [id, options]))

    @jsii.member(jsii_name="onCommentOnPullRequest")
    def on_comment_on_pull_request(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a comment is made on a pull request.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCommentOnPullRequest", [id, options]))

    @jsii.member(jsii_name="onCommit")
    def on_commit(
        self,
        id: builtins.str,
        *,
        branches: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a commit is pushed to a branch.

        :param id: -
        :param branches: The branch to monitor. Default: - All branches
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCommitOptions(
            branches=branches,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCommit", [id, options]))

    @jsii.member(jsii_name="onEvent")
    def on_event(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers for repository events.

        Use
        ``rule.addEventPattern(pattern)`` to specify a filter.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onEvent", [id, options]))

    @jsii.member(jsii_name="onPullRequestStateChange")
    def on_pull_request_state_change(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a pull request state is changed.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onPullRequestStateChange", [id, options]))

    @jsii.member(jsii_name="onReferenceCreated")
    def on_reference_created(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is created (i.e. a new branch/tag is created) to the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onReferenceCreated", [id, options]))

    @jsii.member(jsii_name="onReferenceDeleted")
    def on_reference_deleted(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is delete (i.e. a branch/tag is deleted) from the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onReferenceDeleted", [id, options]))

    @jsii.member(jsii_name="onReferenceUpdated")
    def on_reference_updated(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a reference is updated (i.e. a commit is pushed to an existing or new branch) from the repository.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onReferenceUpdated", [id, options]))

    @jsii.member(jsii_name="onStateChange")
    def on_state_change(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event rule which triggers when a "CodeCommit Repository State Change" event occurs.

        :param id: -
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = _OnEventOptions_8711b8b3(
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onStateChange", [id, options]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryArn")
    def repository_arn(self) -> builtins.str:
        '''The ARN of this Repository.'''
        return typing.cast(builtins.str, jsii.get(self, "repositoryArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlGrc")
    def repository_clone_url_grc(self) -> builtins.str:
        '''The HTTPS (GRC) clone URL.

        HTTPS (GRC) is the protocol to use with git-remote-codecommit (GRC).

        It is the recommended method for supporting connections made with federated
        access, identity providers, and temporary credentials.
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryCloneUrlGrc"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlHttp")
    def repository_clone_url_http(self) -> builtins.str:
        '''The HTTP clone URL.'''
        return typing.cast(builtins.str, jsii.get(self, "repositoryCloneUrlHttp"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCloneUrlSsh")
    def repository_clone_url_ssh(self) -> builtins.str:
        '''The SSH clone URL.'''
        return typing.cast(builtins.str, jsii.get(self, "repositoryCloneUrlSsh"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The human-visible name of this Repository.'''
        return typing.cast(builtins.str, jsii.get(self, "repositoryName"))


@jsii.enum(jsii_type="aws-cdk-lib.aws_codecommit.RepositoryEventTrigger")
class RepositoryEventTrigger(enum.Enum):
    '''Repository events that will cause the trigger to run actions in another service.'''

    ALL = "ALL"
    UPDATE_REF = "UPDATE_REF"
    CREATE_REF = "CREATE_REF"
    DELETE_REF = "DELETE_REF"


@jsii.enum(jsii_type="aws-cdk-lib.aws_codecommit.RepositoryNotificationEvents")
class RepositoryNotificationEvents(enum.Enum):
    '''List of event types for AWS CodeCommit.

    :see: https://docs.aws.amazon.com/dtconsole/latest/userguide/concepts.html#events-ref-repositories
    '''

    COMMIT_COMMENT = "COMMIT_COMMENT"
    '''Trigger notication when comment made on commit.'''
    PULL_REQUEST_COMMENT = "PULL_REQUEST_COMMENT"
    '''Trigger notification when comment made on pull request.'''
    APPROVAL_STATUS_CHANGED = "APPROVAL_STATUS_CHANGED"
    '''Trigger notification when approval status changed.'''
    APPROVAL_RULE_OVERRIDDEN = "APPROVAL_RULE_OVERRIDDEN"
    '''Trigger notifications when approval rule is overridden.'''
    PULL_REQUEST_CREATED = "PULL_REQUEST_CREATED"
    '''Trigger notification when pull request created.'''
    PULL_REQUEST_SOURCE_UPDATED = "PULL_REQUEST_SOURCE_UPDATED"
    '''Trigger notification when pull request source updated.'''
    PULL_REQUEST_STATUS_CHANGED = "PULL_REQUEST_STATUS_CHANGED"
    '''Trigger notification when pull request status is changed.'''
    PULL_REQUEST_MERGED = "PULL_REQUEST_MERGED"
    '''Trigger notification when pull requset is merged.'''
    BRANCH_OR_TAG_CREATED = "BRANCH_OR_TAG_CREATED"
    '''Trigger notification when a branch or tag is created.'''
    BRANCH_OR_TAG_DELETED = "BRANCH_OR_TAG_DELETED"
    '''Trigger notification when a branch or tag is deleted.'''
    BRANCH_OR_TAG_UPDATED = "BRANCH_OR_TAG_UPDATED"
    '''Trigger notification when a branch or tag is updated.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codecommit.RepositoryNotifyOnOptions",
    jsii_struct_bases=[_NotificationRuleOptions_dff73281],
    name_mapping={
        "detail_type": "detailType",
        "enabled": "enabled",
        "notification_rule_name": "notificationRuleName",
        "events": "events",
    },
)
class RepositoryNotifyOnOptions(_NotificationRuleOptions_dff73281):
    def __init__(
        self,
        *,
        detail_type: typing.Optional[_DetailType_cf8135e7] = None,
        enabled: typing.Optional[builtins.bool] = None,
        notification_rule_name: typing.Optional[builtins.str] = None,
        events: typing.Sequence[RepositoryNotificationEvents],
    ) -> None:
        '''Additional options to pass to the notification rule.

        :param detail_type: The level of detail to include in the notifications for this resource. BASIC will include only the contents of the event as it would appear in AWS CloudWatch. FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created. Default: DetailType.FULL
        :param enabled: The status of the notification rule. If the enabled is set to DISABLED, notifications aren't sent for the notification rule. Default: true
        :param notification_rule_name: The name for the notification rule. Notification rule names must be unique in your AWS account. Default: - generated from the ``id``
        :param events: A list of event types associated with this notification rule for CodeCommit repositories. For a complete list of event types and IDs, see Notification concepts in the Developer Tools Console User Guide.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codecommit as codecommit
            from aws_cdk import aws_codestarnotifications as codestarnotifications
            
            repository_notify_on_options = codecommit.RepositoryNotifyOnOptions(
                events=[codecommit.RepositoryNotificationEvents.COMMIT_COMMENT],
            
                # the properties below are optional
                detail_type=codestarnotifications.DetailType.BASIC,
                enabled=False,
                notification_rule_name="notificationRuleName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "events": events,
        }
        if detail_type is not None:
            self._values["detail_type"] = detail_type
        if enabled is not None:
            self._values["enabled"] = enabled
        if notification_rule_name is not None:
            self._values["notification_rule_name"] = notification_rule_name

    @builtins.property
    def detail_type(self) -> typing.Optional[_DetailType_cf8135e7]:
        '''The level of detail to include in the notifications for this resource.

        BASIC will include only the contents of the event as it would appear in AWS CloudWatch.
        FULL will include any supplemental information provided by AWS CodeStar Notifications and/or the service for the resource for which the notification is created.

        :default: DetailType.FULL
        '''
        result = self._values.get("detail_type")
        return typing.cast(typing.Optional[_DetailType_cf8135e7], result)

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''The status of the notification rule.

        If the enabled is set to DISABLED, notifications aren't sent for the notification rule.

        :default: true
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def notification_rule_name(self) -> typing.Optional[builtins.str]:
        '''The name for the notification rule.

        Notification rule names must be unique in your AWS account.

        :default: - generated from the ``id``
        '''
        result = self._values.get("notification_rule_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def events(self) -> typing.List[RepositoryNotificationEvents]:
        '''A list of event types associated with this notification rule for CodeCommit repositories.

        For a complete list of event types and IDs, see Notification concepts in the Developer Tools Console User Guide.

        :see: https://docs.aws.amazon.com/dtconsole/latest/userguide/concepts.html#concepts-api
        '''
        result = self._values.get("events")
        assert result is not None, "Required property 'events' is missing"
        return typing.cast(typing.List[RepositoryNotificationEvents], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RepositoryNotifyOnOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codecommit.RepositoryProps",
    jsii_struct_bases=[],
    name_mapping={
        "repository_name": "repositoryName",
        "code": "code",
        "description": "description",
    },
)
class RepositoryProps:
    def __init__(
        self,
        *,
        repository_name: builtins.str,
        code: typing.Optional[Code] = None,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param repository_name: Name of the repository. This property is required for all CodeCommit repositories.
        :param code: The contents with which to initialize the repository after it has been created. Default: - No initialization (create empty repo)
        :param description: A description of the repository. Use the description to identify the purpose of the repository. Default: - No description.

        :exampleMetadata: lit=aws-codepipeline-actions/test/integ.cfn-template-from-repo.lit.ts infused

        Example::

            # Source stage: read from repository
            repo = codecommit.Repository(stack, "TemplateRepo",
                repository_name="template-repo"
            )
            source_output = codepipeline.Artifact("SourceArtifact")
            source = cpactions.CodeCommitSourceAction(
                action_name="Source",
                repository=repo,
                output=source_output,
                trigger=cpactions.CodeCommitTrigger.POLL
            )
            source_stage = {
                "stage_name": "Source",
                "actions": [source]
            }
            
            # Deployment stage: create and deploy changeset with manual approval
            stack_name = "OurStack"
            change_set_name = "StagedChangeSet"
            
            prod_stage = {
                "stage_name": "Deploy",
                "actions": [
                    cpactions.CloudFormationCreateReplaceChangeSetAction(
                        action_name="PrepareChanges",
                        stack_name=stack_name,
                        change_set_name=change_set_name,
                        admin_permissions=True,
                        template_path=source_output.at_path("template.yaml"),
                        run_order=1
                    ),
                    cpactions.ManualApprovalAction(
                        action_name="ApproveChanges",
                        run_order=2
                    ),
                    cpactions.CloudFormationExecuteChangeSetAction(
                        action_name="ExecuteChanges",
                        stack_name=stack_name,
                        change_set_name=change_set_name,
                        run_order=3
                    )
                ]
            }
            
            codepipeline.Pipeline(stack, "Pipeline",
                stages=[source_stage, prod_stage
                ]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "repository_name": repository_name,
        }
        if code is not None:
            self._values["code"] = code
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def repository_name(self) -> builtins.str:
        '''Name of the repository.

        This property is required for all CodeCommit repositories.
        '''
        result = self._values.get("repository_name")
        assert result is not None, "Required property 'repository_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def code(self) -> typing.Optional[Code]:
        '''The contents with which to initialize the repository after it has been created.

        :default: - No initialization (create empty repo)
        '''
        result = self._values.get("code")
        return typing.cast(typing.Optional[Code], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the repository.

        Use the description to identify the
        purpose of the repository.

        :default: - No description.
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RepositoryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_codecommit.RepositoryTriggerOptions",
    jsii_struct_bases=[],
    name_mapping={
        "branches": "branches",
        "custom_data": "customData",
        "events": "events",
        "name": "name",
    },
)
class RepositoryTriggerOptions:
    def __init__(
        self,
        *,
        branches: typing.Optional[typing.Sequence[builtins.str]] = None,
        custom_data: typing.Optional[builtins.str] = None,
        events: typing.Optional[typing.Sequence[RepositoryEventTrigger]] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Creates for a repository trigger to an SNS topic or Lambda function.

        :param branches: The names of the branches in the AWS CodeCommit repository that contain events that you want to include in the trigger. If you don't specify at least one branch, the trigger applies to all branches.
        :param custom_data: When an event is triggered, additional information that AWS CodeCommit includes when it sends information to the target.
        :param events: The repository events for which AWS CodeCommit sends information to the target, which you specified in the DestinationArn property.If you don't specify events, the trigger runs for all repository events.
        :param name: A name for the trigger.Triggers on a repository must have unique names.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_codecommit as codecommit
            
            repository_trigger_options = codecommit.RepositoryTriggerOptions(
                branches=["branches"],
                custom_data="customData",
                events=[codecommit.RepositoryEventTrigger.ALL],
                name="name"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if branches is not None:
            self._values["branches"] = branches
        if custom_data is not None:
            self._values["custom_data"] = custom_data
        if events is not None:
            self._values["events"] = events
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def branches(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The names of the branches in the AWS CodeCommit repository that contain events that you want to include in the trigger.

        If you don't specify at
        least one branch, the trigger applies to all branches.
        '''
        result = self._values.get("branches")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def custom_data(self) -> typing.Optional[builtins.str]:
        '''When an event is triggered, additional information that AWS CodeCommit includes when it sends information to the target.'''
        result = self._values.get("custom_data")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def events(self) -> typing.Optional[typing.List[RepositoryEventTrigger]]:
        '''The repository events for which AWS CodeCommit sends information to the target, which you specified in the DestinationArn property.If you don't specify events, the trigger runs for all repository events.'''
        result = self._values.get("events")
        return typing.cast(typing.Optional[typing.List[RepositoryEventTrigger]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''A name for the trigger.Triggers on a repository must have unique names.'''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RepositoryTriggerOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnRepository",
    "CfnRepositoryProps",
    "Code",
    "CodeConfig",
    "IRepository",
    "OnCommitOptions",
    "ReferenceEvent",
    "Repository",
    "RepositoryEventTrigger",
    "RepositoryNotificationEvents",
    "RepositoryNotifyOnOptions",
    "RepositoryProps",
    "RepositoryTriggerOptions",
]

publication.publish()
