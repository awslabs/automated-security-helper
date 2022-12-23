'''
# Amazon ECR Construct Library

This package contains constructs for working with Amazon Elastic Container Registry.

## Repositories

Define a repository by creating a new instance of `Repository`. A repository
holds multiple verions of a single container image.

```python
repository = ecr.Repository(self, "Repository")
```

## Image scanning

Amazon ECR image scanning helps in identifying software vulnerabilities in your container images. You can manually scan container images stored in Amazon ECR, or you can configure your repositories to scan images when you push them to a repository. To create a new repository to scan on push, simply enable `imageScanOnPush` in the properties

```python
repository = ecr.Repository(self, "Repo",
    image_scan_on_push=True
)
```

To create an `onImageScanCompleted` event rule and trigger the event target

```python
# repository: ecr.Repository
# target: SomeTarget


repository.on_image_scan_completed("ImageScanComplete").add_target(target)
```

### Authorization Token

Besides the Amazon ECR APIs, ECR also allows the Docker CLI or a language-specific Docker library to push and pull
images from an ECR repository. However, the Docker CLI does not support native IAM authentication methods and
additional steps must be taken so that Amazon ECR can authenticate and authorize Docker push and pull requests.
More information can be found at at [Registry Authentication](https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html#registry_auth).

A Docker authorization token can be obtained using the `GetAuthorizationToken` ECR API. The following code snippets
grants an IAM user access to call this API.

```python
user = iam.User(self, "User")
ecr.AuthorizationToken.grant_read(user)
```

If you access images in the [Public ECR Gallery](https://gallery.ecr.aws/) as well, it is recommended you authenticate to the registry to benefit from
higher rate and bandwidth limits.

> See `Pricing` in https://aws.amazon.com/blogs/aws/amazon-ecr-public-a-new-public-container-registry/ and [Service quotas](https://docs.aws.amazon.com/AmazonECR/latest/public/public-service-quotas.html).

The following code snippet grants an IAM user access to retrieve an authorization token for the public gallery.

```python
user = iam.User(self, "User")
ecr.PublicGalleryAuthorizationToken.grant_read(user)
```

This user can then proceed to login to the registry using one of the [authentication methods](https://docs.aws.amazon.com/AmazonECR/latest/public/public-registries.html#public-registry-auth).

### Image tag immutability

You can set tag immutability on images in our repository using the `imageTagMutability` construct prop.

```python
ecr.Repository(self, "Repo", image_tag_mutability=ecr.TagMutability.IMMUTABLE)
```

### Encryption

By default, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts your data at rest using an AES-256 encryption algorithm. For more control over the encryption for your Amazon ECR repositories, you can use server-side encryption with KMS keys stored in AWS Key Management Service (AWS KMS). Read more about this feature in the [ECR Developer Guide](https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html).

When you use AWS KMS to encrypt your data, you can either use the default AWS managed key, which is managed by Amazon ECR, by specifying `RepositoryEncryption.KMS` in the `encryption` property. Or specify your own customer managed KMS key, by specifying the `encryptionKey` property.

When `encryptionKey` is set, the `encryption` property must be `KMS` or empty.

In the case `encryption` is set to `KMS` but no `encryptionKey` is set, an AWS managed KMS key is used.

```python
ecr.Repository(self, "Repo",
    encryption=ecr.RepositoryEncryption.KMS
)
```

Otherwise, a customer-managed KMS key is used if `encryptionKey` was set and `encryption` was optionally set to `KMS`.

```python
import aws_cdk.aws_kms as kms


ecr.Repository(self, "Repo",
    encryption_key=kms.Key(self, "Key")
)
```

## Automatically clean up repositories

You can set life cycle rules to automatically clean up old images from your
repository. The first life cycle rule that matches an image will be applied
against that image. For example, the following deletes images older than
30 days, while keeping all images tagged with prod (note that the order
is important here):

```python
# repository: ecr.Repository

repository.add_lifecycle_rule(tag_prefix_list=["prod"], max_image_count=9999)
repository.add_lifecycle_rule(max_image_age=Duration.days(30))
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
    RemovalPolicy as _RemovalPolicy_9f93c814,
    Resource as _Resource_45bc6135,
    ResourceProps as _ResourceProps_15a65b4e,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_events import (
    EventPattern as _EventPattern_fe557901,
    IRuleTarget as _IRuleTarget_7a91f454,
    OnEventOptions as _OnEventOptions_8711b8b3,
    Rule as _Rule_334ed2b5,
)
from ..aws_iam import (
    AddToResourcePolicyResult as _AddToResourcePolicyResult_1d0a53ad,
    Grant as _Grant_a7ae64f8,
    IGrantable as _IGrantable_71c4f5de,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_kms import IKey as _IKey_5f11635f


class AuthorizationToken(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.AuthorizationToken",
):
    '''Authorization token to access private ECR repositories in the current environment via Docker CLI.

    :see: https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html
    :exampleMetadata: infused

    Example::

        user = iam.User(self, "User")
        ecr.AuthorizationToken.grant_read(user)
    '''

    @jsii.member(jsii_name="grantRead") # type: ignore[misc]
    @builtins.classmethod
    def grant_read(cls, grantee: _IGrantable_71c4f5de) -> None:
        '''Grant access to retrieve an authorization token.

        :param grantee: -
        '''
        return typing.cast(None, jsii.sinvoke(cls, "grantRead", [grantee]))


@jsii.implements(_IInspectable_c2943556)
class CfnPublicRepository(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.CfnPublicRepository",
):
    '''A CloudFormation ``AWS::ECR::PublicRepository``.

    The ``AWS::ECR::PublicRepository`` resource specifies an Amazon Elastic Container Registry Public (Amazon ECR Public) repository, where users can push and pull Docker images, Open Container Initiative (OCI) images, and OCI compatible artifacts. For more information, see `Amazon ECR public repositories <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repositories.html>`_ in the *Amazon ECR Public User Guide* .

    :cloudformationResource: AWS::ECR::PublicRepository
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ecr as ecr
        
        # repository_catalog_data: Any
        # repository_policy_text: Any
        
        cfn_public_repository = ecr.CfnPublicRepository(self, "MyCfnPublicRepository",
            repository_catalog_data=repository_catalog_data,
            repository_name="repositoryName",
            repository_policy_text=repository_policy_text,
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
        repository_catalog_data: typing.Any = None,
        repository_name: typing.Optional[builtins.str] = None,
        repository_policy_text: typing.Any = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::ECR::PublicRepository``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param repository_catalog_data: The details about the repository that are publicly visible in the Amazon ECR Public Gallery. For more information, see `Amazon ECR Public repository catalog data <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-catalog-data.html>`_ in the *Amazon ECR Public User Guide* .
        :param repository_name: The name to use for the public repository. The repository name may be specified on its own (such as ``nginx-web-app`` ) or it can be prepended with a namespace to group the repository into a category (such as ``project-a/nginx-web-app`` ). If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the repository name. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.
        :param repository_policy_text: The JSON repository policy text to apply to the public repository. For more information, see `Amazon ECR Public repository policies <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html>`_ in the *Amazon ECR Public User Guide* .
        :param tags: An array of key-value pairs to apply to this resource.
        '''
        props = CfnPublicRepositoryProps(
            repository_catalog_data=repository_catalog_data,
            repository_name=repository_name,
            repository_policy_text=repository_policy_text,
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
        '''Returns the Amazon Resource Name (ARN) for the specified ``AWS::ECR::PublicRepository`` resource.

        For example, ``arn:aws:ecr-public:: *123456789012* :repository/ *test-repository*`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html#cfn-ecr-publicrepository-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryCatalogData")
    def repository_catalog_data(self) -> typing.Any:
        '''The details about the repository that are publicly visible in the Amazon ECR Public Gallery.

        For more information, see `Amazon ECR Public repository catalog data <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-catalog-data.html>`_ in the *Amazon ECR Public User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html#cfn-ecr-publicrepository-repositorycatalogdata
        '''
        return typing.cast(typing.Any, jsii.get(self, "repositoryCatalogData"))

    @repository_catalog_data.setter
    def repository_catalog_data(self, value: typing.Any) -> None:
        jsii.set(self, "repositoryCatalogData", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryPolicyText")
    def repository_policy_text(self) -> typing.Any:
        '''The JSON repository policy text to apply to the public repository.

        For more information, see `Amazon ECR Public repository policies <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html>`_ in the *Amazon ECR Public User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html#cfn-ecr-publicrepository-repositorypolicytext
        '''
        return typing.cast(typing.Any, jsii.get(self, "repositoryPolicyText"))

    @repository_policy_text.setter
    def repository_policy_text(self, value: typing.Any) -> None:
        jsii.set(self, "repositoryPolicyText", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> typing.Optional[builtins.str]:
        '''The name to use for the public repository.

        The repository name may be specified on its own (such as ``nginx-web-app`` ) or it can be prepended with a namespace to group the repository into a category (such as ``project-a/nginx-web-app`` ). If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the repository name. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html#cfn-ecr-publicrepository-repositoryname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "repositoryName"))

    @repository_name.setter
    def repository_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "repositoryName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.CfnPublicRepositoryProps",
    jsii_struct_bases=[],
    name_mapping={
        "repository_catalog_data": "repositoryCatalogData",
        "repository_name": "repositoryName",
        "repository_policy_text": "repositoryPolicyText",
        "tags": "tags",
    },
)
class CfnPublicRepositoryProps:
    def __init__(
        self,
        *,
        repository_catalog_data: typing.Any = None,
        repository_name: typing.Optional[builtins.str] = None,
        repository_policy_text: typing.Any = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPublicRepository``.

        :param repository_catalog_data: The details about the repository that are publicly visible in the Amazon ECR Public Gallery. For more information, see `Amazon ECR Public repository catalog data <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-catalog-data.html>`_ in the *Amazon ECR Public User Guide* .
        :param repository_name: The name to use for the public repository. The repository name may be specified on its own (such as ``nginx-web-app`` ) or it can be prepended with a namespace to group the repository into a category (such as ``project-a/nginx-web-app`` ). If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the repository name. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.
        :param repository_policy_text: The JSON repository policy text to apply to the public repository. For more information, see `Amazon ECR Public repository policies <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html>`_ in the *Amazon ECR Public User Guide* .
        :param tags: An array of key-value pairs to apply to this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ecr as ecr
            
            # repository_catalog_data: Any
            # repository_policy_text: Any
            
            cfn_public_repository_props = ecr.CfnPublicRepositoryProps(
                repository_catalog_data=repository_catalog_data,
                repository_name="repositoryName",
                repository_policy_text=repository_policy_text,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if repository_catalog_data is not None:
            self._values["repository_catalog_data"] = repository_catalog_data
        if repository_name is not None:
            self._values["repository_name"] = repository_name
        if repository_policy_text is not None:
            self._values["repository_policy_text"] = repository_policy_text
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def repository_catalog_data(self) -> typing.Any:
        '''The details about the repository that are publicly visible in the Amazon ECR Public Gallery.

        For more information, see `Amazon ECR Public repository catalog data <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-catalog-data.html>`_ in the *Amazon ECR Public User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html#cfn-ecr-publicrepository-repositorycatalogdata
        '''
        result = self._values.get("repository_catalog_data")
        return typing.cast(typing.Any, result)

    @builtins.property
    def repository_name(self) -> typing.Optional[builtins.str]:
        '''The name to use for the public repository.

        The repository name may be specified on its own (such as ``nginx-web-app`` ) or it can be prepended with a namespace to group the repository into a category (such as ``project-a/nginx-web-app`` ). If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the repository name. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html#cfn-ecr-publicrepository-repositoryname
        '''
        result = self._values.get("repository_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def repository_policy_text(self) -> typing.Any:
        '''The JSON repository policy text to apply to the public repository.

        For more information, see `Amazon ECR Public repository policies <https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html>`_ in the *Amazon ECR Public User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html#cfn-ecr-publicrepository-repositorypolicytext
        '''
        result = self._values.get("repository_policy_text")
        return typing.cast(typing.Any, result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-publicrepository.html#cfn-ecr-publicrepository-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPublicRepositoryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPullThroughCacheRule(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.CfnPullThroughCacheRule",
):
    '''A CloudFormation ``AWS::ECR::PullThroughCacheRule``.

    Creates a pull through cache rule. A pull through cache rule provides a way to cache images from an external public registry in your Amazon ECR private registry.

    :cloudformationResource: AWS::ECR::PullThroughCacheRule
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-pullthroughcacherule.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ecr as ecr
        
        cfn_pull_through_cache_rule = ecr.CfnPullThroughCacheRule(self, "MyCfnPullThroughCacheRule",
            ecr_repository_prefix="ecrRepositoryPrefix",
            upstream_registry_url="upstreamRegistryUrl"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        ecr_repository_prefix: typing.Optional[builtins.str] = None,
        upstream_registry_url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ECR::PullThroughCacheRule``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param ecr_repository_prefix: The Amazon ECR repository prefix associated with the pull through cache rule.
        :param upstream_registry_url: The upstream registry URL associated with the pull through cache rule.
        '''
        props = CfnPullThroughCacheRuleProps(
            ecr_repository_prefix=ecr_repository_prefix,
            upstream_registry_url=upstream_registry_url,
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
    @jsii.member(jsii_name="ecrRepositoryPrefix")
    def ecr_repository_prefix(self) -> typing.Optional[builtins.str]:
        '''The Amazon ECR repository prefix associated with the pull through cache rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-pullthroughcacherule.html#cfn-ecr-pullthroughcacherule-ecrrepositoryprefix
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "ecrRepositoryPrefix"))

    @ecr_repository_prefix.setter
    def ecr_repository_prefix(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "ecrRepositoryPrefix", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="upstreamRegistryUrl")
    def upstream_registry_url(self) -> typing.Optional[builtins.str]:
        '''The upstream registry URL associated with the pull through cache rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-pullthroughcacherule.html#cfn-ecr-pullthroughcacherule-upstreamregistryurl
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "upstreamRegistryUrl"))

    @upstream_registry_url.setter
    def upstream_registry_url(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "upstreamRegistryUrl", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.CfnPullThroughCacheRuleProps",
    jsii_struct_bases=[],
    name_mapping={
        "ecr_repository_prefix": "ecrRepositoryPrefix",
        "upstream_registry_url": "upstreamRegistryUrl",
    },
)
class CfnPullThroughCacheRuleProps:
    def __init__(
        self,
        *,
        ecr_repository_prefix: typing.Optional[builtins.str] = None,
        upstream_registry_url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnPullThroughCacheRule``.

        :param ecr_repository_prefix: The Amazon ECR repository prefix associated with the pull through cache rule.
        :param upstream_registry_url: The upstream registry URL associated with the pull through cache rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-pullthroughcacherule.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ecr as ecr
            
            cfn_pull_through_cache_rule_props = ecr.CfnPullThroughCacheRuleProps(
                ecr_repository_prefix="ecrRepositoryPrefix",
                upstream_registry_url="upstreamRegistryUrl"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if ecr_repository_prefix is not None:
            self._values["ecr_repository_prefix"] = ecr_repository_prefix
        if upstream_registry_url is not None:
            self._values["upstream_registry_url"] = upstream_registry_url

    @builtins.property
    def ecr_repository_prefix(self) -> typing.Optional[builtins.str]:
        '''The Amazon ECR repository prefix associated with the pull through cache rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-pullthroughcacherule.html#cfn-ecr-pullthroughcacherule-ecrrepositoryprefix
        '''
        result = self._values.get("ecr_repository_prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def upstream_registry_url(self) -> typing.Optional[builtins.str]:
        '''The upstream registry URL associated with the pull through cache rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-pullthroughcacherule.html#cfn-ecr-pullthroughcacherule-upstreamregistryurl
        '''
        result = self._values.get("upstream_registry_url")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPullThroughCacheRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRegistryPolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.CfnRegistryPolicy",
):
    '''A CloudFormation ``AWS::ECR::RegistryPolicy``.

    The ``AWS::ECR::RegistryPolicy`` resource creates or updates the permissions policy for a private registry.

    A private registry policy is used to specify permissions for another AWS account and is used when configuring cross-account replication. For more information, see `Registry permissions <https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html>`_ in the *Amazon Elastic Container Registry User Guide* .

    :cloudformationResource: AWS::ECR::RegistryPolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-registrypolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ecr as ecr
        
        # policy_text: Any
        
        cfn_registry_policy = ecr.CfnRegistryPolicy(self, "MyCfnRegistryPolicy",
            policy_text=policy_text
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        policy_text: typing.Any,
    ) -> None:
        '''Create a new ``AWS::ECR::RegistryPolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param policy_text: The JSON policy text for your registry.
        '''
        props = CfnRegistryPolicyProps(policy_text=policy_text)

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
    @jsii.member(jsii_name="attrRegistryId")
    def attr_registry_id(self) -> builtins.str:
        '''The account ID of the private registry the policy is associated with.

        :cloudformationAttribute: RegistryId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRegistryId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyText")
    def policy_text(self) -> typing.Any:
        '''The JSON policy text for your registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-registrypolicy.html#cfn-ecr-registrypolicy-policytext
        '''
        return typing.cast(typing.Any, jsii.get(self, "policyText"))

    @policy_text.setter
    def policy_text(self, value: typing.Any) -> None:
        jsii.set(self, "policyText", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.CfnRegistryPolicyProps",
    jsii_struct_bases=[],
    name_mapping={"policy_text": "policyText"},
)
class CfnRegistryPolicyProps:
    def __init__(self, *, policy_text: typing.Any) -> None:
        '''Properties for defining a ``CfnRegistryPolicy``.

        :param policy_text: The JSON policy text for your registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-registrypolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ecr as ecr
            
            # policy_text: Any
            
            cfn_registry_policy_props = ecr.CfnRegistryPolicyProps(
                policy_text=policy_text
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "policy_text": policy_text,
        }

    @builtins.property
    def policy_text(self) -> typing.Any:
        '''The JSON policy text for your registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-registrypolicy.html#cfn-ecr-registrypolicy-policytext
        '''
        result = self._values.get("policy_text")
        assert result is not None, "Required property 'policy_text' is missing"
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRegistryPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnReplicationConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.CfnReplicationConfiguration",
):
    '''A CloudFormation ``AWS::ECR::ReplicationConfiguration``.

    The ``AWS::ECR::ReplicationConfiguration`` resource creates or updates the replication configuration for a private registry. The first time a replication configuration is applied to a private registry, a service-linked IAM role is created in your account for the replication process. For more information, see `Using Service-Linked Roles for Amazon ECR <https://docs.aws.amazon.com/AmazonECR/latest/userguide/using-service-linked-roles.html>`_ in the *Amazon Elastic Container Registry User Guide* .
    .. epigraph::

       When configuring cross-account replication, the destination account must grant the source account permission to replicate. This permission is controlled using a private registry permissions policy. For more information, see ``AWS::ECR::RegistryPolicy`` .

    :cloudformationResource: AWS::ECR::ReplicationConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-replicationconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ecr as ecr
        
        cfn_replication_configuration = ecr.CfnReplicationConfiguration(self, "MyCfnReplicationConfiguration",
            replication_configuration=ecr.CfnReplicationConfiguration.ReplicationConfigurationProperty(
                rules=[ecr.CfnReplicationConfiguration.ReplicationRuleProperty(
                    destinations=[ecr.CfnReplicationConfiguration.ReplicationDestinationProperty(
                        region="region",
                        registry_id="registryId"
                    )],
        
                    # the properties below are optional
                    repository_filters=[ecr.CfnReplicationConfiguration.RepositoryFilterProperty(
                        filter="filter",
                        filter_type="filterType"
                    )]
                )]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        replication_configuration: typing.Union["CfnReplicationConfiguration.ReplicationConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::ECR::ReplicationConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param replication_configuration: The replication configuration for a registry.
        '''
        props = CfnReplicationConfigurationProps(
            replication_configuration=replication_configuration
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
    @jsii.member(jsii_name="attrRegistryId")
    def attr_registry_id(self) -> builtins.str:
        '''The account ID of the destination registry.

        :cloudformationAttribute: RegistryId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRegistryId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationConfiguration")
    def replication_configuration(
        self,
    ) -> typing.Union["CfnReplicationConfiguration.ReplicationConfigurationProperty", _IResolvable_da3f097b]:
        '''The replication configuration for a registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-replicationconfiguration.html#cfn-ecr-replicationconfiguration-replicationconfiguration
        '''
        return typing.cast(typing.Union["CfnReplicationConfiguration.ReplicationConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "replicationConfiguration"))

    @replication_configuration.setter
    def replication_configuration(
        self,
        value: typing.Union["CfnReplicationConfiguration.ReplicationConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "replicationConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ecr.CfnReplicationConfiguration.ReplicationConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"rules": "rules"},
    )
    class ReplicationConfigurationProperty:
        def __init__(
            self,
            *,
            rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnReplicationConfiguration.ReplicationRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''The replication configuration for a registry.

            :param rules: An array of objects representing the replication destinations and repository filters for a replication configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-replicationconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ecr as ecr
                
                replication_configuration_property = ecr.CfnReplicationConfiguration.ReplicationConfigurationProperty(
                    rules=[ecr.CfnReplicationConfiguration.ReplicationRuleProperty(
                        destinations=[ecr.CfnReplicationConfiguration.ReplicationDestinationProperty(
                            region="region",
                            registry_id="registryId"
                        )],
                
                        # the properties below are optional
                        repository_filters=[ecr.CfnReplicationConfiguration.RepositoryFilterProperty(
                            filter="filter",
                            filter_type="filterType"
                        )]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "rules": rules,
            }

        @builtins.property
        def rules(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationConfiguration.ReplicationRuleProperty", _IResolvable_da3f097b]]]:
            '''An array of objects representing the replication destinations and repository filters for a replication configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-replicationconfiguration.html#cfn-ecr-replicationconfiguration-replicationconfiguration-rules
            '''
            result = self._values.get("rules")
            assert result is not None, "Required property 'rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationConfiguration.ReplicationRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ecr.CfnReplicationConfiguration.ReplicationDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={"region": "region", "registry_id": "registryId"},
    )
    class ReplicationDestinationProperty:
        def __init__(self, *, region: builtins.str, registry_id: builtins.str) -> None:
            '''An array of objects representing the destination for a replication rule.

            :param region: The Region to replicate to.
            :param registry_id: The AWS account ID of the Amazon ECR private registry to replicate to. When configuring cross-Region replication within your own registry, specify your own account ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-replicationdestination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ecr as ecr
                
                replication_destination_property = ecr.CfnReplicationConfiguration.ReplicationDestinationProperty(
                    region="region",
                    registry_id="registryId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "region": region,
                "registry_id": registry_id,
            }

        @builtins.property
        def region(self) -> builtins.str:
            '''The Region to replicate to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-replicationdestination.html#cfn-ecr-replicationconfiguration-replicationdestination-region
            '''
            result = self._values.get("region")
            assert result is not None, "Required property 'region' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def registry_id(self) -> builtins.str:
            '''The AWS account ID of the Amazon ECR private registry to replicate to.

            When configuring cross-Region replication within your own registry, specify your own account ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-replicationdestination.html#cfn-ecr-replicationconfiguration-replicationdestination-registryid
            '''
            result = self._values.get("registry_id")
            assert result is not None, "Required property 'registry_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ecr.CfnReplicationConfiguration.ReplicationRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destinations": "destinations",
            "repository_filters": "repositoryFilters",
        },
    )
    class ReplicationRuleProperty:
        def __init__(
            self,
            *,
            destinations: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnReplicationConfiguration.ReplicationDestinationProperty", _IResolvable_da3f097b]]],
            repository_filters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnReplicationConfiguration.RepositoryFilterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''An array of objects representing the replication destinations and repository filters for a replication configuration.

            :param destinations: An array of objects representing the destination for a replication rule.
            :param repository_filters: An array of objects representing the filters for a replication rule. Specifying a repository filter for a replication rule provides a method for controlling which repositories in a private registry are replicated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-replicationrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ecr as ecr
                
                replication_rule_property = ecr.CfnReplicationConfiguration.ReplicationRuleProperty(
                    destinations=[ecr.CfnReplicationConfiguration.ReplicationDestinationProperty(
                        region="region",
                        registry_id="registryId"
                    )],
                
                    # the properties below are optional
                    repository_filters=[ecr.CfnReplicationConfiguration.RepositoryFilterProperty(
                        filter="filter",
                        filter_type="filterType"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destinations": destinations,
            }
            if repository_filters is not None:
                self._values["repository_filters"] = repository_filters

        @builtins.property
        def destinations(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationConfiguration.ReplicationDestinationProperty", _IResolvable_da3f097b]]]:
            '''An array of objects representing the destination for a replication rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-replicationrule.html#cfn-ecr-replicationconfiguration-replicationrule-destinations
            '''
            result = self._values.get("destinations")
            assert result is not None, "Required property 'destinations' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationConfiguration.ReplicationDestinationProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def repository_filters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationConfiguration.RepositoryFilterProperty", _IResolvable_da3f097b]]]]:
            '''An array of objects representing the filters for a replication rule.

            Specifying a repository filter for a replication rule provides a method for controlling which repositories in a private registry are replicated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-replicationrule.html#cfn-ecr-replicationconfiguration-replicationrule-repositoryfilters
            '''
            result = self._values.get("repository_filters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnReplicationConfiguration.RepositoryFilterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ecr.CfnReplicationConfiguration.RepositoryFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"filter": "filter", "filter_type": "filterType"},
    )
    class RepositoryFilterProperty:
        def __init__(self, *, filter: builtins.str, filter_type: builtins.str) -> None:
            '''The filter settings used with image replication.

            Specifying a repository filter to a replication rule provides a method for controlling which repositories in a private registry are replicated. If no repository filter is specified, all images in the repository are replicated.

            :param filter: The repository filter details. When the ``PREFIX_MATCH`` filter type is specified, this value is required and should be the repository name prefix to configure replication for.
            :param filter_type: The repository filter type. The only supported value is ``PREFIX_MATCH`` , which is a repository name prefix specified with the ``filter`` parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-repositoryfilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ecr as ecr
                
                repository_filter_property = ecr.CfnReplicationConfiguration.RepositoryFilterProperty(
                    filter="filter",
                    filter_type="filterType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "filter": filter,
                "filter_type": filter_type,
            }

        @builtins.property
        def filter(self) -> builtins.str:
            '''The repository filter details.

            When the ``PREFIX_MATCH`` filter type is specified, this value is required and should be the repository name prefix to configure replication for.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-repositoryfilter.html#cfn-ecr-replicationconfiguration-repositoryfilter-filter
            '''
            result = self._values.get("filter")
            assert result is not None, "Required property 'filter' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def filter_type(self) -> builtins.str:
            '''The repository filter type.

            The only supported value is ``PREFIX_MATCH`` , which is a repository name prefix specified with the ``filter`` parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-replicationconfiguration-repositoryfilter.html#cfn-ecr-replicationconfiguration-repositoryfilter-filtertype
            '''
            result = self._values.get("filter_type")
            assert result is not None, "Required property 'filter_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RepositoryFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.CfnReplicationConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={"replication_configuration": "replicationConfiguration"},
)
class CfnReplicationConfigurationProps:
    def __init__(
        self,
        *,
        replication_configuration: typing.Union[CfnReplicationConfiguration.ReplicationConfigurationProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnReplicationConfiguration``.

        :param replication_configuration: The replication configuration for a registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-replicationconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ecr as ecr
            
            cfn_replication_configuration_props = ecr.CfnReplicationConfigurationProps(
                replication_configuration=ecr.CfnReplicationConfiguration.ReplicationConfigurationProperty(
                    rules=[ecr.CfnReplicationConfiguration.ReplicationRuleProperty(
                        destinations=[ecr.CfnReplicationConfiguration.ReplicationDestinationProperty(
                            region="region",
                            registry_id="registryId"
                        )],
            
                        # the properties below are optional
                        repository_filters=[ecr.CfnReplicationConfiguration.RepositoryFilterProperty(
                            filter="filter",
                            filter_type="filterType"
                        )]
                    )]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "replication_configuration": replication_configuration,
        }

    @builtins.property
    def replication_configuration(
        self,
    ) -> typing.Union[CfnReplicationConfiguration.ReplicationConfigurationProperty, _IResolvable_da3f097b]:
        '''The replication configuration for a registry.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-replicationconfiguration.html#cfn-ecr-replicationconfiguration-replicationconfiguration
        '''
        result = self._values.get("replication_configuration")
        assert result is not None, "Required property 'replication_configuration' is missing"
        return typing.cast(typing.Union[CfnReplicationConfiguration.ReplicationConfigurationProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnReplicationConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRepository(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.CfnRepository",
):
    '''A CloudFormation ``AWS::ECR::Repository``.

    The ``AWS::ECR::Repository`` resource specifies an Amazon Elastic Container Registry (Amazon ECR) repository, where users can push and pull Docker images, Open Container Initiative (OCI) images, and OCI compatible artifacts. For more information, see `Amazon ECR private repositories <https://docs.aws.amazon.com/AmazonECR/latest/userguide/Repositories.html>`_ in the *Amazon ECR User Guide* .

    :cloudformationResource: AWS::ECR::Repository
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ecr as ecr
        
        # repository_policy_text: Any
        
        cfn_repository = ecr.CfnRepository(self, "MyCfnRepository",
            encryption_configuration=ecr.CfnRepository.EncryptionConfigurationProperty(
                encryption_type="encryptionType",
        
                # the properties below are optional
                kms_key="kmsKey"
            ),
            image_scanning_configuration=ecr.CfnRepository.ImageScanningConfigurationProperty(
                scan_on_push=False
            ),
            image_tag_mutability="imageTagMutability",
            lifecycle_policy=ecr.CfnRepository.LifecyclePolicyProperty(
                lifecycle_policy_text="lifecyclePolicyText",
                registry_id="registryId"
            ),
            repository_name="repositoryName",
            repository_policy_text=repository_policy_text,
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
        encryption_configuration: typing.Optional[typing.Union["CfnRepository.EncryptionConfigurationProperty", _IResolvable_da3f097b]] = None,
        image_scanning_configuration: typing.Optional[typing.Union["CfnRepository.ImageScanningConfigurationProperty", _IResolvable_da3f097b]] = None,
        image_tag_mutability: typing.Optional[builtins.str] = None,
        lifecycle_policy: typing.Optional[typing.Union["CfnRepository.LifecyclePolicyProperty", _IResolvable_da3f097b]] = None,
        repository_name: typing.Optional[builtins.str] = None,
        repository_policy_text: typing.Any = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::ECR::Repository``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param encryption_configuration: The encryption configuration for the repository. This determines how the contents of your repository are encrypted at rest.
        :param image_scanning_configuration: The image scanning configuration for the repository. This determines whether images are scanned for known vulnerabilities after being pushed to the repository.
        :param image_tag_mutability: The tag mutability setting for the repository. If this parameter is omitted, the default setting of ``MUTABLE`` will be used which will allow image tags to be overwritten. If ``IMMUTABLE`` is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.
        :param lifecycle_policy: Creates or updates a lifecycle policy. For information about lifecycle policy syntax, see `Lifecycle policy template <https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html>`_ .
        :param repository_name: The name to use for the repository. The repository name may be specified on its own (such as ``nginx-web-app`` ) or it can be prepended with a namespace to group the repository into a category (such as ``project-a/nginx-web-app`` ). If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the repository name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.
        :param repository_policy_text: The JSON repository policy text to apply to the repository. For more information, see `Amazon ECR repository policies <https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html>`_ in the *Amazon Elastic Container Registry User Guide* .
        :param tags: An array of key-value pairs to apply to this resource.
        '''
        props = CfnRepositoryProps(
            encryption_configuration=encryption_configuration,
            image_scanning_configuration=image_scanning_configuration,
            image_tag_mutability=image_tag_mutability,
            lifecycle_policy=lifecycle_policy,
            repository_name=repository_name,
            repository_policy_text=repository_policy_text,
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
        '''Returns the Amazon Resource Name (ARN) for the specified ``AWS::ECR::Repository`` resource.

        For example, ``arn:aws:ecr: *eu-west-1* : *123456789012* :repository/ *test-repository*`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRepositoryUri")
    def attr_repository_uri(self) -> builtins.str:
        '''Returns the URI for the specified ``AWS::ECR::Repository`` resource.

        For example, ``*123456789012* .dkr.ecr. *us-west-2* .amazonaws.com/repository`` .

        :cloudformationAttribute: RepositoryUri
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRepositoryUri"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryPolicyText")
    def repository_policy_text(self) -> typing.Any:
        '''The JSON repository policy text to apply to the repository.

        For more information, see `Amazon ECR repository policies <https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html>`_ in the *Amazon Elastic Container Registry User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-repositorypolicytext
        '''
        return typing.cast(typing.Any, jsii.get(self, "repositoryPolicyText"))

    @repository_policy_text.setter
    def repository_policy_text(self, value: typing.Any) -> None:
        jsii.set(self, "repositoryPolicyText", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionConfiguration")
    def encryption_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnRepository.EncryptionConfigurationProperty", _IResolvable_da3f097b]]:
        '''The encryption configuration for the repository.

        This determines how the contents of your repository are encrypted at rest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-encryptionconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnRepository.EncryptionConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "encryptionConfiguration"))

    @encryption_configuration.setter
    def encryption_configuration(
        self,
        value: typing.Optional[typing.Union["CfnRepository.EncryptionConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "encryptionConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageScanningConfiguration")
    def image_scanning_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnRepository.ImageScanningConfigurationProperty", _IResolvable_da3f097b]]:
        '''The image scanning configuration for the repository.

        This determines whether images are scanned for known vulnerabilities after being pushed to the repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagescanningconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnRepository.ImageScanningConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "imageScanningConfiguration"))

    @image_scanning_configuration.setter
    def image_scanning_configuration(
        self,
        value: typing.Optional[typing.Union["CfnRepository.ImageScanningConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "imageScanningConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageTagMutability")
    def image_tag_mutability(self) -> typing.Optional[builtins.str]:
        '''The tag mutability setting for the repository.

        If this parameter is omitted, the default setting of ``MUTABLE`` will be used which will allow image tags to be overwritten. If ``IMMUTABLE`` is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "imageTagMutability"))

    @image_tag_mutability.setter
    def image_tag_mutability(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "imageTagMutability", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lifecyclePolicy")
    def lifecycle_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnRepository.LifecyclePolicyProperty", _IResolvable_da3f097b]]:
        '''Creates or updates a lifecycle policy.

        For information about lifecycle policy syntax, see `Lifecycle policy template <https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-lifecyclepolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnRepository.LifecyclePolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "lifecyclePolicy"))

    @lifecycle_policy.setter
    def lifecycle_policy(
        self,
        value: typing.Optional[typing.Union["CfnRepository.LifecyclePolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "lifecyclePolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> typing.Optional[builtins.str]:
        '''The name to use for the repository.

        The repository name may be specified on its own (such as ``nginx-web-app`` ) or it can be prepended with a namespace to group the repository into a category (such as ``project-a/nginx-web-app`` ). If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the repository name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-repositoryname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "repositoryName"))

    @repository_name.setter
    def repository_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "repositoryName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ecr.CfnRepository.EncryptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"encryption_type": "encryptionType", "kms_key": "kmsKey"},
    )
    class EncryptionConfigurationProperty:
        def __init__(
            self,
            *,
            encryption_type: builtins.str,
            kms_key: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The encryption configuration for the repository. This determines how the contents of your repository are encrypted at rest.

            By default, when no encryption configuration is set or the ``AES256`` encryption type is used, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts your data at rest using an AES-256 encryption algorithm. This does not require any action on your part.

            For more control over the encryption of the contents of your repository, you can use server-side encryption with AWS Key Management Service key stored in AWS Key Management Service ( AWS KMS ) to encrypt your images. For more information, see `Amazon ECR encryption at rest <https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html>`_ in the *Amazon Elastic Container Registry User Guide* .

            :param encryption_type: The encryption type to use. If you use the ``KMS`` encryption type, the contents of the repository will be encrypted using server-side encryption with AWS Key Management Service key stored in AWS KMS . When you use AWS KMS to encrypt your data, you can either use the default AWS managed AWS KMS key for Amazon ECR, or specify your own AWS KMS key, which you already created. For more information, see `Protecting data using server-side encryption with an AWS KMS key stored in AWS Key Management Service (SSE-KMS) <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html>`_ in the *Amazon Simple Storage Service Console Developer Guide* . If you use the ``AES256`` encryption type, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts the images in the repository using an AES-256 encryption algorithm. For more information, see `Protecting data using server-side encryption with Amazon S3-managed encryption keys (SSE-S3) <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html>`_ in the *Amazon Simple Storage Service Console Developer Guide* .
            :param kms_key: If you use the ``KMS`` encryption type, specify the AWS KMS key to use for encryption. The alias, key ID, or full ARN of the AWS KMS key can be specified. The key must exist in the same Region as the repository. If no key is specified, the default AWS managed AWS KMS key for Amazon ECR will be used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-encryptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ecr as ecr
                
                encryption_configuration_property = ecr.CfnRepository.EncryptionConfigurationProperty(
                    encryption_type="encryptionType",
                
                    # the properties below are optional
                    kms_key="kmsKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "encryption_type": encryption_type,
            }
            if kms_key is not None:
                self._values["kms_key"] = kms_key

        @builtins.property
        def encryption_type(self) -> builtins.str:
            '''The encryption type to use.

            If you use the ``KMS`` encryption type, the contents of the repository will be encrypted using server-side encryption with AWS Key Management Service key stored in AWS KMS . When you use AWS KMS to encrypt your data, you can either use the default AWS managed AWS KMS key for Amazon ECR, or specify your own AWS KMS key, which you already created. For more information, see `Protecting data using server-side encryption with an AWS KMS key stored in AWS Key Management Service (SSE-KMS) <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html>`_ in the *Amazon Simple Storage Service Console Developer Guide* .

            If you use the ``AES256`` encryption type, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts the images in the repository using an AES-256 encryption algorithm. For more information, see `Protecting data using server-side encryption with Amazon S3-managed encryption keys (SSE-S3) <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html>`_ in the *Amazon Simple Storage Service Console Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-encryptionconfiguration.html#cfn-ecr-repository-encryptionconfiguration-encryptiontype
            '''
            result = self._values.get("encryption_type")
            assert result is not None, "Required property 'encryption_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_key(self) -> typing.Optional[builtins.str]:
            '''If you use the ``KMS`` encryption type, specify the AWS KMS key to use for encryption.

            The alias, key ID, or full ARN of the AWS KMS key can be specified. The key must exist in the same Region as the repository. If no key is specified, the default AWS managed AWS KMS key for Amazon ECR will be used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-encryptionconfiguration.html#cfn-ecr-repository-encryptionconfiguration-kmskey
            '''
            result = self._values.get("kms_key")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ecr.CfnRepository.ImageScanningConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"scan_on_push": "scanOnPush"},
    )
    class ImageScanningConfigurationProperty:
        def __init__(
            self,
            *,
            scan_on_push: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The image scanning configuration for a repository.

            :param scan_on_push: The setting that determines whether images are scanned after being pushed to a repository. If set to ``true`` , images will be scanned after being pushed. If this parameter is not specified, it will default to ``false`` and images will not be scanned unless a scan is manually started.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-imagescanningconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ecr as ecr
                
                image_scanning_configuration_property = ecr.CfnRepository.ImageScanningConfigurationProperty(
                    scan_on_push=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if scan_on_push is not None:
                self._values["scan_on_push"] = scan_on_push

        @builtins.property
        def scan_on_push(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''The setting that determines whether images are scanned after being pushed to a repository.

            If set to ``true`` , images will be scanned after being pushed. If this parameter is not specified, it will default to ``false`` and images will not be scanned unless a scan is manually started.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-imagescanningconfiguration.html#cfn-ecr-repository-imagescanningconfiguration-scanonpush
            '''
            result = self._values.get("scan_on_push")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ImageScanningConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_ecr.CfnRepository.LifecyclePolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "lifecycle_policy_text": "lifecyclePolicyText",
            "registry_id": "registryId",
        },
    )
    class LifecyclePolicyProperty:
        def __init__(
            self,
            *,
            lifecycle_policy_text: typing.Optional[builtins.str] = None,
            registry_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``LifecyclePolicy`` property type specifies a lifecycle policy.

            For information about lifecycle policy syntax, see `Lifecycle policy template <https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html>`_ in the *Amazon ECR User Guide* .

            :param lifecycle_policy_text: The JSON repository policy text to apply to the repository.
            :param registry_id: The AWS account ID associated with the registry that contains the repository. If you do not specify a registry, the default registry is assumed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-lifecyclepolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_ecr as ecr
                
                lifecycle_policy_property = ecr.CfnRepository.LifecyclePolicyProperty(
                    lifecycle_policy_text="lifecyclePolicyText",
                    registry_id="registryId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if lifecycle_policy_text is not None:
                self._values["lifecycle_policy_text"] = lifecycle_policy_text
            if registry_id is not None:
                self._values["registry_id"] = registry_id

        @builtins.property
        def lifecycle_policy_text(self) -> typing.Optional[builtins.str]:
            '''The JSON repository policy text to apply to the repository.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-lifecyclepolicy.html#cfn-ecr-repository-lifecyclepolicy-lifecyclepolicytext
            '''
            result = self._values.get("lifecycle_policy_text")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def registry_id(self) -> typing.Optional[builtins.str]:
            '''The AWS account ID associated with the registry that contains the repository.

            If you do not specify a registry, the default registry is assumed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-lifecyclepolicy.html#cfn-ecr-repository-lifecyclepolicy-registryid
            '''
            result = self._values.get("registry_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LifecyclePolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.CfnRepositoryProps",
    jsii_struct_bases=[],
    name_mapping={
        "encryption_configuration": "encryptionConfiguration",
        "image_scanning_configuration": "imageScanningConfiguration",
        "image_tag_mutability": "imageTagMutability",
        "lifecycle_policy": "lifecyclePolicy",
        "repository_name": "repositoryName",
        "repository_policy_text": "repositoryPolicyText",
        "tags": "tags",
    },
)
class CfnRepositoryProps:
    def __init__(
        self,
        *,
        encryption_configuration: typing.Optional[typing.Union[CfnRepository.EncryptionConfigurationProperty, _IResolvable_da3f097b]] = None,
        image_scanning_configuration: typing.Optional[typing.Union[CfnRepository.ImageScanningConfigurationProperty, _IResolvable_da3f097b]] = None,
        image_tag_mutability: typing.Optional[builtins.str] = None,
        lifecycle_policy: typing.Optional[typing.Union[CfnRepository.LifecyclePolicyProperty, _IResolvable_da3f097b]] = None,
        repository_name: typing.Optional[builtins.str] = None,
        repository_policy_text: typing.Any = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRepository``.

        :param encryption_configuration: The encryption configuration for the repository. This determines how the contents of your repository are encrypted at rest.
        :param image_scanning_configuration: The image scanning configuration for the repository. This determines whether images are scanned for known vulnerabilities after being pushed to the repository.
        :param image_tag_mutability: The tag mutability setting for the repository. If this parameter is omitted, the default setting of ``MUTABLE`` will be used which will allow image tags to be overwritten. If ``IMMUTABLE`` is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.
        :param lifecycle_policy: Creates or updates a lifecycle policy. For information about lifecycle policy syntax, see `Lifecycle policy template <https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html>`_ .
        :param repository_name: The name to use for the repository. The repository name may be specified on its own (such as ``nginx-web-app`` ) or it can be prepended with a namespace to group the repository into a category (such as ``project-a/nginx-web-app`` ). If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the repository name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.
        :param repository_policy_text: The JSON repository policy text to apply to the repository. For more information, see `Amazon ECR repository policies <https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html>`_ in the *Amazon Elastic Container Registry User Guide* .
        :param tags: An array of key-value pairs to apply to this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ecr as ecr
            
            # repository_policy_text: Any
            
            cfn_repository_props = ecr.CfnRepositoryProps(
                encryption_configuration=ecr.CfnRepository.EncryptionConfigurationProperty(
                    encryption_type="encryptionType",
            
                    # the properties below are optional
                    kms_key="kmsKey"
                ),
                image_scanning_configuration=ecr.CfnRepository.ImageScanningConfigurationProperty(
                    scan_on_push=False
                ),
                image_tag_mutability="imageTagMutability",
                lifecycle_policy=ecr.CfnRepository.LifecyclePolicyProperty(
                    lifecycle_policy_text="lifecyclePolicyText",
                    registry_id="registryId"
                ),
                repository_name="repositoryName",
                repository_policy_text=repository_policy_text,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if encryption_configuration is not None:
            self._values["encryption_configuration"] = encryption_configuration
        if image_scanning_configuration is not None:
            self._values["image_scanning_configuration"] = image_scanning_configuration
        if image_tag_mutability is not None:
            self._values["image_tag_mutability"] = image_tag_mutability
        if lifecycle_policy is not None:
            self._values["lifecycle_policy"] = lifecycle_policy
        if repository_name is not None:
            self._values["repository_name"] = repository_name
        if repository_policy_text is not None:
            self._values["repository_policy_text"] = repository_policy_text
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def encryption_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnRepository.EncryptionConfigurationProperty, _IResolvable_da3f097b]]:
        '''The encryption configuration for the repository.

        This determines how the contents of your repository are encrypted at rest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-encryptionconfiguration
        '''
        result = self._values.get("encryption_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnRepository.EncryptionConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def image_scanning_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnRepository.ImageScanningConfigurationProperty, _IResolvable_da3f097b]]:
        '''The image scanning configuration for the repository.

        This determines whether images are scanned for known vulnerabilities after being pushed to the repository.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagescanningconfiguration
        '''
        result = self._values.get("image_scanning_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnRepository.ImageScanningConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def image_tag_mutability(self) -> typing.Optional[builtins.str]:
        '''The tag mutability setting for the repository.

        If this parameter is omitted, the default setting of ``MUTABLE`` will be used which will allow image tags to be overwritten. If ``IMMUTABLE`` is specified, all image tags within the repository will be immutable which will prevent them from being overwritten.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability
        '''
        result = self._values.get("image_tag_mutability")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def lifecycle_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnRepository.LifecyclePolicyProperty, _IResolvable_da3f097b]]:
        '''Creates or updates a lifecycle policy.

        For information about lifecycle policy syntax, see `Lifecycle policy template <https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-lifecyclepolicy
        '''
        result = self._values.get("lifecycle_policy")
        return typing.cast(typing.Optional[typing.Union[CfnRepository.LifecyclePolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def repository_name(self) -> typing.Optional[builtins.str]:
        '''The name to use for the repository.

        The repository name may be specified on its own (such as ``nginx-web-app`` ) or it can be prepended with a namespace to group the repository into a category (such as ``project-a/nginx-web-app`` ). If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the repository name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-repositoryname
        '''
        result = self._values.get("repository_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def repository_policy_text(self) -> typing.Any:
        '''The JSON repository policy text to apply to the repository.

        For more information, see `Amazon ECR repository policies <https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html>`_ in the *Amazon Elastic Container Registry User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-repositorypolicytext
        '''
        result = self._values.get("repository_policy_text")
        return typing.cast(typing.Any, result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRepositoryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_ecr.IRepository")
class IRepository(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents an ECR repository.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryArn")
    def repository_arn(self) -> builtins.str:
        '''The ARN of the repository.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The name of the repository.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryUri")
    def repository_uri(self) -> builtins.str:
        '''The URI of this repository (represents the latest image):.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Add a policy statement to the repository's resource policy.

        :param statement: -
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
        '''Grant the given identity permissions to pull images in this repository.

        :param grantee: -
        '''
        ...

    @jsii.member(jsii_name="grantPullPush")
    def grant_pull_push(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull and push images to this repository.

        :param grantee: -
        '''
        ...

    @jsii.member(jsii_name="onCloudTrailEvent")
    def on_cloud_trail_event(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Define a CloudWatch event that triggers when something happens to this repository.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onCloudTrailImagePushed")
    def on_cloud_trail_image_pushed(
        self,
        id: builtins.str,
        *,
        image_tag: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event rule that can trigger a target when an image is pushed to this repository.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param image_tag: Only watch changes to this image tag. Default: - Watch changes to all tags
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

    @jsii.member(jsii_name="onImageScanCompleted")
    def on_image_scan_completed(
        self,
        id: builtins.str,
        *,
        image_tags: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event rule that can trigger a target when the image scan is completed.

        :param id: The id of the rule.
        :param image_tags: Only watch changes to the image tags spedified. Leave it undefined to watch the full repository. Default: - Watch the changes to the repository with all image tags
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="repositoryUriForDigest")
    def repository_uri_for_digest(
        self,
        digest: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''Returns the URI of the repository for a certain tag. Can be used in ``docker push/pull``.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY[@DIGEST]

        :param digest: Image digest to use (tools usually default to the image with the "latest" tag if omitted).
        '''
        ...

    @jsii.member(jsii_name="repositoryUriForTag")
    def repository_uri_for_tag(
        self,
        tag: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''Returns the URI of the repository for a certain tag. Can be used in ``docker push/pull``.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY[:TAG]

        :param tag: Image tag to use (tools usually default to "latest" if omitted).
        '''
        ...


class _IRepositoryProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents an ECR repository.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_ecr.IRepository"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryArn")
    def repository_arn(self) -> builtins.str:
        '''The ARN of the repository.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The name of the repository.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryUri")
    def repository_uri(self) -> builtins.str:
        '''The URI of this repository (represents the latest image):.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryUri"))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Add a policy statement to the repository's resource policy.

        :param statement: -
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

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
        '''Grant the given identity permissions to pull images in this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPull", [grantee]))

    @jsii.member(jsii_name="grantPullPush")
    def grant_pull_push(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull and push images to this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPullPush", [grantee]))

    @jsii.member(jsii_name="onCloudTrailEvent")
    def on_cloud_trail_event(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Define a CloudWatch event that triggers when something happens to this repository.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
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

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailEvent", [id, options]))

    @jsii.member(jsii_name="onCloudTrailImagePushed")
    def on_cloud_trail_image_pushed(
        self,
        id: builtins.str,
        *,
        image_tag: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event rule that can trigger a target when an image is pushed to this repository.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param image_tag: Only watch changes to this image tag. Default: - Watch changes to all tags
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCloudTrailImagePushedOptions(
            image_tag=image_tag,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailImagePushed", [id, options]))

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

    @jsii.member(jsii_name="onImageScanCompleted")
    def on_image_scan_completed(
        self,
        id: builtins.str,
        *,
        image_tags: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event rule that can trigger a target when the image scan is completed.

        :param id: The id of the rule.
        :param image_tags: Only watch changes to the image tags spedified. Leave it undefined to watch the full repository. Default: - Watch the changes to the repository with all image tags
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnImageScanCompletedOptions(
            image_tags=image_tags,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onImageScanCompleted", [id, options]))

    @jsii.member(jsii_name="repositoryUriForDigest")
    def repository_uri_for_digest(
        self,
        digest: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''Returns the URI of the repository for a certain tag. Can be used in ``docker push/pull``.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY[@DIGEST]

        :param digest: Image digest to use (tools usually default to the image with the "latest" tag if omitted).
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "repositoryUriForDigest", [digest]))

    @jsii.member(jsii_name="repositoryUriForTag")
    def repository_uri_for_tag(
        self,
        tag: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''Returns the URI of the repository for a certain tag. Can be used in ``docker push/pull``.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY[:TAG]

        :param tag: Image tag to use (tools usually default to "latest" if omitted).
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "repositoryUriForTag", [tag]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IRepository).__jsii_proxy_class__ = lambda : _IRepositoryProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.LifecycleRule",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "max_image_age": "maxImageAge",
        "max_image_count": "maxImageCount",
        "rule_priority": "rulePriority",
        "tag_prefix_list": "tagPrefixList",
        "tag_status": "tagStatus",
    },
)
class LifecycleRule:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        max_image_age: typing.Optional[_Duration_4839e8c3] = None,
        max_image_count: typing.Optional[jsii.Number] = None,
        rule_priority: typing.Optional[jsii.Number] = None,
        tag_prefix_list: typing.Optional[typing.Sequence[builtins.str]] = None,
        tag_status: typing.Optional["TagStatus"] = None,
    ) -> None:
        '''An ECR life cycle rule.

        :param description: Describes the purpose of the rule. Default: No description
        :param max_image_age: The maximum age of images to retain. The value must represent a number of days. Specify exactly one of maxImageCount and maxImageAge.
        :param max_image_count: The maximum number of images to retain. Specify exactly one of maxImageCount and maxImageAge.
        :param rule_priority: Controls the order in which rules are evaluated (low to high). All rules must have a unique priority, where lower numbers have higher precedence. The first rule that matches is applied to an image. There can only be one rule with a tagStatus of Any, and it must have the highest rulePriority. All rules without a specified priority will have incrementing priorities automatically assigned to them, higher than any rules that DO have priorities. Default: Automatically assigned
        :param tag_prefix_list: Select images that have ALL the given prefixes in their tag. Only if tagStatus == TagStatus.Tagged
        :param tag_status: Select images based on tags. Only one rule is allowed to select untagged images, and it must have the highest rulePriority. Default: TagStatus.Tagged if tagPrefixList is given, TagStatus.Any otherwise

        :exampleMetadata: infused

        Example::

            # repository: ecr.Repository
            
            repository.add_lifecycle_rule(tag_prefix_list=["prod"], max_image_count=9999)
            repository.add_lifecycle_rule(max_image_age=Duration.days(30))
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if max_image_age is not None:
            self._values["max_image_age"] = max_image_age
        if max_image_count is not None:
            self._values["max_image_count"] = max_image_count
        if rule_priority is not None:
            self._values["rule_priority"] = rule_priority
        if tag_prefix_list is not None:
            self._values["tag_prefix_list"] = tag_prefix_list
        if tag_status is not None:
            self._values["tag_status"] = tag_status

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''Describes the purpose of the rule.

        :default: No description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_image_age(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The maximum age of images to retain. The value must represent a number of days.

        Specify exactly one of maxImageCount and maxImageAge.
        '''
        result = self._values.get("max_image_age")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def max_image_count(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of images to retain.

        Specify exactly one of maxImageCount and maxImageAge.
        '''
        result = self._values.get("max_image_count")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def rule_priority(self) -> typing.Optional[jsii.Number]:
        '''Controls the order in which rules are evaluated (low to high).

        All rules must have a unique priority, where lower numbers have
        higher precedence. The first rule that matches is applied to an image.

        There can only be one rule with a tagStatus of Any, and it must have
        the highest rulePriority.

        All rules without a specified priority will have incrementing priorities
        automatically assigned to them, higher than any rules that DO have priorities.

        :default: Automatically assigned
        '''
        result = self._values.get("rule_priority")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def tag_prefix_list(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Select images that have ALL the given prefixes in their tag.

        Only if tagStatus == TagStatus.Tagged
        '''
        result = self._values.get("tag_prefix_list")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tag_status(self) -> typing.Optional["TagStatus"]:
        '''Select images based on tags.

        Only one rule is allowed to select untagged images, and it must
        have the highest rulePriority.

        :default: TagStatus.Tagged if tagPrefixList is given, TagStatus.Any otherwise
        '''
        result = self._values.get("tag_status")
        return typing.cast(typing.Optional["TagStatus"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LifecycleRule(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.OnCloudTrailImagePushedOptions",
    jsii_struct_bases=[_OnEventOptions_8711b8b3],
    name_mapping={
        "description": "description",
        "event_pattern": "eventPattern",
        "rule_name": "ruleName",
        "target": "target",
        "image_tag": "imageTag",
    },
)
class OnCloudTrailImagePushedOptions(_OnEventOptions_8711b8b3):
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
        image_tag: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options for the onCloudTrailImagePushed method.

        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        :param image_tag: Only watch changes to this image tag. Default: - Watch changes to all tags

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ecr as ecr
            from aws_cdk import aws_events as events
            
            # detail: Any
            # rule_target: events.IRuleTarget
            
            on_cloud_trail_image_pushed_options = ecr.OnCloudTrailImagePushedOptions(
                description="description",
                event_pattern=events.EventPattern(
                    account=["account"],
                    detail={
                        "detail_key": detail
                    },
                    detail_type=["detailType"],
                    id=["id"],
                    region=["region"],
                    resources=["resources"],
                    source=["source"],
                    time=["time"],
                    version=["version"]
                ),
                image_tag="imageTag",
                rule_name="ruleName",
                target=rule_target
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
        if image_tag is not None:
            self._values["image_tag"] = image_tag

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
    def image_tag(self) -> typing.Optional[builtins.str]:
        '''Only watch changes to this image tag.

        :default: - Watch changes to all tags
        '''
        result = self._values.get("image_tag")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OnCloudTrailImagePushedOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.OnImageScanCompletedOptions",
    jsii_struct_bases=[_OnEventOptions_8711b8b3],
    name_mapping={
        "description": "description",
        "event_pattern": "eventPattern",
        "rule_name": "ruleName",
        "target": "target",
        "image_tags": "imageTags",
    },
)
class OnImageScanCompletedOptions(_OnEventOptions_8711b8b3):
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
        image_tags: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Options for the OnImageScanCompleted method.

        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        :param image_tags: Only watch changes to the image tags spedified. Leave it undefined to watch the full repository. Default: - Watch the changes to the repository with all image tags

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ecr as ecr
            from aws_cdk import aws_events as events
            
            # detail: Any
            # rule_target: events.IRuleTarget
            
            on_image_scan_completed_options = ecr.OnImageScanCompletedOptions(
                description="description",
                event_pattern=events.EventPattern(
                    account=["account"],
                    detail={
                        "detail_key": detail
                    },
                    detail_type=["detailType"],
                    id=["id"],
                    region=["region"],
                    resources=["resources"],
                    source=["source"],
                    time=["time"],
                    version=["version"]
                ),
                image_tags=["imageTags"],
                rule_name="ruleName",
                target=rule_target
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
        if image_tags is not None:
            self._values["image_tags"] = image_tags

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
    def image_tags(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Only watch changes to the image tags spedified.

        Leave it undefined to watch the full repository.

        :default: - Watch the changes to the repository with all image tags
        '''
        result = self._values.get("image_tags")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OnImageScanCompletedOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class PublicGalleryAuthorizationToken(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.PublicGalleryAuthorizationToken",
):
    '''Authorization token to access the global public ECR Gallery via Docker CLI.

    :see: https://docs.aws.amazon.com/AmazonECR/latest/public/public-registries.html#public-registry-auth
    :exampleMetadata: infused

    Example::

        user = iam.User(self, "User")
        ecr.PublicGalleryAuthorizationToken.grant_read(user)
    '''

    @jsii.member(jsii_name="grantRead") # type: ignore[misc]
    @builtins.classmethod
    def grant_read(cls, grantee: _IGrantable_71c4f5de) -> None:
        '''Grant access to retrieve an authorization token.

        :param grantee: -
        '''
        return typing.cast(None, jsii.sinvoke(cls, "grantRead", [grantee]))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.RepositoryAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "repository_arn": "repositoryArn",
        "repository_name": "repositoryName",
    },
)
class RepositoryAttributes:
    def __init__(
        self,
        *,
        repository_arn: builtins.str,
        repository_name: builtins.str,
    ) -> None:
        '''
        :param repository_arn: 
        :param repository_name: 

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ecr as ecr
            
            repository_attributes = ecr.RepositoryAttributes(
                repository_arn="repositoryArn",
                repository_name="repositoryName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "repository_arn": repository_arn,
            "repository_name": repository_name,
        }

    @builtins.property
    def repository_arn(self) -> builtins.str:
        result = self._values.get("repository_arn")
        assert result is not None, "Required property 'repository_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def repository_name(self) -> builtins.str:
        result = self._values.get("repository_name")
        assert result is not None, "Required property 'repository_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RepositoryAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IRepository)
class RepositoryBase(
    _Resource_45bc6135,
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_ecr.RepositoryBase",
):
    '''Base class for ECR repository.

    Reused between imported repositories and owned repositories.
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        environment_from_arn: typing.Optional[builtins.str] = None,
        physical_name: typing.Optional[builtins.str] = None,
        region: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param account: The AWS account ID this resource belongs to. Default: - the resource is in the same account as the stack it belongs to
        :param environment_from_arn: ARN to deduce region and account from. The ARN is parsed and the account and region are taken from the ARN. This should be used for imported resources. Cannot be supplied together with either ``account`` or ``region``. Default: - take environment from ``account``, ``region`` parameters, or use Stack environment.
        :param physical_name: The value passed in by users to the physical name prop of the resource. - ``undefined`` implies that a physical name will be allocated by CloudFormation during deployment. - a concrete value implies a specific physical name - ``PhysicalName.GENERATE_IF_NEEDED`` is a marker that indicates that a physical will only be generated by the CDK if it is needed for cross-environment references. Otherwise, it will be allocated by CloudFormation. Default: - The physical name will be allocated by CloudFormation at deployment time
        :param region: The AWS region this resource belongs to. Default: - the resource is in the same region as the stack it belongs to
        '''
        props = _ResourceProps_15a65b4e(
            account=account,
            environment_from_arn=environment_from_arn,
            physical_name=physical_name,
            region=region,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addToResourcePolicy") # type: ignore[misc]
    @abc.abstractmethod
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Add a policy statement to the repository's resource policy.

        :param statement: -
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
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *actions]))

    @jsii.member(jsii_name="grantPull")
    def grant_pull(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to use the images in this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPull", [grantee]))

    @jsii.member(jsii_name="grantPullPush")
    def grant_pull_push(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant the given identity permissions to pull and push images to this repository.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPullPush", [grantee]))

    @jsii.member(jsii_name="onCloudTrailEvent")
    def on_cloud_trail_event(
        self,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Define a CloudWatch event that triggers when something happens to this repository.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
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

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailEvent", [id, options]))

    @jsii.member(jsii_name="onCloudTrailImagePushed")
    def on_cloud_trail_image_pushed(
        self,
        id: builtins.str,
        *,
        image_tag: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event rule that can trigger a target when an image is pushed to this repository.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param image_tag: Only watch changes to this image tag. Default: - Watch changes to all tags
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCloudTrailImagePushedOptions(
            image_tag=image_tag,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailImagePushed", [id, options]))

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

    @jsii.member(jsii_name="onImageScanCompleted")
    def on_image_scan_completed(
        self,
        id: builtins.str,
        *,
        image_tags: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event rule that can trigger a target when an image scan is completed.

        :param id: The id of the rule.
        :param image_tags: Only watch changes to the image tags spedified. Leave it undefined to watch the full repository. Default: - Watch the changes to the repository with all image tags
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnImageScanCompletedOptions(
            image_tags=image_tags,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onImageScanCompleted", [id, options]))

    @jsii.member(jsii_name="repositoryUriForDigest")
    def repository_uri_for_digest(
        self,
        digest: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''Returns the URL of the repository. Can be used in ``docker push/pull``.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY[@DIGEST]

        :param digest: Optional image digest.
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "repositoryUriForDigest", [digest]))

    @jsii.member(jsii_name="repositoryUriForTag")
    def repository_uri_for_tag(
        self,
        tag: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''Returns the URL of the repository. Can be used in ``docker push/pull``.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY[:TAG]

        :param tag: Optional image tag.
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "repositoryUriForTag", [tag]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryArn")
    @abc.abstractmethod
    def repository_arn(self) -> builtins.str:
        '''The ARN of the repository.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    @abc.abstractmethod
    def repository_name(self) -> builtins.str:
        '''The name of the repository.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryUri")
    def repository_uri(self) -> builtins.str:
        '''The URI of this repository (represents the latest image):.

        ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPOSITORY
        '''
        return typing.cast(builtins.str, jsii.get(self, "repositoryUri"))


class _RepositoryBaseProxy(
    RepositoryBase, jsii.proxy_for(_Resource_45bc6135) # type: ignore[misc]
):
    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Add a policy statement to the repository's resource policy.

        :param statement: -
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryArn")
    def repository_arn(self) -> builtins.str:
        '''The ARN of the repository.'''
        return typing.cast(builtins.str, jsii.get(self, "repositoryArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The name of the repository.'''
        return typing.cast(builtins.str, jsii.get(self, "repositoryName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, RepositoryBase).__jsii_proxy_class__ = lambda : _RepositoryBaseProxy


class RepositoryEncryption(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.RepositoryEncryption",
):
    '''Indicates whether server-side encryption is enabled for the object, and whether that encryption is from the AWS Key Management Service (AWS KMS) or from Amazon S3 managed encryption (SSE-S3).

    :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html#SysMetadata
    :exampleMetadata: infused

    Example::

        ecr.Repository(self, "Repo",
            encryption=ecr.RepositoryEncryption.KMS
        )
    '''

    def __init__(self, value: builtins.str) -> None:
        '''
        :param value: the string value of the encryption.
        '''
        jsii.create(self.__class__, self, [value])

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AES_256")
    def AES_256(cls) -> "RepositoryEncryption":
        ''''AES256'.'''
        return typing.cast("RepositoryEncryption", jsii.sget(cls, "AES_256"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="KMS")
    def KMS(cls) -> "RepositoryEncryption":
        ''''KMS'.'''
        return typing.cast("RepositoryEncryption", jsii.sget(cls, "KMS"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="value")
    def value(self) -> builtins.str:
        '''the string value of the encryption.'''
        return typing.cast(builtins.str, jsii.get(self, "value"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr.RepositoryProps",
    jsii_struct_bases=[],
    name_mapping={
        "encryption": "encryption",
        "encryption_key": "encryptionKey",
        "image_scan_on_push": "imageScanOnPush",
        "image_tag_mutability": "imageTagMutability",
        "lifecycle_registry_id": "lifecycleRegistryId",
        "lifecycle_rules": "lifecycleRules",
        "removal_policy": "removalPolicy",
        "repository_name": "repositoryName",
    },
)
class RepositoryProps:
    def __init__(
        self,
        *,
        encryption: typing.Optional[RepositoryEncryption] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        image_scan_on_push: typing.Optional[builtins.bool] = None,
        image_tag_mutability: typing.Optional["TagMutability"] = None,
        lifecycle_registry_id: typing.Optional[builtins.str] = None,
        lifecycle_rules: typing.Optional[typing.Sequence[LifecycleRule]] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        repository_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param encryption: The kind of server-side encryption to apply to this repository. If you choose KMS, you can specify a KMS key via ``encryptionKey``. If encryptionKey is not specified, an AWS managed KMS key is used. Default: - ``KMS`` if ``encryptionKey`` is specified, or ``AES256`` otherwise.
        :param encryption_key: External KMS key to use for repository encryption. The 'encryption' property must be either not specified or set to "KMS". An error will be emitted if encryption is set to "AES256". Default: - If encryption is set to ``KMS`` and this property is undefined, an AWS managed KMS key is used.
        :param image_scan_on_push: Enable the scan on push when creating the repository. Default: false
        :param image_tag_mutability: The tag mutability setting for the repository. If this parameter is omitted, the default setting of MUTABLE will be used which will allow image tags to be overwritten. Default: TagMutability.MUTABLE
        :param lifecycle_registry_id: The AWS account ID associated with the registry that contains the repository. Default: The default registry is assumed.
        :param lifecycle_rules: Life cycle rules to apply to this registry. Default: No life cycle rules
        :param removal_policy: Determine what happens to the repository when the resource/stack is deleted. Default: RemovalPolicy.Retain
        :param repository_name: Name for this repository. Default: Automatically generated name.

        :exampleMetadata: infused

        Example::

            ecr.Repository(self, "Repo", image_tag_mutability=ecr.TagMutability.IMMUTABLE)
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if encryption is not None:
            self._values["encryption"] = encryption
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if image_scan_on_push is not None:
            self._values["image_scan_on_push"] = image_scan_on_push
        if image_tag_mutability is not None:
            self._values["image_tag_mutability"] = image_tag_mutability
        if lifecycle_registry_id is not None:
            self._values["lifecycle_registry_id"] = lifecycle_registry_id
        if lifecycle_rules is not None:
            self._values["lifecycle_rules"] = lifecycle_rules
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if repository_name is not None:
            self._values["repository_name"] = repository_name

    @builtins.property
    def encryption(self) -> typing.Optional[RepositoryEncryption]:
        '''The kind of server-side encryption to apply to this repository.

        If you choose KMS, you can specify a KMS key via ``encryptionKey``. If
        encryptionKey is not specified, an AWS managed KMS key is used.

        :default: - ``KMS`` if ``encryptionKey`` is specified, or ``AES256`` otherwise.
        '''
        result = self._values.get("encryption")
        return typing.cast(typing.Optional[RepositoryEncryption], result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''External KMS key to use for repository encryption.

        The 'encryption' property must be either not specified or set to "KMS".
        An error will be emitted if encryption is set to "AES256".

        :default:

        - If encryption is set to ``KMS`` and this property is undefined,
        an AWS managed KMS key is used.
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def image_scan_on_push(self) -> typing.Optional[builtins.bool]:
        '''Enable the scan on push when creating the repository.

        :default: false
        '''
        result = self._values.get("image_scan_on_push")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def image_tag_mutability(self) -> typing.Optional["TagMutability"]:
        '''The tag mutability setting for the repository.

        If this parameter is omitted, the default setting of MUTABLE will be used which will allow image tags to be overwritten.

        :default: TagMutability.MUTABLE
        '''
        result = self._values.get("image_tag_mutability")
        return typing.cast(typing.Optional["TagMutability"], result)

    @builtins.property
    def lifecycle_registry_id(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID associated with the registry that contains the repository.

        :default: The default registry is assumed.

        :see: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutLifecyclePolicy.html
        '''
        result = self._values.get("lifecycle_registry_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def lifecycle_rules(self) -> typing.Optional[typing.List[LifecycleRule]]:
        '''Life cycle rules to apply to this registry.

        :default: No life cycle rules
        '''
        result = self._values.get("lifecycle_rules")
        return typing.cast(typing.Optional[typing.List[LifecycleRule]], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Determine what happens to the repository when the resource/stack is deleted.

        :default: RemovalPolicy.Retain
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def repository_name(self) -> typing.Optional[builtins.str]:
        '''Name for this repository.

        :default: Automatically generated name.
        '''
        result = self._values.get("repository_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RepositoryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_ecr.TagMutability")
class TagMutability(enum.Enum):
    '''The tag mutability setting for your repository.

    :exampleMetadata: infused

    Example::

        ecr.Repository(self, "Repo", image_tag_mutability=ecr.TagMutability.IMMUTABLE)
    '''

    MUTABLE = "MUTABLE"
    '''allow image tags to be overwritten.'''
    IMMUTABLE = "IMMUTABLE"
    '''all image tags within the repository will be immutable which will prevent them from being overwritten.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_ecr.TagStatus")
class TagStatus(enum.Enum):
    '''Select images based on tags.'''

    ANY = "ANY"
    '''Rule applies to all images.'''
    TAGGED = "TAGGED"
    '''Rule applies to tagged images.'''
    UNTAGGED = "UNTAGGED"
    '''Rule applies to untagged images.'''


class Repository(
    RepositoryBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr.Repository",
):
    '''Define an ECR repository.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_ecr as ecr
        
        
        apprunner.Service(self, "Service",
            source=apprunner.Source.from_ecr(
                image_configuration=apprunner.ImageConfiguration(port=80),
                repository=ecr.Repository.from_repository_name(self, "NginxRepository", "nginx"),
                tag="latest"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        encryption: typing.Optional[RepositoryEncryption] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        image_scan_on_push: typing.Optional[builtins.bool] = None,
        image_tag_mutability: typing.Optional[TagMutability] = None,
        lifecycle_registry_id: typing.Optional[builtins.str] = None,
        lifecycle_rules: typing.Optional[typing.Sequence[LifecycleRule]] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        repository_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param encryption: The kind of server-side encryption to apply to this repository. If you choose KMS, you can specify a KMS key via ``encryptionKey``. If encryptionKey is not specified, an AWS managed KMS key is used. Default: - ``KMS`` if ``encryptionKey`` is specified, or ``AES256`` otherwise.
        :param encryption_key: External KMS key to use for repository encryption. The 'encryption' property must be either not specified or set to "KMS". An error will be emitted if encryption is set to "AES256". Default: - If encryption is set to ``KMS`` and this property is undefined, an AWS managed KMS key is used.
        :param image_scan_on_push: Enable the scan on push when creating the repository. Default: false
        :param image_tag_mutability: The tag mutability setting for the repository. If this parameter is omitted, the default setting of MUTABLE will be used which will allow image tags to be overwritten. Default: TagMutability.MUTABLE
        :param lifecycle_registry_id: The AWS account ID associated with the registry that contains the repository. Default: The default registry is assumed.
        :param lifecycle_rules: Life cycle rules to apply to this registry. Default: No life cycle rules
        :param removal_policy: Determine what happens to the repository when the resource/stack is deleted. Default: RemovalPolicy.Retain
        :param repository_name: Name for this repository. Default: Automatically generated name.
        '''
        props = RepositoryProps(
            encryption=encryption,
            encryption_key=encryption_key,
            image_scan_on_push=image_scan_on_push,
            image_tag_mutability=image_tag_mutability,
            lifecycle_registry_id=lifecycle_registry_id,
            lifecycle_rules=lifecycle_rules,
            removal_policy=removal_policy,
            repository_name=repository_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="arnForLocalRepository") # type: ignore[misc]
    @builtins.classmethod
    def arn_for_local_repository(
        cls,
        repository_name: builtins.str,
        scope: constructs.IConstruct,
        account: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''Returns an ECR ARN for a repository that resides in the same account/region as the current stack.

        :param repository_name: -
        :param scope: -
        :param account: -
        '''
        return typing.cast(builtins.str, jsii.sinvoke(cls, "arnForLocalRepository", [repository_name, scope, account]))

    @jsii.member(jsii_name="fromRepositoryArn") # type: ignore[misc]
    @builtins.classmethod
    def from_repository_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        repository_arn: builtins.str,
    ) -> IRepository:
        '''
        :param scope: -
        :param id: -
        :param repository_arn: -
        '''
        return typing.cast(IRepository, jsii.sinvoke(cls, "fromRepositoryArn", [scope, id, repository_arn]))

    @jsii.member(jsii_name="fromRepositoryAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_repository_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        repository_arn: builtins.str,
        repository_name: builtins.str,
    ) -> IRepository:
        '''Import a repository.

        :param scope: -
        :param id: -
        :param repository_arn: 
        :param repository_name: 
        '''
        attrs = RepositoryAttributes(
            repository_arn=repository_arn, repository_name=repository_name
        )

        return typing.cast(IRepository, jsii.sinvoke(cls, "fromRepositoryAttributes", [scope, id, attrs]))

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

    @jsii.member(jsii_name="addLifecycleRule")
    def add_lifecycle_rule(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        max_image_age: typing.Optional[_Duration_4839e8c3] = None,
        max_image_count: typing.Optional[jsii.Number] = None,
        rule_priority: typing.Optional[jsii.Number] = None,
        tag_prefix_list: typing.Optional[typing.Sequence[builtins.str]] = None,
        tag_status: typing.Optional[TagStatus] = None,
    ) -> None:
        '''Add a life cycle rule to the repository.

        Life cycle rules automatically expire images from the repository that match
        certain conditions.

        :param description: Describes the purpose of the rule. Default: No description
        :param max_image_age: The maximum age of images to retain. The value must represent a number of days. Specify exactly one of maxImageCount and maxImageAge.
        :param max_image_count: The maximum number of images to retain. Specify exactly one of maxImageCount and maxImageAge.
        :param rule_priority: Controls the order in which rules are evaluated (low to high). All rules must have a unique priority, where lower numbers have higher precedence. The first rule that matches is applied to an image. There can only be one rule with a tagStatus of Any, and it must have the highest rulePriority. All rules without a specified priority will have incrementing priorities automatically assigned to them, higher than any rules that DO have priorities. Default: Automatically assigned
        :param tag_prefix_list: Select images that have ALL the given prefixes in their tag. Only if tagStatus == TagStatus.Tagged
        :param tag_status: Select images based on tags. Only one rule is allowed to select untagged images, and it must have the highest rulePriority. Default: TagStatus.Tagged if tagPrefixList is given, TagStatus.Any otherwise
        '''
        rule = LifecycleRule(
            description=description,
            max_image_age=max_image_age,
            max_image_count=max_image_count,
            rule_priority=rule_priority,
            tag_prefix_list=tag_prefix_list,
            tag_status=tag_status,
        )

        return typing.cast(None, jsii.invoke(self, "addLifecycleRule", [rule]))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Add a policy statement to the repository's resource policy.

        :param statement: -
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryArn")
    def repository_arn(self) -> builtins.str:
        '''The ARN of the repository.'''
        return typing.cast(builtins.str, jsii.get(self, "repositoryArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repositoryName")
    def repository_name(self) -> builtins.str:
        '''The name of the repository.'''
        return typing.cast(builtins.str, jsii.get(self, "repositoryName"))


__all__ = [
    "AuthorizationToken",
    "CfnPublicRepository",
    "CfnPublicRepositoryProps",
    "CfnPullThroughCacheRule",
    "CfnPullThroughCacheRuleProps",
    "CfnRegistryPolicy",
    "CfnRegistryPolicyProps",
    "CfnReplicationConfiguration",
    "CfnReplicationConfigurationProps",
    "CfnRepository",
    "CfnRepositoryProps",
    "IRepository",
    "LifecycleRule",
    "OnCloudTrailImagePushedOptions",
    "OnImageScanCompletedOptions",
    "PublicGalleryAuthorizationToken",
    "Repository",
    "RepositoryAttributes",
    "RepositoryBase",
    "RepositoryEncryption",
    "RepositoryProps",
    "TagMutability",
    "TagStatus",
]

publication.publish()
