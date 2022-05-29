'''
# AWS CDK Docker Image Assets

This module allows bundling Docker images as assets.

## Images from Dockerfile

Images are built from a local Docker context directory (with a `Dockerfile`),
uploaded to Amazon Elastic Container Registry (ECR) by the CDK toolkit
and/or your app's CI/CD pipeline, and can be naturally referenced in your CDK app.

```python
from aws_cdk.aws_ecr_assets import DockerImageAsset


asset = DockerImageAsset(self, "MyBuildImage",
    directory=path.join(__dirname, "my-image")
)
```

The directory `my-image` must include a `Dockerfile`.

This will instruct the toolkit to build a Docker image from `my-image`, push it
to an Amazon ECR repository and wire the name of the repository as CloudFormation
parameters to your stack.

By default, all files in the given directory will be copied into the docker
*build context*. If there is a large directory that you know you definitely
don't need in the build context you can improve the performance by adding the
names of files and directories to ignore to a file called `.dockerignore`, or
pass them via the `exclude` property. If both are available, the patterns
found in `exclude` are appended to the patterns found in `.dockerignore`.

The `ignoreMode` property controls how the set of ignore patterns is
interpreted. The recommended setting for Docker image assets is
`IgnoreMode.DOCKER`. If the context flag
`@aws-cdk/aws-ecr-assets:dockerIgnoreSupport` is set to `true` in your
`cdk.json` (this is by default for new projects, but must be set manually for
old projects) then `IgnoreMode.DOCKER` is the default and you don't need to
configure it on the asset itself.

Use `asset.imageUri` to reference the image. It includes both the ECR image URL
and tag.

You can optionally pass build args to the `docker build` command by specifying
the `buildArgs` property. It is recommended to skip hashing of `buildArgs` for
values that can change between different machines to maintain a consistent
asset hash.

```python
from aws_cdk.aws_ecr_assets import DockerImageAsset


asset = DockerImageAsset(self, "MyBuildImage",
    directory=path.join(__dirname, "my-image"),
    build_args={
        "HTTP_PROXY": "http://10.20.30.2:1234"
    },
    invalidation=DockerImageAssetInvalidationOptions(
        build_args=False
    )
)
```

You can optionally pass a target to the `docker build` command by specifying
the `target` property:

```python
from aws_cdk.aws_ecr_assets import DockerImageAsset


asset = DockerImageAsset(self, "MyBuildImage",
    directory=path.join(__dirname, "my-image"),
    target="a-target"
)
```

You can optionally pass networking mode to the `docker build` command by specifying
the `networkMode` property:

```python
from aws_cdk.aws_ecr_assets import DockerImageAsset, NetworkMode


asset = DockerImageAsset(self, "MyBuildImage",
    directory=path.join(__dirname, "my-image"),
    network_mode=NetworkMode.HOST
)
```

## Images from Tarball

Images are loaded from a local tarball, uploaded to ECR by the CDK toolkit and/or your app's CI-CD pipeline, and can be
naturally referenced in your CDK app.

```python
from aws_cdk.aws_ecr_assets import TarballImageAsset


asset = TarballImageAsset(self, "MyBuildImage",
    tarball_file="local-image.tar"
)
```

This will instruct the toolkit to add the tarball as a file asset. During deployment it will load the container image
from `local-image.tar`, push it to an Amazon ECR repository and wire the name of the repository as CloudFormation parameters
to your stack.

## Publishing images to ECR repositories

`DockerImageAsset` is designed for seamless build & consumption of image assets by CDK code deployed to multiple environments
through the CDK CLI or through CI/CD workflows. To that end, the ECR repository behind this construct is controlled by the AWS CDK.
The mechanics of where these images are published and how are intentionally kept as an implementation detail, and the construct
does not support customizations such as specifying the ECR repository name or tags.

If you are looking for a way to *publish* image assets to an ECR repository in your control, you should consider using
[cdklabs/cdk-ecr-deployment](https://github.com/cdklabs/cdk-ecr-deployment), which is able to replicate an image asset from the CDK-controlled ECR repository to a repository of
your choice.

Here an example from the [cdklabs/cdk-ecr-deployment](https://github.com/cdklabs/cdk-ecr-deployment) project:

```text
// This example available in TypeScript only

import { DockerImageAsset } from 'aws-cdk-lib/aws-ecr-assets';
import * as ecrdeploy from 'cdk-ecr-deployment';

const image = new DockerImageAsset(this, 'CDKDockerImage', {
  directory: path.join(__dirname, 'docker'),
});

new ecrdeploy.ECRDeployment(this, 'DeployDockerImage', {
  src: new ecrdeploy.DockerImageName(image.imageUri),
  dest: new ecrdeploy.DockerImageName(`${cdk.Aws.ACCOUNT_ID}.dkr.ecr.us-west-2.amazonaws.com/test:nginx`),
});
```

⚠️ Please note that this is a 3rd-party construct library and is not officially supported by AWS.
You are welcome to +1 [this GitHub issue](https://github.com/aws/aws-cdk/issues/12597) if you would like to see
native support for this use-case in the AWS CDK.

## Pull Permissions

Depending on the consumer of your image asset, you will need to make sure
the principal has permissions to pull the image.

In most cases, you should use the `asset.repository.grantPull(principal)`
method. This will modify the IAM policy of the principal to allow it to
pull images from this repository.

If the pulling principal is not in the same account or is an AWS service that
doesn't assume a role in your account (e.g. AWS CodeBuild), pull permissions
must be granted on the **resource policy** (and not on the principal's policy).
To do that, you can use `asset.repository.addToResourcePolicy(statement)` to
grant the desired principal the following permissions: "ecr:GetDownloadUrlForLayer",
"ecr:BatchGetImage" and "ecr:BatchCheckLayerAvailability".
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
    FileFingerprintOptions as _FileFingerprintOptions_115b8b51,
    IgnoreMode as _IgnoreMode_655a98e8,
    SymlinkFollowMode as _SymlinkFollowMode_047ec1f6,
)
from ..aws_ecr import IRepository as _IRepository_e6004aa6


class DockerImageAsset(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr_assets.DockerImageAsset",
):
    '''An asset that represents a Docker image.

    The image will be created in build time and uploaded to an ECR repository.

    :exampleMetadata: infused

    Example::

        from aws_cdk.aws_ecr_assets import DockerImageAsset, NetworkMode
        
        
        asset = DockerImageAsset(self, "MyBuildImage",
            directory=path.join(__dirname, "my-image"),
            network_mode=NetworkMode.HOST
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        directory: builtins.str,
        build_args: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        file: typing.Optional[builtins.str] = None,
        invalidation: typing.Optional["DockerImageAssetInvalidationOptions"] = None,
        network_mode: typing.Optional["NetworkMode"] = None,
        target: typing.Optional[builtins.str] = None,
        extra_hash: typing.Optional[builtins.str] = None,
        exclude: typing.Optional[typing.Sequence[builtins.str]] = None,
        follow_symlinks: typing.Optional[_SymlinkFollowMode_047ec1f6] = None,
        ignore_mode: typing.Optional[_IgnoreMode_655a98e8] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param directory: The directory where the Dockerfile is stored. Any directory inside with a name that matches the CDK output folder (cdk.out by default) will be excluded from the asset
        :param build_args: Build args to pass to the ``docker build`` command. Since Docker build arguments are resolved before deployment, keys and values cannot refer to unresolved tokens (such as ``lambda.functionArn`` or ``queue.queueUrl``). Default: - no build args are passed
        :param file: Path to the Dockerfile (relative to the directory). Default: 'Dockerfile'
        :param invalidation: Options to control which parameters are used to invalidate the asset hash. Default: - hash all parameters
        :param network_mode: Networking mode for the RUN commands during build. Support docker API 1.25+. Default: - no networking mode specified (the default networking mode ``NetworkMode.DEFAULT`` will be used)
        :param target: Docker target to build to. Default: - no target
        :param extra_hash: Extra information to encode into the fingerprint (e.g. build instructions and other inputs). Default: - hash is only based on source content
        :param exclude: Glob patterns to exclude from the copy. Default: - nothing is excluded
        :param follow_symlinks: A strategy for how to handle symlinks. Default: SymlinkFollowMode.NEVER
        :param ignore_mode: The ignore behavior to use for exclude patterns. Default: IgnoreMode.GLOB
        '''
        props = DockerImageAssetProps(
            directory=directory,
            build_args=build_args,
            file=file,
            invalidation=invalidation,
            network_mode=network_mode,
            target=target,
            extra_hash=extra_hash,
            exclude=exclude,
            follow_symlinks=follow_symlinks,
            ignore_mode=ignore_mode,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addResourceMetadata")
    def add_resource_metadata(
        self,
        resource: _CfnResource_9df397a6,
        resource_property: builtins.str,
    ) -> None:
        '''Adds CloudFormation template metadata to the specified resource with information that indicates which resource property is mapped to this local asset.

        This can be used by tools such as SAM CLI to provide local
        experience such as local invocation and debugging of Lambda functions.

        Asset metadata will only be included if the stack is synthesized with the
        "aws:cdk:enable-asset-metadata" context key defined, which is the default
        behavior when synthesizing via the CDK Toolkit.

        :param resource: The CloudFormation resource which is using this asset [disable-awslint:ref-via-interface].
        :param resource_property: The property name where this asset is referenced.

        :see: https://github.com/aws/aws-cdk/issues/1432
        '''
        return typing.cast(None, jsii.invoke(self, "addResourceMetadata", [resource, resource_property]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assetHash")
    def asset_hash(self) -> builtins.str:
        '''A hash of this asset, which is available at construction time.

        As this is a plain string, it
        can be used in construct IDs in order to enforce creation of a new resource when the content
        hash has changed.
        '''
        return typing.cast(builtins.str, jsii.get(self, "assetHash"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageUri")
    def image_uri(self) -> builtins.str:
        '''The full URI of the image (including a tag).

        Use this reference to pull
        the asset.
        '''
        return typing.cast(builtins.str, jsii.get(self, "imageUri"))

    @image_uri.setter
    def image_uri(self, value: builtins.str) -> None:
        jsii.set(self, "imageUri", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repository")
    def repository(self) -> _IRepository_e6004aa6:
        '''Repository where the image is stored.'''
        return typing.cast(_IRepository_e6004aa6, jsii.get(self, "repository"))

    @repository.setter
    def repository(self, value: _IRepository_e6004aa6) -> None:
        jsii.set(self, "repository", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr_assets.DockerImageAssetInvalidationOptions",
    jsii_struct_bases=[],
    name_mapping={
        "build_args": "buildArgs",
        "extra_hash": "extraHash",
        "file": "file",
        "network_mode": "networkMode",
        "repository_name": "repositoryName",
        "target": "target",
    },
)
class DockerImageAssetInvalidationOptions:
    def __init__(
        self,
        *,
        build_args: typing.Optional[builtins.bool] = None,
        extra_hash: typing.Optional[builtins.bool] = None,
        file: typing.Optional[builtins.bool] = None,
        network_mode: typing.Optional[builtins.bool] = None,
        repository_name: typing.Optional[builtins.bool] = None,
        target: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Options to control invalidation of ``DockerImageAsset`` asset hashes.

        :param build_args: Use ``buildArgs`` while calculating the asset hash. Default: true
        :param extra_hash: Use ``extraHash`` while calculating the asset hash. Default: true
        :param file: Use ``file`` while calculating the asset hash. Default: true
        :param network_mode: Use ``networkMode`` while calculating the asset hash. Default: true
        :param repository_name: Use ``repositoryName`` while calculating the asset hash. Default: true
        :param target: Use ``target`` while calculating the asset hash. Default: true

        :exampleMetadata: infused

        Example::

            from aws_cdk.aws_ecr_assets import DockerImageAsset
            
            
            asset = DockerImageAsset(self, "MyBuildImage",
                directory=path.join(__dirname, "my-image"),
                build_args={
                    "HTTP_PROXY": "http://10.20.30.2:1234"
                },
                invalidation=DockerImageAssetInvalidationOptions(
                    build_args=False
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if build_args is not None:
            self._values["build_args"] = build_args
        if extra_hash is not None:
            self._values["extra_hash"] = extra_hash
        if file is not None:
            self._values["file"] = file
        if network_mode is not None:
            self._values["network_mode"] = network_mode
        if repository_name is not None:
            self._values["repository_name"] = repository_name
        if target is not None:
            self._values["target"] = target

    @builtins.property
    def build_args(self) -> typing.Optional[builtins.bool]:
        '''Use ``buildArgs`` while calculating the asset hash.

        :default: true
        '''
        result = self._values.get("build_args")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def extra_hash(self) -> typing.Optional[builtins.bool]:
        '''Use ``extraHash`` while calculating the asset hash.

        :default: true
        '''
        result = self._values.get("extra_hash")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def file(self) -> typing.Optional[builtins.bool]:
        '''Use ``file`` while calculating the asset hash.

        :default: true
        '''
        result = self._values.get("file")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def network_mode(self) -> typing.Optional[builtins.bool]:
        '''Use ``networkMode`` while calculating the asset hash.

        :default: true
        '''
        result = self._values.get("network_mode")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def repository_name(self) -> typing.Optional[builtins.bool]:
        '''Use ``repositoryName`` while calculating the asset hash.

        :default: true
        '''
        result = self._values.get("repository_name")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def target(self) -> typing.Optional[builtins.bool]:
        '''Use ``target`` while calculating the asset hash.

        :default: true
        '''
        result = self._values.get("target")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DockerImageAssetInvalidationOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr_assets.DockerImageAssetOptions",
    jsii_struct_bases=[_FileFingerprintOptions_115b8b51],
    name_mapping={
        "exclude": "exclude",
        "follow_symlinks": "followSymlinks",
        "ignore_mode": "ignoreMode",
        "extra_hash": "extraHash",
        "build_args": "buildArgs",
        "file": "file",
        "invalidation": "invalidation",
        "network_mode": "networkMode",
        "target": "target",
    },
)
class DockerImageAssetOptions(_FileFingerprintOptions_115b8b51):
    def __init__(
        self,
        *,
        exclude: typing.Optional[typing.Sequence[builtins.str]] = None,
        follow_symlinks: typing.Optional[_SymlinkFollowMode_047ec1f6] = None,
        ignore_mode: typing.Optional[_IgnoreMode_655a98e8] = None,
        extra_hash: typing.Optional[builtins.str] = None,
        build_args: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        file: typing.Optional[builtins.str] = None,
        invalidation: typing.Optional[DockerImageAssetInvalidationOptions] = None,
        network_mode: typing.Optional["NetworkMode"] = None,
        target: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options for DockerImageAsset.

        :param exclude: Glob patterns to exclude from the copy. Default: - nothing is excluded
        :param follow_symlinks: A strategy for how to handle symlinks. Default: SymlinkFollowMode.NEVER
        :param ignore_mode: The ignore behavior to use for exclude patterns. Default: IgnoreMode.GLOB
        :param extra_hash: Extra information to encode into the fingerprint (e.g. build instructions and other inputs). Default: - hash is only based on source content
        :param build_args: Build args to pass to the ``docker build`` command. Since Docker build arguments are resolved before deployment, keys and values cannot refer to unresolved tokens (such as ``lambda.functionArn`` or ``queue.queueUrl``). Default: - no build args are passed
        :param file: Path to the Dockerfile (relative to the directory). Default: 'Dockerfile'
        :param invalidation: Options to control which parameters are used to invalidate the asset hash. Default: - hash all parameters
        :param network_mode: Networking mode for the RUN commands during build. Support docker API 1.25+. Default: - no networking mode specified (the default networking mode ``NetworkMode.DEFAULT`` will be used)
        :param target: Docker target to build to. Default: - no target

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_ecr_assets as ecr_assets
            
            # network_mode: ecr_assets.NetworkMode
            
            docker_image_asset_options = ecr_assets.DockerImageAssetOptions(
                build_args={
                    "build_args_key": "buildArgs"
                },
                exclude=["exclude"],
                extra_hash="extraHash",
                file="file",
                follow_symlinks=cdk.SymlinkFollowMode.NEVER,
                ignore_mode=cdk.IgnoreMode.GLOB,
                invalidation=ecr_assets.DockerImageAssetInvalidationOptions(
                    build_args=False,
                    extra_hash=False,
                    file=False,
                    network_mode=False,
                    repository_name=False,
                    target=False
                ),
                network_mode=network_mode,
                target="target"
            )
        '''
        if isinstance(invalidation, dict):
            invalidation = DockerImageAssetInvalidationOptions(**invalidation)
        self._values: typing.Dict[str, typing.Any] = {}
        if exclude is not None:
            self._values["exclude"] = exclude
        if follow_symlinks is not None:
            self._values["follow_symlinks"] = follow_symlinks
        if ignore_mode is not None:
            self._values["ignore_mode"] = ignore_mode
        if extra_hash is not None:
            self._values["extra_hash"] = extra_hash
        if build_args is not None:
            self._values["build_args"] = build_args
        if file is not None:
            self._values["file"] = file
        if invalidation is not None:
            self._values["invalidation"] = invalidation
        if network_mode is not None:
            self._values["network_mode"] = network_mode
        if target is not None:
            self._values["target"] = target

    @builtins.property
    def exclude(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Glob patterns to exclude from the copy.

        :default: - nothing is excluded
        '''
        result = self._values.get("exclude")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def follow_symlinks(self) -> typing.Optional[_SymlinkFollowMode_047ec1f6]:
        '''A strategy for how to handle symlinks.

        :default: SymlinkFollowMode.NEVER
        '''
        result = self._values.get("follow_symlinks")
        return typing.cast(typing.Optional[_SymlinkFollowMode_047ec1f6], result)

    @builtins.property
    def ignore_mode(self) -> typing.Optional[_IgnoreMode_655a98e8]:
        '''The ignore behavior to use for exclude patterns.

        :default: IgnoreMode.GLOB
        '''
        result = self._values.get("ignore_mode")
        return typing.cast(typing.Optional[_IgnoreMode_655a98e8], result)

    @builtins.property
    def extra_hash(self) -> typing.Optional[builtins.str]:
        '''Extra information to encode into the fingerprint (e.g. build instructions and other inputs).

        :default: - hash is only based on source content
        '''
        result = self._values.get("extra_hash")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def build_args(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Build args to pass to the ``docker build`` command.

        Since Docker build arguments are resolved before deployment, keys and
        values cannot refer to unresolved tokens (such as ``lambda.functionArn`` or
        ``queue.queueUrl``).

        :default: - no build args are passed
        '''
        result = self._values.get("build_args")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def file(self) -> typing.Optional[builtins.str]:
        '''Path to the Dockerfile (relative to the directory).

        :default: 'Dockerfile'
        '''
        result = self._values.get("file")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def invalidation(self) -> typing.Optional[DockerImageAssetInvalidationOptions]:
        '''Options to control which parameters are used to invalidate the asset hash.

        :default: - hash all parameters
        '''
        result = self._values.get("invalidation")
        return typing.cast(typing.Optional[DockerImageAssetInvalidationOptions], result)

    @builtins.property
    def network_mode(self) -> typing.Optional["NetworkMode"]:
        '''Networking mode for the RUN commands during build.

        Support docker API 1.25+.

        :default: - no networking mode specified (the default networking mode ``NetworkMode.DEFAULT`` will be used)
        '''
        result = self._values.get("network_mode")
        return typing.cast(typing.Optional["NetworkMode"], result)

    @builtins.property
    def target(self) -> typing.Optional[builtins.str]:
        '''Docker target to build to.

        :default: - no target
        '''
        result = self._values.get("target")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DockerImageAssetOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr_assets.DockerImageAssetProps",
    jsii_struct_bases=[DockerImageAssetOptions],
    name_mapping={
        "exclude": "exclude",
        "follow_symlinks": "followSymlinks",
        "ignore_mode": "ignoreMode",
        "extra_hash": "extraHash",
        "build_args": "buildArgs",
        "file": "file",
        "invalidation": "invalidation",
        "network_mode": "networkMode",
        "target": "target",
        "directory": "directory",
    },
)
class DockerImageAssetProps(DockerImageAssetOptions):
    def __init__(
        self,
        *,
        exclude: typing.Optional[typing.Sequence[builtins.str]] = None,
        follow_symlinks: typing.Optional[_SymlinkFollowMode_047ec1f6] = None,
        ignore_mode: typing.Optional[_IgnoreMode_655a98e8] = None,
        extra_hash: typing.Optional[builtins.str] = None,
        build_args: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        file: typing.Optional[builtins.str] = None,
        invalidation: typing.Optional[DockerImageAssetInvalidationOptions] = None,
        network_mode: typing.Optional["NetworkMode"] = None,
        target: typing.Optional[builtins.str] = None,
        directory: builtins.str,
    ) -> None:
        '''Props for DockerImageAssets.

        :param exclude: Glob patterns to exclude from the copy. Default: - nothing is excluded
        :param follow_symlinks: A strategy for how to handle symlinks. Default: SymlinkFollowMode.NEVER
        :param ignore_mode: The ignore behavior to use for exclude patterns. Default: IgnoreMode.GLOB
        :param extra_hash: Extra information to encode into the fingerprint (e.g. build instructions and other inputs). Default: - hash is only based on source content
        :param build_args: Build args to pass to the ``docker build`` command. Since Docker build arguments are resolved before deployment, keys and values cannot refer to unresolved tokens (such as ``lambda.functionArn`` or ``queue.queueUrl``). Default: - no build args are passed
        :param file: Path to the Dockerfile (relative to the directory). Default: 'Dockerfile'
        :param invalidation: Options to control which parameters are used to invalidate the asset hash. Default: - hash all parameters
        :param network_mode: Networking mode for the RUN commands during build. Support docker API 1.25+. Default: - no networking mode specified (the default networking mode ``NetworkMode.DEFAULT`` will be used)
        :param target: Docker target to build to. Default: - no target
        :param directory: The directory where the Dockerfile is stored. Any directory inside with a name that matches the CDK output folder (cdk.out by default) will be excluded from the asset

        :exampleMetadata: infused

        Example::

            from aws_cdk.aws_ecr_assets import DockerImageAsset
            
            
            asset = DockerImageAsset(self, "MyBuildImage",
                directory=path.join(__dirname, "my-image"),
                build_args={
                    "HTTP_PROXY": "http://10.20.30.2:1234"
                },
                invalidation=DockerImageAssetInvalidationOptions(
                    build_args=False
                )
            )
        '''
        if isinstance(invalidation, dict):
            invalidation = DockerImageAssetInvalidationOptions(**invalidation)
        self._values: typing.Dict[str, typing.Any] = {
            "directory": directory,
        }
        if exclude is not None:
            self._values["exclude"] = exclude
        if follow_symlinks is not None:
            self._values["follow_symlinks"] = follow_symlinks
        if ignore_mode is not None:
            self._values["ignore_mode"] = ignore_mode
        if extra_hash is not None:
            self._values["extra_hash"] = extra_hash
        if build_args is not None:
            self._values["build_args"] = build_args
        if file is not None:
            self._values["file"] = file
        if invalidation is not None:
            self._values["invalidation"] = invalidation
        if network_mode is not None:
            self._values["network_mode"] = network_mode
        if target is not None:
            self._values["target"] = target

    @builtins.property
    def exclude(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Glob patterns to exclude from the copy.

        :default: - nothing is excluded
        '''
        result = self._values.get("exclude")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def follow_symlinks(self) -> typing.Optional[_SymlinkFollowMode_047ec1f6]:
        '''A strategy for how to handle symlinks.

        :default: SymlinkFollowMode.NEVER
        '''
        result = self._values.get("follow_symlinks")
        return typing.cast(typing.Optional[_SymlinkFollowMode_047ec1f6], result)

    @builtins.property
    def ignore_mode(self) -> typing.Optional[_IgnoreMode_655a98e8]:
        '''The ignore behavior to use for exclude patterns.

        :default: IgnoreMode.GLOB
        '''
        result = self._values.get("ignore_mode")
        return typing.cast(typing.Optional[_IgnoreMode_655a98e8], result)

    @builtins.property
    def extra_hash(self) -> typing.Optional[builtins.str]:
        '''Extra information to encode into the fingerprint (e.g. build instructions and other inputs).

        :default: - hash is only based on source content
        '''
        result = self._values.get("extra_hash")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def build_args(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Build args to pass to the ``docker build`` command.

        Since Docker build arguments are resolved before deployment, keys and
        values cannot refer to unresolved tokens (such as ``lambda.functionArn`` or
        ``queue.queueUrl``).

        :default: - no build args are passed
        '''
        result = self._values.get("build_args")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def file(self) -> typing.Optional[builtins.str]:
        '''Path to the Dockerfile (relative to the directory).

        :default: 'Dockerfile'
        '''
        result = self._values.get("file")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def invalidation(self) -> typing.Optional[DockerImageAssetInvalidationOptions]:
        '''Options to control which parameters are used to invalidate the asset hash.

        :default: - hash all parameters
        '''
        result = self._values.get("invalidation")
        return typing.cast(typing.Optional[DockerImageAssetInvalidationOptions], result)

    @builtins.property
    def network_mode(self) -> typing.Optional["NetworkMode"]:
        '''Networking mode for the RUN commands during build.

        Support docker API 1.25+.

        :default: - no networking mode specified (the default networking mode ``NetworkMode.DEFAULT`` will be used)
        '''
        result = self._values.get("network_mode")
        return typing.cast(typing.Optional["NetworkMode"], result)

    @builtins.property
    def target(self) -> typing.Optional[builtins.str]:
        '''Docker target to build to.

        :default: - no target
        '''
        result = self._values.get("target")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def directory(self) -> builtins.str:
        '''The directory where the Dockerfile is stored.

        Any directory inside with a name that matches the CDK output folder (cdk.out by default) will be excluded from the asset
        '''
        result = self._values.get("directory")
        assert result is not None, "Required property 'directory' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DockerImageAssetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class NetworkMode(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr_assets.NetworkMode",
):
    '''networking mode on build time supported by docker.

    :exampleMetadata: infused

    Example::

        from aws_cdk.aws_ecr_assets import DockerImageAsset, NetworkMode
        
        
        asset = DockerImageAsset(self, "MyBuildImage",
            directory=path.join(__dirname, "my-image"),
            network_mode=NetworkMode.HOST
        )
    '''

    @jsii.member(jsii_name="custom") # type: ignore[misc]
    @builtins.classmethod
    def custom(cls, mode: builtins.str) -> "NetworkMode":
        '''Used to specify a custom networking mode Use this if the networking mode name is not yet supported by the CDK.

        :param mode: The networking mode to use for docker build.
        '''
        return typing.cast("NetworkMode", jsii.sinvoke(cls, "custom", [mode]))

    @jsii.member(jsii_name="fromContainer") # type: ignore[misc]
    @builtins.classmethod
    def from_container(cls, container_id: builtins.str) -> "NetworkMode":
        '''Reuse another container's network stack.

        :param container_id: The target container's id or name.
        '''
        return typing.cast("NetworkMode", jsii.sinvoke(cls, "fromContainer", [container_id]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="DEFAULT")
    def DEFAULT(cls) -> "NetworkMode":
        '''The default networking mode if omitted, create a network stack on the default Docker bridge.'''
        return typing.cast("NetworkMode", jsii.sget(cls, "DEFAULT"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="HOST")
    def HOST(cls) -> "NetworkMode":
        '''Use the Docker host network stack.'''
        return typing.cast("NetworkMode", jsii.sget(cls, "HOST"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="NONE")
    def NONE(cls) -> "NetworkMode":
        '''Disable the network stack, only the loopback device will be created.'''
        return typing.cast("NetworkMode", jsii.sget(cls, "NONE"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="mode")
    def mode(self) -> builtins.str:
        '''The networking mode to use for docker build.'''
        return typing.cast(builtins.str, jsii.get(self, "mode"))


class TarballImageAsset(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_ecr_assets.TarballImageAsset",
):
    '''An asset that represents a Docker image.

    The image will loaded from an existing tarball and uploaded to an ECR repository.

    :exampleMetadata: infused

    Example::

        from aws_cdk.aws_ecr_assets import TarballImageAsset
        
        
        asset = TarballImageAsset(self, "MyBuildImage",
            tarball_file="local-image.tar"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        tarball_file: builtins.str,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param tarball_file: Absolute path to the tarball. It is recommended to to use the script running directory (e.g. ``__dirname`` in Node.js projects or dirname of ``__file__`` in Python) if your tarball is located as a resource inside your project.
        '''
        props = TarballImageAssetProps(tarball_file=tarball_file)

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assetHash")
    def asset_hash(self) -> builtins.str:
        '''A hash of this asset, which is available at construction time.

        As this is a plain string, it
        can be used in construct IDs in order to enforce creation of a new resource when the content
        hash has changed.
        '''
        return typing.cast(builtins.str, jsii.get(self, "assetHash"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="imageUri")
    def image_uri(self) -> builtins.str:
        '''The full URI of the image (including a tag).

        Use this reference to pull
        the asset.
        '''
        return typing.cast(builtins.str, jsii.get(self, "imageUri"))

    @image_uri.setter
    def image_uri(self, value: builtins.str) -> None:
        jsii.set(self, "imageUri", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="repository")
    def repository(self) -> _IRepository_e6004aa6:
        '''Repository where the image is stored.'''
        return typing.cast(_IRepository_e6004aa6, jsii.get(self, "repository"))

    @repository.setter
    def repository(self, value: _IRepository_e6004aa6) -> None:
        jsii.set(self, "repository", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_ecr_assets.TarballImageAssetProps",
    jsii_struct_bases=[],
    name_mapping={"tarball_file": "tarballFile"},
)
class TarballImageAssetProps:
    def __init__(self, *, tarball_file: builtins.str) -> None:
        '''Options for TarballImageAsset.

        :param tarball_file: Absolute path to the tarball. It is recommended to to use the script running directory (e.g. ``__dirname`` in Node.js projects or dirname of ``__file__`` in Python) if your tarball is located as a resource inside your project.

        :exampleMetadata: infused

        Example::

            from aws_cdk.aws_ecr_assets import TarballImageAsset
            
            
            asset = TarballImageAsset(self, "MyBuildImage",
                tarball_file="local-image.tar"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "tarball_file": tarball_file,
        }

    @builtins.property
    def tarball_file(self) -> builtins.str:
        '''Absolute path to the tarball.

        It is recommended to to use the script running directory (e.g. ``__dirname``
        in Node.js projects or dirname of ``__file__`` in Python) if your tarball
        is located as a resource inside your project.
        '''
        result = self._values.get("tarball_file")
        assert result is not None, "Required property 'tarball_file' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TarballImageAssetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "DockerImageAsset",
    "DockerImageAssetInvalidationOptions",
    "DockerImageAssetOptions",
    "DockerImageAssetProps",
    "NetworkMode",
    "TarballImageAsset",
    "TarballImageAssetProps",
]

publication.publish()
