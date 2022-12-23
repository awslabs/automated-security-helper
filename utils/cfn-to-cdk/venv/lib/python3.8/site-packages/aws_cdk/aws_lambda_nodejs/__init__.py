'''
# Amazon Lambda Node.js Library

This library provides constructs for Node.js Lambda functions.

## Node.js Function

The `NodejsFunction` construct creates a Lambda function with automatic transpiling and bundling
of TypeScript or Javascript code. This results in smaller Lambda packages that contain only the
code and dependencies needed to run the function.

It uses [esbuild](https://esbuild.github.io/) under the hood.

## Reference project architecture

The `NodejsFunction` allows you to define your CDK and runtime dependencies in a single
package.json and to collocate your runtime code with your infrastructure code:

```plaintext
.
├── lib
│   ├── my-construct.api.ts # Lambda handler for API
│   ├── my-construct.auth.ts # Lambda handler for Auth
│   └── my-construct.ts # CDK construct with two Lambda functions
├── package-lock.json # single lock file
├── package.json # CDK and runtime dependencies defined in a single package.json
└── tsconfig.json
```

By default, the construct will use the name of the defining file and the construct's
id to look up the entry file. In `my-construct.ts` above we have:

```python
# automatic entry look up
api_handler = lambda_.NodejsFunction(self, "api")
auth_handler = lambda_.NodejsFunction(self, "auth")
```

Alternatively, an entry file and handler can be specified:

```python
lambda_.NodejsFunction(self, "MyFunction",
    entry="/path/to/my/file.ts",  # accepts .js, .jsx, .ts, .tsx and .mjs files
    handler="myExportedFunc"
)
```

For monorepos, the reference architecture becomes:

```plaintext
.
├── packages
│   ├── cool-package
│   │   ├── lib
│   │   │   ├── cool-construct.api.ts
│   │   │   ├── cool-construct.auth.ts
│   │   │   └── cool-construct.ts
│   │   ├── package.json # CDK and runtime dependencies for cool-package
│   │   └── tsconfig.json
│   └── super-package
│       ├── lib
│       │   ├── super-construct.handler.ts
│       │   └── super-construct.ts
│       ├── package.json # CDK and runtime dependencies for super-package
│       └── tsconfig.json
├── package-lock.json # single lock file
├── package.json # root dependencies
└── tsconfig.json
```

## Customizing the underlying Lambda function

All properties of `lambda.Function` can be used to customize the underlying `lambda.Function`.

See also the [AWS Lambda construct library](https://github.com/aws/aws-cdk/tree/master/packages/%40aws-cdk/aws-lambda).

The `NodejsFunction` construct automatically [reuses existing connections](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/node-reusing-connections.html)
when working with the AWS SDK for JavaScript. Set the `awsSdkConnectionReuse` prop to `false` to disable it.

## Lock file

The `NodejsFunction` requires a dependencies lock file (`yarn.lock`, `pnpm-lock.yaml` or
`package-lock.json`). When bundling in a Docker container, the path containing this lock file is
used as the source (`/asset-input`) for the volume mounted in the container.

By default, the construct will try to automatically determine your project lock file.
Alternatively, you can specify the `depsLockFilePath` prop manually. In this
case you need to ensure that this path includes `entry` and any module/dependencies
used by your function. Otherwise bundling will fail.

## Local bundling

If `esbuild` is available it will be used to bundle your code in your environment. Otherwise,
bundling will happen in a [Lambda compatible Docker container](https://gallery.ecr.aws/sam/build-nodejs12.x)
with the Docker platform based on the target architecture of the Lambda function.

For macOS the recommendend approach is to install `esbuild` as Docker volume performance is really poor.

`esbuild` can be installed with:

```console
$ npm install --save-dev esbuild@0
```

OR

```console
$ yarn add --dev esbuild@0
```

If you're using a monorepo layout, the `esbuild` dependency needs to be installed in the "root" `package.json` file,
not in the workspace. From the reference architecture described [above](#reference-project-architecture), the `esbuild`
dev dependency needs to be in `./package.json`, not `packages/cool-package/package.json` or
`packages/super-package/package.json`.

To force bundling in a Docker container even if `esbuild` is available in your environment,
set `bundling.forceDockerBundling` to `true`. This is useful if your function relies on node
modules that should be installed (`nodeModules` prop, see [below](#install-modules)) in a Lambda
compatible environment. This is usually the case with modules using native dependencies.

## Working with modules

### Externals

By default, all node modules are bundled except for `aws-sdk`. This can be configured by specifying
`bundling.externalModules`:

```python
lambda_.NodejsFunction(self, "my-handler",
    bundling=lambda.BundlingOptions(
        external_modules=["aws-sdk", "cool-module"
        ]
    )
)
```

### Install modules

By default, all node modules referenced in your Lambda code will be bundled by `esbuild`.
Use the `nodeModules` prop under `bundling` to specify a list of modules that should not be
bundled but instead included in the `node_modules` folder of the Lambda package. This is useful
when working with native dependencies or when `esbuild` fails to bundle a module.

```python
lambda_.NodejsFunction(self, "my-handler",
    bundling=lambda.BundlingOptions(
        node_modules=["native-module", "other-module"]
    )
)
```

The modules listed in `nodeModules` must be present in the `package.json`'s dependencies or
installed. The same version will be used for installation. The lock file (`yarn.lock`,
`pnpm-lock.yaml` or `package-lock.json`) will be used along with the right installer (`yarn`,
`pnpm` or `npm`).

When working with `nodeModules` using native dependencies, you might want to force bundling in a
Docker container even if `esbuild` is available in your environment. This can be done by setting
`bundling.forceDockerBundling` to `true`.

## Configuring `esbuild`

The `NodejsFunction` construct exposes some [esbuild options](https://esbuild.github.io/api/#build-api)
via properties under `bundling`:

```python
lambda_.NodejsFunction(self, "my-handler",
    bundling=lambda.BundlingOptions(
        minify=True,  # minify code, defaults to false
        source_map=True,  # include source map, defaults to false
        source_map_mode=lambda_.SourceMapMode.INLINE,  # defaults to SourceMapMode.DEFAULT
        sources_content=False,  # do not include original source into source map, defaults to true
        target="es2020",  # target environment for the generated JavaScript code
        loader={ # Use the 'dataurl' loader for '.png' files
            ".png": "dataurl"},
        define={ # Replace strings during build time
            "process.env._aPI__kEY": JSON.stringify("xxx-xxxx-xxx"),
            "process.env._pRODUCTION": JSON.stringify(True),
            "process.env._nUMBER": JSON.stringify(123)},
        log_level=lambda_.LogLevel.SILENT,  # defaults to LogLevel.WARNING
        keep_names=True,  # defaults to false
        tsconfig="custom-tsconfig.json",  # use custom-tsconfig.json instead of default,
        metafile=True,  # include meta file, defaults to false
        banner="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
        footer="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
        charset=lambda_.Charset.UTF8,  # do not escape non-ASCII characters, defaults to Charset.ASCII
        format=lambda_.OutputFormat.ESM,  # ECMAScript module output format, defaults to OutputFormat.CJS (OutputFormat.ESM requires Node.js 14.x)
        main_fields=["module", "main"]
    )
)
```

## Command hooks

It is possible to run additional commands by specifying the `commandHooks` prop:

```text
// This example only available in TypeScript
// Run additional props via `commandHooks`
new lambda.NodejsFunction(this, 'my-handler-with-commands', {
  bundling: {
    commandHooks: {
      beforeBundling(inputDir: string, outputDir: string): string[] {
        return [
          `echo hello > ${inputDir}/a.txt`,
          `cp ${inputDir}/a.txt ${outputDir}`,
        ];
      },
      afterBundling(inputDir: string, outputDir: string): string[] {
        return [`cp ${inputDir}/b.txt ${outputDir}/txt`];
      },
      beforeInstall() {
        return [];
      },
      // ...
    },
    // ...
  },
});
```

The following hooks are available:

* `beforeBundling`: runs before all bundling commands
* `beforeInstall`: runs before node modules installation
* `afterBundling`: runs after all bundling commands

They all receive the directory containing the lock file (`inputDir`) and the
directory where the bundled asset will be output (`outputDir`). They must return
an array of commands to run. Commands are chained with `&&`.

The commands will run in the environment in which bundling occurs: inside the
container for Docker bundling or on the host OS for local bundling.

## Pre Compilation with TSC

In some cases, `esbuild` may not yet support some newer features of the typescript language, such as,
[`emitDecoratorMetadata`](https://www.typescriptlang.org/tsconfig#emitDecoratorMetadata).
In such cases, it is possible to run pre-compilation using `tsc` by setting the `preCompilation` flag.

```python
lambda_.NodejsFunction(self, "my-handler",
    bundling=lambda.BundlingOptions(
        pre_compilation=True
    )
)
```

Note: A [`tsconfig.json` file](https://www.typescriptlang.org/docs/handbook/tsconfig-json.html) is required

## Customizing Docker bundling

Use `bundling.environment` to define environments variables when `esbuild` runs:

```python
lambda_.NodejsFunction(self, "my-handler",
    bundling=lambda.BundlingOptions(
        environment={
            "NODE_ENV": "production"
        }
    )
)
```

Use `bundling.buildArgs` to pass build arguments when building the Docker bundling image:

```python
lambda_.NodejsFunction(self, "my-handler",
    bundling=lambda.BundlingOptions(
        build_args={
            "HTTPS_PROXY": "https://127.0.0.1:3001"
        }
    )
)
```

Use `bundling.dockerImage` to use a custom Docker bundling image:

```python
lambda_.NodejsFunction(self, "my-handler",
    bundling=lambda.BundlingOptions(
        docker_image=DockerImage.from_build("/path/to/Dockerfile")
    )
)
```

This image should have `esbuild` installed **globally**. If you plan to use `nodeModules` it
should also have `npm`, `yarn` or `pnpm` depending on the lock file you're using.

Use the [default image provided by `@aws-cdk/aws-lambda-nodejs`](https://github.com/aws/aws-cdk/blob/master/packages/%40aws-cdk/aws-lambda-nodejs/lib/Dockerfile)
as a source of inspiration.

## Asset hash

By default the asset hash will be calculated based on the bundled output (`AssetHashType.OUTPUT`).

Use the `assetHash` prop to pass a custom hash:

```python
lambda_.NodejsFunction(self, "my-handler",
    bundling=lambda.BundlingOptions(
        asset_hash="my-custom-hash"
    )
)
```

If you chose to customize the hash, you will need to make sure it is updated every time the asset
changes, or otherwise it is possible that some deployments will not be invalidated.
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
from .. import DockerImage as _DockerImage_f97a0c12, Duration as _Duration_4839e8c3
from ..aws_codeguruprofiler import IProfilingGroup as _IProfilingGroup_0bba72c4
from ..aws_ec2 import (
    ISecurityGroup as _ISecurityGroup_acf8a799,
    IVpc as _IVpc_f30d5663,
    SubnetSelection as _SubnetSelection_e57d76df,
)
from ..aws_iam import (
    IRole as _IRole_235f5d8e, PolicyStatement as _PolicyStatement_0fe33853
)
from ..aws_kms import IKey as _IKey_5f11635f
from ..aws_lambda import (
    Architecture as _Architecture_12d5a53f,
    FileSystem as _FileSystem_a5fa005d,
    Function as _Function_244f85d8,
    FunctionOptions as _FunctionOptions_328f4d39,
    ICodeSigningConfig as _ICodeSigningConfig_edb41d1f,
    IDestination as _IDestination_40f19de4,
    IEventSource as _IEventSource_3686b3f8,
    ILayerVersion as _ILayerVersion_5ac127c8,
    LambdaInsightsVersion as _LambdaInsightsVersion_9dfbfef9,
    LogRetentionRetryOptions as _LogRetentionRetryOptions_ad797a7a,
    Runtime as _Runtime_b4eaa844,
    Tracing as _Tracing_9fe8e2bb,
    VersionOptions as _VersionOptions_981bb3c0,
)
from ..aws_logs import RetentionDays as _RetentionDays_070f99f0
from ..aws_sns import ITopic as _ITopic_9eca4852
from ..aws_sqs import IQueue as _IQueue_7ed6f679


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lambda_nodejs.BundlingOptions",
    jsii_struct_bases=[],
    name_mapping={
        "asset_hash": "assetHash",
        "banner": "banner",
        "build_args": "buildArgs",
        "charset": "charset",
        "command_hooks": "commandHooks",
        "define": "define",
        "docker_image": "dockerImage",
        "environment": "environment",
        "esbuild_version": "esbuildVersion",
        "external_modules": "externalModules",
        "footer": "footer",
        "force_docker_bundling": "forceDockerBundling",
        "format": "format",
        "keep_names": "keepNames",
        "loader": "loader",
        "log_level": "logLevel",
        "main_fields": "mainFields",
        "metafile": "metafile",
        "minify": "minify",
        "node_modules": "nodeModules",
        "pre_compilation": "preCompilation",
        "source_map": "sourceMap",
        "source_map_mode": "sourceMapMode",
        "sources_content": "sourcesContent",
        "target": "target",
        "tsconfig": "tsconfig",
    },
)
class BundlingOptions:
    def __init__(
        self,
        *,
        asset_hash: typing.Optional[builtins.str] = None,
        banner: typing.Optional[builtins.str] = None,
        build_args: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        charset: typing.Optional["Charset"] = None,
        command_hooks: typing.Optional["ICommandHooks"] = None,
        define: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        docker_image: typing.Optional[_DockerImage_f97a0c12] = None,
        environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        esbuild_version: typing.Optional[builtins.str] = None,
        external_modules: typing.Optional[typing.Sequence[builtins.str]] = None,
        footer: typing.Optional[builtins.str] = None,
        force_docker_bundling: typing.Optional[builtins.bool] = None,
        format: typing.Optional["OutputFormat"] = None,
        keep_names: typing.Optional[builtins.bool] = None,
        loader: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        log_level: typing.Optional["LogLevel"] = None,
        main_fields: typing.Optional[typing.Sequence[builtins.str]] = None,
        metafile: typing.Optional[builtins.bool] = None,
        minify: typing.Optional[builtins.bool] = None,
        node_modules: typing.Optional[typing.Sequence[builtins.str]] = None,
        pre_compilation: typing.Optional[builtins.bool] = None,
        source_map: typing.Optional[builtins.bool] = None,
        source_map_mode: typing.Optional["SourceMapMode"] = None,
        sources_content: typing.Optional[builtins.bool] = None,
        target: typing.Optional[builtins.str] = None,
        tsconfig: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Bundling options.

        :param asset_hash: Specify a custom hash for this asset. For consistency, this custom hash will be SHA256 hashed and encoded as hex. The resulting hash will be the asset hash. NOTE: the hash is used in order to identify a specific revision of the asset, and used for optimizing and caching deployment activities related to this asset such as packaging, uploading to Amazon S3, etc. If you chose to customize the hash, you will need to make sure it is updated every time the asset changes, or otherwise it is possible that some deployments will not be invalidated. Default: - asset hash is calculated based on the bundled output
        :param banner: Use this to insert an arbitrary string at the beginning of generated JavaScript files. This is similar to footer which inserts at the end instead of the beginning. This is commonly used to insert comments: Default: - no comments are passed
        :param build_args: Build arguments to pass when building the bundling image. Default: - no build arguments are passed
        :param charset: The charset to use for esbuild's output. By default esbuild's output is ASCII-only. Any non-ASCII characters are escaped using backslash escape sequences. Using escape sequences makes the generated output slightly bigger, and also makes it harder to read. If you would like for esbuild to print the original characters without using escape sequences, use ``Charset.UTF8``. Default: Charset.ASCII
        :param command_hooks: Command hooks. Default: - do not run additional commands
        :param define: Replace global identifiers with constant expressions. For example, ``{ 'process.env.DEBUG': 'true' }``. Another example, ``{ 'process.env.API_KEY': JSON.stringify('xxx-xxxx-xxx') }``. Default: - no replacements are made
        :param docker_image: A custom bundling Docker image. This image should have esbuild installed globally. If you plan to use ``nodeModules`` it should also have ``npm`` or ``yarn`` depending on the lock file you're using. See https://github.com/aws/aws-cdk/blob/master/packages/%40aws-cdk/aws-lambda-nodejs/lib/Dockerfile for the default image provided by @aws-cdk/aws-lambda-nodejs. Default: - use the Docker image provided by
        :param environment: Environment variables defined when bundling runs. Default: - no environment variables are defined.
        :param esbuild_version: The version of esbuild to use when running in a Docker container. Default: - latest v0
        :param external_modules: A list of modules that should be considered as externals (already available in the runtime). Default: ['aws-sdk']
        :param footer: Use this to insert an arbitrary string at the end of generated JavaScript files. This is similar to banner which inserts at the beginning instead of the end. This is commonly used to insert comments Default: - no comments are passed
        :param force_docker_bundling: Force bundling in a Docker container even if local bundling is possible. This is useful if your function relies on node modules that should be installed (``nodeModules``) in a Lambda compatible environment. Default: false
        :param format: Output format for the generated JavaScript files. Default: OutputFormat.CJS
        :param keep_names: Whether to preserve the original ``name`` values even in minified code. In JavaScript the ``name`` property on functions and classes defaults to a nearby identifier in the source code. However, minification renames symbols to reduce code size and bundling sometimes need to rename symbols to avoid collisions. That changes value of the ``name`` property for many of these cases. This is usually fine because the ``name`` property is normally only used for debugging. However, some frameworks rely on the ``name`` property for registration and binding purposes. If this is the case, you can enable this option to preserve the original ``name`` values even in minified code. Default: false
        :param loader: Use loaders to change how a given input file is interpreted. Configuring a loader for a given file type lets you load that file type with an ``import`` statement or a ``require`` call. Default: - use esbuild default loaders
        :param log_level: Log level for esbuild. This is also propagated to the package manager and applies to its specific install command. Default: LogLevel.WARNING
        :param main_fields: How to determine the entry point for modules. Try ['module', 'main'] to default to ES module versions. Default: ['main', 'module']
        :param metafile: This option tells esbuild to write out a JSON file relative to output directory with metadata about the build. The metadata in this JSON file follows this schema (specified using TypeScript syntax):: { outputs: { [path: string]: { bytes: number inputs: { [path: string]: { bytesInOutput: number } } imports: { path: string }[] exports: string[] } } } This data can then be analyzed by other tools. For example, bundle buddy can consume esbuild's metadata format and generates a treemap visualization of the modules in your bundle and how much space each one takes up. Default: false
        :param minify: Whether to minify files when bundling. Default: false
        :param node_modules: A list of modules that should be installed instead of bundled. Modules are installed in a Lambda compatible environment only when bundling runs in Docker. Default: - all modules are bundled
        :param pre_compilation: Run compilation using tsc before running file through bundling step. This usually is not required unless you are using new experimental features that are only supported by typescript's ``tsc`` compiler. One example of such feature is ``emitDecoratorMetadata``. Default: false
        :param source_map: Whether to include source maps when bundling. Default: false
        :param source_map_mode: Source map mode to be used when bundling. Default: SourceMapMode.DEFAULT
        :param sources_content: Whether to include original source code in source maps when bundling. Default: true
        :param target: Target environment for the generated JavaScript code. Default: - the node version of the runtime
        :param tsconfig: Normally the esbuild automatically discovers ``tsconfig.json`` files and reads their contents during a build. However, you can also configure a custom ``tsconfig.json`` file to use instead. This is similar to entry path, you need to provide path to your custom ``tsconfig.json``. This can be useful if you need to do multiple builds of the same code with different settings. For example, ``{ 'tsconfig': 'path/custom.tsconfig.json' }``. Default: - automatically discovered by ``esbuild``

        :exampleMetadata: infused

        Example::

            lambda_.NodejsFunction(self, "my-handler",
                bundling=lambda.BundlingOptions(
                    docker_image=DockerImage.from_build("/path/to/Dockerfile")
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if asset_hash is not None:
            self._values["asset_hash"] = asset_hash
        if banner is not None:
            self._values["banner"] = banner
        if build_args is not None:
            self._values["build_args"] = build_args
        if charset is not None:
            self._values["charset"] = charset
        if command_hooks is not None:
            self._values["command_hooks"] = command_hooks
        if define is not None:
            self._values["define"] = define
        if docker_image is not None:
            self._values["docker_image"] = docker_image
        if environment is not None:
            self._values["environment"] = environment
        if esbuild_version is not None:
            self._values["esbuild_version"] = esbuild_version
        if external_modules is not None:
            self._values["external_modules"] = external_modules
        if footer is not None:
            self._values["footer"] = footer
        if force_docker_bundling is not None:
            self._values["force_docker_bundling"] = force_docker_bundling
        if format is not None:
            self._values["format"] = format
        if keep_names is not None:
            self._values["keep_names"] = keep_names
        if loader is not None:
            self._values["loader"] = loader
        if log_level is not None:
            self._values["log_level"] = log_level
        if main_fields is not None:
            self._values["main_fields"] = main_fields
        if metafile is not None:
            self._values["metafile"] = metafile
        if minify is not None:
            self._values["minify"] = minify
        if node_modules is not None:
            self._values["node_modules"] = node_modules
        if pre_compilation is not None:
            self._values["pre_compilation"] = pre_compilation
        if source_map is not None:
            self._values["source_map"] = source_map
        if source_map_mode is not None:
            self._values["source_map_mode"] = source_map_mode
        if sources_content is not None:
            self._values["sources_content"] = sources_content
        if target is not None:
            self._values["target"] = target
        if tsconfig is not None:
            self._values["tsconfig"] = tsconfig

    @builtins.property
    def asset_hash(self) -> typing.Optional[builtins.str]:
        '''Specify a custom hash for this asset.

        For consistency, this custom hash will
        be SHA256 hashed and encoded as hex. The resulting hash will be the asset
        hash.

        NOTE: the hash is used in order to identify a specific revision of the asset, and
        used for optimizing and caching deployment activities related to this asset such as
        packaging, uploading to Amazon S3, etc. If you chose to customize the hash, you will
        need to make sure it is updated every time the asset changes, or otherwise it is
        possible that some deployments will not be invalidated.

        :default: - asset hash is calculated based on the bundled output
        '''
        result = self._values.get("asset_hash")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def banner(self) -> typing.Optional[builtins.str]:
        '''Use this to insert an arbitrary string at the beginning of generated JavaScript files.

        This is similar to footer which inserts at the end instead of the beginning.

        This is commonly used to insert comments:

        :default: - no comments are passed
        '''
        result = self._values.get("banner")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def build_args(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Build arguments to pass when building the bundling image.

        :default: - no build arguments are passed
        '''
        result = self._values.get("build_args")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def charset(self) -> typing.Optional["Charset"]:
        '''The charset to use for esbuild's output.

        By default esbuild's output is ASCII-only. Any non-ASCII characters are escaped
        using backslash escape sequences. Using escape sequences makes the generated output
        slightly bigger, and also makes it harder to read. If you would like for esbuild to print
        the original characters without using escape sequences, use ``Charset.UTF8``.

        :default: Charset.ASCII

        :see: https://esbuild.github.io/api/#charset
        '''
        result = self._values.get("charset")
        return typing.cast(typing.Optional["Charset"], result)

    @builtins.property
    def command_hooks(self) -> typing.Optional["ICommandHooks"]:
        '''Command hooks.

        :default: - do not run additional commands
        '''
        result = self._values.get("command_hooks")
        return typing.cast(typing.Optional["ICommandHooks"], result)

    @builtins.property
    def define(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Replace global identifiers with constant expressions.

        For example, ``{ 'process.env.DEBUG': 'true' }``.

        Another example, ``{ 'process.env.API_KEY': JSON.stringify('xxx-xxxx-xxx') }``.

        :default: - no replacements are made
        '''
        result = self._values.get("define")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def docker_image(self) -> typing.Optional[_DockerImage_f97a0c12]:
        '''A custom bundling Docker image.

        This image should have esbuild installed globally. If you plan to use ``nodeModules``
        it should also have ``npm`` or ``yarn`` depending on the lock file you're using.

        See https://github.com/aws/aws-cdk/blob/master/packages/%40aws-cdk/aws-lambda-nodejs/lib/Dockerfile
        for the default image provided by @aws-cdk/aws-lambda-nodejs.

        :default: - use the Docker image provided by

        :aws-cdk: /aws-lambda-nodejs
        '''
        result = self._values.get("docker_image")
        return typing.cast(typing.Optional[_DockerImage_f97a0c12], result)

    @builtins.property
    def environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Environment variables defined when bundling runs.

        :default: - no environment variables are defined.
        '''
        result = self._values.get("environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def esbuild_version(self) -> typing.Optional[builtins.str]:
        '''The version of esbuild to use when running in a Docker container.

        :default: - latest v0
        '''
        result = self._values.get("esbuild_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def external_modules(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of modules that should be considered as externals (already available in the runtime).

        :default: ['aws-sdk']
        '''
        result = self._values.get("external_modules")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def footer(self) -> typing.Optional[builtins.str]:
        '''Use this to insert an arbitrary string at the end of generated JavaScript files.

        This is similar to banner which inserts at the beginning instead of the end.

        This is commonly used to insert comments

        :default: - no comments are passed
        '''
        result = self._values.get("footer")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def force_docker_bundling(self) -> typing.Optional[builtins.bool]:
        '''Force bundling in a Docker container even if local bundling is possible.

        This is useful if your function relies on node modules
        that should be installed (``nodeModules``) in a Lambda compatible
        environment.

        :default: false
        '''
        result = self._values.get("force_docker_bundling")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def format(self) -> typing.Optional["OutputFormat"]:
        '''Output format for the generated JavaScript files.

        :default: OutputFormat.CJS
        '''
        result = self._values.get("format")
        return typing.cast(typing.Optional["OutputFormat"], result)

    @builtins.property
    def keep_names(self) -> typing.Optional[builtins.bool]:
        '''Whether to preserve the original ``name`` values even in minified code.

        In JavaScript the ``name`` property on functions and classes defaults to a
        nearby identifier in the source code.

        However, minification renames symbols to reduce code size and bundling
        sometimes need to rename symbols to avoid collisions. That changes value of
        the ``name`` property for many of these cases. This is usually fine because
        the ``name`` property is normally only used for debugging. However, some
        frameworks rely on the ``name`` property for registration and binding purposes.
        If this is the case, you can enable this option to preserve the original
        ``name`` values even in minified code.

        :default: false
        '''
        result = self._values.get("keep_names")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def loader(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Use loaders to change how a given input file is interpreted.

        Configuring a loader for a given file type lets you load that file type with
        an ``import`` statement or a ``require`` call.

        :default: - use esbuild default loaders

        :see:

        https://esbuild.github.io/api/#loader

        For example, ``{ '.png': 'dataurl' }``.
        '''
        result = self._values.get("loader")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def log_level(self) -> typing.Optional["LogLevel"]:
        '''Log level for esbuild.

        This is also propagated to the package manager and
        applies to its specific install command.

        :default: LogLevel.WARNING
        '''
        result = self._values.get("log_level")
        return typing.cast(typing.Optional["LogLevel"], result)

    @builtins.property
    def main_fields(self) -> typing.Optional[typing.List[builtins.str]]:
        '''How to determine the entry point for modules.

        Try ['module', 'main'] to default to ES module versions.

        :default: ['main', 'module']
        '''
        result = self._values.get("main_fields")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def metafile(self) -> typing.Optional[builtins.bool]:
        '''This option tells esbuild to write out a JSON file relative to output directory with metadata about the build.

        The metadata in this JSON file follows this schema (specified using TypeScript syntax)::

           {
              outputs: {
                [path: string]: {
                  bytes: number
                  inputs: {
                    [path: string]: { bytesInOutput: number }
                  }
                  imports: { path: string }[]
                  exports: string[]
                }
              }
           }

        This data can then be analyzed by other tools. For example,
        bundle buddy can consume esbuild's metadata format and generates a treemap visualization
        of the modules in your bundle and how much space each one takes up.

        :default: false

        :see: https://esbuild.github.io/api/#metafile
        '''
        result = self._values.get("metafile")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def minify(self) -> typing.Optional[builtins.bool]:
        '''Whether to minify files when bundling.

        :default: false
        '''
        result = self._values.get("minify")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def node_modules(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of modules that should be installed instead of bundled.

        Modules are
        installed in a Lambda compatible environment only when bundling runs in
        Docker.

        :default: - all modules are bundled
        '''
        result = self._values.get("node_modules")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def pre_compilation(self) -> typing.Optional[builtins.bool]:
        '''Run compilation using tsc before running file through bundling step.

        This usually is not required unless you are using new experimental features that
        are only supported by typescript's ``tsc`` compiler.
        One example of such feature is ``emitDecoratorMetadata``.

        :default: false
        '''
        result = self._values.get("pre_compilation")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def source_map(self) -> typing.Optional[builtins.bool]:
        '''Whether to include source maps when bundling.

        :default: false
        '''
        result = self._values.get("source_map")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def source_map_mode(self) -> typing.Optional["SourceMapMode"]:
        '''Source map mode to be used when bundling.

        :default: SourceMapMode.DEFAULT

        :see: https://esbuild.github.io/api/#sourcemap
        '''
        result = self._values.get("source_map_mode")
        return typing.cast(typing.Optional["SourceMapMode"], result)

    @builtins.property
    def sources_content(self) -> typing.Optional[builtins.bool]:
        '''Whether to include original source code in source maps when bundling.

        :default: true

        :see: https://esbuild.github.io/api/#sources-content
        '''
        result = self._values.get("sources_content")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def target(self) -> typing.Optional[builtins.str]:
        '''Target environment for the generated JavaScript code.

        :default: - the node version of the runtime

        :see: https://esbuild.github.io/api/#target
        '''
        result = self._values.get("target")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tsconfig(self) -> typing.Optional[builtins.str]:
        '''Normally the esbuild automatically discovers ``tsconfig.json`` files and reads their contents during a build.

        However, you can also configure a custom ``tsconfig.json`` file to use instead.

        This is similar to entry path, you need to provide path to your custom ``tsconfig.json``.

        This can be useful if you need to do multiple builds of the same code with different settings.

        For example, ``{ 'tsconfig': 'path/custom.tsconfig.json' }``.

        :default: - automatically discovered by ``esbuild``
        '''
        result = self._values.get("tsconfig")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BundlingOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_lambda_nodejs.Charset")
class Charset(enum.Enum):
    '''Charset for esbuild's output.

    :exampleMetadata: infused

    Example::

        lambda_.NodejsFunction(self, "my-handler",
            bundling=lambda.BundlingOptions(
                minify=True,  # minify code, defaults to false
                source_map=True,  # include source map, defaults to false
                source_map_mode=lambda_.SourceMapMode.INLINE,  # defaults to SourceMapMode.DEFAULT
                sources_content=False,  # do not include original source into source map, defaults to true
                target="es2020",  # target environment for the generated JavaScript code
                loader={ # Use the 'dataurl' loader for '.png' files
                    ".png": "dataurl"},
                define={ # Replace strings during build time
                    "process.env._aPI__kEY": JSON.stringify("xxx-xxxx-xxx"),
                    "process.env._pRODUCTION": JSON.stringify(True),
                    "process.env._nUMBER": JSON.stringify(123)},
                log_level=lambda_.LogLevel.SILENT,  # defaults to LogLevel.WARNING
                keep_names=True,  # defaults to false
                tsconfig="custom-tsconfig.json",  # use custom-tsconfig.json instead of default,
                metafile=True,  # include meta file, defaults to false
                banner="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                footer="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                charset=lambda_.Charset.UTF8,  # do not escape non-ASCII characters, defaults to Charset.ASCII
                format=lambda_.OutputFormat.ESM,  # ECMAScript module output format, defaults to OutputFormat.CJS (OutputFormat.ESM requires Node.js 14.x)
                main_fields=["module", "main"]
            )
        )
    '''

    ASCII = "ASCII"
    '''ASCII.

    Any non-ASCII characters are escaped using backslash escape sequences
    '''
    UTF8 = "UTF8"
    '''UTF-8.

    Keep original characters without using escape sequences
    '''


@jsii.interface(jsii_type="aws-cdk-lib.aws_lambda_nodejs.ICommandHooks")
class ICommandHooks(typing_extensions.Protocol):
    '''Command hooks.

    These commands will run in the environment in which bundling occurs: inside
    the container for Docker bundling or on the host OS for local bundling.

    Commands are chained with ``&&``.

    The following example (specified in TypeScript) copies a file from the input
    directory to the output directory to include it in the bundled asset::

       afterBundling(inputDir: string, outputDir: string): string[]{
          return [`cp ${inputDir}/my-binary.node ${outputDir}`];
       }
    '''

    @jsii.member(jsii_name="afterBundling")
    def after_bundling(
        self,
        input_dir: builtins.str,
        output_dir: builtins.str,
    ) -> typing.List[builtins.str]:
        '''Returns commands to run after bundling.

        Commands are chained with ``&&``.

        :param input_dir: -
        :param output_dir: -
        '''
        ...

    @jsii.member(jsii_name="beforeBundling")
    def before_bundling(
        self,
        input_dir: builtins.str,
        output_dir: builtins.str,
    ) -> typing.List[builtins.str]:
        '''Returns commands to run before bundling.

        Commands are chained with ``&&``.

        :param input_dir: -
        :param output_dir: -
        '''
        ...

    @jsii.member(jsii_name="beforeInstall")
    def before_install(
        self,
        input_dir: builtins.str,
        output_dir: builtins.str,
    ) -> typing.List[builtins.str]:
        '''Returns commands to run before installing node modules.

        This hook only runs when node modules are installed.

        Commands are chained with ``&&``.

        :param input_dir: -
        :param output_dir: -
        '''
        ...


class _ICommandHooksProxy:
    '''Command hooks.

    These commands will run in the environment in which bundling occurs: inside
    the container for Docker bundling or on the host OS for local bundling.

    Commands are chained with ``&&``.

    The following example (specified in TypeScript) copies a file from the input
    directory to the output directory to include it in the bundled asset::

       afterBundling(inputDir: string, outputDir: string): string[]{
          return [`cp ${inputDir}/my-binary.node ${outputDir}`];
       }
    '''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_lambda_nodejs.ICommandHooks"

    @jsii.member(jsii_name="afterBundling")
    def after_bundling(
        self,
        input_dir: builtins.str,
        output_dir: builtins.str,
    ) -> typing.List[builtins.str]:
        '''Returns commands to run after bundling.

        Commands are chained with ``&&``.

        :param input_dir: -
        :param output_dir: -
        '''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "afterBundling", [input_dir, output_dir]))

    @jsii.member(jsii_name="beforeBundling")
    def before_bundling(
        self,
        input_dir: builtins.str,
        output_dir: builtins.str,
    ) -> typing.List[builtins.str]:
        '''Returns commands to run before bundling.

        Commands are chained with ``&&``.

        :param input_dir: -
        :param output_dir: -
        '''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "beforeBundling", [input_dir, output_dir]))

    @jsii.member(jsii_name="beforeInstall")
    def before_install(
        self,
        input_dir: builtins.str,
        output_dir: builtins.str,
    ) -> typing.List[builtins.str]:
        '''Returns commands to run before installing node modules.

        This hook only runs when node modules are installed.

        Commands are chained with ``&&``.

        :param input_dir: -
        :param output_dir: -
        '''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "beforeInstall", [input_dir, output_dir]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ICommandHooks).__jsii_proxy_class__ = lambda : _ICommandHooksProxy


@jsii.enum(jsii_type="aws-cdk-lib.aws_lambda_nodejs.LogLevel")
class LogLevel(enum.Enum):
    '''Log levels for esbuild and package managers' install commands.

    :exampleMetadata: infused

    Example::

        lambda_.NodejsFunction(self, "my-handler",
            bundling=lambda.BundlingOptions(
                minify=True,  # minify code, defaults to false
                source_map=True,  # include source map, defaults to false
                source_map_mode=lambda_.SourceMapMode.INLINE,  # defaults to SourceMapMode.DEFAULT
                sources_content=False,  # do not include original source into source map, defaults to true
                target="es2020",  # target environment for the generated JavaScript code
                loader={ # Use the 'dataurl' loader for '.png' files
                    ".png": "dataurl"},
                define={ # Replace strings during build time
                    "process.env._aPI__kEY": JSON.stringify("xxx-xxxx-xxx"),
                    "process.env._pRODUCTION": JSON.stringify(True),
                    "process.env._nUMBER": JSON.stringify(123)},
                log_level=lambda_.LogLevel.SILENT,  # defaults to LogLevel.WARNING
                keep_names=True,  # defaults to false
                tsconfig="custom-tsconfig.json",  # use custom-tsconfig.json instead of default,
                metafile=True,  # include meta file, defaults to false
                banner="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                footer="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                charset=lambda_.Charset.UTF8,  # do not escape non-ASCII characters, defaults to Charset.ASCII
                format=lambda_.OutputFormat.ESM,  # ECMAScript module output format, defaults to OutputFormat.CJS (OutputFormat.ESM requires Node.js 14.x)
                main_fields=["module", "main"]
            )
        )
    '''

    INFO = "INFO"
    '''Show everything.'''
    WARNING = "WARNING"
    '''Show warnings and errors.'''
    ERROR = "ERROR"
    '''Show errors only.'''
    SILENT = "SILENT"
    '''Show nothing.'''


class NodejsFunction(
    _Function_244f85d8,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_lambda_nodejs.NodejsFunction",
):
    '''A Node.js Lambda function bundled using esbuild.

    :exampleMetadata: infused

    Example::

        lambda_.NodejsFunction(self, "my-handler",
            bundling=lambda.BundlingOptions(
                minify=True,  # minify code, defaults to false
                source_map=True,  # include source map, defaults to false
                source_map_mode=lambda_.SourceMapMode.INLINE,  # defaults to SourceMapMode.DEFAULT
                sources_content=False,  # do not include original source into source map, defaults to true
                target="es2020",  # target environment for the generated JavaScript code
                loader={ # Use the 'dataurl' loader for '.png' files
                    ".png": "dataurl"},
                define={ # Replace strings during build time
                    "process.env._aPI__kEY": JSON.stringify("xxx-xxxx-xxx"),
                    "process.env._pRODUCTION": JSON.stringify(True),
                    "process.env._nUMBER": JSON.stringify(123)},
                log_level=lambda_.LogLevel.SILENT,  # defaults to LogLevel.WARNING
                keep_names=True,  # defaults to false
                tsconfig="custom-tsconfig.json",  # use custom-tsconfig.json instead of default,
                metafile=True,  # include meta file, defaults to false
                banner="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                footer="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                charset=lambda_.Charset.UTF8,  # do not escape non-ASCII characters, defaults to Charset.ASCII
                format=lambda_.OutputFormat.ESM,  # ECMAScript module output format, defaults to OutputFormat.CJS (OutputFormat.ESM requires Node.js 14.x)
                main_fields=["module", "main"]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        aws_sdk_connection_reuse: typing.Optional[builtins.bool] = None,
        bundling: typing.Optional[BundlingOptions] = None,
        deps_lock_file_path: typing.Optional[builtins.str] = None,
        entry: typing.Optional[builtins.str] = None,
        handler: typing.Optional[builtins.str] = None,
        project_root: typing.Optional[builtins.str] = None,
        runtime: typing.Optional[_Runtime_b4eaa844] = None,
        allow_all_outbound: typing.Optional[builtins.bool] = None,
        allow_public_subnet: typing.Optional[builtins.bool] = None,
        architecture: typing.Optional[_Architecture_12d5a53f] = None,
        code_signing_config: typing.Optional[_ICodeSigningConfig_edb41d1f] = None,
        current_version_options: typing.Optional[_VersionOptions_981bb3c0] = None,
        dead_letter_queue: typing.Optional[_IQueue_7ed6f679] = None,
        dead_letter_queue_enabled: typing.Optional[builtins.bool] = None,
        dead_letter_topic: typing.Optional[_ITopic_9eca4852] = None,
        description: typing.Optional[builtins.str] = None,
        environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        environment_encryption: typing.Optional[_IKey_5f11635f] = None,
        events: typing.Optional[typing.Sequence[_IEventSource_3686b3f8]] = None,
        filesystem: typing.Optional[_FileSystem_a5fa005d] = None,
        function_name: typing.Optional[builtins.str] = None,
        initial_policy: typing.Optional[typing.Sequence[_PolicyStatement_0fe33853]] = None,
        insights_version: typing.Optional[_LambdaInsightsVersion_9dfbfef9] = None,
        layers: typing.Optional[typing.Sequence[_ILayerVersion_5ac127c8]] = None,
        log_retention: typing.Optional[_RetentionDays_070f99f0] = None,
        log_retention_retry_options: typing.Optional[_LogRetentionRetryOptions_ad797a7a] = None,
        log_retention_role: typing.Optional[_IRole_235f5d8e] = None,
        memory_size: typing.Optional[jsii.Number] = None,
        profiling: typing.Optional[builtins.bool] = None,
        profiling_group: typing.Optional[_IProfilingGroup_0bba72c4] = None,
        reserved_concurrent_executions: typing.Optional[jsii.Number] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        tracing: typing.Optional[_Tracing_9fe8e2bb] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        max_event_age: typing.Optional[_Duration_4839e8c3] = None,
        on_failure: typing.Optional[_IDestination_40f19de4] = None,
        on_success: typing.Optional[_IDestination_40f19de4] = None,
        retry_attempts: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param aws_sdk_connection_reuse: Whether to automatically reuse TCP connections when working with the AWS SDK for JavaScript. This sets the ``AWS_NODEJS_CONNECTION_REUSE_ENABLED`` environment variable to ``1``. Default: true
        :param bundling: Bundling options. Default: - use default bundling options: no minify, no sourcemap, all modules are bundled.
        :param deps_lock_file_path: The path to the dependencies lock file (``yarn.lock`` or ``package-lock.json``). This will be used as the source for the volume mounted in the Docker container. Modules specified in ``nodeModules`` will be installed using the right installer (``npm`` or ``yarn``) along with this lock file. Default: - the path is found by walking up parent directories searching for a ``yarn.lock`` or ``package-lock.json`` file
        :param entry: Path to the entry file (JavaScript or TypeScript). Default: - Derived from the name of the defining file and the construct's id. If the ``NodejsFunction`` is defined in ``stack.ts`` with ``my-handler`` as id (``new NodejsFunction(this, 'my-handler')``), the construct will look at ``stack.my-handler.ts`` and ``stack.my-handler.js``.
        :param handler: The name of the exported handler in the entry file. Default: handler
        :param project_root: The path to the directory containing project config files (``package.json`` or ``tsconfig.json``). Default: - the directory containing the ``depsLockFilePath``
        :param runtime: The runtime environment. Only runtimes of the Node.js family are supported. Default: Runtime.NODEJS_14_X
        :param allow_all_outbound: Whether to allow the Lambda to send all network traffic. If set to false, you must individually add traffic rules to allow the Lambda to connect to network targets. Default: true
        :param allow_public_subnet: Lambda Functions in a public subnet can NOT access the internet. Use this property to acknowledge this limitation and still place the function in a public subnet. Default: false
        :param architecture: The system architectures compatible with this lambda function. Default: Architecture.X86_64
        :param code_signing_config: Code signing config associated with this function. Default: - Not Sign the Code
        :param current_version_options: Options for the ``lambda.Version`` resource automatically created by the ``fn.currentVersion`` method. Default: - default options as described in ``VersionOptions``
        :param dead_letter_queue: The SQS queue to use if DLQ is enabled. If SNS topic is desired, specify ``deadLetterTopic`` property instead. Default: - SQS queue with 14 day retention period if ``deadLetterQueueEnabled`` is ``true``
        :param dead_letter_queue_enabled: Enabled DLQ. If ``deadLetterQueue`` is undefined, an SQS queue with default options will be defined for your Function. Default: - false unless ``deadLetterQueue`` is set, which implies DLQ is enabled.
        :param dead_letter_topic: The SNS topic to use as a DLQ. Note that if ``deadLetterQueueEnabled`` is set to ``true``, an SQS queue will be created rather than an SNS topic. Using an SNS topic as a DLQ requires this property to be set explicitly. Default: - no SNS topic
        :param description: A description of the function. Default: - No description.
        :param environment: Key-value pairs that Lambda caches and makes available for your Lambda functions. Use environment variables to apply configuration changes, such as test and production environment configurations, without changing your Lambda function source code. Default: - No environment variables.
        :param environment_encryption: The AWS KMS key that's used to encrypt your function's environment variables. Default: - AWS Lambda creates and uses an AWS managed customer master key (CMK).
        :param events: Event sources for this function. You can also add event sources using ``addEventSource``. Default: - No event sources.
        :param filesystem: The filesystem configuration for the lambda function. Default: - will not mount any filesystem
        :param function_name: A name for the function. Default: - AWS CloudFormation generates a unique physical ID and uses that ID for the function's name. For more information, see Name Type.
        :param initial_policy: Initial policy statements to add to the created Lambda Role. You can call ``addToRolePolicy`` to the created lambda to add statements post creation. Default: - No policy statements are added to the created Lambda role.
        :param insights_version: Specify the version of CloudWatch Lambda insights to use for monitoring. Default: - No Lambda Insights
        :param layers: A list of layers to add to the function's execution environment. You can configure your Lambda function to pull in additional code during initialization in the form of layers. Layers are packages of libraries or other dependencies that can be used by multiple functions. Default: - No layers.
        :param log_retention: The number of days log events are kept in CloudWatch Logs. When updating this property, unsetting it doesn't remove the log retention policy. To remove the retention policy, set the value to ``INFINITE``. Default: logs.RetentionDays.INFINITE
        :param log_retention_retry_options: When log retention is specified, a custom resource attempts to create the CloudWatch log group. These options control the retry policy when interacting with CloudWatch APIs. Default: - Default AWS SDK retry options.
        :param log_retention_role: The IAM role for the Lambda function associated with the custom resource that sets the retention policy. Default: - A new role is created.
        :param memory_size: The amount of memory, in MB, that is allocated to your Lambda function. Lambda uses this value to proportionally allocate the amount of CPU power. For more information, see Resource Model in the AWS Lambda Developer Guide. Default: 128
        :param profiling: Enable profiling. Default: - No profiling.
        :param profiling_group: Profiling Group. Default: - A new profiling group will be created if ``profiling`` is set.
        :param reserved_concurrent_executions: The maximum of concurrent executions you want to reserve for the function. Default: - No specific limit - account limit.
        :param role: Lambda execution role. This is the role that will be assumed by the function upon execution. It controls the permissions that the function will have. The Role must be assumable by the 'lambda.amazonaws.com' service principal. The default Role automatically has permissions granted for Lambda execution. If you provide a Role, you must add the relevant AWS managed policies yourself. The relevant managed policies are "service-role/AWSLambdaBasicExecutionRole" and "service-role/AWSLambdaVPCAccessExecutionRole". Default: - A unique role will be generated for this lambda function. Both supplied and generated roles can always be changed by calling ``addToRolePolicy``.
        :param security_groups: The list of security groups to associate with the Lambda's network interfaces. Only used if 'vpc' is supplied. Default: - If the function is placed within a VPC and a security group is not specified, either by this or securityGroup prop, a dedicated security group will be created for this function.
        :param timeout: The function execution time (in seconds) after which Lambda terminates the function. Because the execution time affects cost, set this value based on the function's expected execution time. Default: Duration.seconds(3)
        :param tracing: Enable AWS X-Ray Tracing for Lambda Function. Default: Tracing.Disabled
        :param vpc: VPC network to place Lambda network interfaces. Specify this if the Lambda function needs to access resources in a VPC. Default: - Function is not placed within a VPC.
        :param vpc_subnets: Where to place the network interfaces within the VPC. Only used if 'vpc' is supplied. Note: internet access for Lambdas requires a NAT gateway, so picking Public subnets is not allowed. Default: - the Vpc default strategy if not specified
        :param max_event_age: The maximum age of a request that Lambda sends to a function for processing. Minimum: 60 seconds Maximum: 6 hours Default: Duration.hours(6)
        :param on_failure: The destination for failed invocations. Default: - no destination
        :param on_success: The destination for successful invocations. Default: - no destination
        :param retry_attempts: The maximum number of times to retry when the function returns an error. Minimum: 0 Maximum: 2 Default: 2
        '''
        props = NodejsFunctionProps(
            aws_sdk_connection_reuse=aws_sdk_connection_reuse,
            bundling=bundling,
            deps_lock_file_path=deps_lock_file_path,
            entry=entry,
            handler=handler,
            project_root=project_root,
            runtime=runtime,
            allow_all_outbound=allow_all_outbound,
            allow_public_subnet=allow_public_subnet,
            architecture=architecture,
            code_signing_config=code_signing_config,
            current_version_options=current_version_options,
            dead_letter_queue=dead_letter_queue,
            dead_letter_queue_enabled=dead_letter_queue_enabled,
            dead_letter_topic=dead_letter_topic,
            description=description,
            environment=environment,
            environment_encryption=environment_encryption,
            events=events,
            filesystem=filesystem,
            function_name=function_name,
            initial_policy=initial_policy,
            insights_version=insights_version,
            layers=layers,
            log_retention=log_retention,
            log_retention_retry_options=log_retention_retry_options,
            log_retention_role=log_retention_role,
            memory_size=memory_size,
            profiling=profiling,
            profiling_group=profiling_group,
            reserved_concurrent_executions=reserved_concurrent_executions,
            role=role,
            security_groups=security_groups,
            timeout=timeout,
            tracing=tracing,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
            max_event_age=max_event_age,
            on_failure=on_failure,
            on_success=on_success,
            retry_attempts=retry_attempts,
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lambda_nodejs.NodejsFunctionProps",
    jsii_struct_bases=[_FunctionOptions_328f4d39],
    name_mapping={
        "max_event_age": "maxEventAge",
        "on_failure": "onFailure",
        "on_success": "onSuccess",
        "retry_attempts": "retryAttempts",
        "allow_all_outbound": "allowAllOutbound",
        "allow_public_subnet": "allowPublicSubnet",
        "architecture": "architecture",
        "code_signing_config": "codeSigningConfig",
        "current_version_options": "currentVersionOptions",
        "dead_letter_queue": "deadLetterQueue",
        "dead_letter_queue_enabled": "deadLetterQueueEnabled",
        "dead_letter_topic": "deadLetterTopic",
        "description": "description",
        "environment": "environment",
        "environment_encryption": "environmentEncryption",
        "events": "events",
        "filesystem": "filesystem",
        "function_name": "functionName",
        "initial_policy": "initialPolicy",
        "insights_version": "insightsVersion",
        "layers": "layers",
        "log_retention": "logRetention",
        "log_retention_retry_options": "logRetentionRetryOptions",
        "log_retention_role": "logRetentionRole",
        "memory_size": "memorySize",
        "profiling": "profiling",
        "profiling_group": "profilingGroup",
        "reserved_concurrent_executions": "reservedConcurrentExecutions",
        "role": "role",
        "security_groups": "securityGroups",
        "timeout": "timeout",
        "tracing": "tracing",
        "vpc": "vpc",
        "vpc_subnets": "vpcSubnets",
        "aws_sdk_connection_reuse": "awsSdkConnectionReuse",
        "bundling": "bundling",
        "deps_lock_file_path": "depsLockFilePath",
        "entry": "entry",
        "handler": "handler",
        "project_root": "projectRoot",
        "runtime": "runtime",
    },
)
class NodejsFunctionProps(_FunctionOptions_328f4d39):
    def __init__(
        self,
        *,
        max_event_age: typing.Optional[_Duration_4839e8c3] = None,
        on_failure: typing.Optional[_IDestination_40f19de4] = None,
        on_success: typing.Optional[_IDestination_40f19de4] = None,
        retry_attempts: typing.Optional[jsii.Number] = None,
        allow_all_outbound: typing.Optional[builtins.bool] = None,
        allow_public_subnet: typing.Optional[builtins.bool] = None,
        architecture: typing.Optional[_Architecture_12d5a53f] = None,
        code_signing_config: typing.Optional[_ICodeSigningConfig_edb41d1f] = None,
        current_version_options: typing.Optional[_VersionOptions_981bb3c0] = None,
        dead_letter_queue: typing.Optional[_IQueue_7ed6f679] = None,
        dead_letter_queue_enabled: typing.Optional[builtins.bool] = None,
        dead_letter_topic: typing.Optional[_ITopic_9eca4852] = None,
        description: typing.Optional[builtins.str] = None,
        environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        environment_encryption: typing.Optional[_IKey_5f11635f] = None,
        events: typing.Optional[typing.Sequence[_IEventSource_3686b3f8]] = None,
        filesystem: typing.Optional[_FileSystem_a5fa005d] = None,
        function_name: typing.Optional[builtins.str] = None,
        initial_policy: typing.Optional[typing.Sequence[_PolicyStatement_0fe33853]] = None,
        insights_version: typing.Optional[_LambdaInsightsVersion_9dfbfef9] = None,
        layers: typing.Optional[typing.Sequence[_ILayerVersion_5ac127c8]] = None,
        log_retention: typing.Optional[_RetentionDays_070f99f0] = None,
        log_retention_retry_options: typing.Optional[_LogRetentionRetryOptions_ad797a7a] = None,
        log_retention_role: typing.Optional[_IRole_235f5d8e] = None,
        memory_size: typing.Optional[jsii.Number] = None,
        profiling: typing.Optional[builtins.bool] = None,
        profiling_group: typing.Optional[_IProfilingGroup_0bba72c4] = None,
        reserved_concurrent_executions: typing.Optional[jsii.Number] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        tracing: typing.Optional[_Tracing_9fe8e2bb] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        aws_sdk_connection_reuse: typing.Optional[builtins.bool] = None,
        bundling: typing.Optional[BundlingOptions] = None,
        deps_lock_file_path: typing.Optional[builtins.str] = None,
        entry: typing.Optional[builtins.str] = None,
        handler: typing.Optional[builtins.str] = None,
        project_root: typing.Optional[builtins.str] = None,
        runtime: typing.Optional[_Runtime_b4eaa844] = None,
    ) -> None:
        '''Properties for a NodejsFunction.

        :param max_event_age: The maximum age of a request that Lambda sends to a function for processing. Minimum: 60 seconds Maximum: 6 hours Default: Duration.hours(6)
        :param on_failure: The destination for failed invocations. Default: - no destination
        :param on_success: The destination for successful invocations. Default: - no destination
        :param retry_attempts: The maximum number of times to retry when the function returns an error. Minimum: 0 Maximum: 2 Default: 2
        :param allow_all_outbound: Whether to allow the Lambda to send all network traffic. If set to false, you must individually add traffic rules to allow the Lambda to connect to network targets. Default: true
        :param allow_public_subnet: Lambda Functions in a public subnet can NOT access the internet. Use this property to acknowledge this limitation and still place the function in a public subnet. Default: false
        :param architecture: The system architectures compatible with this lambda function. Default: Architecture.X86_64
        :param code_signing_config: Code signing config associated with this function. Default: - Not Sign the Code
        :param current_version_options: Options for the ``lambda.Version`` resource automatically created by the ``fn.currentVersion`` method. Default: - default options as described in ``VersionOptions``
        :param dead_letter_queue: The SQS queue to use if DLQ is enabled. If SNS topic is desired, specify ``deadLetterTopic`` property instead. Default: - SQS queue with 14 day retention period if ``deadLetterQueueEnabled`` is ``true``
        :param dead_letter_queue_enabled: Enabled DLQ. If ``deadLetterQueue`` is undefined, an SQS queue with default options will be defined for your Function. Default: - false unless ``deadLetterQueue`` is set, which implies DLQ is enabled.
        :param dead_letter_topic: The SNS topic to use as a DLQ. Note that if ``deadLetterQueueEnabled`` is set to ``true``, an SQS queue will be created rather than an SNS topic. Using an SNS topic as a DLQ requires this property to be set explicitly. Default: - no SNS topic
        :param description: A description of the function. Default: - No description.
        :param environment: Key-value pairs that Lambda caches and makes available for your Lambda functions. Use environment variables to apply configuration changes, such as test and production environment configurations, without changing your Lambda function source code. Default: - No environment variables.
        :param environment_encryption: The AWS KMS key that's used to encrypt your function's environment variables. Default: - AWS Lambda creates and uses an AWS managed customer master key (CMK).
        :param events: Event sources for this function. You can also add event sources using ``addEventSource``. Default: - No event sources.
        :param filesystem: The filesystem configuration for the lambda function. Default: - will not mount any filesystem
        :param function_name: A name for the function. Default: - AWS CloudFormation generates a unique physical ID and uses that ID for the function's name. For more information, see Name Type.
        :param initial_policy: Initial policy statements to add to the created Lambda Role. You can call ``addToRolePolicy`` to the created lambda to add statements post creation. Default: - No policy statements are added to the created Lambda role.
        :param insights_version: Specify the version of CloudWatch Lambda insights to use for monitoring. Default: - No Lambda Insights
        :param layers: A list of layers to add to the function's execution environment. You can configure your Lambda function to pull in additional code during initialization in the form of layers. Layers are packages of libraries or other dependencies that can be used by multiple functions. Default: - No layers.
        :param log_retention: The number of days log events are kept in CloudWatch Logs. When updating this property, unsetting it doesn't remove the log retention policy. To remove the retention policy, set the value to ``INFINITE``. Default: logs.RetentionDays.INFINITE
        :param log_retention_retry_options: When log retention is specified, a custom resource attempts to create the CloudWatch log group. These options control the retry policy when interacting with CloudWatch APIs. Default: - Default AWS SDK retry options.
        :param log_retention_role: The IAM role for the Lambda function associated with the custom resource that sets the retention policy. Default: - A new role is created.
        :param memory_size: The amount of memory, in MB, that is allocated to your Lambda function. Lambda uses this value to proportionally allocate the amount of CPU power. For more information, see Resource Model in the AWS Lambda Developer Guide. Default: 128
        :param profiling: Enable profiling. Default: - No profiling.
        :param profiling_group: Profiling Group. Default: - A new profiling group will be created if ``profiling`` is set.
        :param reserved_concurrent_executions: The maximum of concurrent executions you want to reserve for the function. Default: - No specific limit - account limit.
        :param role: Lambda execution role. This is the role that will be assumed by the function upon execution. It controls the permissions that the function will have. The Role must be assumable by the 'lambda.amazonaws.com' service principal. The default Role automatically has permissions granted for Lambda execution. If you provide a Role, you must add the relevant AWS managed policies yourself. The relevant managed policies are "service-role/AWSLambdaBasicExecutionRole" and "service-role/AWSLambdaVPCAccessExecutionRole". Default: - A unique role will be generated for this lambda function. Both supplied and generated roles can always be changed by calling ``addToRolePolicy``.
        :param security_groups: The list of security groups to associate with the Lambda's network interfaces. Only used if 'vpc' is supplied. Default: - If the function is placed within a VPC and a security group is not specified, either by this or securityGroup prop, a dedicated security group will be created for this function.
        :param timeout: The function execution time (in seconds) after which Lambda terminates the function. Because the execution time affects cost, set this value based on the function's expected execution time. Default: Duration.seconds(3)
        :param tracing: Enable AWS X-Ray Tracing for Lambda Function. Default: Tracing.Disabled
        :param vpc: VPC network to place Lambda network interfaces. Specify this if the Lambda function needs to access resources in a VPC. Default: - Function is not placed within a VPC.
        :param vpc_subnets: Where to place the network interfaces within the VPC. Only used if 'vpc' is supplied. Note: internet access for Lambdas requires a NAT gateway, so picking Public subnets is not allowed. Default: - the Vpc default strategy if not specified
        :param aws_sdk_connection_reuse: Whether to automatically reuse TCP connections when working with the AWS SDK for JavaScript. This sets the ``AWS_NODEJS_CONNECTION_REUSE_ENABLED`` environment variable to ``1``. Default: true
        :param bundling: Bundling options. Default: - use default bundling options: no minify, no sourcemap, all modules are bundled.
        :param deps_lock_file_path: The path to the dependencies lock file (``yarn.lock`` or ``package-lock.json``). This will be used as the source for the volume mounted in the Docker container. Modules specified in ``nodeModules`` will be installed using the right installer (``npm`` or ``yarn``) along with this lock file. Default: - the path is found by walking up parent directories searching for a ``yarn.lock`` or ``package-lock.json`` file
        :param entry: Path to the entry file (JavaScript or TypeScript). Default: - Derived from the name of the defining file and the construct's id. If the ``NodejsFunction`` is defined in ``stack.ts`` with ``my-handler`` as id (``new NodejsFunction(this, 'my-handler')``), the construct will look at ``stack.my-handler.ts`` and ``stack.my-handler.js``.
        :param handler: The name of the exported handler in the entry file. Default: handler
        :param project_root: The path to the directory containing project config files (``package.json`` or ``tsconfig.json``). Default: - the directory containing the ``depsLockFilePath``
        :param runtime: The runtime environment. Only runtimes of the Node.js family are supported. Default: Runtime.NODEJS_14_X

        :exampleMetadata: infused

        Example::

            lambda_.NodejsFunction(self, "my-handler",
                bundling=lambda.BundlingOptions(
                    minify=True,  # minify code, defaults to false
                    source_map=True,  # include source map, defaults to false
                    source_map_mode=lambda_.SourceMapMode.INLINE,  # defaults to SourceMapMode.DEFAULT
                    sources_content=False,  # do not include original source into source map, defaults to true
                    target="es2020",  # target environment for the generated JavaScript code
                    loader={ # Use the 'dataurl' loader for '.png' files
                        ".png": "dataurl"},
                    define={ # Replace strings during build time
                        "process.env._aPI__kEY": JSON.stringify("xxx-xxxx-xxx"),
                        "process.env._pRODUCTION": JSON.stringify(True),
                        "process.env._nUMBER": JSON.stringify(123)},
                    log_level=lambda_.LogLevel.SILENT,  # defaults to LogLevel.WARNING
                    keep_names=True,  # defaults to false
                    tsconfig="custom-tsconfig.json",  # use custom-tsconfig.json instead of default,
                    metafile=True,  # include meta file, defaults to false
                    banner="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                    footer="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                    charset=lambda_.Charset.UTF8,  # do not escape non-ASCII characters, defaults to Charset.ASCII
                    format=lambda_.OutputFormat.ESM,  # ECMAScript module output format, defaults to OutputFormat.CJS (OutputFormat.ESM requires Node.js 14.x)
                    main_fields=["module", "main"]
                )
            )
        '''
        if isinstance(current_version_options, dict):
            current_version_options = _VersionOptions_981bb3c0(**current_version_options)
        if isinstance(log_retention_retry_options, dict):
            log_retention_retry_options = _LogRetentionRetryOptions_ad797a7a(**log_retention_retry_options)
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        if isinstance(bundling, dict):
            bundling = BundlingOptions(**bundling)
        self._values: typing.Dict[str, typing.Any] = {}
        if max_event_age is not None:
            self._values["max_event_age"] = max_event_age
        if on_failure is not None:
            self._values["on_failure"] = on_failure
        if on_success is not None:
            self._values["on_success"] = on_success
        if retry_attempts is not None:
            self._values["retry_attempts"] = retry_attempts
        if allow_all_outbound is not None:
            self._values["allow_all_outbound"] = allow_all_outbound
        if allow_public_subnet is not None:
            self._values["allow_public_subnet"] = allow_public_subnet
        if architecture is not None:
            self._values["architecture"] = architecture
        if code_signing_config is not None:
            self._values["code_signing_config"] = code_signing_config
        if current_version_options is not None:
            self._values["current_version_options"] = current_version_options
        if dead_letter_queue is not None:
            self._values["dead_letter_queue"] = dead_letter_queue
        if dead_letter_queue_enabled is not None:
            self._values["dead_letter_queue_enabled"] = dead_letter_queue_enabled
        if dead_letter_topic is not None:
            self._values["dead_letter_topic"] = dead_letter_topic
        if description is not None:
            self._values["description"] = description
        if environment is not None:
            self._values["environment"] = environment
        if environment_encryption is not None:
            self._values["environment_encryption"] = environment_encryption
        if events is not None:
            self._values["events"] = events
        if filesystem is not None:
            self._values["filesystem"] = filesystem
        if function_name is not None:
            self._values["function_name"] = function_name
        if initial_policy is not None:
            self._values["initial_policy"] = initial_policy
        if insights_version is not None:
            self._values["insights_version"] = insights_version
        if layers is not None:
            self._values["layers"] = layers
        if log_retention is not None:
            self._values["log_retention"] = log_retention
        if log_retention_retry_options is not None:
            self._values["log_retention_retry_options"] = log_retention_retry_options
        if log_retention_role is not None:
            self._values["log_retention_role"] = log_retention_role
        if memory_size is not None:
            self._values["memory_size"] = memory_size
        if profiling is not None:
            self._values["profiling"] = profiling
        if profiling_group is not None:
            self._values["profiling_group"] = profiling_group
        if reserved_concurrent_executions is not None:
            self._values["reserved_concurrent_executions"] = reserved_concurrent_executions
        if role is not None:
            self._values["role"] = role
        if security_groups is not None:
            self._values["security_groups"] = security_groups
        if timeout is not None:
            self._values["timeout"] = timeout
        if tracing is not None:
            self._values["tracing"] = tracing
        if vpc is not None:
            self._values["vpc"] = vpc
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets
        if aws_sdk_connection_reuse is not None:
            self._values["aws_sdk_connection_reuse"] = aws_sdk_connection_reuse
        if bundling is not None:
            self._values["bundling"] = bundling
        if deps_lock_file_path is not None:
            self._values["deps_lock_file_path"] = deps_lock_file_path
        if entry is not None:
            self._values["entry"] = entry
        if handler is not None:
            self._values["handler"] = handler
        if project_root is not None:
            self._values["project_root"] = project_root
        if runtime is not None:
            self._values["runtime"] = runtime

    @builtins.property
    def max_event_age(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The maximum age of a request that Lambda sends to a function for processing.

        Minimum: 60 seconds
        Maximum: 6 hours

        :default: Duration.hours(6)
        '''
        result = self._values.get("max_event_age")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def on_failure(self) -> typing.Optional[_IDestination_40f19de4]:
        '''The destination for failed invocations.

        :default: - no destination
        '''
        result = self._values.get("on_failure")
        return typing.cast(typing.Optional[_IDestination_40f19de4], result)

    @builtins.property
    def on_success(self) -> typing.Optional[_IDestination_40f19de4]:
        '''The destination for successful invocations.

        :default: - no destination
        '''
        result = self._values.get("on_success")
        return typing.cast(typing.Optional[_IDestination_40f19de4], result)

    @builtins.property
    def retry_attempts(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of times to retry when the function returns an error.

        Minimum: 0
        Maximum: 2

        :default: 2
        '''
        result = self._values.get("retry_attempts")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def allow_all_outbound(self) -> typing.Optional[builtins.bool]:
        '''Whether to allow the Lambda to send all network traffic.

        If set to false, you must individually add traffic rules to allow the
        Lambda to connect to network targets.

        :default: true
        '''
        result = self._values.get("allow_all_outbound")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def allow_public_subnet(self) -> typing.Optional[builtins.bool]:
        '''Lambda Functions in a public subnet can NOT access the internet.

        Use this property to acknowledge this limitation and still place the function in a public subnet.

        :default: false

        :see: https://stackoverflow.com/questions/52992085/why-cant-an-aws-lambda-function-inside-a-public-subnet-in-a-vpc-connect-to-the/52994841#52994841
        '''
        result = self._values.get("allow_public_subnet")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def architecture(self) -> typing.Optional[_Architecture_12d5a53f]:
        '''The system architectures compatible with this lambda function.

        :default: Architecture.X86_64
        '''
        result = self._values.get("architecture")
        return typing.cast(typing.Optional[_Architecture_12d5a53f], result)

    @builtins.property
    def code_signing_config(self) -> typing.Optional[_ICodeSigningConfig_edb41d1f]:
        '''Code signing config associated with this function.

        :default: - Not Sign the Code
        '''
        result = self._values.get("code_signing_config")
        return typing.cast(typing.Optional[_ICodeSigningConfig_edb41d1f], result)

    @builtins.property
    def current_version_options(self) -> typing.Optional[_VersionOptions_981bb3c0]:
        '''Options for the ``lambda.Version`` resource automatically created by the ``fn.currentVersion`` method.

        :default: - default options as described in ``VersionOptions``
        '''
        result = self._values.get("current_version_options")
        return typing.cast(typing.Optional[_VersionOptions_981bb3c0], result)

    @builtins.property
    def dead_letter_queue(self) -> typing.Optional[_IQueue_7ed6f679]:
        '''The SQS queue to use if DLQ is enabled.

        If SNS topic is desired, specify ``deadLetterTopic`` property instead.

        :default: - SQS queue with 14 day retention period if ``deadLetterQueueEnabled`` is ``true``
        '''
        result = self._values.get("dead_letter_queue")
        return typing.cast(typing.Optional[_IQueue_7ed6f679], result)

    @builtins.property
    def dead_letter_queue_enabled(self) -> typing.Optional[builtins.bool]:
        '''Enabled DLQ.

        If ``deadLetterQueue`` is undefined,
        an SQS queue with default options will be defined for your Function.

        :default: - false unless ``deadLetterQueue`` is set, which implies DLQ is enabled.
        '''
        result = self._values.get("dead_letter_queue_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def dead_letter_topic(self) -> typing.Optional[_ITopic_9eca4852]:
        '''The SNS topic to use as a DLQ.

        Note that if ``deadLetterQueueEnabled`` is set to ``true``, an SQS queue will be created
        rather than an SNS topic. Using an SNS topic as a DLQ requires this property to be set explicitly.

        :default: - no SNS topic
        '''
        result = self._values.get("dead_letter_topic")
        return typing.cast(typing.Optional[_ITopic_9eca4852], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the function.

        :default: - No description.
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Key-value pairs that Lambda caches and makes available for your Lambda functions.

        Use environment variables to apply configuration changes, such
        as test and production environment configurations, without changing your
        Lambda function source code.

        :default: - No environment variables.
        '''
        result = self._values.get("environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def environment_encryption(self) -> typing.Optional[_IKey_5f11635f]:
        '''The AWS KMS key that's used to encrypt your function's environment variables.

        :default: - AWS Lambda creates and uses an AWS managed customer master key (CMK).
        '''
        result = self._values.get("environment_encryption")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def events(self) -> typing.Optional[typing.List[_IEventSource_3686b3f8]]:
        '''Event sources for this function.

        You can also add event sources using ``addEventSource``.

        :default: - No event sources.
        '''
        result = self._values.get("events")
        return typing.cast(typing.Optional[typing.List[_IEventSource_3686b3f8]], result)

    @builtins.property
    def filesystem(self) -> typing.Optional[_FileSystem_a5fa005d]:
        '''The filesystem configuration for the lambda function.

        :default: - will not mount any filesystem
        '''
        result = self._values.get("filesystem")
        return typing.cast(typing.Optional[_FileSystem_a5fa005d], result)

    @builtins.property
    def function_name(self) -> typing.Optional[builtins.str]:
        '''A name for the function.

        :default:

        - AWS CloudFormation generates a unique physical ID and uses that
        ID for the function's name. For more information, see Name Type.
        '''
        result = self._values.get("function_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def initial_policy(self) -> typing.Optional[typing.List[_PolicyStatement_0fe33853]]:
        '''Initial policy statements to add to the created Lambda Role.

        You can call ``addToRolePolicy`` to the created lambda to add statements post creation.

        :default: - No policy statements are added to the created Lambda role.
        '''
        result = self._values.get("initial_policy")
        return typing.cast(typing.Optional[typing.List[_PolicyStatement_0fe33853]], result)

    @builtins.property
    def insights_version(self) -> typing.Optional[_LambdaInsightsVersion_9dfbfef9]:
        '''Specify the version of CloudWatch Lambda insights to use for monitoring.

        :default: - No Lambda Insights

        :see: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Lambda-Insights-Getting-Started-docker.html
        '''
        result = self._values.get("insights_version")
        return typing.cast(typing.Optional[_LambdaInsightsVersion_9dfbfef9], result)

    @builtins.property
    def layers(self) -> typing.Optional[typing.List[_ILayerVersion_5ac127c8]]:
        '''A list of layers to add to the function's execution environment.

        You can configure your Lambda function to pull in
        additional code during initialization in the form of layers. Layers are packages of libraries or other dependencies
        that can be used by multiple functions.

        :default: - No layers.
        '''
        result = self._values.get("layers")
        return typing.cast(typing.Optional[typing.List[_ILayerVersion_5ac127c8]], result)

    @builtins.property
    def log_retention(self) -> typing.Optional[_RetentionDays_070f99f0]:
        '''The number of days log events are kept in CloudWatch Logs.

        When updating
        this property, unsetting it doesn't remove the log retention policy. To
        remove the retention policy, set the value to ``INFINITE``.

        :default: logs.RetentionDays.INFINITE
        '''
        result = self._values.get("log_retention")
        return typing.cast(typing.Optional[_RetentionDays_070f99f0], result)

    @builtins.property
    def log_retention_retry_options(
        self,
    ) -> typing.Optional[_LogRetentionRetryOptions_ad797a7a]:
        '''When log retention is specified, a custom resource attempts to create the CloudWatch log group.

        These options control the retry policy when interacting with CloudWatch APIs.

        :default: - Default AWS SDK retry options.
        '''
        result = self._values.get("log_retention_retry_options")
        return typing.cast(typing.Optional[_LogRetentionRetryOptions_ad797a7a], result)

    @builtins.property
    def log_retention_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The IAM role for the Lambda function associated with the custom resource that sets the retention policy.

        :default: - A new role is created.
        '''
        result = self._values.get("log_retention_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def memory_size(self) -> typing.Optional[jsii.Number]:
        '''The amount of memory, in MB, that is allocated to your Lambda function.

        Lambda uses this value to proportionally allocate the amount of CPU
        power. For more information, see Resource Model in the AWS Lambda
        Developer Guide.

        :default: 128
        '''
        result = self._values.get("memory_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def profiling(self) -> typing.Optional[builtins.bool]:
        '''Enable profiling.

        :default: - No profiling.

        :see: https://docs.aws.amazon.com/codeguru/latest/profiler-ug/setting-up-lambda.html
        '''
        result = self._values.get("profiling")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def profiling_group(self) -> typing.Optional[_IProfilingGroup_0bba72c4]:
        '''Profiling Group.

        :default: - A new profiling group will be created if ``profiling`` is set.

        :see: https://docs.aws.amazon.com/codeguru/latest/profiler-ug/setting-up-lambda.html
        '''
        result = self._values.get("profiling_group")
        return typing.cast(typing.Optional[_IProfilingGroup_0bba72c4], result)

    @builtins.property
    def reserved_concurrent_executions(self) -> typing.Optional[jsii.Number]:
        '''The maximum of concurrent executions you want to reserve for the function.

        :default: - No specific limit - account limit.

        :see: https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html
        '''
        result = self._values.get("reserved_concurrent_executions")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''Lambda execution role.

        This is the role that will be assumed by the function upon execution.
        It controls the permissions that the function will have. The Role must
        be assumable by the 'lambda.amazonaws.com' service principal.

        The default Role automatically has permissions granted for Lambda execution. If you
        provide a Role, you must add the relevant AWS managed policies yourself.

        The relevant managed policies are "service-role/AWSLambdaBasicExecutionRole" and
        "service-role/AWSLambdaVPCAccessExecutionRole".

        :default:

        - A unique role will be generated for this lambda function.
        Both supplied and generated roles can always be changed by calling ``addToRolePolicy``.
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def security_groups(self) -> typing.Optional[typing.List[_ISecurityGroup_acf8a799]]:
        '''The list of security groups to associate with the Lambda's network interfaces.

        Only used if 'vpc' is supplied.

        :default:

        - If the function is placed within a VPC and a security group is
        not specified, either by this or securityGroup prop, a dedicated security
        group will be created for this function.
        '''
        result = self._values.get("security_groups")
        return typing.cast(typing.Optional[typing.List[_ISecurityGroup_acf8a799]], result)

    @builtins.property
    def timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The function execution time (in seconds) after which Lambda terminates the function.

        Because the execution time affects cost, set this value
        based on the function's expected execution time.

        :default: Duration.seconds(3)
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def tracing(self) -> typing.Optional[_Tracing_9fe8e2bb]:
        '''Enable AWS X-Ray Tracing for Lambda Function.

        :default: Tracing.Disabled
        '''
        result = self._values.get("tracing")
        return typing.cast(typing.Optional[_Tracing_9fe8e2bb], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''VPC network to place Lambda network interfaces.

        Specify this if the Lambda function needs to access resources in a VPC.

        :default: - Function is not placed within a VPC.
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Where to place the network interfaces within the VPC.

        Only used if 'vpc' is supplied. Note: internet access for Lambdas
        requires a NAT gateway, so picking Public subnets is not allowed.

        :default: - the Vpc default strategy if not specified
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def aws_sdk_connection_reuse(self) -> typing.Optional[builtins.bool]:
        '''Whether to automatically reuse TCP connections when working with the AWS SDK for JavaScript.

        This sets the ``AWS_NODEJS_CONNECTION_REUSE_ENABLED`` environment variable
        to ``1``.

        :default: true

        :see: https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/node-reusing-connections.html
        '''
        result = self._values.get("aws_sdk_connection_reuse")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def bundling(self) -> typing.Optional[BundlingOptions]:
        '''Bundling options.

        :default:

        - use default bundling options: no minify, no sourcemap, all
        modules are bundled.
        '''
        result = self._values.get("bundling")
        return typing.cast(typing.Optional[BundlingOptions], result)

    @builtins.property
    def deps_lock_file_path(self) -> typing.Optional[builtins.str]:
        '''The path to the dependencies lock file (``yarn.lock`` or ``package-lock.json``).

        This will be used as the source for the volume mounted in the Docker
        container.

        Modules specified in ``nodeModules`` will be installed using the right
        installer (``npm`` or ``yarn``) along with this lock file.

        :default:

        - the path is found by walking up parent directories searching for
        a ``yarn.lock`` or ``package-lock.json`` file
        '''
        result = self._values.get("deps_lock_file_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def entry(self) -> typing.Optional[builtins.str]:
        '''Path to the entry file (JavaScript or TypeScript).

        :default:

        - Derived from the name of the defining file and the construct's id.
        If the ``NodejsFunction`` is defined in ``stack.ts`` with ``my-handler`` as id
        (``new NodejsFunction(this, 'my-handler')``), the construct will look at ``stack.my-handler.ts``
        and ``stack.my-handler.js``.
        '''
        result = self._values.get("entry")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def handler(self) -> typing.Optional[builtins.str]:
        '''The name of the exported handler in the entry file.

        :default: handler
        '''
        result = self._values.get("handler")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def project_root(self) -> typing.Optional[builtins.str]:
        '''The path to the directory containing project config files (``package.json`` or ``tsconfig.json``).

        :default: - the directory containing the ``depsLockFilePath``
        '''
        result = self._values.get("project_root")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def runtime(self) -> typing.Optional[_Runtime_b4eaa844]:
        '''The runtime environment.

        Only runtimes of the Node.js family are
        supported.

        :default: Runtime.NODEJS_14_X
        '''
        result = self._values.get("runtime")
        return typing.cast(typing.Optional[_Runtime_b4eaa844], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NodejsFunctionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_lambda_nodejs.OutputFormat")
class OutputFormat(enum.Enum):
    '''Output format for the generated JavaScript files.

    :exampleMetadata: infused

    Example::

        lambda_.NodejsFunction(self, "my-handler",
            bundling=lambda.BundlingOptions(
                minify=True,  # minify code, defaults to false
                source_map=True,  # include source map, defaults to false
                source_map_mode=lambda_.SourceMapMode.INLINE,  # defaults to SourceMapMode.DEFAULT
                sources_content=False,  # do not include original source into source map, defaults to true
                target="es2020",  # target environment for the generated JavaScript code
                loader={ # Use the 'dataurl' loader for '.png' files
                    ".png": "dataurl"},
                define={ # Replace strings during build time
                    "process.env._aPI__kEY": JSON.stringify("xxx-xxxx-xxx"),
                    "process.env._pRODUCTION": JSON.stringify(True),
                    "process.env._nUMBER": JSON.stringify(123)},
                log_level=lambda_.LogLevel.SILENT,  # defaults to LogLevel.WARNING
                keep_names=True,  # defaults to false
                tsconfig="custom-tsconfig.json",  # use custom-tsconfig.json instead of default,
                metafile=True,  # include meta file, defaults to false
                banner="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                footer="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                charset=lambda_.Charset.UTF8,  # do not escape non-ASCII characters, defaults to Charset.ASCII
                format=lambda_.OutputFormat.ESM,  # ECMAScript module output format, defaults to OutputFormat.CJS (OutputFormat.ESM requires Node.js 14.x)
                main_fields=["module", "main"]
            )
        )
    '''

    CJS = "CJS"
    '''CommonJS.'''
    ESM = "ESM"
    '''ECMAScript module.

    Requires a running environment that supports ``import`` and ``export`` syntax.
    '''


@jsii.enum(jsii_type="aws-cdk-lib.aws_lambda_nodejs.SourceMapMode")
class SourceMapMode(enum.Enum):
    '''SourceMap mode for esbuild.

    :see: https://esbuild.github.io/api/#sourcemap
    :exampleMetadata: infused

    Example::

        lambda_.NodejsFunction(self, "my-handler",
            bundling=lambda.BundlingOptions(
                minify=True,  # minify code, defaults to false
                source_map=True,  # include source map, defaults to false
                source_map_mode=lambda_.SourceMapMode.INLINE,  # defaults to SourceMapMode.DEFAULT
                sources_content=False,  # do not include original source into source map, defaults to true
                target="es2020",  # target environment for the generated JavaScript code
                loader={ # Use the 'dataurl' loader for '.png' files
                    ".png": "dataurl"},
                define={ # Replace strings during build time
                    "process.env._aPI__kEY": JSON.stringify("xxx-xxxx-xxx"),
                    "process.env._pRODUCTION": JSON.stringify(True),
                    "process.env._nUMBER": JSON.stringify(123)},
                log_level=lambda_.LogLevel.SILENT,  # defaults to LogLevel.WARNING
                keep_names=True,  # defaults to false
                tsconfig="custom-tsconfig.json",  # use custom-tsconfig.json instead of default,
                metafile=True,  # include meta file, defaults to false
                banner="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                footer="/* comments */",  # requires esbuild >= 0.9.0, defaults to none
                charset=lambda_.Charset.UTF8,  # do not escape non-ASCII characters, defaults to Charset.ASCII
                format=lambda_.OutputFormat.ESM,  # ECMAScript module output format, defaults to OutputFormat.CJS (OutputFormat.ESM requires Node.js 14.x)
                main_fields=["module", "main"]
            )
        )
    '''

    DEFAULT = "DEFAULT"
    '''Default sourceMap mode - will generate a .js.map file alongside any generated .js file and add a special //# sourceMappingURL= comment to the bottom of the .js file pointing to the .js.map file.'''
    EXTERNAL = "EXTERNAL"
    '''External sourceMap mode - If you want to omit the special //# sourceMappingURL= comment from the generated .js file but you still want to generate the .js.map files.'''
    INLINE = "INLINE"
    '''Inline sourceMap mode - If you want to insert the entire source map into the .js file instead of generating a separate .js.map file.'''
    BOTH = "BOTH"
    '''Both sourceMap mode - If you want to have the effect of both inline and external simultaneously.'''


__all__ = [
    "BundlingOptions",
    "Charset",
    "ICommandHooks",
    "LogLevel",
    "NodejsFunction",
    "NodejsFunctionProps",
    "OutputFormat",
    "SourceMapMode",
]

publication.publish()
