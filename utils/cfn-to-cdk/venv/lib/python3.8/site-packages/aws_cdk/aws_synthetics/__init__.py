'''
# AWS::Synthetics Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_synthetics as synthetics
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-synthetics-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Synthetics](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Synthetics.html).

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
class CfnCanary(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary",
):
    '''A CloudFormation ``AWS::Synthetics::Canary``.

    Creates or updates a canary. Canaries are scripts that monitor your endpoints and APIs from the outside-in. Canaries help you check the availability and latency of your web services and troubleshoot anomalies by investigating load time data, screenshots of the UI, logs, and metrics. You can set up a canary to run continuously or just once.

    To create canaries, you must have the ``CloudWatchSyntheticsFullAccess`` policy. If you are creating a new IAM role for the canary, you also need the the ``iam:CreateRole`` , ``iam:CreatePolicy`` and ``iam:AttachRolePolicy`` permissions. For more information, see `Necessary Roles and Permissions <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_Roles>`_ .

    Do not include secrets or proprietary information in your canary names. The canary name makes up part of the Amazon Resource Name (ARN) for the canary, and the ARN is included in outbound calls over the internet. For more information, see `Security Considerations for Synthetics Canaries <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/servicelens_canaries_security.html>`_ .

    :cloudformationResource: AWS::Synthetics::Canary
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_synthetics as synthetics
        
        cfn_canary = synthetics.CfnCanary(self, "MyCfnCanary",
            artifact_s3_location="artifactS3Location",
            code=synthetics.CfnCanary.CodeProperty(
                handler="handler",
        
                # the properties below are optional
                s3_bucket="s3Bucket",
                s3_key="s3Key",
                s3_object_version="s3ObjectVersion",
                script="script"
            ),
            execution_role_arn="executionRoleArn",
            name="name",
            runtime_version="runtimeVersion",
            schedule=synthetics.CfnCanary.ScheduleProperty(
                expression="expression",
        
                # the properties below are optional
                duration_in_seconds="durationInSeconds"
            ),
            start_canary_after_creation=False,
        
            # the properties below are optional
            artifact_config=synthetics.CfnCanary.ArtifactConfigProperty(
                s3_encryption=synthetics.CfnCanary.S3EncryptionProperty(
                    encryption_mode="encryptionMode",
                    kms_key_arn="kmsKeyArn"
                )
            ),
            failure_retention_period=123,
            run_config=synthetics.CfnCanary.RunConfigProperty(
                active_tracing=False,
                environment_variables={
                    "environment_variables_key": "environmentVariables"
                },
                memory_in_mb=123,
                timeout_in_seconds=123
            ),
            success_retention_period=123,
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            visual_reference=synthetics.CfnCanary.VisualReferenceProperty(
                base_canary_run_id="baseCanaryRunId",
        
                # the properties below are optional
                base_screenshots=[synthetics.CfnCanary.BaseScreenshotProperty(
                    screenshot_name="screenshotName",
        
                    # the properties below are optional
                    ignore_coordinates=["ignoreCoordinates"]
                )]
            ),
            vpc_config=synthetics.CfnCanary.VPCConfigProperty(
                security_group_ids=["securityGroupIds"],
                subnet_ids=["subnetIds"],
        
                # the properties below are optional
                vpc_id="vpcId"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        artifact_s3_location: builtins.str,
        code: typing.Union["CfnCanary.CodeProperty", _IResolvable_da3f097b],
        execution_role_arn: builtins.str,
        name: builtins.str,
        runtime_version: builtins.str,
        schedule: typing.Union["CfnCanary.ScheduleProperty", _IResolvable_da3f097b],
        start_canary_after_creation: typing.Union[builtins.bool, _IResolvable_da3f097b],
        artifact_config: typing.Optional[typing.Union["CfnCanary.ArtifactConfigProperty", _IResolvable_da3f097b]] = None,
        failure_retention_period: typing.Optional[jsii.Number] = None,
        run_config: typing.Optional[typing.Union["CfnCanary.RunConfigProperty", _IResolvable_da3f097b]] = None,
        success_retention_period: typing.Optional[jsii.Number] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        visual_reference: typing.Optional[typing.Union["CfnCanary.VisualReferenceProperty", _IResolvable_da3f097b]] = None,
        vpc_config: typing.Optional[typing.Union["CfnCanary.VPCConfigProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Synthetics::Canary``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param artifact_s3_location: The location in Amazon S3 where Synthetics stores artifacts from the runs of this canary. Artifacts include the log file, screenshots, and HAR files. Specify the full location path, including ``s3://`` at the beginning of the path.
        :param code: Use this structure to input your script code for the canary. This structure contains the Lambda handler with the location where the canary should start running the script. If the script is stored in an S3 bucket, the bucket name, key, and version are also included. If the script is passed into the canary directly, the script code is contained in the value of ``Script`` .
        :param execution_role_arn: The ARN of the IAM role to be used to run the canary. This role must already exist, and must include ``lambda.amazonaws.com`` as a principal in the trust policy. The role must also have the following permissions: - ``s3:PutObject`` - ``s3:GetBucketLocation`` - ``s3:ListAllMyBuckets`` - ``cloudwatch:PutMetricData`` - ``logs:CreateLogGroup`` - ``logs:CreateLogStream`` - ``logs:PutLogEvents``
        :param name: The name for this canary. Be sure to give it a descriptive name that distinguishes it from other canaries in your account. Do not include secrets or proprietary information in your canary names. The canary name makes up part of the canary ARN, and the ARN is included in outbound calls over the internet. For more information, see `Security Considerations for Synthetics Canaries <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/servicelens_canaries_security.html>`_ .
        :param runtime_version: Specifies the runtime version to use for the canary. For more information about runtime versions, see `Canary Runtime Versions <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_Library.html>`_ .
        :param schedule: A structure that contains information about how often the canary is to run, and when these runs are to stop.
        :param start_canary_after_creation: Specify TRUE to have the canary start making runs immediately after it is created. A canary that you create using CloudFormation can't be used to monitor the CloudFormation stack that creates the canary or to roll back that stack if there is a failure.
        :param artifact_config: A structure that contains the configuration for canary artifacts, including the encryption-at-rest settings for artifacts that the canary uploads to Amazon S3.
        :param failure_retention_period: The number of days to retain data about failed runs of this canary. If you omit this field, the default of 31 days is used. The valid range is 1 to 455 days.
        :param run_config: A structure that contains input information for a canary run. If you omit this structure, the frequency of the canary is used as canary's timeout value, up to a maximum of 900 seconds.
        :param success_retention_period: The number of days to retain data about successful runs of this canary. If you omit this field, the default of 31 days is used. The valid range is 1 to 455 days.
        :param tags: The list of key-value pairs that are associated with the canary.
        :param visual_reference: If this canary performs visual monitoring by comparing screenshots, this structure contains the ID of the canary run to use as the baseline for screenshots, and the coordinates of any parts of the screen to ignore during the visual monitoring comparison.
        :param vpc_config: If this canary is to test an endpoint in a VPC, this structure contains information about the subnet and security groups of the VPC endpoint. For more information, see `Running a Canary in a VPC <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_VPC.html>`_ .
        '''
        props = CfnCanaryProps(
            artifact_s3_location=artifact_s3_location,
            code=code,
            execution_role_arn=execution_role_arn,
            name=name,
            runtime_version=runtime_version,
            schedule=schedule,
            start_canary_after_creation=start_canary_after_creation,
            artifact_config=artifact_config,
            failure_retention_period=failure_retention_period,
            run_config=run_config,
            success_retention_period=success_retention_period,
            tags=tags,
            visual_reference=visual_reference,
            vpc_config=vpc_config,
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
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The ID of the canary.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrState")
    def attr_state(self) -> builtins.str:
        '''The state of the canary.

        For example, ``RUNNING`` .

        :cloudformationAttribute: State
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrState"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The list of key-value pairs that are associated with the canary.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="artifactS3Location")
    def artifact_s3_location(self) -> builtins.str:
        '''The location in Amazon S3 where Synthetics stores artifacts from the runs of this canary.

        Artifacts include the log file, screenshots, and HAR files. Specify the full location path, including ``s3://`` at the beginning of the path.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-artifacts3location
        '''
        return typing.cast(builtins.str, jsii.get(self, "artifactS3Location"))

    @artifact_s3_location.setter
    def artifact_s3_location(self, value: builtins.str) -> None:
        jsii.set(self, "artifactS3Location", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="code")
    def code(self) -> typing.Union["CfnCanary.CodeProperty", _IResolvable_da3f097b]:
        '''Use this structure to input your script code for the canary.

        This structure contains the Lambda handler with the location where the canary should start running the script. If the script is stored in an S3 bucket, the bucket name, key, and version are also included. If the script is passed into the canary directly, the script code is contained in the value of ``Script`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-code
        '''
        return typing.cast(typing.Union["CfnCanary.CodeProperty", _IResolvable_da3f097b], jsii.get(self, "code"))

    @code.setter
    def code(
        self,
        value: typing.Union["CfnCanary.CodeProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "code", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="executionRoleArn")
    def execution_role_arn(self) -> builtins.str:
        '''The ARN of the IAM role to be used to run the canary.

        This role must already exist, and must include ``lambda.amazonaws.com`` as a principal in the trust policy. The role must also have the following permissions:

        - ``s3:PutObject``
        - ``s3:GetBucketLocation``
        - ``s3:ListAllMyBuckets``
        - ``cloudwatch:PutMetricData``
        - ``logs:CreateLogGroup``
        - ``logs:CreateLogStream``
        - ``logs:PutLogEvents``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-executionrolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "executionRoleArn"))

    @execution_role_arn.setter
    def execution_role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "executionRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name for this canary.

        Be sure to give it a descriptive name that distinguishes it from other canaries in your account.

        Do not include secrets or proprietary information in your canary names. The canary name makes up part of the canary ARN, and the ARN is included in outbound calls over the internet. For more information, see `Security Considerations for Synthetics Canaries <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/servicelens_canaries_security.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="runtimeVersion")
    def runtime_version(self) -> builtins.str:
        '''Specifies the runtime version to use for the canary.

        For more information about runtime versions, see `Canary Runtime Versions <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_Library.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-runtimeversion
        '''
        return typing.cast(builtins.str, jsii.get(self, "runtimeVersion"))

    @runtime_version.setter
    def runtime_version(self, value: builtins.str) -> None:
        jsii.set(self, "runtimeVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schedule")
    def schedule(
        self,
    ) -> typing.Union["CfnCanary.ScheduleProperty", _IResolvable_da3f097b]:
        '''A structure that contains information about how often the canary is to run, and when these runs are to stop.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-schedule
        '''
        return typing.cast(typing.Union["CfnCanary.ScheduleProperty", _IResolvable_da3f097b], jsii.get(self, "schedule"))

    @schedule.setter
    def schedule(
        self,
        value: typing.Union["CfnCanary.ScheduleProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "schedule", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="startCanaryAfterCreation")
    def start_canary_after_creation(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Specify TRUE to have the canary start making runs immediately after it is created.

        A canary that you create using CloudFormation can't be used to monitor the CloudFormation stack that creates the canary or to roll back that stack if there is a failure.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-startcanaryaftercreation
        '''
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], jsii.get(self, "startCanaryAfterCreation"))

    @start_canary_after_creation.setter
    def start_canary_after_creation(
        self,
        value: typing.Union[builtins.bool, _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "startCanaryAfterCreation", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="artifactConfig")
    def artifact_config(
        self,
    ) -> typing.Optional[typing.Union["CfnCanary.ArtifactConfigProperty", _IResolvable_da3f097b]]:
        '''A structure that contains the configuration for canary artifacts, including the encryption-at-rest settings for artifacts that the canary uploads to Amazon S3.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-artifactconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCanary.ArtifactConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "artifactConfig"))

    @artifact_config.setter
    def artifact_config(
        self,
        value: typing.Optional[typing.Union["CfnCanary.ArtifactConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "artifactConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="failureRetentionPeriod")
    def failure_retention_period(self) -> typing.Optional[jsii.Number]:
        '''The number of days to retain data about failed runs of this canary.

        If you omit this field, the default of 31 days is used. The valid range is 1 to 455 days.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-failureretentionperiod
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "failureRetentionPeriod"))

    @failure_retention_period.setter
    def failure_retention_period(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "failureRetentionPeriod", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="runConfig")
    def run_config(
        self,
    ) -> typing.Optional[typing.Union["CfnCanary.RunConfigProperty", _IResolvable_da3f097b]]:
        '''A structure that contains input information for a canary run.

        If you omit this structure, the frequency of the canary is used as canary's timeout value, up to a maximum of 900 seconds.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-runconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCanary.RunConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "runConfig"))

    @run_config.setter
    def run_config(
        self,
        value: typing.Optional[typing.Union["CfnCanary.RunConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "runConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="successRetentionPeriod")
    def success_retention_period(self) -> typing.Optional[jsii.Number]:
        '''The number of days to retain data about successful runs of this canary.

        If you omit this field, the default of 31 days is used. The valid range is 1 to 455 days.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-successretentionperiod
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "successRetentionPeriod"))

    @success_retention_period.setter
    def success_retention_period(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "successRetentionPeriod", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="visualReference")
    def visual_reference(
        self,
    ) -> typing.Optional[typing.Union["CfnCanary.VisualReferenceProperty", _IResolvable_da3f097b]]:
        '''If this canary performs visual monitoring by comparing screenshots, this structure contains the ID of the canary run to use as the baseline for screenshots, and the coordinates of any parts of the screen to ignore during the visual monitoring comparison.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-visualreference
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCanary.VisualReferenceProperty", _IResolvable_da3f097b]], jsii.get(self, "visualReference"))

    @visual_reference.setter
    def visual_reference(
        self,
        value: typing.Optional[typing.Union["CfnCanary.VisualReferenceProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "visualReference", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcConfig")
    def vpc_config(
        self,
    ) -> typing.Optional[typing.Union["CfnCanary.VPCConfigProperty", _IResolvable_da3f097b]]:
        '''If this canary is to test an endpoint in a VPC, this structure contains information about the subnet and security groups of the VPC endpoint.

        For more information, see `Running a Canary in a VPC <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_VPC.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-vpcconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCanary.VPCConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "vpcConfig"))

    @vpc_config.setter
    def vpc_config(
        self,
        value: typing.Optional[typing.Union["CfnCanary.VPCConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "vpcConfig", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary.ArtifactConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"s3_encryption": "s3Encryption"},
    )
    class ArtifactConfigProperty:
        def __init__(
            self,
            *,
            s3_encryption: typing.Optional[typing.Union["CfnCanary.S3EncryptionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A structure that contains the configuration for canary artifacts, including the encryption-at-rest settings for artifacts that the canary uploads to Amazon S3 .

            :param s3_encryption: A structure that contains the configuration of the encryption-at-rest settings for artifacts that the canary uploads to Amazon S3 . Artifact encryption functionality is available only for canaries that use Synthetics runtime version syn-nodejs-puppeteer-3.3 or later. For more information, see `Encrypting canary artifacts <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_artifact_encryption.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-artifactconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_synthetics as synthetics
                
                artifact_config_property = synthetics.CfnCanary.ArtifactConfigProperty(
                    s3_encryption=synthetics.CfnCanary.S3EncryptionProperty(
                        encryption_mode="encryptionMode",
                        kms_key_arn="kmsKeyArn"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if s3_encryption is not None:
                self._values["s3_encryption"] = s3_encryption

        @builtins.property
        def s3_encryption(
            self,
        ) -> typing.Optional[typing.Union["CfnCanary.S3EncryptionProperty", _IResolvable_da3f097b]]:
            '''A structure that contains the configuration of the encryption-at-rest settings for artifacts that the canary uploads to Amazon S3 .

            Artifact encryption functionality is available only for canaries that use Synthetics runtime version syn-nodejs-puppeteer-3.3 or later. For more information, see `Encrypting canary artifacts <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_artifact_encryption.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-artifactconfig.html#cfn-synthetics-canary-artifactconfig-s3encryption
            '''
            result = self._values.get("s3_encryption")
            return typing.cast(typing.Optional[typing.Union["CfnCanary.S3EncryptionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ArtifactConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary.BaseScreenshotProperty",
        jsii_struct_bases=[],
        name_mapping={
            "screenshot_name": "screenshotName",
            "ignore_coordinates": "ignoreCoordinates",
        },
    )
    class BaseScreenshotProperty:
        def __init__(
            self,
            *,
            screenshot_name: builtins.str,
            ignore_coordinates: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''A structure representing a screenshot that is used as a baseline during visual monitoring comparisons made by the canary.

            :param screenshot_name: The name of the screenshot. This is generated the first time the canary is run after the ``UpdateCanary`` operation that specified for this canary to perform visual monitoring.
            :param ignore_coordinates: Coordinates that define the part of a screen to ignore during screenshot comparisons. To obtain the coordinates to use here, use the CloudWatch Logs console to draw the boundaries on the screen. For more information, see {LINK}

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-basescreenshot.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_synthetics as synthetics
                
                base_screenshot_property = synthetics.CfnCanary.BaseScreenshotProperty(
                    screenshot_name="screenshotName",
                
                    # the properties below are optional
                    ignore_coordinates=["ignoreCoordinates"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "screenshot_name": screenshot_name,
            }
            if ignore_coordinates is not None:
                self._values["ignore_coordinates"] = ignore_coordinates

        @builtins.property
        def screenshot_name(self) -> builtins.str:
            '''The name of the screenshot.

            This is generated the first time the canary is run after the ``UpdateCanary`` operation that specified for this canary to perform visual monitoring.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-basescreenshot.html#cfn-synthetics-canary-basescreenshot-screenshotname
            '''
            result = self._values.get("screenshot_name")
            assert result is not None, "Required property 'screenshot_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ignore_coordinates(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Coordinates that define the part of a screen to ignore during screenshot comparisons.

            To obtain the coordinates to use here, use the CloudWatch Logs console to draw the boundaries on the screen. For more information, see {LINK}

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-basescreenshot.html#cfn-synthetics-canary-basescreenshot-ignorecoordinates
            '''
            result = self._values.get("ignore_coordinates")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BaseScreenshotProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary.CodeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "handler": "handler",
            "s3_bucket": "s3Bucket",
            "s3_key": "s3Key",
            "s3_object_version": "s3ObjectVersion",
            "script": "script",
        },
    )
    class CodeProperty:
        def __init__(
            self,
            *,
            handler: builtins.str,
            s3_bucket: typing.Optional[builtins.str] = None,
            s3_key: typing.Optional[builtins.str] = None,
            s3_object_version: typing.Optional[builtins.str] = None,
            script: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Use this structure to input your script code for the canary.

            This structure contains the Lambda handler with the location where the canary should start running the script. If the script is stored in an S3 bucket, the bucket name, key, and version are also included. If the script is passed into the canary directly, the script code is contained in the value of ``Script`` .

            :param handler: The entry point to use for the source code when running the canary. This value must end with the string ``.handler`` . The string is limited to 29 characters or fewer.
            :param s3_bucket: If your canary script is located in S3, specify the bucket name here. The bucket must already exist.
            :param s3_key: The S3 key of your script. For more information, see `Working with Amazon S3 Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingObjects.html>`_ .
            :param s3_object_version: The S3 version ID of your script.
            :param script: If you input your canary script directly into the canary instead of referring to an S3 location, the value of this parameter is the script in plain text. It can be up to 5 MB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-code.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_synthetics as synthetics
                
                code_property = synthetics.CfnCanary.CodeProperty(
                    handler="handler",
                
                    # the properties below are optional
                    s3_bucket="s3Bucket",
                    s3_key="s3Key",
                    s3_object_version="s3ObjectVersion",
                    script="script"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "handler": handler,
            }
            if s3_bucket is not None:
                self._values["s3_bucket"] = s3_bucket
            if s3_key is not None:
                self._values["s3_key"] = s3_key
            if s3_object_version is not None:
                self._values["s3_object_version"] = s3_object_version
            if script is not None:
                self._values["script"] = script

        @builtins.property
        def handler(self) -> builtins.str:
            '''The entry point to use for the source code when running the canary.

            This value must end with the string ``.handler`` . The string is limited to 29 characters or fewer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-code.html#cfn-synthetics-canary-code-handler
            '''
            result = self._values.get("handler")
            assert result is not None, "Required property 'handler' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_bucket(self) -> typing.Optional[builtins.str]:
            '''If your canary script is located in S3, specify the bucket name here.

            The bucket must already exist.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-code.html#cfn-synthetics-canary-code-s3bucket
            '''
            result = self._values.get("s3_bucket")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3_key(self) -> typing.Optional[builtins.str]:
            '''The S3 key of your script.

            For more information, see `Working with Amazon S3 Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingObjects.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-code.html#cfn-synthetics-canary-code-s3key
            '''
            result = self._values.get("s3_key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3_object_version(self) -> typing.Optional[builtins.str]:
            '''The S3 version ID of your script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-code.html#cfn-synthetics-canary-code-s3objectversion
            '''
            result = self._values.get("s3_object_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def script(self) -> typing.Optional[builtins.str]:
            '''If you input your canary script directly into the canary instead of referring to an S3 location, the value of this parameter is the script in plain text.

            It can be up to 5 MB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-code.html#cfn-synthetics-canary-code-script
            '''
            result = self._values.get("script")
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
        jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary.RunConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "active_tracing": "activeTracing",
            "environment_variables": "environmentVariables",
            "memory_in_mb": "memoryInMb",
            "timeout_in_seconds": "timeoutInSeconds",
        },
    )
    class RunConfigProperty:
        def __init__(
            self,
            *,
            active_tracing: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            environment_variables: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            memory_in_mb: typing.Optional[jsii.Number] = None,
            timeout_in_seconds: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''A structure that contains input information for a canary run.

            This structure is required.

            :param active_tracing: Specifies whether this canary is to use active AWS X-Ray tracing when it runs. Active tracing enables this canary run to be displayed in the ServiceLens and X-Ray service maps even if the canary does not hit an endpoint that has X-Ray tracing enabled. Using X-Ray tracing incurs charges. For more information, see `Canaries and X-Ray tracing <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_tracing.html>`_ . You can enable active tracing only for canaries that use version ``syn-nodejs-2.0`` or later for their canary runtime.
            :param environment_variables: Specifies the keys and values to use for any environment variables used in the canary script. Use the following format: { "key1" : "value1", "key2" : "value2", ...} Keys must start with a letter and be at least two characters. The total size of your environment variables cannot exceed 4 KB. You can't specify any Lambda reserved environment variables as the keys for your environment variables. For more information about reserved keys, see `Runtime environment variables <https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-runtime>`_ .
            :param memory_in_mb: The maximum amount of memory that the canary can use while running. This value must be a multiple of 64. The range is 960 to 3008.
            :param timeout_in_seconds: How long the canary is allowed to run before it must stop. You can't set this time to be longer than the frequency of the runs of this canary. If you omit this field, the frequency of the canary is used as this value, up to a maximum of 900 seconds.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-runconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_synthetics as synthetics
                
                run_config_property = synthetics.CfnCanary.RunConfigProperty(
                    active_tracing=False,
                    environment_variables={
                        "environment_variables_key": "environmentVariables"
                    },
                    memory_in_mb=123,
                    timeout_in_seconds=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if active_tracing is not None:
                self._values["active_tracing"] = active_tracing
            if environment_variables is not None:
                self._values["environment_variables"] = environment_variables
            if memory_in_mb is not None:
                self._values["memory_in_mb"] = memory_in_mb
            if timeout_in_seconds is not None:
                self._values["timeout_in_seconds"] = timeout_in_seconds

        @builtins.property
        def active_tracing(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether this canary is to use active AWS X-Ray tracing when it runs.

            Active tracing enables this canary run to be displayed in the ServiceLens and X-Ray service maps even if the canary does not hit an endpoint that has X-Ray tracing enabled. Using X-Ray tracing incurs charges. For more information, see `Canaries and X-Ray tracing <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_tracing.html>`_ .

            You can enable active tracing only for canaries that use version ``syn-nodejs-2.0`` or later for their canary runtime.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-runconfig.html#cfn-synthetics-canary-runconfig-activetracing
            '''
            result = self._values.get("active_tracing")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def environment_variables(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''Specifies the keys and values to use for any environment variables used in the canary script.

            Use the following format:

            { "key1" : "value1", "key2" : "value2", ...}

            Keys must start with a letter and be at least two characters. The total size of your environment variables cannot exceed 4 KB. You can't specify any Lambda reserved environment variables as the keys for your environment variables. For more information about reserved keys, see `Runtime environment variables <https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-runtime>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-runconfig.html#cfn-synthetics-canary-runconfig-environmentvariables
            '''
            result = self._values.get("environment_variables")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def memory_in_mb(self) -> typing.Optional[jsii.Number]:
            '''The maximum amount of memory that the canary can use while running.

            This value must be a multiple of 64. The range is 960 to 3008.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-runconfig.html#cfn-synthetics-canary-runconfig-memoryinmb
            '''
            result = self._values.get("memory_in_mb")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def timeout_in_seconds(self) -> typing.Optional[jsii.Number]:
            '''How long the canary is allowed to run before it must stop.

            You can't set this time to be longer than the frequency of the runs of this canary.

            If you omit this field, the frequency of the canary is used as this value, up to a maximum of 900 seconds.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-runconfig.html#cfn-synthetics-canary-runconfig-timeoutinseconds
            '''
            result = self._values.get("timeout_in_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RunConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary.S3EncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={"encryption_mode": "encryptionMode", "kms_key_arn": "kmsKeyArn"},
    )
    class S3EncryptionProperty:
        def __init__(
            self,
            *,
            encryption_mode: typing.Optional[builtins.str] = None,
            kms_key_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that contains the configuration of the encryption-at-rest settings for artifacts that the canary uploads to Amazon S3 .

            Artifact encryption functionality is available only for canaries that use Synthetics runtime version syn-nodejs-puppeteer-3.3 or later. For more information, see `Encrypting canary artifacts <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_artifact_encryption.html>`_ .

            :param encryption_mode: The encryption method to use for artifacts created by this canary. Specify ``SSE_S3`` to use server-side encryption (SSE) with an Amazon S3-managed key. Specify ``SSE-KMS`` to use server-side encryption with a customer-managed AWS KMS key. If you omit this parameter, an AWS -managed AWS KMS key is used.
            :param kms_key_arn: The ARN of the customer-managed AWS KMS key to use, if you specify ``SSE-KMS`` for ``EncryptionMode``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-s3encryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_synthetics as synthetics
                
                s3_encryption_property = synthetics.CfnCanary.S3EncryptionProperty(
                    encryption_mode="encryptionMode",
                    kms_key_arn="kmsKeyArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if encryption_mode is not None:
                self._values["encryption_mode"] = encryption_mode
            if kms_key_arn is not None:
                self._values["kms_key_arn"] = kms_key_arn

        @builtins.property
        def encryption_mode(self) -> typing.Optional[builtins.str]:
            '''The encryption method to use for artifacts created by this canary.

            Specify ``SSE_S3`` to use server-side encryption (SSE) with an Amazon S3-managed key. Specify ``SSE-KMS`` to use server-side encryption with a customer-managed AWS KMS key.

            If you omit this parameter, an AWS -managed AWS KMS key is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-s3encryption.html#cfn-synthetics-canary-s3encryption-encryptionmode
            '''
            result = self._values.get("encryption_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the customer-managed AWS KMS key to use, if you specify ``SSE-KMS`` for ``EncryptionMode``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-s3encryption.html#cfn-synthetics-canary-s3encryption-kmskeyarn
            '''
            result = self._values.get("kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3EncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary.ScheduleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "expression": "expression",
            "duration_in_seconds": "durationInSeconds",
        },
    )
    class ScheduleProperty:
        def __init__(
            self,
            *,
            expression: builtins.str,
            duration_in_seconds: typing.Optional[builtins.str] = None,
        ) -> None:
            '''This structure specifies how often a canary is to make runs and the date and time when it should stop making runs.

            :param expression: A ``rate`` expression or a ``cron`` expression that defines how often the canary is to run. For a rate expression, The syntax is ``rate( *number unit* )`` . *unit* can be ``minute`` , ``minutes`` , or ``hour`` . For example, ``rate(1 minute)`` runs the canary once a minute, ``rate(10 minutes)`` runs it once every 10 minutes, and ``rate(1 hour)`` runs it once every hour. You can specify a frequency between ``rate(1 minute)`` and ``rate(1 hour)`` . Specifying ``rate(0 minute)`` or ``rate(0 hour)`` is a special value that causes the canary to run only once when it is started. Use ``cron( *expression* )`` to specify a cron expression. You can't schedule a canary to wait for more than a year before running. For information about the syntax for cron expressions, see `Scheduling canary runs using cron <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_cron.html>`_ .
            :param duration_in_seconds: How long, in seconds, for the canary to continue making regular runs according to the schedule in the ``Expression`` value. If you specify 0, the canary continues making runs until you stop it. If you omit this field, the default of 0 is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-schedule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_synthetics as synthetics
                
                schedule_property = synthetics.CfnCanary.ScheduleProperty(
                    expression="expression",
                
                    # the properties below are optional
                    duration_in_seconds="durationInSeconds"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "expression": expression,
            }
            if duration_in_seconds is not None:
                self._values["duration_in_seconds"] = duration_in_seconds

        @builtins.property
        def expression(self) -> builtins.str:
            '''A ``rate`` expression or a ``cron`` expression that defines how often the canary is to run.

            For a rate expression, The syntax is ``rate( *number unit* )`` . *unit* can be ``minute`` , ``minutes`` , or ``hour`` .

            For example, ``rate(1 minute)`` runs the canary once a minute, ``rate(10 minutes)`` runs it once every 10 minutes, and ``rate(1 hour)`` runs it once every hour. You can specify a frequency between ``rate(1 minute)`` and ``rate(1 hour)`` .

            Specifying ``rate(0 minute)`` or ``rate(0 hour)`` is a special value that causes the canary to run only once when it is started.

            Use ``cron( *expression* )`` to specify a cron expression. You can't schedule a canary to wait for more than a year before running. For information about the syntax for cron expressions, see `Scheduling canary runs using cron <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_cron.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-schedule.html#cfn-synthetics-canary-schedule-expression
            '''
            result = self._values.get("expression")
            assert result is not None, "Required property 'expression' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def duration_in_seconds(self) -> typing.Optional[builtins.str]:
            '''How long, in seconds, for the canary to continue making regular runs according to the schedule in the ``Expression`` value.

            If you specify 0, the canary continues making runs until you stop it. If you omit this field, the default of 0 is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-schedule.html#cfn-synthetics-canary-schedule-durationinseconds
            '''
            result = self._values.get("duration_in_seconds")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScheduleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary.VPCConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "security_group_ids": "securityGroupIds",
            "subnet_ids": "subnetIds",
            "vpc_id": "vpcId",
        },
    )
    class VPCConfigProperty:
        def __init__(
            self,
            *,
            security_group_ids: typing.Sequence[builtins.str],
            subnet_ids: typing.Sequence[builtins.str],
            vpc_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''If this canary is to test an endpoint in a VPC, this structure contains information about the subnet and security groups of the VPC endpoint.

            For more information, see `Running a Canary in a VPC <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_VPC.html>`_ .

            :param security_group_ids: The IDs of the security groups for this canary.
            :param subnet_ids: The IDs of the subnets where this canary is to run.
            :param vpc_id: The ID of the VPC where this canary is to run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-vpcconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_synthetics as synthetics
                
                v_pCConfig_property = synthetics.CfnCanary.VPCConfigProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"],
                
                    # the properties below are optional
                    vpc_id="vpcId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "security_group_ids": security_group_ids,
                "subnet_ids": subnet_ids,
            }
            if vpc_id is not None:
                self._values["vpc_id"] = vpc_id

        @builtins.property
        def security_group_ids(self) -> typing.List[builtins.str]:
            '''The IDs of the security groups for this canary.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-vpcconfig.html#cfn-synthetics-canary-vpcconfig-securitygroupids
            '''
            result = self._values.get("security_group_ids")
            assert result is not None, "Required property 'security_group_ids' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def subnet_ids(self) -> typing.List[builtins.str]:
            '''The IDs of the subnets where this canary is to run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-vpcconfig.html#cfn-synthetics-canary-vpcconfig-subnetids
            '''
            result = self._values.get("subnet_ids")
            assert result is not None, "Required property 'subnet_ids' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def vpc_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the VPC where this canary is to run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-vpcconfig.html#cfn-synthetics-canary-vpcconfig-vpcid
            '''
            result = self._values.get("vpc_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VPCConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_synthetics.CfnCanary.VisualReferenceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "base_canary_run_id": "baseCanaryRunId",
            "base_screenshots": "baseScreenshots",
        },
    )
    class VisualReferenceProperty:
        def __init__(
            self,
            *,
            base_canary_run_id: builtins.str,
            base_screenshots: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCanary.BaseScreenshotProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Defines the screenshots to use as the baseline for comparisons during visual monitoring comparisons during future runs of this canary.

            If you omit this parameter, no changes are made to any baseline screenshots that the canary might be using already.

            Visual monitoring is supported only on canaries running the *syn-puppeteer-node-3.2* runtime or later. For more information, see `Visual monitoring <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Library_SyntheticsLogger_VisualTesting.html>`_ and `Visual monitoring blueprint <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_Blueprints_VisualTesting.html>`_

            :param base_canary_run_id: Specifies which canary run to use the screenshots from as the baseline for future visual monitoring with this canary. Valid values are ``nextrun`` to use the screenshots from the next run after this update is made, ``lastrun`` to use the screenshots from the most recent run before this update was made, or the value of ``Id`` in the `CanaryRun <https://docs.aws.amazon.com/AmazonSynthetics/latest/APIReference/API_CanaryRun.html>`_ from any past run of this canary.
            :param base_screenshots: An array of screenshots that are used as the baseline for comparisons during visual monitoring.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-visualreference.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_synthetics as synthetics
                
                visual_reference_property = synthetics.CfnCanary.VisualReferenceProperty(
                    base_canary_run_id="baseCanaryRunId",
                
                    # the properties below are optional
                    base_screenshots=[synthetics.CfnCanary.BaseScreenshotProperty(
                        screenshot_name="screenshotName",
                
                        # the properties below are optional
                        ignore_coordinates=["ignoreCoordinates"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "base_canary_run_id": base_canary_run_id,
            }
            if base_screenshots is not None:
                self._values["base_screenshots"] = base_screenshots

        @builtins.property
        def base_canary_run_id(self) -> builtins.str:
            '''Specifies which canary run to use the screenshots from as the baseline for future visual monitoring with this canary.

            Valid values are ``nextrun`` to use the screenshots from the next run after this update is made, ``lastrun`` to use the screenshots from the most recent run before this update was made, or the value of ``Id`` in the `CanaryRun <https://docs.aws.amazon.com/AmazonSynthetics/latest/APIReference/API_CanaryRun.html>`_ from any past run of this canary.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-visualreference.html#cfn-synthetics-canary-visualreference-basecanaryrunid
            '''
            result = self._values.get("base_canary_run_id")
            assert result is not None, "Required property 'base_canary_run_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def base_screenshots(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCanary.BaseScreenshotProperty", _IResolvable_da3f097b]]]]:
            '''An array of screenshots that are used as the baseline for comparisons during visual monitoring.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-synthetics-canary-visualreference.html#cfn-synthetics-canary-visualreference-basescreenshots
            '''
            result = self._values.get("base_screenshots")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCanary.BaseScreenshotProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VisualReferenceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_synthetics.CfnCanaryProps",
    jsii_struct_bases=[],
    name_mapping={
        "artifact_s3_location": "artifactS3Location",
        "code": "code",
        "execution_role_arn": "executionRoleArn",
        "name": "name",
        "runtime_version": "runtimeVersion",
        "schedule": "schedule",
        "start_canary_after_creation": "startCanaryAfterCreation",
        "artifact_config": "artifactConfig",
        "failure_retention_period": "failureRetentionPeriod",
        "run_config": "runConfig",
        "success_retention_period": "successRetentionPeriod",
        "tags": "tags",
        "visual_reference": "visualReference",
        "vpc_config": "vpcConfig",
    },
)
class CfnCanaryProps:
    def __init__(
        self,
        *,
        artifact_s3_location: builtins.str,
        code: typing.Union[CfnCanary.CodeProperty, _IResolvable_da3f097b],
        execution_role_arn: builtins.str,
        name: builtins.str,
        runtime_version: builtins.str,
        schedule: typing.Union[CfnCanary.ScheduleProperty, _IResolvable_da3f097b],
        start_canary_after_creation: typing.Union[builtins.bool, _IResolvable_da3f097b],
        artifact_config: typing.Optional[typing.Union[CfnCanary.ArtifactConfigProperty, _IResolvable_da3f097b]] = None,
        failure_retention_period: typing.Optional[jsii.Number] = None,
        run_config: typing.Optional[typing.Union[CfnCanary.RunConfigProperty, _IResolvable_da3f097b]] = None,
        success_retention_period: typing.Optional[jsii.Number] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        visual_reference: typing.Optional[typing.Union[CfnCanary.VisualReferenceProperty, _IResolvable_da3f097b]] = None,
        vpc_config: typing.Optional[typing.Union[CfnCanary.VPCConfigProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnCanary``.

        :param artifact_s3_location: The location in Amazon S3 where Synthetics stores artifacts from the runs of this canary. Artifacts include the log file, screenshots, and HAR files. Specify the full location path, including ``s3://`` at the beginning of the path.
        :param code: Use this structure to input your script code for the canary. This structure contains the Lambda handler with the location where the canary should start running the script. If the script is stored in an S3 bucket, the bucket name, key, and version are also included. If the script is passed into the canary directly, the script code is contained in the value of ``Script`` .
        :param execution_role_arn: The ARN of the IAM role to be used to run the canary. This role must already exist, and must include ``lambda.amazonaws.com`` as a principal in the trust policy. The role must also have the following permissions: - ``s3:PutObject`` - ``s3:GetBucketLocation`` - ``s3:ListAllMyBuckets`` - ``cloudwatch:PutMetricData`` - ``logs:CreateLogGroup`` - ``logs:CreateLogStream`` - ``logs:PutLogEvents``
        :param name: The name for this canary. Be sure to give it a descriptive name that distinguishes it from other canaries in your account. Do not include secrets or proprietary information in your canary names. The canary name makes up part of the canary ARN, and the ARN is included in outbound calls over the internet. For more information, see `Security Considerations for Synthetics Canaries <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/servicelens_canaries_security.html>`_ .
        :param runtime_version: Specifies the runtime version to use for the canary. For more information about runtime versions, see `Canary Runtime Versions <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_Library.html>`_ .
        :param schedule: A structure that contains information about how often the canary is to run, and when these runs are to stop.
        :param start_canary_after_creation: Specify TRUE to have the canary start making runs immediately after it is created. A canary that you create using CloudFormation can't be used to monitor the CloudFormation stack that creates the canary or to roll back that stack if there is a failure.
        :param artifact_config: A structure that contains the configuration for canary artifacts, including the encryption-at-rest settings for artifacts that the canary uploads to Amazon S3.
        :param failure_retention_period: The number of days to retain data about failed runs of this canary. If you omit this field, the default of 31 days is used. The valid range is 1 to 455 days.
        :param run_config: A structure that contains input information for a canary run. If you omit this structure, the frequency of the canary is used as canary's timeout value, up to a maximum of 900 seconds.
        :param success_retention_period: The number of days to retain data about successful runs of this canary. If you omit this field, the default of 31 days is used. The valid range is 1 to 455 days.
        :param tags: The list of key-value pairs that are associated with the canary.
        :param visual_reference: If this canary performs visual monitoring by comparing screenshots, this structure contains the ID of the canary run to use as the baseline for screenshots, and the coordinates of any parts of the screen to ignore during the visual monitoring comparison.
        :param vpc_config: If this canary is to test an endpoint in a VPC, this structure contains information about the subnet and security groups of the VPC endpoint. For more information, see `Running a Canary in a VPC <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_VPC.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_synthetics as synthetics
            
            cfn_canary_props = synthetics.CfnCanaryProps(
                artifact_s3_location="artifactS3Location",
                code=synthetics.CfnCanary.CodeProperty(
                    handler="handler",
            
                    # the properties below are optional
                    s3_bucket="s3Bucket",
                    s3_key="s3Key",
                    s3_object_version="s3ObjectVersion",
                    script="script"
                ),
                execution_role_arn="executionRoleArn",
                name="name",
                runtime_version="runtimeVersion",
                schedule=synthetics.CfnCanary.ScheduleProperty(
                    expression="expression",
            
                    # the properties below are optional
                    duration_in_seconds="durationInSeconds"
                ),
                start_canary_after_creation=False,
            
                # the properties below are optional
                artifact_config=synthetics.CfnCanary.ArtifactConfigProperty(
                    s3_encryption=synthetics.CfnCanary.S3EncryptionProperty(
                        encryption_mode="encryptionMode",
                        kms_key_arn="kmsKeyArn"
                    )
                ),
                failure_retention_period=123,
                run_config=synthetics.CfnCanary.RunConfigProperty(
                    active_tracing=False,
                    environment_variables={
                        "environment_variables_key": "environmentVariables"
                    },
                    memory_in_mb=123,
                    timeout_in_seconds=123
                ),
                success_retention_period=123,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                visual_reference=synthetics.CfnCanary.VisualReferenceProperty(
                    base_canary_run_id="baseCanaryRunId",
            
                    # the properties below are optional
                    base_screenshots=[synthetics.CfnCanary.BaseScreenshotProperty(
                        screenshot_name="screenshotName",
            
                        # the properties below are optional
                        ignore_coordinates=["ignoreCoordinates"]
                    )]
                ),
                vpc_config=synthetics.CfnCanary.VPCConfigProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"],
            
                    # the properties below are optional
                    vpc_id="vpcId"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "artifact_s3_location": artifact_s3_location,
            "code": code,
            "execution_role_arn": execution_role_arn,
            "name": name,
            "runtime_version": runtime_version,
            "schedule": schedule,
            "start_canary_after_creation": start_canary_after_creation,
        }
        if artifact_config is not None:
            self._values["artifact_config"] = artifact_config
        if failure_retention_period is not None:
            self._values["failure_retention_period"] = failure_retention_period
        if run_config is not None:
            self._values["run_config"] = run_config
        if success_retention_period is not None:
            self._values["success_retention_period"] = success_retention_period
        if tags is not None:
            self._values["tags"] = tags
        if visual_reference is not None:
            self._values["visual_reference"] = visual_reference
        if vpc_config is not None:
            self._values["vpc_config"] = vpc_config

    @builtins.property
    def artifact_s3_location(self) -> builtins.str:
        '''The location in Amazon S3 where Synthetics stores artifacts from the runs of this canary.

        Artifacts include the log file, screenshots, and HAR files. Specify the full location path, including ``s3://`` at the beginning of the path.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-artifacts3location
        '''
        result = self._values.get("artifact_s3_location")
        assert result is not None, "Required property 'artifact_s3_location' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def code(self) -> typing.Union[CfnCanary.CodeProperty, _IResolvable_da3f097b]:
        '''Use this structure to input your script code for the canary.

        This structure contains the Lambda handler with the location where the canary should start running the script. If the script is stored in an S3 bucket, the bucket name, key, and version are also included. If the script is passed into the canary directly, the script code is contained in the value of ``Script`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-code
        '''
        result = self._values.get("code")
        assert result is not None, "Required property 'code' is missing"
        return typing.cast(typing.Union[CfnCanary.CodeProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def execution_role_arn(self) -> builtins.str:
        '''The ARN of the IAM role to be used to run the canary.

        This role must already exist, and must include ``lambda.amazonaws.com`` as a principal in the trust policy. The role must also have the following permissions:

        - ``s3:PutObject``
        - ``s3:GetBucketLocation``
        - ``s3:ListAllMyBuckets``
        - ``cloudwatch:PutMetricData``
        - ``logs:CreateLogGroup``
        - ``logs:CreateLogStream``
        - ``logs:PutLogEvents``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-executionrolearn
        '''
        result = self._values.get("execution_role_arn")
        assert result is not None, "Required property 'execution_role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''The name for this canary.

        Be sure to give it a descriptive name that distinguishes it from other canaries in your account.

        Do not include secrets or proprietary information in your canary names. The canary name makes up part of the canary ARN, and the ARN is included in outbound calls over the internet. For more information, see `Security Considerations for Synthetics Canaries <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/servicelens_canaries_security.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def runtime_version(self) -> builtins.str:
        '''Specifies the runtime version to use for the canary.

        For more information about runtime versions, see `Canary Runtime Versions <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_Library.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-runtimeversion
        '''
        result = self._values.get("runtime_version")
        assert result is not None, "Required property 'runtime_version' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def schedule(
        self,
    ) -> typing.Union[CfnCanary.ScheduleProperty, _IResolvable_da3f097b]:
        '''A structure that contains information about how often the canary is to run, and when these runs are to stop.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-schedule
        '''
        result = self._values.get("schedule")
        assert result is not None, "Required property 'schedule' is missing"
        return typing.cast(typing.Union[CfnCanary.ScheduleProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def start_canary_after_creation(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Specify TRUE to have the canary start making runs immediately after it is created.

        A canary that you create using CloudFormation can't be used to monitor the CloudFormation stack that creates the canary or to roll back that stack if there is a failure.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-startcanaryaftercreation
        '''
        result = self._values.get("start_canary_after_creation")
        assert result is not None, "Required property 'start_canary_after_creation' is missing"
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

    @builtins.property
    def artifact_config(
        self,
    ) -> typing.Optional[typing.Union[CfnCanary.ArtifactConfigProperty, _IResolvable_da3f097b]]:
        '''A structure that contains the configuration for canary artifacts, including the encryption-at-rest settings for artifacts that the canary uploads to Amazon S3.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-artifactconfig
        '''
        result = self._values.get("artifact_config")
        return typing.cast(typing.Optional[typing.Union[CfnCanary.ArtifactConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def failure_retention_period(self) -> typing.Optional[jsii.Number]:
        '''The number of days to retain data about failed runs of this canary.

        If you omit this field, the default of 31 days is used. The valid range is 1 to 455 days.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-failureretentionperiod
        '''
        result = self._values.get("failure_retention_period")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def run_config(
        self,
    ) -> typing.Optional[typing.Union[CfnCanary.RunConfigProperty, _IResolvable_da3f097b]]:
        '''A structure that contains input information for a canary run.

        If you omit this structure, the frequency of the canary is used as canary's timeout value, up to a maximum of 900 seconds.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-runconfig
        '''
        result = self._values.get("run_config")
        return typing.cast(typing.Optional[typing.Union[CfnCanary.RunConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def success_retention_period(self) -> typing.Optional[jsii.Number]:
        '''The number of days to retain data about successful runs of this canary.

        If you omit this field, the default of 31 days is used. The valid range is 1 to 455 days.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-successretentionperiod
        '''
        result = self._values.get("success_retention_period")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The list of key-value pairs that are associated with the canary.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def visual_reference(
        self,
    ) -> typing.Optional[typing.Union[CfnCanary.VisualReferenceProperty, _IResolvable_da3f097b]]:
        '''If this canary performs visual monitoring by comparing screenshots, this structure contains the ID of the canary run to use as the baseline for screenshots, and the coordinates of any parts of the screen to ignore during the visual monitoring comparison.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-visualreference
        '''
        result = self._values.get("visual_reference")
        return typing.cast(typing.Optional[typing.Union[CfnCanary.VisualReferenceProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def vpc_config(
        self,
    ) -> typing.Optional[typing.Union[CfnCanary.VPCConfigProperty, _IResolvable_da3f097b]]:
        '''If this canary is to test an endpoint in a VPC, this structure contains information about the subnet and security groups of the VPC endpoint.

        For more information, see `Running a Canary in a VPC <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_VPC.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-synthetics-canary.html#cfn-synthetics-canary-vpcconfig
        '''
        result = self._values.get("vpc_config")
        return typing.cast(typing.Optional[typing.Union[CfnCanary.VPCConfigProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCanaryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnCanary",
    "CfnCanaryProps",
]

publication.publish()
