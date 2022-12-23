'''
# AWS::MWAA Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_mwaa as mwaa
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-mwaa-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::MWAA](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_MWAA.html).

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
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnEnvironment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_mwaa.CfnEnvironment",
):
    '''A CloudFormation ``AWS::MWAA::Environment``.

    The ``AWS::MWAA::Environment`` resource creates an Amazon Managed Workflows for Apache Airflow (MWAA) environment.

    :cloudformationResource: AWS::MWAA::Environment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_mwaa as mwaa
        
        # airflow_configuration_options: Any
        # tags: Any
        
        cfn_environment = mwaa.CfnEnvironment(self, "MyCfnEnvironment",
            name="name",
        
            # the properties below are optional
            airflow_configuration_options=airflow_configuration_options,
            airflow_version="airflowVersion",
            dag_s3_path="dagS3Path",
            environment_class="environmentClass",
            execution_role_arn="executionRoleArn",
            kms_key="kmsKey",
            logging_configuration=mwaa.CfnEnvironment.LoggingConfigurationProperty(
                dag_processing_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                    enabled=False,
                    log_level="logLevel"
                ),
                scheduler_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                    enabled=False,
                    log_level="logLevel"
                ),
                task_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                    enabled=False,
                    log_level="logLevel"
                ),
                webserver_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                    enabled=False,
                    log_level="logLevel"
                ),
                worker_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                    enabled=False,
                    log_level="logLevel"
                )
            ),
            max_workers=123,
            min_workers=123,
            network_configuration=mwaa.CfnEnvironment.NetworkConfigurationProperty(
                security_group_ids=["securityGroupIds"],
                subnet_ids=["subnetIds"]
            ),
            plugins_s3_object_version="pluginsS3ObjectVersion",
            plugins_s3_path="pluginsS3Path",
            requirements_s3_object_version="requirementsS3ObjectVersion",
            requirements_s3_path="requirementsS3Path",
            schedulers=123,
            source_bucket_arn="sourceBucketArn",
            tags=tags,
            webserver_access_mode="webserverAccessMode",
            weekly_maintenance_window_start="weeklyMaintenanceWindowStart"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        airflow_configuration_options: typing.Any = None,
        airflow_version: typing.Optional[builtins.str] = None,
        dag_s3_path: typing.Optional[builtins.str] = None,
        environment_class: typing.Optional[builtins.str] = None,
        execution_role_arn: typing.Optional[builtins.str] = None,
        kms_key: typing.Optional[builtins.str] = None,
        logging_configuration: typing.Optional[typing.Union["CfnEnvironment.LoggingConfigurationProperty", _IResolvable_da3f097b]] = None,
        max_workers: typing.Optional[jsii.Number] = None,
        min_workers: typing.Optional[jsii.Number] = None,
        network_configuration: typing.Optional[typing.Union["CfnEnvironment.NetworkConfigurationProperty", _IResolvable_da3f097b]] = None,
        plugins_s3_object_version: typing.Optional[builtins.str] = None,
        plugins_s3_path: typing.Optional[builtins.str] = None,
        requirements_s3_object_version: typing.Optional[builtins.str] = None,
        requirements_s3_path: typing.Optional[builtins.str] = None,
        schedulers: typing.Optional[jsii.Number] = None,
        source_bucket_arn: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
        webserver_access_mode: typing.Optional[builtins.str] = None,
        weekly_maintenance_window_start: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::MWAA::Environment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of your Amazon MWAA environment.
        :param airflow_configuration_options: A list of key-value pairs containing the Airflow configuration options for your environment. For example, ``core.default_timezone: utc`` . To learn more, see `Apache Airflow configuration options <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-env-variables.html>`_ .
        :param airflow_version: The version of Apache Airflow to use for the environment. If no value is specified, defaults to the latest version. Valid values: ``2.0.2`` , ``1.10.12`` .
        :param dag_s3_path: The relative path to the DAGs folder on your Amazon S3 bucket. For example, ``dags`` . To learn more, see `Adding or updating DAGs <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-folder.html>`_ .
        :param environment_class: The environment class type. Valid values: ``mw1.small`` , ``mw1.medium`` , ``mw1.large`` . To learn more, see `Amazon MWAA environment class <https://docs.aws.amazon.com/mwaa/latest/userguide/environment-class.html>`_ .
        :param execution_role_arn: The Amazon Resource Name (ARN) of the execution role in IAM that allows MWAA to access AWS resources in your environment. For example, ``arn:aws:iam::123456789:role/my-execution-role`` . To learn more, see `Amazon MWAA Execution role <https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html>`_ .
        :param kms_key: The AWS Key Management Service (KMS) key to encrypt and decrypt the data in your environment. You can use an AWS KMS key managed by MWAA, or a customer-managed KMS key (advanced).
        :param logging_configuration: The Apache Airflow logs being sent to CloudWatch Logs: ``DagProcessingLogs`` , ``SchedulerLogs`` , ``TaskLogs`` , ``WebserverLogs`` , ``WorkerLogs`` .
        :param max_workers: The maximum number of workers that you want to run in your environment. MWAA scales the number of Apache Airflow workers up to the number you specify in the ``MaxWorkers`` field. For example, ``20`` . When there are no more tasks running, and no more in the queue, MWAA disposes of the extra workers leaving the one worker that is included with your environment, or the number you specify in ``MinWorkers`` .
        :param min_workers: The minimum number of workers that you want to run in your environment. MWAA scales the number of Apache Airflow workers up to the number you specify in the ``MaxWorkers`` field. When there are no more tasks running, and no more in the queue, MWAA disposes of the extra workers leaving the worker count you specify in the ``MinWorkers`` field. For example, ``2`` .
        :param network_configuration: The VPC networking components used to secure and enable network traffic between the AWS resources for your environment. To learn more, see `About networking on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/networking-about.html>`_ .
        :param plugins_s3_object_version: The version of the plugins.zip file on your Amazon S3 bucket. To learn more, see `Installing custom plugins <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-import-plugins.html>`_ .
        :param plugins_s3_path: The relative path to the ``plugins.zip`` file on your Amazon S3 bucket. For example, ``plugins.zip`` . To learn more, see `Installing custom plugins <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-import-plugins.html>`_ .
        :param requirements_s3_object_version: The version of the requirements.txt file on your Amazon S3 bucket. To learn more, see `Installing Python dependencies <https://docs.aws.amazon.com/mwaa/latest/userguide/working-dags-dependencies.html>`_ .
        :param requirements_s3_path: The relative path to the ``requirements.txt`` file on your Amazon S3 bucket. For example, ``requirements.txt`` . To learn more, see `Installing Python dependencies <https://docs.aws.amazon.com/mwaa/latest/userguide/working-dags-dependencies.html>`_ .
        :param schedulers: The number of schedulers that you want to run in your environment. Valid values:. - *v2.0.2* - Accepts between 2 to 5. Defaults to 2. - *v1.10.12* - Accepts 1.
        :param source_bucket_arn: The Amazon Resource Name (ARN) of the Amazon S3 bucket where your DAG code and supporting files are stored. For example, ``arn:aws:s3:::my-airflow-bucket-unique-name`` . To learn more, see `Create an Amazon S3 bucket for Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-s3-bucket.html>`_ .
        :param tags: The key-value tag pairs associated to your environment. For example, ``"Environment": "Staging"`` . To learn more, see `Tagging <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`_ .
        :param webserver_access_mode: The Apache Airflow *Web server* access mode. To learn more, see `Apache Airflow access modes <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-networking.html>`_ . Valid values: ``PRIVATE_ONLY`` or ``PUBLIC_ONLY`` .
        :param weekly_maintenance_window_start: The day and time of the week to start weekly maintenance updates of your environment in the following format: ``DAY:HH:MM`` . For example: ``TUE:03:30`` . You can specify a start time in 30 minute increments only. Supported input includes the following: - MON|TUE|WED|THU|FRI|SAT|SUN:([01]\\d|2[0-3]):(00|30)
        '''
        props = CfnEnvironmentProps(
            name=name,
            airflow_configuration_options=airflow_configuration_options,
            airflow_version=airflow_version,
            dag_s3_path=dag_s3_path,
            environment_class=environment_class,
            execution_role_arn=execution_role_arn,
            kms_key=kms_key,
            logging_configuration=logging_configuration,
            max_workers=max_workers,
            min_workers=min_workers,
            network_configuration=network_configuration,
            plugins_s3_object_version=plugins_s3_object_version,
            plugins_s3_path=plugins_s3_path,
            requirements_s3_object_version=requirements_s3_object_version,
            requirements_s3_path=requirements_s3_path,
            schedulers=schedulers,
            source_bucket_arn=source_bucket_arn,
            tags=tags,
            webserver_access_mode=webserver_access_mode,
            weekly_maintenance_window_start=weekly_maintenance_window_start,
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
        '''The ARN for the Amazon MWAA environment.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoggingConfigurationDagProcessingLogsCloudWatchLogGroupArn")
    def attr_logging_configuration_dag_processing_logs_cloud_watch_log_group_arn(
        self,
    ) -> builtins.str:
        '''The ARN for the CloudWatch Logs group where the Apache Airflow DAG processing logs are published.

        :cloudformationAttribute: LoggingConfiguration.DagProcessingLogs.CloudWatchLogGroupArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoggingConfigurationDagProcessingLogsCloudWatchLogGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoggingConfigurationSchedulerLogsCloudWatchLogGroupArn")
    def attr_logging_configuration_scheduler_logs_cloud_watch_log_group_arn(
        self,
    ) -> builtins.str:
        '''The ARN for the CloudWatch Logs group where the Apache Airflow Scheduler logs are published.

        :cloudformationAttribute: LoggingConfiguration.SchedulerLogs.CloudWatchLogGroupArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoggingConfigurationSchedulerLogsCloudWatchLogGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoggingConfigurationTaskLogsCloudWatchLogGroupArn")
    def attr_logging_configuration_task_logs_cloud_watch_log_group_arn(
        self,
    ) -> builtins.str:
        '''The ARN for the CloudWatch Logs group where the Apache Airflow task logs are published.

        :cloudformationAttribute: LoggingConfiguration.TaskLogs.CloudWatchLogGroupArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoggingConfigurationTaskLogsCloudWatchLogGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoggingConfigurationWebserverLogsCloudWatchLogGroupArn")
    def attr_logging_configuration_webserver_logs_cloud_watch_log_group_arn(
        self,
    ) -> builtins.str:
        '''The ARN for the CloudWatch Logs group where the Apache Airflow Web server logs are published.

        :cloudformationAttribute: LoggingConfiguration.WebserverLogs.CloudWatchLogGroupArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoggingConfigurationWebserverLogsCloudWatchLogGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoggingConfigurationWorkerLogsCloudWatchLogGroupArn")
    def attr_logging_configuration_worker_logs_cloud_watch_log_group_arn(
        self,
    ) -> builtins.str:
        '''The ARN for the CloudWatch Logs group where the Apache Airflow Worker logs are published.

        :cloudformationAttribute: LoggingConfiguration.WorkerLogs.CloudWatchLogGroupArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoggingConfigurationWorkerLogsCloudWatchLogGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrWebserverUrl")
    def attr_webserver_url(self) -> builtins.str:
        '''The URL of your Apache Airflow UI.

        :cloudformationAttribute: WebserverUrl
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrWebserverUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The key-value tag pairs associated to your environment.

        For example, ``"Environment": "Staging"`` . To learn more, see `Tagging <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="airflowConfigurationOptions")
    def airflow_configuration_options(self) -> typing.Any:
        '''A list of key-value pairs containing the Airflow configuration options for your environment.

        For example, ``core.default_timezone: utc`` . To learn more, see `Apache Airflow configuration options <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-env-variables.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-airflowconfigurationoptions
        '''
        return typing.cast(typing.Any, jsii.get(self, "airflowConfigurationOptions"))

    @airflow_configuration_options.setter
    def airflow_configuration_options(self, value: typing.Any) -> None:
        jsii.set(self, "airflowConfigurationOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of your Amazon MWAA environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="airflowVersion")
    def airflow_version(self) -> typing.Optional[builtins.str]:
        '''The version of Apache Airflow to use for the environment.

        If no value is specified, defaults to the latest version. Valid values: ``2.0.2`` , ``1.10.12`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-airflowversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "airflowVersion"))

    @airflow_version.setter
    def airflow_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "airflowVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dagS3Path")
    def dag_s3_path(self) -> typing.Optional[builtins.str]:
        '''The relative path to the DAGs folder on your Amazon S3 bucket.

        For example, ``dags`` . To learn more, see `Adding or updating DAGs <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-folder.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-dags3path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dagS3Path"))

    @dag_s3_path.setter
    def dag_s3_path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dagS3Path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="environmentClass")
    def environment_class(self) -> typing.Optional[builtins.str]:
        '''The environment class type.

        Valid values: ``mw1.small`` , ``mw1.medium`` , ``mw1.large`` . To learn more, see `Amazon MWAA environment class <https://docs.aws.amazon.com/mwaa/latest/userguide/environment-class.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-environmentclass
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "environmentClass"))

    @environment_class.setter
    def environment_class(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "environmentClass", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="executionRoleArn")
    def execution_role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the execution role in IAM that allows MWAA to access AWS resources in your environment.

        For example, ``arn:aws:iam::123456789:role/my-execution-role`` . To learn more, see `Amazon MWAA Execution role <https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-executionrolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "executionRoleArn"))

    @execution_role_arn.setter
    def execution_role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "executionRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKey")
    def kms_key(self) -> typing.Optional[builtins.str]:
        '''The AWS Key Management Service (KMS) key to encrypt and decrypt the data in your environment.

        You can use an AWS KMS key managed by MWAA, or a customer-managed KMS key (advanced).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-kmskey
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKey"))

    @kms_key.setter
    def kms_key(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKey", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loggingConfiguration")
    def logging_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnEnvironment.LoggingConfigurationProperty", _IResolvable_da3f097b]]:
        '''The Apache Airflow logs being sent to CloudWatch Logs: ``DagProcessingLogs`` , ``SchedulerLogs`` , ``TaskLogs`` , ``WebserverLogs`` , ``WorkerLogs`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-loggingconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEnvironment.LoggingConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "loggingConfiguration"))

    @logging_configuration.setter
    def logging_configuration(
        self,
        value: typing.Optional[typing.Union["CfnEnvironment.LoggingConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "loggingConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxWorkers")
    def max_workers(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of workers that you want to run in your environment.

        MWAA scales the number of Apache Airflow workers up to the number you specify in the ``MaxWorkers`` field. For example, ``20`` . When there are no more tasks running, and no more in the queue, MWAA disposes of the extra workers leaving the one worker that is included with your environment, or the number you specify in ``MinWorkers`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-maxworkers
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxWorkers"))

    @max_workers.setter
    def max_workers(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxWorkers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="minWorkers")
    def min_workers(self) -> typing.Optional[jsii.Number]:
        '''The minimum number of workers that you want to run in your environment.

        MWAA scales the number of Apache Airflow workers up to the number you specify in the ``MaxWorkers`` field. When there are no more tasks running, and no more in the queue, MWAA disposes of the extra workers leaving the worker count you specify in the ``MinWorkers`` field. For example, ``2`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-minworkers
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "minWorkers"))

    @min_workers.setter
    def min_workers(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "minWorkers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="networkConfiguration")
    def network_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnEnvironment.NetworkConfigurationProperty", _IResolvable_da3f097b]]:
        '''The VPC networking components used to secure and enable network traffic between the AWS resources for your environment.

        To learn more, see `About networking on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/networking-about.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-networkconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEnvironment.NetworkConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "networkConfiguration"))

    @network_configuration.setter
    def network_configuration(
        self,
        value: typing.Optional[typing.Union["CfnEnvironment.NetworkConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "networkConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="pluginsS3ObjectVersion")
    def plugins_s3_object_version(self) -> typing.Optional[builtins.str]:
        '''The version of the plugins.zip file on your Amazon S3 bucket. To learn more, see `Installing custom plugins <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-import-plugins.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-pluginss3objectversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "pluginsS3ObjectVersion"))

    @plugins_s3_object_version.setter
    def plugins_s3_object_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "pluginsS3ObjectVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="pluginsS3Path")
    def plugins_s3_path(self) -> typing.Optional[builtins.str]:
        '''The relative path to the ``plugins.zip`` file on your Amazon S3 bucket. For example, ``plugins.zip`` . To learn more, see `Installing custom plugins <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-import-plugins.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-pluginss3path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "pluginsS3Path"))

    @plugins_s3_path.setter
    def plugins_s3_path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "pluginsS3Path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="requirementsS3ObjectVersion")
    def requirements_s3_object_version(self) -> typing.Optional[builtins.str]:
        '''The version of the requirements.txt file on your Amazon S3 bucket. To learn more, see `Installing Python dependencies <https://docs.aws.amazon.com/mwaa/latest/userguide/working-dags-dependencies.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-requirementss3objectversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "requirementsS3ObjectVersion"))

    @requirements_s3_object_version.setter
    def requirements_s3_object_version(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "requirementsS3ObjectVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="requirementsS3Path")
    def requirements_s3_path(self) -> typing.Optional[builtins.str]:
        '''The relative path to the ``requirements.txt`` file on your Amazon S3 bucket. For example, ``requirements.txt`` . To learn more, see `Installing Python dependencies <https://docs.aws.amazon.com/mwaa/latest/userguide/working-dags-dependencies.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-requirementss3path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "requirementsS3Path"))

    @requirements_s3_path.setter
    def requirements_s3_path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "requirementsS3Path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schedulers")
    def schedulers(self) -> typing.Optional[jsii.Number]:
        '''The number of schedulers that you want to run in your environment. Valid values:.

        - *v2.0.2* - Accepts between 2 to 5. Defaults to 2.
        - *v1.10.12* - Accepts 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-schedulers
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "schedulers"))

    @schedulers.setter
    def schedulers(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "schedulers", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceBucketArn")
    def source_bucket_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the Amazon S3 bucket where your DAG code and supporting files are stored.

        For example, ``arn:aws:s3:::my-airflow-bucket-unique-name`` . To learn more, see `Create an Amazon S3 bucket for Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-s3-bucket.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-sourcebucketarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "sourceBucketArn"))

    @source_bucket_arn.setter
    def source_bucket_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "sourceBucketArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="webserverAccessMode")
    def webserver_access_mode(self) -> typing.Optional[builtins.str]:
        '''The Apache Airflow *Web server* access mode.

        To learn more, see `Apache Airflow access modes <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-networking.html>`_ . Valid values: ``PRIVATE_ONLY`` or ``PUBLIC_ONLY`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-webserveraccessmode
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "webserverAccessMode"))

    @webserver_access_mode.setter
    def webserver_access_mode(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "webserverAccessMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="weeklyMaintenanceWindowStart")
    def weekly_maintenance_window_start(self) -> typing.Optional[builtins.str]:
        '''The day and time of the week to start weekly maintenance updates of your environment in the following format: ``DAY:HH:MM`` .

        For example: ``TUE:03:30`` . You can specify a start time in 30 minute increments only. Supported input includes the following:

        - MON|TUE|WED|THU|FRI|SAT|SUN:([01]\\d|2[0-3]):(00|30)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-weeklymaintenancewindowstart
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "weeklyMaintenanceWindowStart"))

    @weekly_maintenance_window_start.setter
    def weekly_maintenance_window_start(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "weeklyMaintenanceWindowStart", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mwaa.CfnEnvironment.LoggingConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "dag_processing_logs": "dagProcessingLogs",
            "scheduler_logs": "schedulerLogs",
            "task_logs": "taskLogs",
            "webserver_logs": "webserverLogs",
            "worker_logs": "workerLogs",
        },
    )
    class LoggingConfigurationProperty:
        def __init__(
            self,
            *,
            dag_processing_logs: typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]] = None,
            scheduler_logs: typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]] = None,
            task_logs: typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]] = None,
            webserver_logs: typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]] = None,
            worker_logs: typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The type of Apache Airflow logs to send to CloudWatch Logs.

            :param dag_processing_logs: Defines the processing logs sent to CloudWatch Logs and the logging level to send.
            :param scheduler_logs: Defines the scheduler logs sent to CloudWatch Logs and the logging level to send.
            :param task_logs: Defines the task logs sent to CloudWatch Logs and the logging level to send.
            :param webserver_logs: Defines the web server logs sent to CloudWatch Logs and the logging level to send.
            :param worker_logs: Defines the worker logs sent to CloudWatch Logs and the logging level to send.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-loggingconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mwaa as mwaa
                
                logging_configuration_property = mwaa.CfnEnvironment.LoggingConfigurationProperty(
                    dag_processing_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    ),
                    scheduler_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    ),
                    task_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    ),
                    webserver_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    ),
                    worker_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if dag_processing_logs is not None:
                self._values["dag_processing_logs"] = dag_processing_logs
            if scheduler_logs is not None:
                self._values["scheduler_logs"] = scheduler_logs
            if task_logs is not None:
                self._values["task_logs"] = task_logs
            if webserver_logs is not None:
                self._values["webserver_logs"] = webserver_logs
            if worker_logs is not None:
                self._values["worker_logs"] = worker_logs

        @builtins.property
        def dag_processing_logs(
            self,
        ) -> typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]]:
            '''Defines the processing logs sent to CloudWatch Logs and the logging level to send.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-loggingconfiguration.html#cfn-mwaa-environment-loggingconfiguration-dagprocessinglogs
            '''
            result = self._values.get("dag_processing_logs")
            return typing.cast(typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def scheduler_logs(
            self,
        ) -> typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]]:
            '''Defines the scheduler logs sent to CloudWatch Logs and the logging level to send.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-loggingconfiguration.html#cfn-mwaa-environment-loggingconfiguration-schedulerlogs
            '''
            result = self._values.get("scheduler_logs")
            return typing.cast(typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def task_logs(
            self,
        ) -> typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]]:
            '''Defines the task logs sent to CloudWatch Logs and the logging level to send.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-loggingconfiguration.html#cfn-mwaa-environment-loggingconfiguration-tasklogs
            '''
            result = self._values.get("task_logs")
            return typing.cast(typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def webserver_logs(
            self,
        ) -> typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]]:
            '''Defines the web server logs sent to CloudWatch Logs and the logging level to send.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-loggingconfiguration.html#cfn-mwaa-environment-loggingconfiguration-webserverlogs
            '''
            result = self._values.get("webserver_logs")
            return typing.cast(typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def worker_logs(
            self,
        ) -> typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]]:
            '''Defines the worker logs sent to CloudWatch Logs and the logging level to send.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-loggingconfiguration.html#cfn-mwaa-environment-loggingconfiguration-workerlogs
            '''
            result = self._values.get("worker_logs")
            return typing.cast(typing.Optional[typing.Union["CfnEnvironment.ModuleLoggingConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggingConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_log_group_arn": "cloudWatchLogGroupArn",
            "enabled": "enabled",
            "log_level": "logLevel",
        },
    )
    class ModuleLoggingConfigurationProperty:
        def __init__(
            self,
            *,
            cloud_watch_log_group_arn: typing.Optional[builtins.str] = None,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            log_level: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines the type of logs to send for the Apache Airflow log type (e.g. ``DagProcessingLogs`` ).

            :param cloud_watch_log_group_arn: The ARN of the CloudWatch Logs log group for each type of Apache Airflow log type that you have enabled. .. epigraph:: ``CloudWatchLogGroupArn`` is available only as a return value, accessible when specified as an attribute in the ```Fn:GetAtt`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#aws-resource-mwaa-environment-return-values>`_ intrinsic function. Any value you provide for ``CloudWatchLogGroupArn`` is discarded by Amazon MWAA.
            :param enabled: Indicates whether to enable the Apache Airflow log type (e.g. ``DagProcessingLogs`` ) in CloudWatch Logs.
            :param log_level: Defines the Apache Airflow logs to send for the log type (e.g. ``DagProcessingLogs`` ) to CloudWatch Logs. Valid values: ``CRITICAL`` , ``ERROR`` , ``WARNING`` , ``INFO`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-moduleloggingconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mwaa as mwaa
                
                module_logging_configuration_property = mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                    enabled=False,
                    log_level="logLevel"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cloud_watch_log_group_arn is not None:
                self._values["cloud_watch_log_group_arn"] = cloud_watch_log_group_arn
            if enabled is not None:
                self._values["enabled"] = enabled
            if log_level is not None:
                self._values["log_level"] = log_level

        @builtins.property
        def cloud_watch_log_group_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the CloudWatch Logs log group for each type of Apache Airflow log type that you have enabled.

            .. epigraph::

               ``CloudWatchLogGroupArn`` is available only as a return value, accessible when specified as an attribute in the ```Fn:GetAtt`` <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#aws-resource-mwaa-environment-return-values>`_ intrinsic function. Any value you provide for ``CloudWatchLogGroupArn`` is discarded by Amazon MWAA.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-moduleloggingconfiguration.html#cfn-mwaa-environment-moduleloggingconfiguration-cloudwatchloggrouparn
            '''
            result = self._values.get("cloud_watch_log_group_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether to enable the Apache Airflow log type (e.g. ``DagProcessingLogs`` ) in CloudWatch Logs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-moduleloggingconfiguration.html#cfn-mwaa-environment-moduleloggingconfiguration-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def log_level(self) -> typing.Optional[builtins.str]:
            '''Defines the Apache Airflow logs to send for the log type (e.g. ``DagProcessingLogs`` ) to CloudWatch Logs. Valid values: ``CRITICAL`` , ``ERROR`` , ``WARNING`` , ``INFO`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-moduleloggingconfiguration.html#cfn-mwaa-environment-moduleloggingconfiguration-loglevel
            '''
            result = self._values.get("log_level")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ModuleLoggingConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_mwaa.CfnEnvironment.NetworkConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "security_group_ids": "securityGroupIds",
            "subnet_ids": "subnetIds",
        },
    )
    class NetworkConfigurationProperty:
        def __init__(
            self,
            *,
            security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The VPC networking components used to secure and enable network traffic between the AWS resources for your environment.

            To learn more, see `About networking on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/networking-about.html>`_ .

            :param security_group_ids: A list of one or more security group IDs. Accepts up to 5 security group IDs. A security group must be attached to the same VPC as the subnets. To learn more, see `Security in your VPC on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/vpc-security.html>`_ .
            :param subnet_ids: A list of subnet IDs. *Required* to create an environment. Must be private subnets in two different availability zones. A subnet must be attached to the same VPC as the security group. To learn more, see `About networking on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/networking-about.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-networkconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_mwaa as mwaa
                
                network_configuration_property = mwaa.CfnEnvironment.NetworkConfigurationProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if security_group_ids is not None:
                self._values["security_group_ids"] = security_group_ids
            if subnet_ids is not None:
                self._values["subnet_ids"] = subnet_ids

        @builtins.property
        def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of one or more security group IDs.

            Accepts up to 5 security group IDs. A security group must be attached to the same VPC as the subnets. To learn more, see `Security in your VPC on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/vpc-security.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-networkconfiguration.html#cfn-mwaa-environment-networkconfiguration-securitygroupids
            '''
            result = self._values.get("security_group_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of subnet IDs.

            *Required* to create an environment. Must be private subnets in two different availability zones. A subnet must be attached to the same VPC as the security group. To learn more, see `About networking on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/networking-about.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-mwaa-environment-networkconfiguration.html#cfn-mwaa-environment-networkconfiguration-subnetids
            '''
            result = self._values.get("subnet_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NetworkConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_mwaa.CfnEnvironmentProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "airflow_configuration_options": "airflowConfigurationOptions",
        "airflow_version": "airflowVersion",
        "dag_s3_path": "dagS3Path",
        "environment_class": "environmentClass",
        "execution_role_arn": "executionRoleArn",
        "kms_key": "kmsKey",
        "logging_configuration": "loggingConfiguration",
        "max_workers": "maxWorkers",
        "min_workers": "minWorkers",
        "network_configuration": "networkConfiguration",
        "plugins_s3_object_version": "pluginsS3ObjectVersion",
        "plugins_s3_path": "pluginsS3Path",
        "requirements_s3_object_version": "requirementsS3ObjectVersion",
        "requirements_s3_path": "requirementsS3Path",
        "schedulers": "schedulers",
        "source_bucket_arn": "sourceBucketArn",
        "tags": "tags",
        "webserver_access_mode": "webserverAccessMode",
        "weekly_maintenance_window_start": "weeklyMaintenanceWindowStart",
    },
)
class CfnEnvironmentProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        airflow_configuration_options: typing.Any = None,
        airflow_version: typing.Optional[builtins.str] = None,
        dag_s3_path: typing.Optional[builtins.str] = None,
        environment_class: typing.Optional[builtins.str] = None,
        execution_role_arn: typing.Optional[builtins.str] = None,
        kms_key: typing.Optional[builtins.str] = None,
        logging_configuration: typing.Optional[typing.Union[CfnEnvironment.LoggingConfigurationProperty, _IResolvable_da3f097b]] = None,
        max_workers: typing.Optional[jsii.Number] = None,
        min_workers: typing.Optional[jsii.Number] = None,
        network_configuration: typing.Optional[typing.Union[CfnEnvironment.NetworkConfigurationProperty, _IResolvable_da3f097b]] = None,
        plugins_s3_object_version: typing.Optional[builtins.str] = None,
        plugins_s3_path: typing.Optional[builtins.str] = None,
        requirements_s3_object_version: typing.Optional[builtins.str] = None,
        requirements_s3_path: typing.Optional[builtins.str] = None,
        schedulers: typing.Optional[jsii.Number] = None,
        source_bucket_arn: typing.Optional[builtins.str] = None,
        tags: typing.Any = None,
        webserver_access_mode: typing.Optional[builtins.str] = None,
        weekly_maintenance_window_start: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnEnvironment``.

        :param name: The name of your Amazon MWAA environment.
        :param airflow_configuration_options: A list of key-value pairs containing the Airflow configuration options for your environment. For example, ``core.default_timezone: utc`` . To learn more, see `Apache Airflow configuration options <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-env-variables.html>`_ .
        :param airflow_version: The version of Apache Airflow to use for the environment. If no value is specified, defaults to the latest version. Valid values: ``2.0.2`` , ``1.10.12`` .
        :param dag_s3_path: The relative path to the DAGs folder on your Amazon S3 bucket. For example, ``dags`` . To learn more, see `Adding or updating DAGs <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-folder.html>`_ .
        :param environment_class: The environment class type. Valid values: ``mw1.small`` , ``mw1.medium`` , ``mw1.large`` . To learn more, see `Amazon MWAA environment class <https://docs.aws.amazon.com/mwaa/latest/userguide/environment-class.html>`_ .
        :param execution_role_arn: The Amazon Resource Name (ARN) of the execution role in IAM that allows MWAA to access AWS resources in your environment. For example, ``arn:aws:iam::123456789:role/my-execution-role`` . To learn more, see `Amazon MWAA Execution role <https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html>`_ .
        :param kms_key: The AWS Key Management Service (KMS) key to encrypt and decrypt the data in your environment. You can use an AWS KMS key managed by MWAA, or a customer-managed KMS key (advanced).
        :param logging_configuration: The Apache Airflow logs being sent to CloudWatch Logs: ``DagProcessingLogs`` , ``SchedulerLogs`` , ``TaskLogs`` , ``WebserverLogs`` , ``WorkerLogs`` .
        :param max_workers: The maximum number of workers that you want to run in your environment. MWAA scales the number of Apache Airflow workers up to the number you specify in the ``MaxWorkers`` field. For example, ``20`` . When there are no more tasks running, and no more in the queue, MWAA disposes of the extra workers leaving the one worker that is included with your environment, or the number you specify in ``MinWorkers`` .
        :param min_workers: The minimum number of workers that you want to run in your environment. MWAA scales the number of Apache Airflow workers up to the number you specify in the ``MaxWorkers`` field. When there are no more tasks running, and no more in the queue, MWAA disposes of the extra workers leaving the worker count you specify in the ``MinWorkers`` field. For example, ``2`` .
        :param network_configuration: The VPC networking components used to secure and enable network traffic between the AWS resources for your environment. To learn more, see `About networking on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/networking-about.html>`_ .
        :param plugins_s3_object_version: The version of the plugins.zip file on your Amazon S3 bucket. To learn more, see `Installing custom plugins <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-import-plugins.html>`_ .
        :param plugins_s3_path: The relative path to the ``plugins.zip`` file on your Amazon S3 bucket. For example, ``plugins.zip`` . To learn more, see `Installing custom plugins <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-import-plugins.html>`_ .
        :param requirements_s3_object_version: The version of the requirements.txt file on your Amazon S3 bucket. To learn more, see `Installing Python dependencies <https://docs.aws.amazon.com/mwaa/latest/userguide/working-dags-dependencies.html>`_ .
        :param requirements_s3_path: The relative path to the ``requirements.txt`` file on your Amazon S3 bucket. For example, ``requirements.txt`` . To learn more, see `Installing Python dependencies <https://docs.aws.amazon.com/mwaa/latest/userguide/working-dags-dependencies.html>`_ .
        :param schedulers: The number of schedulers that you want to run in your environment. Valid values:. - *v2.0.2* - Accepts between 2 to 5. Defaults to 2. - *v1.10.12* - Accepts 1.
        :param source_bucket_arn: The Amazon Resource Name (ARN) of the Amazon S3 bucket where your DAG code and supporting files are stored. For example, ``arn:aws:s3:::my-airflow-bucket-unique-name`` . To learn more, see `Create an Amazon S3 bucket for Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-s3-bucket.html>`_ .
        :param tags: The key-value tag pairs associated to your environment. For example, ``"Environment": "Staging"`` . To learn more, see `Tagging <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`_ .
        :param webserver_access_mode: The Apache Airflow *Web server* access mode. To learn more, see `Apache Airflow access modes <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-networking.html>`_ . Valid values: ``PRIVATE_ONLY`` or ``PUBLIC_ONLY`` .
        :param weekly_maintenance_window_start: The day and time of the week to start weekly maintenance updates of your environment in the following format: ``DAY:HH:MM`` . For example: ``TUE:03:30`` . You can specify a start time in 30 minute increments only. Supported input includes the following: - MON|TUE|WED|THU|FRI|SAT|SUN:([01]\\d|2[0-3]):(00|30)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_mwaa as mwaa
            
            # airflow_configuration_options: Any
            # tags: Any
            
            cfn_environment_props = mwaa.CfnEnvironmentProps(
                name="name",
            
                # the properties below are optional
                airflow_configuration_options=airflow_configuration_options,
                airflow_version="airflowVersion",
                dag_s3_path="dagS3Path",
                environment_class="environmentClass",
                execution_role_arn="executionRoleArn",
                kms_key="kmsKey",
                logging_configuration=mwaa.CfnEnvironment.LoggingConfigurationProperty(
                    dag_processing_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    ),
                    scheduler_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    ),
                    task_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    ),
                    webserver_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    ),
                    worker_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                        cloud_watch_log_group_arn="cloudWatchLogGroupArn",
                        enabled=False,
                        log_level="logLevel"
                    )
                ),
                max_workers=123,
                min_workers=123,
                network_configuration=mwaa.CfnEnvironment.NetworkConfigurationProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"]
                ),
                plugins_s3_object_version="pluginsS3ObjectVersion",
                plugins_s3_path="pluginsS3Path",
                requirements_s3_object_version="requirementsS3ObjectVersion",
                requirements_s3_path="requirementsS3Path",
                schedulers=123,
                source_bucket_arn="sourceBucketArn",
                tags=tags,
                webserver_access_mode="webserverAccessMode",
                weekly_maintenance_window_start="weeklyMaintenanceWindowStart"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if airflow_configuration_options is not None:
            self._values["airflow_configuration_options"] = airflow_configuration_options
        if airflow_version is not None:
            self._values["airflow_version"] = airflow_version
        if dag_s3_path is not None:
            self._values["dag_s3_path"] = dag_s3_path
        if environment_class is not None:
            self._values["environment_class"] = environment_class
        if execution_role_arn is not None:
            self._values["execution_role_arn"] = execution_role_arn
        if kms_key is not None:
            self._values["kms_key"] = kms_key
        if logging_configuration is not None:
            self._values["logging_configuration"] = logging_configuration
        if max_workers is not None:
            self._values["max_workers"] = max_workers
        if min_workers is not None:
            self._values["min_workers"] = min_workers
        if network_configuration is not None:
            self._values["network_configuration"] = network_configuration
        if plugins_s3_object_version is not None:
            self._values["plugins_s3_object_version"] = plugins_s3_object_version
        if plugins_s3_path is not None:
            self._values["plugins_s3_path"] = plugins_s3_path
        if requirements_s3_object_version is not None:
            self._values["requirements_s3_object_version"] = requirements_s3_object_version
        if requirements_s3_path is not None:
            self._values["requirements_s3_path"] = requirements_s3_path
        if schedulers is not None:
            self._values["schedulers"] = schedulers
        if source_bucket_arn is not None:
            self._values["source_bucket_arn"] = source_bucket_arn
        if tags is not None:
            self._values["tags"] = tags
        if webserver_access_mode is not None:
            self._values["webserver_access_mode"] = webserver_access_mode
        if weekly_maintenance_window_start is not None:
            self._values["weekly_maintenance_window_start"] = weekly_maintenance_window_start

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of your Amazon MWAA environment.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def airflow_configuration_options(self) -> typing.Any:
        '''A list of key-value pairs containing the Airflow configuration options for your environment.

        For example, ``core.default_timezone: utc`` . To learn more, see `Apache Airflow configuration options <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-env-variables.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-airflowconfigurationoptions
        '''
        result = self._values.get("airflow_configuration_options")
        return typing.cast(typing.Any, result)

    @builtins.property
    def airflow_version(self) -> typing.Optional[builtins.str]:
        '''The version of Apache Airflow to use for the environment.

        If no value is specified, defaults to the latest version. Valid values: ``2.0.2`` , ``1.10.12`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-airflowversion
        '''
        result = self._values.get("airflow_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def dag_s3_path(self) -> typing.Optional[builtins.str]:
        '''The relative path to the DAGs folder on your Amazon S3 bucket.

        For example, ``dags`` . To learn more, see `Adding or updating DAGs <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-folder.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-dags3path
        '''
        result = self._values.get("dag_s3_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def environment_class(self) -> typing.Optional[builtins.str]:
        '''The environment class type.

        Valid values: ``mw1.small`` , ``mw1.medium`` , ``mw1.large`` . To learn more, see `Amazon MWAA environment class <https://docs.aws.amazon.com/mwaa/latest/userguide/environment-class.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-environmentclass
        '''
        result = self._values.get("environment_class")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def execution_role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the execution role in IAM that allows MWAA to access AWS resources in your environment.

        For example, ``arn:aws:iam::123456789:role/my-execution-role`` . To learn more, see `Amazon MWAA Execution role <https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-executionrolearn
        '''
        result = self._values.get("execution_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key(self) -> typing.Optional[builtins.str]:
        '''The AWS Key Management Service (KMS) key to encrypt and decrypt the data in your environment.

        You can use an AWS KMS key managed by MWAA, or a customer-managed KMS key (advanced).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-kmskey
        '''
        result = self._values.get("kms_key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def logging_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnEnvironment.LoggingConfigurationProperty, _IResolvable_da3f097b]]:
        '''The Apache Airflow logs being sent to CloudWatch Logs: ``DagProcessingLogs`` , ``SchedulerLogs`` , ``TaskLogs`` , ``WebserverLogs`` , ``WorkerLogs`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-loggingconfiguration
        '''
        result = self._values.get("logging_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnEnvironment.LoggingConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def max_workers(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of workers that you want to run in your environment.

        MWAA scales the number of Apache Airflow workers up to the number you specify in the ``MaxWorkers`` field. For example, ``20`` . When there are no more tasks running, and no more in the queue, MWAA disposes of the extra workers leaving the one worker that is included with your environment, or the number you specify in ``MinWorkers`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-maxworkers
        '''
        result = self._values.get("max_workers")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_workers(self) -> typing.Optional[jsii.Number]:
        '''The minimum number of workers that you want to run in your environment.

        MWAA scales the number of Apache Airflow workers up to the number you specify in the ``MaxWorkers`` field. When there are no more tasks running, and no more in the queue, MWAA disposes of the extra workers leaving the worker count you specify in the ``MinWorkers`` field. For example, ``2`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-minworkers
        '''
        result = self._values.get("min_workers")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def network_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnEnvironment.NetworkConfigurationProperty, _IResolvable_da3f097b]]:
        '''The VPC networking components used to secure and enable network traffic between the AWS resources for your environment.

        To learn more, see `About networking on Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/networking-about.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-networkconfiguration
        '''
        result = self._values.get("network_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnEnvironment.NetworkConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def plugins_s3_object_version(self) -> typing.Optional[builtins.str]:
        '''The version of the plugins.zip file on your Amazon S3 bucket. To learn more, see `Installing custom plugins <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-import-plugins.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-pluginss3objectversion
        '''
        result = self._values.get("plugins_s3_object_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def plugins_s3_path(self) -> typing.Optional[builtins.str]:
        '''The relative path to the ``plugins.zip`` file on your Amazon S3 bucket. For example, ``plugins.zip`` . To learn more, see `Installing custom plugins <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-dag-import-plugins.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-pluginss3path
        '''
        result = self._values.get("plugins_s3_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def requirements_s3_object_version(self) -> typing.Optional[builtins.str]:
        '''The version of the requirements.txt file on your Amazon S3 bucket. To learn more, see `Installing Python dependencies <https://docs.aws.amazon.com/mwaa/latest/userguide/working-dags-dependencies.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-requirementss3objectversion
        '''
        result = self._values.get("requirements_s3_object_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def requirements_s3_path(self) -> typing.Optional[builtins.str]:
        '''The relative path to the ``requirements.txt`` file on your Amazon S3 bucket. For example, ``requirements.txt`` . To learn more, see `Installing Python dependencies <https://docs.aws.amazon.com/mwaa/latest/userguide/working-dags-dependencies.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-requirementss3path
        '''
        result = self._values.get("requirements_s3_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def schedulers(self) -> typing.Optional[jsii.Number]:
        '''The number of schedulers that you want to run in your environment. Valid values:.

        - *v2.0.2* - Accepts between 2 to 5. Defaults to 2.
        - *v1.10.12* - Accepts 1.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-schedulers
        '''
        result = self._values.get("schedulers")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def source_bucket_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the Amazon S3 bucket where your DAG code and supporting files are stored.

        For example, ``arn:aws:s3:::my-airflow-bucket-unique-name`` . To learn more, see `Create an Amazon S3 bucket for Amazon MWAA <https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-s3-bucket.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-sourcebucketarn
        '''
        result = self._values.get("source_bucket_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''The key-value tag pairs associated to your environment.

        For example, ``"Environment": "Staging"`` . To learn more, see `Tagging <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def webserver_access_mode(self) -> typing.Optional[builtins.str]:
        '''The Apache Airflow *Web server* access mode.

        To learn more, see `Apache Airflow access modes <https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-networking.html>`_ . Valid values: ``PRIVATE_ONLY`` or ``PUBLIC_ONLY`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-webserveraccessmode
        '''
        result = self._values.get("webserver_access_mode")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def weekly_maintenance_window_start(self) -> typing.Optional[builtins.str]:
        '''The day and time of the week to start weekly maintenance updates of your environment in the following format: ``DAY:HH:MM`` .

        For example: ``TUE:03:30`` . You can specify a start time in 30 minute increments only. Supported input includes the following:

        - MON|TUE|WED|THU|FRI|SAT|SUN:([01]\\d|2[0-3]):(00|30)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-weeklymaintenancewindowstart
        '''
        result = self._values.get("weekly_maintenance_window_start")
        return typing.cast(typing.Optional[builtins.str], result)

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
