'''
# AWS::Timestream Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_timestream as timestream
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-timestream-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Timestream](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Timestream.html).

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
class CfnDatabase(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_timestream.CfnDatabase",
):
    '''A CloudFormation ``AWS::Timestream::Database``.

    Creates a new Timestream database. If the AWS KMS key is not specified, the database will be encrypted with a Timestream managed AWS KMS key located in your account. Refer to `AWS managed AWS KMS keys <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-cmk>`_ for more info. `Service quotas apply <https://docs.aws.amazon.com/timestream/latest/developerguide/ts-limits.html>`_ . See `code sample <https://docs.aws.amazon.com/timestream/latest/developerguide/code-samples.create-db.html>`_ for details.

    :cloudformationResource: AWS::Timestream::Database
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_timestream as timestream
        
        cfn_database = timestream.CfnDatabase(self, "MyCfnDatabase",
            database_name="databaseName",
            kms_key_id="kmsKeyId",
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
        database_name: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Timestream::Database``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param database_name: The name of the Timestream database. *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.
        :param kms_key_id: The identifier of the AWS KMS key used to encrypt the data stored in the database.
        :param tags: The tags to add to the database.
        '''
        props = CfnDatabaseProps(
            database_name=database_name, kms_key_id=kms_key_id, tags=tags
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
        '''The ``arn`` of the database.

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
        '''The tags to add to the database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="databaseName")
    def database_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Timestream database.

        *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-databasename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "databaseName"))

    @database_name.setter
    def database_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "databaseName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The identifier of the AWS KMS key used to encrypt the data stored in the database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_timestream.CfnDatabaseProps",
    jsii_struct_bases=[],
    name_mapping={
        "database_name": "databaseName",
        "kms_key_id": "kmsKeyId",
        "tags": "tags",
    },
)
class CfnDatabaseProps:
    def __init__(
        self,
        *,
        database_name: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDatabase``.

        :param database_name: The name of the Timestream database. *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.
        :param kms_key_id: The identifier of the AWS KMS key used to encrypt the data stored in the database.
        :param tags: The tags to add to the database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_timestream as timestream
            
            cfn_database_props = timestream.CfnDatabaseProps(
                database_name="databaseName",
                kms_key_id="kmsKeyId",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if database_name is not None:
            self._values["database_name"] = database_name
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def database_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Timestream database.

        *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-databasename
        '''
        result = self._values.get("database_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The identifier of the AWS KMS key used to encrypt the data stored in the database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to add to the database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDatabaseProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnScheduledQuery(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery",
):
    '''A CloudFormation ``AWS::Timestream::ScheduledQuery``.

    Create a scheduled query that will be run on your behalf at the configured schedule. Timestream assumes the execution role provided as part of the ``ScheduledQueryExecutionRoleArn`` parameter to run the query. You can use the ``NotificationConfiguration`` parameter to configure notification for your scheduled query operations.

    :cloudformationResource: AWS::Timestream::ScheduledQuery
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_timestream as timestream
        
        cfn_scheduled_query = timestream.CfnScheduledQuery(self, "MyCfnScheduledQuery",
            error_report_configuration=timestream.CfnScheduledQuery.ErrorReportConfigurationProperty(
                s3_configuration=timestream.CfnScheduledQuery.S3ConfigurationProperty(
                    bucket_name="bucketName",
        
                    # the properties below are optional
                    encryption_option="encryptionOption",
                    object_key_prefix="objectKeyPrefix"
                )
            ),
            notification_configuration=timestream.CfnScheduledQuery.NotificationConfigurationProperty(
                sns_configuration=timestream.CfnScheduledQuery.SnsConfigurationProperty(
                    topic_arn="topicArn"
                )
            ),
            query_string="queryString",
            schedule_configuration=timestream.CfnScheduledQuery.ScheduleConfigurationProperty(
                schedule_expression="scheduleExpression"
            ),
            scheduled_query_execution_role_arn="scheduledQueryExecutionRoleArn",
        
            # the properties below are optional
            client_token="clientToken",
            kms_key_id="kmsKeyId",
            scheduled_query_name="scheduledQueryName",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            target_configuration=timestream.CfnScheduledQuery.TargetConfigurationProperty(
                timestream_configuration=timestream.CfnScheduledQuery.TimestreamConfigurationProperty(
                    database_name="databaseName",
                    dimension_mappings=[timestream.CfnScheduledQuery.DimensionMappingProperty(
                        dimension_value_type="dimensionValueType",
                        name="name"
                    )],
                    table_name="tableName",
                    time_column="timeColumn",
        
                    # the properties below are optional
                    measure_name_column="measureNameColumn",
                    mixed_measure_mappings=[timestream.CfnScheduledQuery.MixedMeasureMappingProperty(
                        measure_value_type="measureValueType",
        
                        # the properties below are optional
                        measure_name="measureName",
                        multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                            measure_value_type="measureValueType",
                            source_column="sourceColumn",
        
                            # the properties below are optional
                            target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                        )],
                        source_column="sourceColumn",
                        target_measure_name="targetMeasureName"
                    )],
                    multi_measure_mappings=timestream.CfnScheduledQuery.MultiMeasureMappingsProperty(
                        multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                            measure_value_type="measureValueType",
                            source_column="sourceColumn",
        
                            # the properties below are optional
                            target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                        )],
        
                        # the properties below are optional
                        target_multi_measure_name="targetMultiMeasureName"
                    )
                )
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        error_report_configuration: typing.Union["CfnScheduledQuery.ErrorReportConfigurationProperty", _IResolvable_da3f097b],
        notification_configuration: typing.Union["CfnScheduledQuery.NotificationConfigurationProperty", _IResolvable_da3f097b],
        query_string: builtins.str,
        schedule_configuration: typing.Union["CfnScheduledQuery.ScheduleConfigurationProperty", _IResolvable_da3f097b],
        scheduled_query_execution_role_arn: builtins.str,
        client_token: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        scheduled_query_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        target_configuration: typing.Optional[typing.Union["CfnScheduledQuery.TargetConfigurationProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Timestream::ScheduledQuery``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param error_report_configuration: Configuration for error reporting. Error reports will be generated when a problem is encountered when writing the query results.
        :param notification_configuration: Notification configuration for the scheduled query. A notification is sent by Timestream when a query run finishes, when the state is updated or when you delete it.
        :param query_string: The query string to run. Parameter names can be specified in the query string ``@`` character followed by an identifier. The named Parameter ``@scheduled_runtime`` is reserved and can be used in the query to get the time at which the query is scheduled to run. The timestamp calculated according to the ScheduleConfiguration parameter, will be the value of ``@scheduled_runtime`` paramater for each query run. For example, consider an instance of a scheduled query executing on 2021-12-01 00:00:00. For this instance, the ``@scheduled_runtime`` parameter is initialized to the timestamp 2021-12-01 00:00:00 when invoking the query.
        :param schedule_configuration: Schedule configuration.
        :param scheduled_query_execution_role_arn: The ARN for the IAM role that Timestream will assume when running the scheduled query.
        :param client_token: Using a ClientToken makes the call to CreateScheduledQuery idempotent, in other words, making the same request repeatedly will produce the same result. Making multiple identical CreateScheduledQuery requests has the same effect as making a single request. - If CreateScheduledQuery is called without a ``ClientToken`` , the Query SDK generates a ``ClientToken`` on your behalf. - After 8 hours, any request with the same ``ClientToken`` is treated as a new request.
        :param kms_key_id: The Amazon KMS key used to encrypt the scheduled query resource, at-rest. If the Amazon KMS key is not specified, the scheduled query resource will be encrypted with a Timestream owned Amazon KMS key. To specify a KMS key, use the key ID, key ARN, alias name, or alias ARN. When using an alias name, prefix the name with *alias/* If ErrorReportConfiguration uses ``SSE_KMS`` as encryption type, the same KmsKeyId is used to encrypt the error report at rest.
        :param scheduled_query_name: A name for the query. Scheduled query names must be unique within each Region.
        :param tags: A list of key-value pairs to label the scheduled query.
        :param target_configuration: Scheduled query target store configuration.
        '''
        props = CfnScheduledQueryProps(
            error_report_configuration=error_report_configuration,
            notification_configuration=notification_configuration,
            query_string=query_string,
            schedule_configuration=schedule_configuration,
            scheduled_query_execution_role_arn=scheduled_query_execution_role_arn,
            client_token=client_token,
            kms_key_id=kms_key_id,
            scheduled_query_name=scheduled_query_name,
            tags=tags,
            target_configuration=target_configuration,
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
        '''The ``ARN`` of the scheduled query.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSqErrorReportConfiguration")
    def attr_sq_error_report_configuration(self) -> builtins.str:
        '''The scheduled query error reporting configuration.

        :cloudformationAttribute: SQErrorReportConfiguration
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSqErrorReportConfiguration"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSqKmsKeyId")
    def attr_sq_kms_key_id(self) -> builtins.str:
        '''The KMS key used to encrypt the query resource, if a customer managed KMS key was provided.

        :cloudformationAttribute: SQKmsKeyId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSqKmsKeyId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSqName")
    def attr_sq_name(self) -> builtins.str:
        '''The scheduled query name.

        :cloudformationAttribute: SQName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSqName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSqNotificationConfiguration")
    def attr_sq_notification_configuration(self) -> builtins.str:
        '''The scheduled query notification configuration.

        :cloudformationAttribute: SQNotificationConfiguration
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSqNotificationConfiguration"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSqQueryString")
    def attr_sq_query_string(self) -> builtins.str:
        '''The scheduled query string..

        :cloudformationAttribute: SQQueryString
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSqQueryString"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSqScheduleConfiguration")
    def attr_sq_schedule_configuration(self) -> builtins.str:
        '''The scheduled query schedule configuration.

        :cloudformationAttribute: SQScheduleConfiguration
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSqScheduleConfiguration"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSqScheduledQueryExecutionRoleArn")
    def attr_sq_scheduled_query_execution_role_arn(self) -> builtins.str:
        '''The ARN of the IAM role that will be used by Timestream to run the query.

        :cloudformationAttribute: SQScheduledQueryExecutionRoleArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSqScheduledQueryExecutionRoleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSqTargetConfiguration")
    def attr_sq_target_configuration(self) -> builtins.str:
        '''The configuration for query output.

        :cloudformationAttribute: SQTargetConfiguration
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSqTargetConfiguration"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A list of key-value pairs to label the scheduled query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="errorReportConfiguration")
    def error_report_configuration(
        self,
    ) -> typing.Union["CfnScheduledQuery.ErrorReportConfigurationProperty", _IResolvable_da3f097b]:
        '''Configuration for error reporting.

        Error reports will be generated when a problem is encountered when writing the query results.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-errorreportconfiguration
        '''
        return typing.cast(typing.Union["CfnScheduledQuery.ErrorReportConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "errorReportConfiguration"))

    @error_report_configuration.setter
    def error_report_configuration(
        self,
        value: typing.Union["CfnScheduledQuery.ErrorReportConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "errorReportConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationConfiguration")
    def notification_configuration(
        self,
    ) -> typing.Union["CfnScheduledQuery.NotificationConfigurationProperty", _IResolvable_da3f097b]:
        '''Notification configuration for the scheduled query.

        A notification is sent by Timestream when a query run finishes, when the state is updated or when you delete it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-notificationconfiguration
        '''
        return typing.cast(typing.Union["CfnScheduledQuery.NotificationConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "notificationConfiguration"))

    @notification_configuration.setter
    def notification_configuration(
        self,
        value: typing.Union["CfnScheduledQuery.NotificationConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "notificationConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queryString")
    def query_string(self) -> builtins.str:
        '''The query string to run.

        Parameter names can be specified in the query string ``@`` character followed by an identifier. The named Parameter ``@scheduled_runtime`` is reserved and can be used in the query to get the time at which the query is scheduled to run.

        The timestamp calculated according to the ScheduleConfiguration parameter, will be the value of ``@scheduled_runtime`` paramater for each query run. For example, consider an instance of a scheduled query executing on 2021-12-01 00:00:00. For this instance, the ``@scheduled_runtime`` parameter is initialized to the timestamp 2021-12-01 00:00:00 when invoking the query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-querystring
        '''
        return typing.cast(builtins.str, jsii.get(self, "queryString"))

    @query_string.setter
    def query_string(self, value: builtins.str) -> None:
        jsii.set(self, "queryString", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scheduleConfiguration")
    def schedule_configuration(
        self,
    ) -> typing.Union["CfnScheduledQuery.ScheduleConfigurationProperty", _IResolvable_da3f097b]:
        '''Schedule configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-scheduleconfiguration
        '''
        return typing.cast(typing.Union["CfnScheduledQuery.ScheduleConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "scheduleConfiguration"))

    @schedule_configuration.setter
    def schedule_configuration(
        self,
        value: typing.Union["CfnScheduledQuery.ScheduleConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "scheduleConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scheduledQueryExecutionRoleArn")
    def scheduled_query_execution_role_arn(self) -> builtins.str:
        '''The ARN for the IAM role that Timestream will assume when running the scheduled query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-scheduledqueryexecutionrolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "scheduledQueryExecutionRoleArn"))

    @scheduled_query_execution_role_arn.setter
    def scheduled_query_execution_role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "scheduledQueryExecutionRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clientToken")
    def client_token(self) -> typing.Optional[builtins.str]:
        '''Using a ClientToken makes the call to CreateScheduledQuery idempotent, in other words, making the same request repeatedly will produce the same result.

        Making multiple identical CreateScheduledQuery requests has the same effect as making a single request.

        - If CreateScheduledQuery is called without a ``ClientToken`` , the Query SDK generates a ``ClientToken`` on your behalf.
        - After 8 hours, any request with the same ``ClientToken`` is treated as a new request.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-clienttoken
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "clientToken"))

    @client_token.setter
    def client_token(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "clientToken", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The Amazon KMS key used to encrypt the scheduled query resource, at-rest.

        If the Amazon KMS key is not specified, the scheduled query resource will be encrypted with a Timestream owned Amazon KMS key. To specify a KMS key, use the key ID, key ARN, alias name, or alias ARN. When using an alias name, prefix the name with *alias/*

        If ErrorReportConfiguration uses ``SSE_KMS`` as encryption type, the same KmsKeyId is used to encrypt the error report at rest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scheduledQueryName")
    def scheduled_query_name(self) -> typing.Optional[builtins.str]:
        '''A name for the query.

        Scheduled query names must be unique within each Region.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-scheduledqueryname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "scheduledQueryName"))

    @scheduled_query_name.setter
    def scheduled_query_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "scheduledQueryName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetConfiguration")
    def target_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnScheduledQuery.TargetConfigurationProperty", _IResolvable_da3f097b]]:
        '''Scheduled query target store configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-targetconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnScheduledQuery.TargetConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "targetConfiguration"))

    @target_configuration.setter
    def target_configuration(
        self,
        value: typing.Optional[typing.Union["CfnScheduledQuery.TargetConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "targetConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.DimensionMappingProperty",
        jsii_struct_bases=[],
        name_mapping={"dimension_value_type": "dimensionValueType", "name": "name"},
    )
    class DimensionMappingProperty:
        def __init__(
            self,
            *,
            dimension_value_type: builtins.str,
            name: builtins.str,
        ) -> None:
            '''This type is used to map column(s) from the query result to a dimension in the destination table.

            :param dimension_value_type: Type for the dimension.
            :param name: Column name from query result.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-dimensionmapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                dimension_mapping_property = timestream.CfnScheduledQuery.DimensionMappingProperty(
                    dimension_value_type="dimensionValueType",
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "dimension_value_type": dimension_value_type,
                "name": name,
            }

        @builtins.property
        def dimension_value_type(self) -> builtins.str:
            '''Type for the dimension.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-dimensionmapping.html#cfn-timestream-scheduledquery-dimensionmapping-dimensionvaluetype
            '''
            result = self._values.get("dimension_value_type")
            assert result is not None, "Required property 'dimension_value_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def name(self) -> builtins.str:
            '''Column name from query result.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-dimensionmapping.html#cfn-timestream-scheduledquery-dimensionmapping-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DimensionMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.ErrorReportConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"s3_configuration": "s3Configuration"},
    )
    class ErrorReportConfigurationProperty:
        def __init__(
            self,
            *,
            s3_configuration: typing.Union["CfnScheduledQuery.S3ConfigurationProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Configuration required for error reporting.

            :param s3_configuration: The S3 configuration for the error reports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-errorreportconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                error_report_configuration_property = timestream.CfnScheduledQuery.ErrorReportConfigurationProperty(
                    s3_configuration=timestream.CfnScheduledQuery.S3ConfigurationProperty(
                        bucket_name="bucketName",
                
                        # the properties below are optional
                        encryption_option="encryptionOption",
                        object_key_prefix="objectKeyPrefix"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "s3_configuration": s3_configuration,
            }

        @builtins.property
        def s3_configuration(
            self,
        ) -> typing.Union["CfnScheduledQuery.S3ConfigurationProperty", _IResolvable_da3f097b]:
            '''The S3 configuration for the error reports.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-errorreportconfiguration.html#cfn-timestream-scheduledquery-errorreportconfiguration-s3configuration
            '''
            result = self._values.get("s3_configuration")
            assert result is not None, "Required property 's3_configuration' is missing"
            return typing.cast(typing.Union["CfnScheduledQuery.S3ConfigurationProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ErrorReportConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.MixedMeasureMappingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "measure_value_type": "measureValueType",
            "measure_name": "measureName",
            "multi_measure_attribute_mappings": "multiMeasureAttributeMappings",
            "source_column": "sourceColumn",
            "target_measure_name": "targetMeasureName",
        },
    )
    class MixedMeasureMappingProperty:
        def __init__(
            self,
            *,
            measure_value_type: builtins.str,
            measure_name: typing.Optional[builtins.str] = None,
            multi_measure_attribute_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnScheduledQuery.MultiMeasureAttributeMappingProperty", _IResolvable_da3f097b]]]] = None,
            source_column: typing.Optional[builtins.str] = None,
            target_measure_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''MixedMeasureMappings are mappings that can be used to ingest data into a mixture of narrow and multi measures in the derived table.

            :param measure_value_type: Type of the value that is to be read from sourceColumn. If the mapping is for MULTI, use MeasureValueType.MULTI.
            :param measure_name: Refers to the value of measure_name in a result row. This field is required if MeasureNameColumn is provided.
            :param multi_measure_attribute_mappings: Required when measureValueType is MULTI. Attribute mappings for MULTI value measures.
            :param source_column: This field refers to the source column from which measure-value is to be read for result materialization.
            :param target_measure_name: Target measure name to be used. If not provided, the target measure name by default would be measure-name if provided, or sourceColumn otherwise.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-mixedmeasuremapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                mixed_measure_mapping_property = timestream.CfnScheduledQuery.MixedMeasureMappingProperty(
                    measure_value_type="measureValueType",
                
                    # the properties below are optional
                    measure_name="measureName",
                    multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                        measure_value_type="measureValueType",
                        source_column="sourceColumn",
                
                        # the properties below are optional
                        target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                    )],
                    source_column="sourceColumn",
                    target_measure_name="targetMeasureName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "measure_value_type": measure_value_type,
            }
            if measure_name is not None:
                self._values["measure_name"] = measure_name
            if multi_measure_attribute_mappings is not None:
                self._values["multi_measure_attribute_mappings"] = multi_measure_attribute_mappings
            if source_column is not None:
                self._values["source_column"] = source_column
            if target_measure_name is not None:
                self._values["target_measure_name"] = target_measure_name

        @builtins.property
        def measure_value_type(self) -> builtins.str:
            '''Type of the value that is to be read from sourceColumn.

            If the mapping is for MULTI, use MeasureValueType.MULTI.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-mixedmeasuremapping.html#cfn-timestream-scheduledquery-mixedmeasuremapping-measurevaluetype
            '''
            result = self._values.get("measure_value_type")
            assert result is not None, "Required property 'measure_value_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def measure_name(self) -> typing.Optional[builtins.str]:
            '''Refers to the value of measure_name in a result row.

            This field is required if MeasureNameColumn is provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-mixedmeasuremapping.html#cfn-timestream-scheduledquery-mixedmeasuremapping-measurename
            '''
            result = self._values.get("measure_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def multi_measure_attribute_mappings(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScheduledQuery.MultiMeasureAttributeMappingProperty", _IResolvable_da3f097b]]]]:
            '''Required when measureValueType is MULTI.

            Attribute mappings for MULTI value measures.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-mixedmeasuremapping.html#cfn-timestream-scheduledquery-mixedmeasuremapping-multimeasureattributemappings
            '''
            result = self._values.get("multi_measure_attribute_mappings")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScheduledQuery.MultiMeasureAttributeMappingProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def source_column(self) -> typing.Optional[builtins.str]:
            '''This field refers to the source column from which measure-value is to be read for result materialization.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-mixedmeasuremapping.html#cfn-timestream-scheduledquery-mixedmeasuremapping-sourcecolumn
            '''
            result = self._values.get("source_column")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def target_measure_name(self) -> typing.Optional[builtins.str]:
            '''Target measure name to be used.

            If not provided, the target measure name by default would be measure-name if provided, or sourceColumn otherwise.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-mixedmeasuremapping.html#cfn-timestream-scheduledquery-mixedmeasuremapping-targetmeasurename
            '''
            result = self._values.get("target_measure_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MixedMeasureMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "measure_value_type": "measureValueType",
            "source_column": "sourceColumn",
            "target_multi_measure_attribute_name": "targetMultiMeasureAttributeName",
        },
    )
    class MultiMeasureAttributeMappingProperty:
        def __init__(
            self,
            *,
            measure_value_type: builtins.str,
            source_column: builtins.str,
            target_multi_measure_attribute_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Attribute mapping for MULTI value measures.

            :param measure_value_type: Type of the attribute to be read from the source column.
            :param source_column: Source column from where the attribute value is to be read.
            :param target_multi_measure_attribute_name: Custom name to be used for attribute name in derived table. If not provided, source column name would be used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-multimeasureattributemapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                multi_measure_attribute_mapping_property = timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                    measure_value_type="measureValueType",
                    source_column="sourceColumn",
                
                    # the properties below are optional
                    target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "measure_value_type": measure_value_type,
                "source_column": source_column,
            }
            if target_multi_measure_attribute_name is not None:
                self._values["target_multi_measure_attribute_name"] = target_multi_measure_attribute_name

        @builtins.property
        def measure_value_type(self) -> builtins.str:
            '''Type of the attribute to be read from the source column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-multimeasureattributemapping.html#cfn-timestream-scheduledquery-multimeasureattributemapping-measurevaluetype
            '''
            result = self._values.get("measure_value_type")
            assert result is not None, "Required property 'measure_value_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source_column(self) -> builtins.str:
            '''Source column from where the attribute value is to be read.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-multimeasureattributemapping.html#cfn-timestream-scheduledquery-multimeasureattributemapping-sourcecolumn
            '''
            result = self._values.get("source_column")
            assert result is not None, "Required property 'source_column' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def target_multi_measure_attribute_name(self) -> typing.Optional[builtins.str]:
            '''Custom name to be used for attribute name in derived table.

            If not provided, source column name would be used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-multimeasureattributemapping.html#cfn-timestream-scheduledquery-multimeasureattributemapping-targetmultimeasureattributename
            '''
            result = self._values.get("target_multi_measure_attribute_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MultiMeasureAttributeMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.MultiMeasureMappingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "multi_measure_attribute_mappings": "multiMeasureAttributeMappings",
            "target_multi_measure_name": "targetMultiMeasureName",
        },
    )
    class MultiMeasureMappingsProperty:
        def __init__(
            self,
            *,
            multi_measure_attribute_mappings: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnScheduledQuery.MultiMeasureAttributeMappingProperty", _IResolvable_da3f097b]]],
            target_multi_measure_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Only one of MixedMeasureMappings or MultiMeasureMappings is to be provided.

            MultiMeasureMappings can be used to ingest data as multi measures in the derived table.

            :param multi_measure_attribute_mappings: Required. Attribute mappings to be used for mapping query results to ingest data for multi-measure attributes.
            :param target_multi_measure_name: The name of the target multi-measure name in the derived table. This input is required when measureNameColumn is not provided. If MeasureNameColumn is provided, then value from that column will be used as multi-measure name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-multimeasuremappings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                multi_measure_mappings_property = timestream.CfnScheduledQuery.MultiMeasureMappingsProperty(
                    multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                        measure_value_type="measureValueType",
                        source_column="sourceColumn",
                
                        # the properties below are optional
                        target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                    )],
                
                    # the properties below are optional
                    target_multi_measure_name="targetMultiMeasureName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "multi_measure_attribute_mappings": multi_measure_attribute_mappings,
            }
            if target_multi_measure_name is not None:
                self._values["target_multi_measure_name"] = target_multi_measure_name

        @builtins.property
        def multi_measure_attribute_mappings(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScheduledQuery.MultiMeasureAttributeMappingProperty", _IResolvable_da3f097b]]]:
            '''Required.

            Attribute mappings to be used for mapping query results to ingest data for multi-measure attributes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-multimeasuremappings.html#cfn-timestream-scheduledquery-multimeasuremappings-multimeasureattributemappings
            '''
            result = self._values.get("multi_measure_attribute_mappings")
            assert result is not None, "Required property 'multi_measure_attribute_mappings' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScheduledQuery.MultiMeasureAttributeMappingProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def target_multi_measure_name(self) -> typing.Optional[builtins.str]:
            '''The name of the target multi-measure name in the derived table.

            This input is required when measureNameColumn is not provided. If MeasureNameColumn is provided, then value from that column will be used as multi-measure name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-multimeasuremappings.html#cfn-timestream-scheduledquery-multimeasuremappings-targetmultimeasurename
            '''
            result = self._values.get("target_multi_measure_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MultiMeasureMappingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.NotificationConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"sns_configuration": "snsConfiguration"},
    )
    class NotificationConfigurationProperty:
        def __init__(
            self,
            *,
            sns_configuration: typing.Union["CfnScheduledQuery.SnsConfigurationProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Notification configuration for a scheduled query.

            A notification is sent by Timestream when a scheduled query is created, its state is updated or when it is deleted.

            :param sns_configuration: Details on SNS configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-notificationconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                notification_configuration_property = timestream.CfnScheduledQuery.NotificationConfigurationProperty(
                    sns_configuration=timestream.CfnScheduledQuery.SnsConfigurationProperty(
                        topic_arn="topicArn"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "sns_configuration": sns_configuration,
            }

        @builtins.property
        def sns_configuration(
            self,
        ) -> typing.Union["CfnScheduledQuery.SnsConfigurationProperty", _IResolvable_da3f097b]:
            '''Details on SNS configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-notificationconfiguration.html#cfn-timestream-scheduledquery-notificationconfiguration-snsconfiguration
            '''
            result = self._values.get("sns_configuration")
            assert result is not None, "Required property 'sns_configuration' is missing"
            return typing.cast(typing.Union["CfnScheduledQuery.SnsConfigurationProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotificationConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.S3ConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_name": "bucketName",
            "encryption_option": "encryptionOption",
            "object_key_prefix": "objectKeyPrefix",
        },
    )
    class S3ConfigurationProperty:
        def __init__(
            self,
            *,
            bucket_name: builtins.str,
            encryption_option: typing.Optional[builtins.str] = None,
            object_key_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Details on S3 location for error reports that result from running a query.

            :param bucket_name: Name of the S3 bucket under which error reports will be created.
            :param encryption_option: Encryption at rest options for the error reports. If no encryption option is specified, Timestream will choose SSE_S3 as default.
            :param object_key_prefix: Prefix for the error report key. Timestream by default adds the following prefix to the error report path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-s3configuration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                s3_configuration_property = timestream.CfnScheduledQuery.S3ConfigurationProperty(
                    bucket_name="bucketName",
                
                    # the properties below are optional
                    encryption_option="encryptionOption",
                    object_key_prefix="objectKeyPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_name": bucket_name,
            }
            if encryption_option is not None:
                self._values["encryption_option"] = encryption_option
            if object_key_prefix is not None:
                self._values["object_key_prefix"] = object_key_prefix

        @builtins.property
        def bucket_name(self) -> builtins.str:
            '''Name of the S3 bucket under which error reports will be created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-s3configuration.html#cfn-timestream-scheduledquery-s3configuration-bucketname
            '''
            result = self._values.get("bucket_name")
            assert result is not None, "Required property 'bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def encryption_option(self) -> typing.Optional[builtins.str]:
            '''Encryption at rest options for the error reports.

            If no encryption option is specified, Timestream will choose SSE_S3 as default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-s3configuration.html#cfn-timestream-scheduledquery-s3configuration-encryptionoption
            '''
            result = self._values.get("encryption_option")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def object_key_prefix(self) -> typing.Optional[builtins.str]:
            '''Prefix for the error report key.

            Timestream by default adds the following prefix to the error report path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-s3configuration.html#cfn-timestream-scheduledquery-s3configuration-objectkeyprefix
            '''
            result = self._values.get("object_key_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3ConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.ScheduleConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"schedule_expression": "scheduleExpression"},
    )
    class ScheduleConfigurationProperty:
        def __init__(self, *, schedule_expression: builtins.str) -> None:
            '''Configuration of the schedule of the query.

            :param schedule_expression: An expression that denotes when to trigger the scheduled query run. This can be a cron expression or a rate expression.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-scheduleconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                schedule_configuration_property = timestream.CfnScheduledQuery.ScheduleConfigurationProperty(
                    schedule_expression="scheduleExpression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "schedule_expression": schedule_expression,
            }

        @builtins.property
        def schedule_expression(self) -> builtins.str:
            '''An expression that denotes when to trigger the scheduled query run.

            This can be a cron expression or a rate expression.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-scheduleconfiguration.html#cfn-timestream-scheduledquery-scheduleconfiguration-scheduleexpression
            '''
            result = self._values.get("schedule_expression")
            assert result is not None, "Required property 'schedule_expression' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScheduleConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.SnsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"topic_arn": "topicArn"},
    )
    class SnsConfigurationProperty:
        def __init__(self, *, topic_arn: builtins.str) -> None:
            '''Details on SNS that are required to send the notification.

            :param topic_arn: SNS topic ARN that the scheduled query status notifications will be sent to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-snsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                sns_configuration_property = timestream.CfnScheduledQuery.SnsConfigurationProperty(
                    topic_arn="topicArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "topic_arn": topic_arn,
            }

        @builtins.property
        def topic_arn(self) -> builtins.str:
            '''SNS topic ARN that the scheduled query status notifications will be sent to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-snsconfiguration.html#cfn-timestream-scheduledquery-snsconfiguration-topicarn
            '''
            result = self._values.get("topic_arn")
            assert result is not None, "Required property 'topic_arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SnsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.TargetConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"timestream_configuration": "timestreamConfiguration"},
    )
    class TargetConfigurationProperty:
        def __init__(
            self,
            *,
            timestream_configuration: typing.Union["CfnScheduledQuery.TimestreamConfigurationProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Configuration used for writing the output of a query.

            :param timestream_configuration: Configuration needed to write data into the Timestream database and table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-targetconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                target_configuration_property = timestream.CfnScheduledQuery.TargetConfigurationProperty(
                    timestream_configuration=timestream.CfnScheduledQuery.TimestreamConfigurationProperty(
                        database_name="databaseName",
                        dimension_mappings=[timestream.CfnScheduledQuery.DimensionMappingProperty(
                            dimension_value_type="dimensionValueType",
                            name="name"
                        )],
                        table_name="tableName",
                        time_column="timeColumn",
                
                        # the properties below are optional
                        measure_name_column="measureNameColumn",
                        mixed_measure_mappings=[timestream.CfnScheduledQuery.MixedMeasureMappingProperty(
                            measure_value_type="measureValueType",
                
                            # the properties below are optional
                            measure_name="measureName",
                            multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                                measure_value_type="measureValueType",
                                source_column="sourceColumn",
                
                                # the properties below are optional
                                target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                            )],
                            source_column="sourceColumn",
                            target_measure_name="targetMeasureName"
                        )],
                        multi_measure_mappings=timestream.CfnScheduledQuery.MultiMeasureMappingsProperty(
                            multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                                measure_value_type="measureValueType",
                                source_column="sourceColumn",
                
                                # the properties below are optional
                                target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                            )],
                
                            # the properties below are optional
                            target_multi_measure_name="targetMultiMeasureName"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "timestream_configuration": timestream_configuration,
            }

        @builtins.property
        def timestream_configuration(
            self,
        ) -> typing.Union["CfnScheduledQuery.TimestreamConfigurationProperty", _IResolvable_da3f097b]:
            '''Configuration needed to write data into the Timestream database and table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-targetconfiguration.html#cfn-timestream-scheduledquery-targetconfiguration-timestreamconfiguration
            '''
            result = self._values.get("timestream_configuration")
            assert result is not None, "Required property 'timestream_configuration' is missing"
            return typing.cast(typing.Union["CfnScheduledQuery.TimestreamConfigurationProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQuery.TimestreamConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "database_name": "databaseName",
            "dimension_mappings": "dimensionMappings",
            "table_name": "tableName",
            "time_column": "timeColumn",
            "measure_name_column": "measureNameColumn",
            "mixed_measure_mappings": "mixedMeasureMappings",
            "multi_measure_mappings": "multiMeasureMappings",
        },
    )
    class TimestreamConfigurationProperty:
        def __init__(
            self,
            *,
            database_name: builtins.str,
            dimension_mappings: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnScheduledQuery.DimensionMappingProperty", _IResolvable_da3f097b]]],
            table_name: builtins.str,
            time_column: builtins.str,
            measure_name_column: typing.Optional[builtins.str] = None,
            mixed_measure_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnScheduledQuery.MixedMeasureMappingProperty", _IResolvable_da3f097b]]]] = None,
            multi_measure_mappings: typing.Optional[typing.Union["CfnScheduledQuery.MultiMeasureMappingsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Configuration to write data into Timestream database and table.

            This configuration allows the user to map the query result select columns into the destination table columns.

            :param database_name: Name of Timestream database to which the query result will be written.
            :param dimension_mappings: This is to allow mapping column(s) from the query result to the dimension in the destination table.
            :param table_name: Name of Timestream table that the query result will be written to. The table should be within the same database that is provided in Timestream configuration.
            :param time_column: Column from query result that should be used as the time column in destination table. Column type for this should be TIMESTAMP.
            :param measure_name_column: Name of the measure column.
            :param mixed_measure_mappings: Specifies how to map measures to multi-measure records.
            :param multi_measure_mappings: Multi-measure mappings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-timestreamconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_timestream as timestream
                
                timestream_configuration_property = timestream.CfnScheduledQuery.TimestreamConfigurationProperty(
                    database_name="databaseName",
                    dimension_mappings=[timestream.CfnScheduledQuery.DimensionMappingProperty(
                        dimension_value_type="dimensionValueType",
                        name="name"
                    )],
                    table_name="tableName",
                    time_column="timeColumn",
                
                    # the properties below are optional
                    measure_name_column="measureNameColumn",
                    mixed_measure_mappings=[timestream.CfnScheduledQuery.MixedMeasureMappingProperty(
                        measure_value_type="measureValueType",
                
                        # the properties below are optional
                        measure_name="measureName",
                        multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                            measure_value_type="measureValueType",
                            source_column="sourceColumn",
                
                            # the properties below are optional
                            target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                        )],
                        source_column="sourceColumn",
                        target_measure_name="targetMeasureName"
                    )],
                    multi_measure_mappings=timestream.CfnScheduledQuery.MultiMeasureMappingsProperty(
                        multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                            measure_value_type="measureValueType",
                            source_column="sourceColumn",
                
                            # the properties below are optional
                            target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                        )],
                
                        # the properties below are optional
                        target_multi_measure_name="targetMultiMeasureName"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database_name": database_name,
                "dimension_mappings": dimension_mappings,
                "table_name": table_name,
                "time_column": time_column,
            }
            if measure_name_column is not None:
                self._values["measure_name_column"] = measure_name_column
            if mixed_measure_mappings is not None:
                self._values["mixed_measure_mappings"] = mixed_measure_mappings
            if multi_measure_mappings is not None:
                self._values["multi_measure_mappings"] = multi_measure_mappings

        @builtins.property
        def database_name(self) -> builtins.str:
            '''Name of Timestream database to which the query result will be written.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-timestreamconfiguration.html#cfn-timestream-scheduledquery-timestreamconfiguration-databasename
            '''
            result = self._values.get("database_name")
            assert result is not None, "Required property 'database_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def dimension_mappings(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScheduledQuery.DimensionMappingProperty", _IResolvable_da3f097b]]]:
            '''This is to allow mapping column(s) from the query result to the dimension in the destination table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-timestreamconfiguration.html#cfn-timestream-scheduledquery-timestreamconfiguration-dimensionmappings
            '''
            result = self._values.get("dimension_mappings")
            assert result is not None, "Required property 'dimension_mappings' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScheduledQuery.DimensionMappingProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def table_name(self) -> builtins.str:
            '''Name of Timestream table that the query result will be written to.

            The table should be within the same database that is provided in Timestream configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-timestreamconfiguration.html#cfn-timestream-scheduledquery-timestreamconfiguration-tablename
            '''
            result = self._values.get("table_name")
            assert result is not None, "Required property 'table_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def time_column(self) -> builtins.str:
            '''Column from query result that should be used as the time column in destination table.

            Column type for this should be TIMESTAMP.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-timestreamconfiguration.html#cfn-timestream-scheduledquery-timestreamconfiguration-timecolumn
            '''
            result = self._values.get("time_column")
            assert result is not None, "Required property 'time_column' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def measure_name_column(self) -> typing.Optional[builtins.str]:
            '''Name of the measure column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-timestreamconfiguration.html#cfn-timestream-scheduledquery-timestreamconfiguration-measurenamecolumn
            '''
            result = self._values.get("measure_name_column")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def mixed_measure_mappings(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScheduledQuery.MixedMeasureMappingProperty", _IResolvable_da3f097b]]]]:
            '''Specifies how to map measures to multi-measure records.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-timestreamconfiguration.html#cfn-timestream-scheduledquery-timestreamconfiguration-mixedmeasuremappings
            '''
            result = self._values.get("mixed_measure_mappings")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScheduledQuery.MixedMeasureMappingProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def multi_measure_mappings(
            self,
        ) -> typing.Optional[typing.Union["CfnScheduledQuery.MultiMeasureMappingsProperty", _IResolvable_da3f097b]]:
            '''Multi-measure mappings.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-timestream-scheduledquery-timestreamconfiguration.html#cfn-timestream-scheduledquery-timestreamconfiguration-multimeasuremappings
            '''
            result = self._values.get("multi_measure_mappings")
            return typing.cast(typing.Optional[typing.Union["CfnScheduledQuery.MultiMeasureMappingsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TimestreamConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_timestream.CfnScheduledQueryProps",
    jsii_struct_bases=[],
    name_mapping={
        "error_report_configuration": "errorReportConfiguration",
        "notification_configuration": "notificationConfiguration",
        "query_string": "queryString",
        "schedule_configuration": "scheduleConfiguration",
        "scheduled_query_execution_role_arn": "scheduledQueryExecutionRoleArn",
        "client_token": "clientToken",
        "kms_key_id": "kmsKeyId",
        "scheduled_query_name": "scheduledQueryName",
        "tags": "tags",
        "target_configuration": "targetConfiguration",
    },
)
class CfnScheduledQueryProps:
    def __init__(
        self,
        *,
        error_report_configuration: typing.Union[CfnScheduledQuery.ErrorReportConfigurationProperty, _IResolvable_da3f097b],
        notification_configuration: typing.Union[CfnScheduledQuery.NotificationConfigurationProperty, _IResolvable_da3f097b],
        query_string: builtins.str,
        schedule_configuration: typing.Union[CfnScheduledQuery.ScheduleConfigurationProperty, _IResolvable_da3f097b],
        scheduled_query_execution_role_arn: builtins.str,
        client_token: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        scheduled_query_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        target_configuration: typing.Optional[typing.Union[CfnScheduledQuery.TargetConfigurationProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnScheduledQuery``.

        :param error_report_configuration: Configuration for error reporting. Error reports will be generated when a problem is encountered when writing the query results.
        :param notification_configuration: Notification configuration for the scheduled query. A notification is sent by Timestream when a query run finishes, when the state is updated or when you delete it.
        :param query_string: The query string to run. Parameter names can be specified in the query string ``@`` character followed by an identifier. The named Parameter ``@scheduled_runtime`` is reserved and can be used in the query to get the time at which the query is scheduled to run. The timestamp calculated according to the ScheduleConfiguration parameter, will be the value of ``@scheduled_runtime`` paramater for each query run. For example, consider an instance of a scheduled query executing on 2021-12-01 00:00:00. For this instance, the ``@scheduled_runtime`` parameter is initialized to the timestamp 2021-12-01 00:00:00 when invoking the query.
        :param schedule_configuration: Schedule configuration.
        :param scheduled_query_execution_role_arn: The ARN for the IAM role that Timestream will assume when running the scheduled query.
        :param client_token: Using a ClientToken makes the call to CreateScheduledQuery idempotent, in other words, making the same request repeatedly will produce the same result. Making multiple identical CreateScheduledQuery requests has the same effect as making a single request. - If CreateScheduledQuery is called without a ``ClientToken`` , the Query SDK generates a ``ClientToken`` on your behalf. - After 8 hours, any request with the same ``ClientToken`` is treated as a new request.
        :param kms_key_id: The Amazon KMS key used to encrypt the scheduled query resource, at-rest. If the Amazon KMS key is not specified, the scheduled query resource will be encrypted with a Timestream owned Amazon KMS key. To specify a KMS key, use the key ID, key ARN, alias name, or alias ARN. When using an alias name, prefix the name with *alias/* If ErrorReportConfiguration uses ``SSE_KMS`` as encryption type, the same KmsKeyId is used to encrypt the error report at rest.
        :param scheduled_query_name: A name for the query. Scheduled query names must be unique within each Region.
        :param tags: A list of key-value pairs to label the scheduled query.
        :param target_configuration: Scheduled query target store configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_timestream as timestream
            
            cfn_scheduled_query_props = timestream.CfnScheduledQueryProps(
                error_report_configuration=timestream.CfnScheduledQuery.ErrorReportConfigurationProperty(
                    s3_configuration=timestream.CfnScheduledQuery.S3ConfigurationProperty(
                        bucket_name="bucketName",
            
                        # the properties below are optional
                        encryption_option="encryptionOption",
                        object_key_prefix="objectKeyPrefix"
                    )
                ),
                notification_configuration=timestream.CfnScheduledQuery.NotificationConfigurationProperty(
                    sns_configuration=timestream.CfnScheduledQuery.SnsConfigurationProperty(
                        topic_arn="topicArn"
                    )
                ),
                query_string="queryString",
                schedule_configuration=timestream.CfnScheduledQuery.ScheduleConfigurationProperty(
                    schedule_expression="scheduleExpression"
                ),
                scheduled_query_execution_role_arn="scheduledQueryExecutionRoleArn",
            
                # the properties below are optional
                client_token="clientToken",
                kms_key_id="kmsKeyId",
                scheduled_query_name="scheduledQueryName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                target_configuration=timestream.CfnScheduledQuery.TargetConfigurationProperty(
                    timestream_configuration=timestream.CfnScheduledQuery.TimestreamConfigurationProperty(
                        database_name="databaseName",
                        dimension_mappings=[timestream.CfnScheduledQuery.DimensionMappingProperty(
                            dimension_value_type="dimensionValueType",
                            name="name"
                        )],
                        table_name="tableName",
                        time_column="timeColumn",
            
                        # the properties below are optional
                        measure_name_column="measureNameColumn",
                        mixed_measure_mappings=[timestream.CfnScheduledQuery.MixedMeasureMappingProperty(
                            measure_value_type="measureValueType",
            
                            # the properties below are optional
                            measure_name="measureName",
                            multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                                measure_value_type="measureValueType",
                                source_column="sourceColumn",
            
                                # the properties below are optional
                                target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                            )],
                            source_column="sourceColumn",
                            target_measure_name="targetMeasureName"
                        )],
                        multi_measure_mappings=timestream.CfnScheduledQuery.MultiMeasureMappingsProperty(
                            multi_measure_attribute_mappings=[timestream.CfnScheduledQuery.MultiMeasureAttributeMappingProperty(
                                measure_value_type="measureValueType",
                                source_column="sourceColumn",
            
                                # the properties below are optional
                                target_multi_measure_attribute_name="targetMultiMeasureAttributeName"
                            )],
            
                            # the properties below are optional
                            target_multi_measure_name="targetMultiMeasureName"
                        )
                    )
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "error_report_configuration": error_report_configuration,
            "notification_configuration": notification_configuration,
            "query_string": query_string,
            "schedule_configuration": schedule_configuration,
            "scheduled_query_execution_role_arn": scheduled_query_execution_role_arn,
        }
        if client_token is not None:
            self._values["client_token"] = client_token
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if scheduled_query_name is not None:
            self._values["scheduled_query_name"] = scheduled_query_name
        if tags is not None:
            self._values["tags"] = tags
        if target_configuration is not None:
            self._values["target_configuration"] = target_configuration

    @builtins.property
    def error_report_configuration(
        self,
    ) -> typing.Union[CfnScheduledQuery.ErrorReportConfigurationProperty, _IResolvable_da3f097b]:
        '''Configuration for error reporting.

        Error reports will be generated when a problem is encountered when writing the query results.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-errorreportconfiguration
        '''
        result = self._values.get("error_report_configuration")
        assert result is not None, "Required property 'error_report_configuration' is missing"
        return typing.cast(typing.Union[CfnScheduledQuery.ErrorReportConfigurationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def notification_configuration(
        self,
    ) -> typing.Union[CfnScheduledQuery.NotificationConfigurationProperty, _IResolvable_da3f097b]:
        '''Notification configuration for the scheduled query.

        A notification is sent by Timestream when a query run finishes, when the state is updated or when you delete it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-notificationconfiguration
        '''
        result = self._values.get("notification_configuration")
        assert result is not None, "Required property 'notification_configuration' is missing"
        return typing.cast(typing.Union[CfnScheduledQuery.NotificationConfigurationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def query_string(self) -> builtins.str:
        '''The query string to run.

        Parameter names can be specified in the query string ``@`` character followed by an identifier. The named Parameter ``@scheduled_runtime`` is reserved and can be used in the query to get the time at which the query is scheduled to run.

        The timestamp calculated according to the ScheduleConfiguration parameter, will be the value of ``@scheduled_runtime`` paramater for each query run. For example, consider an instance of a scheduled query executing on 2021-12-01 00:00:00. For this instance, the ``@scheduled_runtime`` parameter is initialized to the timestamp 2021-12-01 00:00:00 when invoking the query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-querystring
        '''
        result = self._values.get("query_string")
        assert result is not None, "Required property 'query_string' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def schedule_configuration(
        self,
    ) -> typing.Union[CfnScheduledQuery.ScheduleConfigurationProperty, _IResolvable_da3f097b]:
        '''Schedule configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-scheduleconfiguration
        '''
        result = self._values.get("schedule_configuration")
        assert result is not None, "Required property 'schedule_configuration' is missing"
        return typing.cast(typing.Union[CfnScheduledQuery.ScheduleConfigurationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def scheduled_query_execution_role_arn(self) -> builtins.str:
        '''The ARN for the IAM role that Timestream will assume when running the scheduled query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-scheduledqueryexecutionrolearn
        '''
        result = self._values.get("scheduled_query_execution_role_arn")
        assert result is not None, "Required property 'scheduled_query_execution_role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_token(self) -> typing.Optional[builtins.str]:
        '''Using a ClientToken makes the call to CreateScheduledQuery idempotent, in other words, making the same request repeatedly will produce the same result.

        Making multiple identical CreateScheduledQuery requests has the same effect as making a single request.

        - If CreateScheduledQuery is called without a ``ClientToken`` , the Query SDK generates a ``ClientToken`` on your behalf.
        - After 8 hours, any request with the same ``ClientToken`` is treated as a new request.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-clienttoken
        '''
        result = self._values.get("client_token")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The Amazon KMS key used to encrypt the scheduled query resource, at-rest.

        If the Amazon KMS key is not specified, the scheduled query resource will be encrypted with a Timestream owned Amazon KMS key. To specify a KMS key, use the key ID, key ARN, alias name, or alias ARN. When using an alias name, prefix the name with *alias/*

        If ErrorReportConfiguration uses ``SSE_KMS`` as encryption type, the same KmsKeyId is used to encrypt the error report at rest.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def scheduled_query_name(self) -> typing.Optional[builtins.str]:
        '''A name for the query.

        Scheduled query names must be unique within each Region.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-scheduledqueryname
        '''
        result = self._values.get("scheduled_query_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of key-value pairs to label the scheduled query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def target_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnScheduledQuery.TargetConfigurationProperty, _IResolvable_da3f097b]]:
        '''Scheduled query target store configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-scheduledquery.html#cfn-timestream-scheduledquery-targetconfiguration
        '''
        result = self._values.get("target_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnScheduledQuery.TargetConfigurationProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnScheduledQueryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTable(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_timestream.CfnTable",
):
    '''A CloudFormation ``AWS::Timestream::Table``.

    The CreateTable operation adds a new table to an existing database in your account. In an AWS account, table names must be at least unique within each Region if they are in the same database. You may have identical table names in the same Region if the tables are in separate databases. While creating the table, you must specify the table name, database name, and the retention properties. `Service quotas apply <https://docs.aws.amazon.com/timestream/latest/developerguide/ts-limits.html>`_ . See `code sample <https://docs.aws.amazon.com/timestream/latest/developerguide/code-samples.create-table.html>`_ for details.

    :cloudformationResource: AWS::Timestream::Table
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_timestream as timestream
        
        # magnetic_store_write_properties: Any
        # retention_properties: Any
        
        cfn_table = timestream.CfnTable(self, "MyCfnTable",
            database_name="databaseName",
        
            # the properties below are optional
            magnetic_store_write_properties=magnetic_store_write_properties,
            retention_properties=retention_properties,
            table_name="tableName",
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
        database_name: builtins.str,
        magnetic_store_write_properties: typing.Any = None,
        retention_properties: typing.Any = None,
        table_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Timestream::Table``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param database_name: The name of the Timestream database that contains this table. *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.
        :param magnetic_store_write_properties: Contains properties to set on the table when enabling magnetic store writes. This object has the following attributes: - *EnableMagneticStoreWrites* : A ``boolean`` flag to enable magnetic store writes. - *MagneticStoreRejectedDataLocation* : The location to write error reports for records rejected, asynchronously, during magnetic store writes. Only ``S3Configuration`` objects are allowed. The ``S3Configuration`` object has the following attributes: - *BucketName* : The name of the S3 bucket. - *EncryptionOption* : The encryption option for the S3 location. Valid values are S3 server-side encryption with an S3 managed key ( ``SSE_S3`` ) or AWS managed key ( ``SSE_KMS`` ). - *KmsKeyId* : The AWS KMS key ID to use when encrypting with an AWS managed key. - *ObjectKeyPrefix* : The prefix to use option for the objects stored in S3. Both ``BucketName`` and ``EncryptionOption`` are *required* when ``S3Configuration`` is specified. If you specify ``SSE_KMS`` as your ``EncryptionOption`` then ``KmsKeyId`` is *required* . ``EnableMagneticStoreWrites`` attribute is *required* when ``MagneticStoreWriteProperties`` is specified. ``MagneticStoreRejectedDataLocation`` attribute is *required* when ``EnableMagneticStoreWrites`` is set to ``true`` . See the following examples: *JSON:: { "Type" : AWS::Timestream::Table", "Properties":{ "DatabaseName":"TestDatabase", "TableName":"TestTable", "MagneticStoreWriteProperties":{ "EnableMagneticStoreWrites":true, "MagneticStoreRejectedDataLocation":{ "S3Configuration":{ "BucketName":"testbucket", "EncryptionOption":"SSE_KMS", "KmsKeyId":"1234abcd-12ab-34cd-56ef-1234567890ab", "ObjectKeyPrefix":"prefix" } } } } } *YAML:: Type: AWS::Timestream::Table DependsOn: TestDatabase Properties: TableName: "TestTable" DatabaseName: "TestDatabase" MagneticStoreWriteProperties: EnableMagneticStoreWrites: true MagneticStoreRejectedDataLocation: S3Configuration: BucketName: "testbucket" EncryptionOption: "SSE_KMS" BucketName: "1234abcd-12ab-34cd-56ef-1234567890ab" EncryptionOption: "prefix"
        :param retention_properties: The retention duration for the memory store and magnetic store. This object has the following attributes:. - *MemoryStoreRetentionPeriodInHours* : Retention duration for memory store, in hours. - *MagneticStoreRetentionPeriodInDays* : Retention duration for magnetic store, in days. Both attributes are of type ``string`` . Both attributes are *required* when ``RetentionProperties`` is specified. See the following examples: *JSON* ``{ "Type" : AWS::Timestream::Table", "Properties" : { "DatabaseName" : "TestDatabase", "TableName" : "TestTable", "RetentionProperties" : { "MemoryStoreRetentionPeriodInHours": "24", "MagneticStoreRetentionPeriodInDays": "7" } } }`` *YAML:: Type: AWS::Timestream::Table DependsOn: TestDatabase Properties: TableName: "TestTable" DatabaseName: "TestDatabase" RetentionProperties: MemoryStoreRetentionPeriodInHours: "24" MagneticStoreRetentionPeriodInDays: "7"
        :param table_name: The name of the Timestream table. *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.
        :param tags: The tags to add to the table.
        '''
        props = CfnTableProps(
            database_name=database_name,
            magnetic_store_write_properties=magnetic_store_write_properties,
            retention_properties=retention_properties,
            table_name=table_name,
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
        '''The ``arn`` of the table.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the table.

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
        '''The tags to add to the table.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="databaseName")
    def database_name(self) -> builtins.str:
        '''The name of the Timestream database that contains this table.

        *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-databasename
        '''
        return typing.cast(builtins.str, jsii.get(self, "databaseName"))

    @database_name.setter
    def database_name(self, value: builtins.str) -> None:
        jsii.set(self, "databaseName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="magneticStoreWriteProperties")
    def magnetic_store_write_properties(self) -> typing.Any:
        '''Contains properties to set on the table when enabling magnetic store writes.

        This object has the following attributes:

        - *EnableMagneticStoreWrites* : A ``boolean`` flag to enable magnetic store writes.
        - *MagneticStoreRejectedDataLocation* : The location to write error reports for records rejected, asynchronously, during magnetic store writes. Only ``S3Configuration`` objects are allowed. The ``S3Configuration`` object has the following attributes:
        - *BucketName* : The name of the S3 bucket.
        - *EncryptionOption* : The encryption option for the S3 location. Valid values are S3 server-side encryption with an S3 managed key ( ``SSE_S3`` ) or AWS managed key ( ``SSE_KMS`` ).
        - *KmsKeyId* : The AWS KMS key ID to use when encrypting with an AWS managed key.
        - *ObjectKeyPrefix* : The prefix to use option for the objects stored in S3.

        Both ``BucketName`` and ``EncryptionOption`` are *required* when ``S3Configuration`` is specified. If you specify ``SSE_KMS`` as your ``EncryptionOption`` then ``KmsKeyId`` is *required* .

        ``EnableMagneticStoreWrites`` attribute is *required* when ``MagneticStoreWriteProperties`` is specified. ``MagneticStoreRejectedDataLocation`` attribute is *required* when ``EnableMagneticStoreWrites`` is set to ``true`` .

        See the following examples:

        *JSON::

           { "Type" : AWS::Timestream::Table", "Properties":{ "DatabaseName":"TestDatabase", "TableName":"TestTable", "MagneticStoreWriteProperties":{ "EnableMagneticStoreWrites":true, "MagneticStoreRejectedDataLocation":{ "S3Configuration":{ "BucketName":"testbucket", "EncryptionOption":"SSE_KMS", "KmsKeyId":"1234abcd-12ab-34cd-56ef-1234567890ab", "ObjectKeyPrefix":"prefix" } } } }
           }

        *YAML::

           Type: AWS::Timestream::Table
           DependsOn: TestDatabase
           Properties: TableName: "TestTable" DatabaseName: "TestDatabase" MagneticStoreWriteProperties: EnableMagneticStoreWrites: true MagneticStoreRejectedDataLocation: S3Configuration: BucketName: "testbucket" EncryptionOption: "SSE_KMS" BucketName: "1234abcd-12ab-34cd-56ef-1234567890ab" EncryptionOption: "prefix"

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-magneticstorewriteproperties
        '''
        return typing.cast(typing.Any, jsii.get(self, "magneticStoreWriteProperties"))

    @magnetic_store_write_properties.setter
    def magnetic_store_write_properties(self, value: typing.Any) -> None:
        jsii.set(self, "magneticStoreWriteProperties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="retentionProperties")
    def retention_properties(self) -> typing.Any:
        '''The retention duration for the memory store and magnetic store. This object has the following attributes:.

        - *MemoryStoreRetentionPeriodInHours* : Retention duration for memory store, in hours.
        - *MagneticStoreRetentionPeriodInDays* : Retention duration for magnetic store, in days.

        Both attributes are of type ``string`` . Both attributes are *required* when ``RetentionProperties`` is specified.

        See the following examples:

        *JSON*

        ``{ "Type" : AWS::Timestream::Table", "Properties" : { "DatabaseName" : "TestDatabase", "TableName" : "TestTable", "RetentionProperties" : { "MemoryStoreRetentionPeriodInHours": "24", "MagneticStoreRetentionPeriodInDays": "7" } } }``

        *YAML::

           Type: AWS::Timestream::Table
           DependsOn: TestDatabase
           Properties: TableName: "TestTable" DatabaseName: "TestDatabase" RetentionProperties: MemoryStoreRetentionPeriodInHours: "24" MagneticStoreRetentionPeriodInDays: "7"

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-retentionproperties
        '''
        return typing.cast(typing.Any, jsii.get(self, "retentionProperties"))

    @retention_properties.setter
    def retention_properties(self, value: typing.Any) -> None:
        jsii.set(self, "retentionProperties", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tableName")
    def table_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Timestream table.

        *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-tablename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "tableName"))

    @table_name.setter
    def table_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "tableName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_timestream.CfnTableProps",
    jsii_struct_bases=[],
    name_mapping={
        "database_name": "databaseName",
        "magnetic_store_write_properties": "magneticStoreWriteProperties",
        "retention_properties": "retentionProperties",
        "table_name": "tableName",
        "tags": "tags",
    },
)
class CfnTableProps:
    def __init__(
        self,
        *,
        database_name: builtins.str,
        magnetic_store_write_properties: typing.Any = None,
        retention_properties: typing.Any = None,
        table_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnTable``.

        :param database_name: The name of the Timestream database that contains this table. *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.
        :param magnetic_store_write_properties: Contains properties to set on the table when enabling magnetic store writes. This object has the following attributes: - *EnableMagneticStoreWrites* : A ``boolean`` flag to enable magnetic store writes. - *MagneticStoreRejectedDataLocation* : The location to write error reports for records rejected, asynchronously, during magnetic store writes. Only ``S3Configuration`` objects are allowed. The ``S3Configuration`` object has the following attributes: - *BucketName* : The name of the S3 bucket. - *EncryptionOption* : The encryption option for the S3 location. Valid values are S3 server-side encryption with an S3 managed key ( ``SSE_S3`` ) or AWS managed key ( ``SSE_KMS`` ). - *KmsKeyId* : The AWS KMS key ID to use when encrypting with an AWS managed key. - *ObjectKeyPrefix* : The prefix to use option for the objects stored in S3. Both ``BucketName`` and ``EncryptionOption`` are *required* when ``S3Configuration`` is specified. If you specify ``SSE_KMS`` as your ``EncryptionOption`` then ``KmsKeyId`` is *required* . ``EnableMagneticStoreWrites`` attribute is *required* when ``MagneticStoreWriteProperties`` is specified. ``MagneticStoreRejectedDataLocation`` attribute is *required* when ``EnableMagneticStoreWrites`` is set to ``true`` . See the following examples: *JSON:: { "Type" : AWS::Timestream::Table", "Properties":{ "DatabaseName":"TestDatabase", "TableName":"TestTable", "MagneticStoreWriteProperties":{ "EnableMagneticStoreWrites":true, "MagneticStoreRejectedDataLocation":{ "S3Configuration":{ "BucketName":"testbucket", "EncryptionOption":"SSE_KMS", "KmsKeyId":"1234abcd-12ab-34cd-56ef-1234567890ab", "ObjectKeyPrefix":"prefix" } } } } } *YAML:: Type: AWS::Timestream::Table DependsOn: TestDatabase Properties: TableName: "TestTable" DatabaseName: "TestDatabase" MagneticStoreWriteProperties: EnableMagneticStoreWrites: true MagneticStoreRejectedDataLocation: S3Configuration: BucketName: "testbucket" EncryptionOption: "SSE_KMS" BucketName: "1234abcd-12ab-34cd-56ef-1234567890ab" EncryptionOption: "prefix"
        :param retention_properties: The retention duration for the memory store and magnetic store. This object has the following attributes:. - *MemoryStoreRetentionPeriodInHours* : Retention duration for memory store, in hours. - *MagneticStoreRetentionPeriodInDays* : Retention duration for magnetic store, in days. Both attributes are of type ``string`` . Both attributes are *required* when ``RetentionProperties`` is specified. See the following examples: *JSON* ``{ "Type" : AWS::Timestream::Table", "Properties" : { "DatabaseName" : "TestDatabase", "TableName" : "TestTable", "RetentionProperties" : { "MemoryStoreRetentionPeriodInHours": "24", "MagneticStoreRetentionPeriodInDays": "7" } } }`` *YAML:: Type: AWS::Timestream::Table DependsOn: TestDatabase Properties: TableName: "TestTable" DatabaseName: "TestDatabase" RetentionProperties: MemoryStoreRetentionPeriodInHours: "24" MagneticStoreRetentionPeriodInDays: "7"
        :param table_name: The name of the Timestream table. *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.
        :param tags: The tags to add to the table.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_timestream as timestream
            
            # magnetic_store_write_properties: Any
            # retention_properties: Any
            
            cfn_table_props = timestream.CfnTableProps(
                database_name="databaseName",
            
                # the properties below are optional
                magnetic_store_write_properties=magnetic_store_write_properties,
                retention_properties=retention_properties,
                table_name="tableName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "database_name": database_name,
        }
        if magnetic_store_write_properties is not None:
            self._values["magnetic_store_write_properties"] = magnetic_store_write_properties
        if retention_properties is not None:
            self._values["retention_properties"] = retention_properties
        if table_name is not None:
            self._values["table_name"] = table_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def database_name(self) -> builtins.str:
        '''The name of the Timestream database that contains this table.

        *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-databasename
        '''
        result = self._values.get("database_name")
        assert result is not None, "Required property 'database_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def magnetic_store_write_properties(self) -> typing.Any:
        '''Contains properties to set on the table when enabling magnetic store writes.

        This object has the following attributes:

        - *EnableMagneticStoreWrites* : A ``boolean`` flag to enable magnetic store writes.
        - *MagneticStoreRejectedDataLocation* : The location to write error reports for records rejected, asynchronously, during magnetic store writes. Only ``S3Configuration`` objects are allowed. The ``S3Configuration`` object has the following attributes:
        - *BucketName* : The name of the S3 bucket.
        - *EncryptionOption* : The encryption option for the S3 location. Valid values are S3 server-side encryption with an S3 managed key ( ``SSE_S3`` ) or AWS managed key ( ``SSE_KMS`` ).
        - *KmsKeyId* : The AWS KMS key ID to use when encrypting with an AWS managed key.
        - *ObjectKeyPrefix* : The prefix to use option for the objects stored in S3.

        Both ``BucketName`` and ``EncryptionOption`` are *required* when ``S3Configuration`` is specified. If you specify ``SSE_KMS`` as your ``EncryptionOption`` then ``KmsKeyId`` is *required* .

        ``EnableMagneticStoreWrites`` attribute is *required* when ``MagneticStoreWriteProperties`` is specified. ``MagneticStoreRejectedDataLocation`` attribute is *required* when ``EnableMagneticStoreWrites`` is set to ``true`` .

        See the following examples:

        *JSON::

           { "Type" : AWS::Timestream::Table", "Properties":{ "DatabaseName":"TestDatabase", "TableName":"TestTable", "MagneticStoreWriteProperties":{ "EnableMagneticStoreWrites":true, "MagneticStoreRejectedDataLocation":{ "S3Configuration":{ "BucketName":"testbucket", "EncryptionOption":"SSE_KMS", "KmsKeyId":"1234abcd-12ab-34cd-56ef-1234567890ab", "ObjectKeyPrefix":"prefix" } } } }
           }

        *YAML::

           Type: AWS::Timestream::Table
           DependsOn: TestDatabase
           Properties: TableName: "TestTable" DatabaseName: "TestDatabase" MagneticStoreWriteProperties: EnableMagneticStoreWrites: true MagneticStoreRejectedDataLocation: S3Configuration: BucketName: "testbucket" EncryptionOption: "SSE_KMS" BucketName: "1234abcd-12ab-34cd-56ef-1234567890ab" EncryptionOption: "prefix"

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-magneticstorewriteproperties
        '''
        result = self._values.get("magnetic_store_write_properties")
        return typing.cast(typing.Any, result)

    @builtins.property
    def retention_properties(self) -> typing.Any:
        '''The retention duration for the memory store and magnetic store. This object has the following attributes:.

        - *MemoryStoreRetentionPeriodInHours* : Retention duration for memory store, in hours.
        - *MagneticStoreRetentionPeriodInDays* : Retention duration for magnetic store, in days.

        Both attributes are of type ``string`` . Both attributes are *required* when ``RetentionProperties`` is specified.

        See the following examples:

        *JSON*

        ``{ "Type" : AWS::Timestream::Table", "Properties" : { "DatabaseName" : "TestDatabase", "TableName" : "TestTable", "RetentionProperties" : { "MemoryStoreRetentionPeriodInHours": "24", "MagneticStoreRetentionPeriodInDays": "7" } } }``

        *YAML::

           Type: AWS::Timestream::Table
           DependsOn: TestDatabase
           Properties: TableName: "TestTable" DatabaseName: "TestDatabase" RetentionProperties: MemoryStoreRetentionPeriodInHours: "24" MagneticStoreRetentionPeriodInDays: "7"

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-retentionproperties
        '''
        result = self._values.get("retention_properties")
        return typing.cast(typing.Any, result)

    @builtins.property
    def table_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Timestream table.

        *Length Constraints* : Minimum length of 3 bytes. Maximum length of 256 bytes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-tablename
        '''
        result = self._values.get("table_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to add to the table.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html#cfn-timestream-table-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnTableProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnDatabase",
    "CfnDatabaseProps",
    "CfnScheduledQuery",
    "CfnScheduledQueryProps",
    "CfnTable",
    "CfnTableProps",
]

publication.publish()
