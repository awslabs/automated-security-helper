'''
# AWS Database Migration Service Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_dms as dms
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-dms-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::DMS](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_DMS.html).

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
class CfnCertificate(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_dms.CfnCertificate",
):
    '''A CloudFormation ``AWS::DMS::Certificate``.

    The ``AWS::DMS::Certificate`` resource creates an SSL certificate that encrypts connections between AWS DMS endpoints and the replication instance.

    :cloudformationResource: AWS::DMS::Certificate
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-certificate.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_dms as dms
        
        cfn_certificate = dms.CfnCertificate(self, "MyCfnCertificate",
            certificate_identifier="certificateIdentifier",
            certificate_pem="certificatePem",
            certificate_wallet="certificateWallet"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        certificate_identifier: typing.Optional[builtins.str] = None,
        certificate_pem: typing.Optional[builtins.str] = None,
        certificate_wallet: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::DMS::Certificate``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param certificate_identifier: A customer-assigned name for the certificate. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen or contain two consecutive hyphens.
        :param certificate_pem: The contents of a ``.pem`` file, which contains an X.509 certificate.
        :param certificate_wallet: The location of an imported Oracle Wallet certificate for use with SSL. Example: ``filebase64("${path.root}/rds-ca-2019-root.sso")``
        '''
        props = CfnCertificateProps(
            certificate_identifier=certificate_identifier,
            certificate_pem=certificate_pem,
            certificate_wallet=certificate_wallet,
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
    @jsii.member(jsii_name="certificateIdentifier")
    def certificate_identifier(self) -> typing.Optional[builtins.str]:
        '''A customer-assigned name for the certificate.

        Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-certificate.html#cfn-dms-certificate-certificateidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificateIdentifier"))

    @certificate_identifier.setter
    def certificate_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "certificateIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificatePem")
    def certificate_pem(self) -> typing.Optional[builtins.str]:
        '''The contents of a ``.pem`` file, which contains an X.509 certificate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-certificate.html#cfn-dms-certificate-certificatepem
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificatePem"))

    @certificate_pem.setter
    def certificate_pem(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "certificatePem", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateWallet")
    def certificate_wallet(self) -> typing.Optional[builtins.str]:
        '''The location of an imported Oracle Wallet certificate for use with SSL.

        Example: ``filebase64("${path.root}/rds-ca-2019-root.sso")``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-certificate.html#cfn-dms-certificate-certificatewallet
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificateWallet"))

    @certificate_wallet.setter
    def certificate_wallet(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "certificateWallet", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_dms.CfnCertificateProps",
    jsii_struct_bases=[],
    name_mapping={
        "certificate_identifier": "certificateIdentifier",
        "certificate_pem": "certificatePem",
        "certificate_wallet": "certificateWallet",
    },
)
class CfnCertificateProps:
    def __init__(
        self,
        *,
        certificate_identifier: typing.Optional[builtins.str] = None,
        certificate_pem: typing.Optional[builtins.str] = None,
        certificate_wallet: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnCertificate``.

        :param certificate_identifier: A customer-assigned name for the certificate. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen or contain two consecutive hyphens.
        :param certificate_pem: The contents of a ``.pem`` file, which contains an X.509 certificate.
        :param certificate_wallet: The location of an imported Oracle Wallet certificate for use with SSL. Example: ``filebase64("${path.root}/rds-ca-2019-root.sso")``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-certificate.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_dms as dms
            
            cfn_certificate_props = dms.CfnCertificateProps(
                certificate_identifier="certificateIdentifier",
                certificate_pem="certificatePem",
                certificate_wallet="certificateWallet"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if certificate_identifier is not None:
            self._values["certificate_identifier"] = certificate_identifier
        if certificate_pem is not None:
            self._values["certificate_pem"] = certificate_pem
        if certificate_wallet is not None:
            self._values["certificate_wallet"] = certificate_wallet

    @builtins.property
    def certificate_identifier(self) -> typing.Optional[builtins.str]:
        '''A customer-assigned name for the certificate.

        Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-certificate.html#cfn-dms-certificate-certificateidentifier
        '''
        result = self._values.get("certificate_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def certificate_pem(self) -> typing.Optional[builtins.str]:
        '''The contents of a ``.pem`` file, which contains an X.509 certificate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-certificate.html#cfn-dms-certificate-certificatepem
        '''
        result = self._values.get("certificate_pem")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def certificate_wallet(self) -> typing.Optional[builtins.str]:
        '''The location of an imported Oracle Wallet certificate for use with SSL.

        Example: ``filebase64("${path.root}/rds-ca-2019-root.sso")``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-certificate.html#cfn-dms-certificate-certificatewallet
        '''
        result = self._values.get("certificate_wallet")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnCertificateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnEndpoint(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint",
):
    '''A CloudFormation ``AWS::DMS::Endpoint``.

    The ``AWS::DMS::Endpoint`` resource creates an AWS DMS endpoint.

    Currently, the only endpoint setting types that AWS CloudFormation supports are *DynamoDBSettings* , *ElasticSearchSettings* , and *NeptuneSettings* .

    :cloudformationResource: AWS::DMS::Endpoint
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_dms as dms
        
        cfn_endpoint = dms.CfnEndpoint(self, "MyCfnEndpoint",
            endpoint_type="endpointType",
            engine_name="engineName",
        
            # the properties below are optional
            certificate_arn="certificateArn",
            database_name="databaseName",
            doc_db_settings=dms.CfnEndpoint.DocDbSettingsProperty(
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId"
            ),
            dynamo_db_settings=dms.CfnEndpoint.DynamoDbSettingsProperty(
                service_access_role_arn="serviceAccessRoleArn"
            ),
            elasticsearch_settings=dms.CfnEndpoint.ElasticsearchSettingsProperty(
                endpoint_uri="endpointUri",
                error_retry_duration=123,
                full_load_error_percentage=123,
                service_access_role_arn="serviceAccessRoleArn"
            ),
            endpoint_identifier="endpointIdentifier",
            extra_connection_attributes="extraConnectionAttributes",
            gcp_my_sql_settings=dms.CfnEndpoint.GcpMySQLSettingsProperty(
                after_connect_script="afterConnectScript",
                clean_source_metadata_on_mismatch=False,
                database_name="databaseName",
                events_poll_interval=123,
                max_file_size=123,
                parallel_load_threads=123,
                password="password",
                port=123,
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId",
                server_name="serverName",
                server_timezone="serverTimezone",
                username="username"
            ),
            ibm_db2_settings=dms.CfnEndpoint.IbmDb2SettingsProperty(
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId"
            ),
            kafka_settings=dms.CfnEndpoint.KafkaSettingsProperty(
                broker="broker",
                include_control_details=False,
                include_null_and_empty=False,
                include_table_alter_operations=False,
                include_transaction_details=False,
                no_hex_prefix=False,
                partition_include_schema_table=False,
                sasl_password="saslPassword",
                sasl_user_name="saslUserName",
                security_protocol="securityProtocol",
                ssl_ca_certificate_arn="sslCaCertificateArn",
                ssl_client_certificate_arn="sslClientCertificateArn",
                ssl_client_key_arn="sslClientKeyArn",
                ssl_client_key_password="sslClientKeyPassword",
                topic="topic"
            ),
            kinesis_settings=dms.CfnEndpoint.KinesisSettingsProperty(
                include_control_details=False,
                include_null_and_empty=False,
                include_table_alter_operations=False,
                include_transaction_details=False,
                message_format="messageFormat",
                no_hex_prefix=False,
                partition_include_schema_table=False,
                service_access_role_arn="serviceAccessRoleArn",
                stream_arn="streamArn"
            ),
            kms_key_id="kmsKeyId",
            microsoft_sql_server_settings=dms.CfnEndpoint.MicrosoftSqlServerSettingsProperty(
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId"
            ),
            mongo_db_settings=dms.CfnEndpoint.MongoDbSettingsProperty(
                auth_mechanism="authMechanism",
                auth_source="authSource",
                auth_type="authType",
                database_name="databaseName",
                docs_to_investigate="docsToInvestigate",
                extract_doc_id="extractDocId",
                nesting_level="nestingLevel",
                password="password",
                port=123,
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId",
                server_name="serverName",
                username="username"
            ),
            my_sql_settings=dms.CfnEndpoint.MySqlSettingsProperty(
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId"
            ),
            neptune_settings=dms.CfnEndpoint.NeptuneSettingsProperty(
                error_retry_duration=123,
                iam_auth_enabled=False,
                max_file_size=123,
                max_retry_count=123,
                s3_bucket_folder="s3BucketFolder",
                s3_bucket_name="s3BucketName",
                service_access_role_arn="serviceAccessRoleArn"
            ),
            oracle_settings=dms.CfnEndpoint.OracleSettingsProperty(
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_oracle_asm_access_role_arn="secretsManagerOracleAsmAccessRoleArn",
                secrets_manager_oracle_asm_secret_id="secretsManagerOracleAsmSecretId",
                secrets_manager_secret_id="secretsManagerSecretId"
            ),
            password="password",
            port=123,
            postgre_sql_settings=dms.CfnEndpoint.PostgreSqlSettingsProperty(
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId"
            ),
            redis_settings=dms.CfnEndpoint.RedisSettingsProperty(
                auth_password="authPassword",
                auth_type="authType",
                auth_user_name="authUserName",
                port=123,
                server_name="serverName",
                ssl_ca_certificate_arn="sslCaCertificateArn",
                ssl_security_protocol="sslSecurityProtocol"
            ),
            redshift_settings=dms.CfnEndpoint.RedshiftSettingsProperty(
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId"
            ),
            resource_identifier="resourceIdentifier",
            s3_settings=dms.CfnEndpoint.S3SettingsProperty(
                add_column_name=False,
                bucket_folder="bucketFolder",
                bucket_name="bucketName",
                canned_acl_for_objects="cannedAclForObjects",
                cdc_inserts_and_updates=False,
                cdc_inserts_only=False,
                cdc_max_batch_interval=123,
                cdc_min_file_size=123,
                cdc_path="cdcPath",
                compression_type="compressionType",
                csv_delimiter="csvDelimiter",
                csv_no_sup_value="csvNoSupValue",
                csv_null_value="csvNullValue",
                csv_row_delimiter="csvRowDelimiter",
                data_format="dataFormat",
                data_page_size=123,
                date_partition_delimiter="datePartitionDelimiter",
                date_partition_enabled=False,
                date_partition_sequence="datePartitionSequence",
                date_partition_timezone="datePartitionTimezone",
                dict_page_size_limit=123,
                enable_statistics=False,
                encoding_type="encodingType",
                encryption_mode="encryptionMode",
                external_table_definition="externalTableDefinition",
                ignore_header_rows=123,
                include_op_for_full_load=False,
                max_file_size=123,
                parquet_timestamp_in_millisecond=False,
                parquet_version="parquetVersion",
                preserve_transactions=False,
                rfc4180=False,
                row_group_length=123,
                server_side_encryption_kms_key_id="serverSideEncryptionKmsKeyId",
                service_access_role_arn="serviceAccessRoleArn",
                timestamp_column_name="timestampColumnName",
                use_csv_no_sup_value=False,
                use_task_start_time_for_full_load_timestamp=False
            ),
            server_name="serverName",
            ssl_mode="sslMode",
            sybase_settings=dms.CfnEndpoint.SybaseSettingsProperty(
                secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                secrets_manager_secret_id="secretsManagerSecretId"
            ),
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            username="username"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        endpoint_type: builtins.str,
        engine_name: builtins.str,
        certificate_arn: typing.Optional[builtins.str] = None,
        database_name: typing.Optional[builtins.str] = None,
        doc_db_settings: typing.Optional[typing.Union["CfnEndpoint.DocDbSettingsProperty", _IResolvable_da3f097b]] = None,
        dynamo_db_settings: typing.Optional[typing.Union["CfnEndpoint.DynamoDbSettingsProperty", _IResolvable_da3f097b]] = None,
        elasticsearch_settings: typing.Optional[typing.Union["CfnEndpoint.ElasticsearchSettingsProperty", _IResolvable_da3f097b]] = None,
        endpoint_identifier: typing.Optional[builtins.str] = None,
        extra_connection_attributes: typing.Optional[builtins.str] = None,
        gcp_my_sql_settings: typing.Optional[typing.Union["CfnEndpoint.GcpMySQLSettingsProperty", _IResolvable_da3f097b]] = None,
        ibm_db2_settings: typing.Optional[typing.Union["CfnEndpoint.IbmDb2SettingsProperty", _IResolvable_da3f097b]] = None,
        kafka_settings: typing.Optional[typing.Union["CfnEndpoint.KafkaSettingsProperty", _IResolvable_da3f097b]] = None,
        kinesis_settings: typing.Optional[typing.Union["CfnEndpoint.KinesisSettingsProperty", _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        microsoft_sql_server_settings: typing.Optional[typing.Union["CfnEndpoint.MicrosoftSqlServerSettingsProperty", _IResolvable_da3f097b]] = None,
        mongo_db_settings: typing.Optional[typing.Union["CfnEndpoint.MongoDbSettingsProperty", _IResolvable_da3f097b]] = None,
        my_sql_settings: typing.Optional[typing.Union["CfnEndpoint.MySqlSettingsProperty", _IResolvable_da3f097b]] = None,
        neptune_settings: typing.Optional[typing.Union["CfnEndpoint.NeptuneSettingsProperty", _IResolvable_da3f097b]] = None,
        oracle_settings: typing.Optional[typing.Union["CfnEndpoint.OracleSettingsProperty", _IResolvable_da3f097b]] = None,
        password: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        postgre_sql_settings: typing.Optional[typing.Union["CfnEndpoint.PostgreSqlSettingsProperty", _IResolvable_da3f097b]] = None,
        redis_settings: typing.Optional[typing.Union["CfnEndpoint.RedisSettingsProperty", _IResolvable_da3f097b]] = None,
        redshift_settings: typing.Optional[typing.Union["CfnEndpoint.RedshiftSettingsProperty", _IResolvable_da3f097b]] = None,
        resource_identifier: typing.Optional[builtins.str] = None,
        s3_settings: typing.Optional[typing.Union["CfnEndpoint.S3SettingsProperty", _IResolvable_da3f097b]] = None,
        server_name: typing.Optional[builtins.str] = None,
        ssl_mode: typing.Optional[builtins.str] = None,
        sybase_settings: typing.Optional[typing.Union["CfnEndpoint.SybaseSettingsProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        username: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::DMS::Endpoint``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param endpoint_type: The type of endpoint. Valid values are ``source`` and ``target`` .
        :param engine_name: The type of engine for the endpoint. Valid values, depending on the ``EndpointType`` value, include ``"mysql"`` , ``"oracle"`` , ``"postgres"`` , ``"mariadb"`` , ``"aurora"`` , ``"aurora-postgresql"`` , ``"opensearch"`` , ``"redshift"`` , ``"s3"`` , ``"db2"`` , ``"azuredb"`` , ``"sybase"`` , ``"dynamodb"`` , ``"mongodb"`` , ``"kinesis"`` , ``"kafka"`` , ``"elasticsearch"`` , ``"docdb"`` , ``"sqlserver"`` , and ``"neptune"`` .
        :param certificate_arn: The Amazon Resource Name (ARN) for the certificate.
        :param database_name: The name of the endpoint database. For a MySQL source or target endpoint, do not specify DatabaseName. To migrate to a specific database, use this setting and ``targetDbType`` .
        :param doc_db_settings: Settings in JSON format for the source DocumentDB endpoint. For more information about the available settings, see the configuration properties section in `Using DocumentDB as a Target for AWS Database Migration Service <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.DocumentDB.html>`_ in the *AWS Database Migration Service User Guide.*
        :param dynamo_db_settings: Settings in JSON format for the target Amazon DynamoDB endpoint. For information about other available settings, see `Using Object Mapping to Migrate Data to DynamoDB <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.DynamoDB.html#CHAP_Target.DynamoDB.ObjectMapping>`_ in the *AWS Database Migration Service User Guide.*
        :param elasticsearch_settings: Settings in JSON format for the target OpenSearch endpoint. For more information about the available settings, see `Extra Connection Attributes When Using OpenSearch as a Target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Elasticsearch.html#CHAP_Target.Elasticsearch.Configuration>`_ in the *AWS Database Migration Service User Guide* .
        :param endpoint_identifier: The database endpoint identifier. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.
        :param extra_connection_attributes: Additional attributes associated with the connection. Each attribute is specified as a name-value pair associated by an equal sign (=). Multiple attributes are separated by a semicolon (;) with no additional white space. For information on the attributes available for connecting your source or target endpoint, see `Working with AWS DMS Endpoints <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Endpoints.html>`_ in the *AWS Database Migration Service User Guide.*
        :param gcp_my_sql_settings: Settings in JSON format for the source GCP MySQL endpoint.
        :param ibm_db2_settings: Not currently supported by AWS CloudFormation .
        :param kafka_settings: Settings in JSON format for the target Apache Kafka endpoint. For more information about the available settings, see `Using object mapping to migrate data to a Kafka topic <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Kafka.html#CHAP_Target.Kafka.ObjectMapping>`_ in the *AWS Database Migration Service User Guide.*
        :param kinesis_settings: Settings in JSON format for the target endpoint for Amazon Kinesis Data Streams. For more information about the available settings, see `Using Amazon Kinesis Data Streams as a Target for AWS Database Migration Service <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Kinesis.html>`_ in the *AWS Database Migration Service User Guide.*
        :param kms_key_id: An AWS KMS key identifier that is used to encrypt the connection parameters for the endpoint. If you don't specify a value for the ``KmsKeyId`` parameter, then AWS DMS uses your default encryption key. AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Region .
        :param microsoft_sql_server_settings: Not currently supported by AWS CloudFormation .
        :param mongo_db_settings: Not currently supported by AWS CloudFormation .
        :param my_sql_settings: Settings in JSON format for the source and target MySQL endpoint. For information about other available settings, see `Extra connection attributes when using MySQL as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.MySQL.html#CHAP_Source.MySQL.ConnectionAttrib>`_ and `Extra connection attributes when using a MySQL-compatible database as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.MySQL.html#CHAP_Target.MySQL.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*
        :param neptune_settings: ``AWS::DMS::Endpoint.NeptuneSettings``.
        :param oracle_settings: Settings in JSON format for the source and target Oracle endpoint. For information about other available settings, see `Extra connection attributes when using Oracle as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.Oracle.html#CHAP_Source.Oracle.ConnectionAttrib>`_ and `Extra connection attributes when using Oracle as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Oracle.html#CHAP_Target.Oracle.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*
        :param password: The password to be used to log in to the endpoint database.
        :param port: The port used by the endpoint database.
        :param postgre_sql_settings: Not currently supported by AWS CloudFormation .
        :param redis_settings: Settings in JSON format for the target Redis endpoint.
        :param redshift_settings: Not currently supported by AWS CloudFormation .
        :param resource_identifier: A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object. The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .
        :param s3_settings: Settings in JSON format for the target Amazon S3 endpoint. For more information about the available settings, see `Extra Connection Attributes When Using Amazon S3 as a Target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring>`_ in the *AWS Database Migration Service User Guide.*
        :param server_name: The name of the server where the endpoint database resides.
        :param ssl_mode: The Secure Sockets Layer (SSL) mode to use for the SSL connection. The default is ``none`` . .. epigraph:: When ``engine_name`` is set to S3, then the only allowed value is ``none`` .
        :param sybase_settings: Settings in JSON format for the source and target SAP ASE endpoint. For information about other available settings, see `Extra connection attributes when using SAP ASE as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.SAP.html#CHAP_Source.SAP.ConnectionAttrib>`_ and `Extra connection attributes when using SAP ASE as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.SAP.html#CHAP_Target.SAP.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*
        :param tags: One or more tags to be assigned to the endpoint.
        :param username: The user name to be used to log in to the endpoint database.
        '''
        props = CfnEndpointProps(
            endpoint_type=endpoint_type,
            engine_name=engine_name,
            certificate_arn=certificate_arn,
            database_name=database_name,
            doc_db_settings=doc_db_settings,
            dynamo_db_settings=dynamo_db_settings,
            elasticsearch_settings=elasticsearch_settings,
            endpoint_identifier=endpoint_identifier,
            extra_connection_attributes=extra_connection_attributes,
            gcp_my_sql_settings=gcp_my_sql_settings,
            ibm_db2_settings=ibm_db2_settings,
            kafka_settings=kafka_settings,
            kinesis_settings=kinesis_settings,
            kms_key_id=kms_key_id,
            microsoft_sql_server_settings=microsoft_sql_server_settings,
            mongo_db_settings=mongo_db_settings,
            my_sql_settings=my_sql_settings,
            neptune_settings=neptune_settings,
            oracle_settings=oracle_settings,
            password=password,
            port=port,
            postgre_sql_settings=postgre_sql_settings,
            redis_settings=redis_settings,
            redshift_settings=redshift_settings,
            resource_identifier=resource_identifier,
            s3_settings=s3_settings,
            server_name=server_name,
            ssl_mode=ssl_mode,
            sybase_settings=sybase_settings,
            tags=tags,
            username=username,
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
    @jsii.member(jsii_name="attrExternalId")
    def attr_external_id(self) -> builtins.str:
        '''A value that can be used for cross-account validation.

        :cloudformationAttribute: ExternalId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrExternalId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''One or more tags to be assigned to the endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="endpointType")
    def endpoint_type(self) -> builtins.str:
        '''The type of endpoint.

        Valid values are ``source`` and ``target`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-endpointtype
        '''
        return typing.cast(builtins.str, jsii.get(self, "endpointType"))

    @endpoint_type.setter
    def endpoint_type(self, value: builtins.str) -> None:
        jsii.set(self, "endpointType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineName")
    def engine_name(self) -> builtins.str:
        '''The type of engine for the endpoint.

        Valid values, depending on the ``EndpointType`` value, include ``"mysql"`` , ``"oracle"`` , ``"postgres"`` , ``"mariadb"`` , ``"aurora"`` , ``"aurora-postgresql"`` , ``"opensearch"`` , ``"redshift"`` , ``"s3"`` , ``"db2"`` , ``"azuredb"`` , ``"sybase"`` , ``"dynamodb"`` , ``"mongodb"`` , ``"kinesis"`` , ``"kafka"`` , ``"elasticsearch"`` , ``"docdb"`` , ``"sqlserver"`` , and ``"neptune"`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename
        '''
        return typing.cast(builtins.str, jsii.get(self, "engineName"))

    @engine_name.setter
    def engine_name(self, value: builtins.str) -> None:
        jsii.set(self, "engineName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) for the certificate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-certificatearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificateArn"))

    @certificate_arn.setter
    def certificate_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "certificateArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="databaseName")
    def database_name(self) -> typing.Optional[builtins.str]:
        '''The name of the endpoint database.

        For a MySQL source or target endpoint, do not specify DatabaseName. To migrate to a specific database, use this setting and ``targetDbType`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-databasename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "databaseName"))

    @database_name.setter
    def database_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "databaseName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="docDbSettings")
    def doc_db_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.DocDbSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source DocumentDB endpoint.

        For more information about the available settings, see the configuration properties section in `Using DocumentDB as a Target for AWS Database Migration Service <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.DocumentDB.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-docdbsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.DocDbSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "docDbSettings"))

    @doc_db_settings.setter
    def doc_db_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.DocDbSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "docDbSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dynamoDbSettings")
    def dynamo_db_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.DynamoDbSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target Amazon DynamoDB endpoint.

        For information about other available settings, see `Using Object Mapping to Migrate Data to DynamoDB <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.DynamoDB.html#CHAP_Target.DynamoDB.ObjectMapping>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-dynamodbsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.DynamoDbSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "dynamoDbSettings"))

    @dynamo_db_settings.setter
    def dynamo_db_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.DynamoDbSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "dynamoDbSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="elasticsearchSettings")
    def elasticsearch_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.ElasticsearchSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target OpenSearch endpoint.

        For more information about the available settings, see `Extra Connection Attributes When Using OpenSearch as a Target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Elasticsearch.html#CHAP_Target.Elasticsearch.Configuration>`_ in the *AWS Database Migration Service User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-elasticsearchsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.ElasticsearchSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "elasticsearchSettings"))

    @elasticsearch_settings.setter
    def elasticsearch_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.ElasticsearchSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "elasticsearchSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="endpointIdentifier")
    def endpoint_identifier(self) -> typing.Optional[builtins.str]:
        '''The database endpoint identifier.

        Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-endpointidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "endpointIdentifier"))

    @endpoint_identifier.setter
    def endpoint_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "endpointIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="extraConnectionAttributes")
    def extra_connection_attributes(self) -> typing.Optional[builtins.str]:
        '''Additional attributes associated with the connection.

        Each attribute is specified as a name-value pair associated by an equal sign (=). Multiple attributes are separated by a semicolon (;) with no additional white space. For information on the attributes available for connecting your source or target endpoint, see `Working with AWS DMS Endpoints <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Endpoints.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-extraconnectionattributes
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "extraConnectionAttributes"))

    @extra_connection_attributes.setter
    def extra_connection_attributes(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "extraConnectionAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="gcpMySqlSettings")
    def gcp_my_sql_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.GcpMySQLSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source GCP MySQL endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-gcpmysqlsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.GcpMySQLSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "gcpMySqlSettings"))

    @gcp_my_sql_settings.setter
    def gcp_my_sql_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.GcpMySQLSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "gcpMySqlSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ibmDb2Settings")
    def ibm_db2_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.IbmDb2SettingsProperty", _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-ibmdb2settings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.IbmDb2SettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "ibmDb2Settings"))

    @ibm_db2_settings.setter
    def ibm_db2_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.IbmDb2SettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ibmDb2Settings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kafkaSettings")
    def kafka_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.KafkaSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target Apache Kafka endpoint.

        For more information about the available settings, see `Using object mapping to migrate data to a Kafka topic <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Kafka.html#CHAP_Target.Kafka.ObjectMapping>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-kafkasettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.KafkaSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "kafkaSettings"))

    @kafka_settings.setter
    def kafka_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.KafkaSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "kafkaSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kinesisSettings")
    def kinesis_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.KinesisSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target endpoint for Amazon Kinesis Data Streams.

        For more information about the available settings, see `Using Amazon Kinesis Data Streams as a Target for AWS Database Migration Service <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Kinesis.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-kinesissettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.KinesisSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "kinesisSettings"))

    @kinesis_settings.setter
    def kinesis_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.KinesisSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "kinesisSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''An AWS KMS key identifier that is used to encrypt the connection parameters for the endpoint.

        If you don't specify a value for the ``KmsKeyId`` parameter, then AWS DMS uses your default encryption key.

        AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Region .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="microsoftSqlServerSettings")
    def microsoft_sql_server_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.MicrosoftSqlServerSettingsProperty", _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-microsoftsqlserversettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.MicrosoftSqlServerSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "microsoftSqlServerSettings"))

    @microsoft_sql_server_settings.setter
    def microsoft_sql_server_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.MicrosoftSqlServerSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "microsoftSqlServerSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="mongoDbSettings")
    def mongo_db_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.MongoDbSettingsProperty", _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-mongodbsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.MongoDbSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "mongoDbSettings"))

    @mongo_db_settings.setter
    def mongo_db_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.MongoDbSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "mongoDbSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="mySqlSettings")
    def my_sql_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.MySqlSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source and target MySQL endpoint.

        For information about other available settings, see `Extra connection attributes when using MySQL as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.MySQL.html#CHAP_Source.MySQL.ConnectionAttrib>`_ and `Extra connection attributes when using a MySQL-compatible database as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.MySQL.html#CHAP_Target.MySQL.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-mysqlsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.MySqlSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "mySqlSettings"))

    @my_sql_settings.setter
    def my_sql_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.MySqlSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "mySqlSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="neptuneSettings")
    def neptune_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.NeptuneSettingsProperty", _IResolvable_da3f097b]]:
        '''``AWS::DMS::Endpoint.NeptuneSettings``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-neptunesettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.NeptuneSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "neptuneSettings"))

    @neptune_settings.setter
    def neptune_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.NeptuneSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "neptuneSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="oracleSettings")
    def oracle_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.OracleSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source and target Oracle endpoint.

        For information about other available settings, see `Extra connection attributes when using Oracle as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.Oracle.html#CHAP_Source.Oracle.ConnectionAttrib>`_ and `Extra connection attributes when using Oracle as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Oracle.html#CHAP_Target.Oracle.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-oraclesettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.OracleSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "oracleSettings"))

    @oracle_settings.setter
    def oracle_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.OracleSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "oracleSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="password")
    def password(self) -> typing.Optional[builtins.str]:
        '''The password to be used to log in to the endpoint database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-password
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "password"))

    @password.setter
    def password(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "password", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="port")
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port used by the endpoint database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-port
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "port"))

    @port.setter
    def port(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "port", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="postgreSqlSettings")
    def postgre_sql_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.PostgreSqlSettingsProperty", _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-postgresqlsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.PostgreSqlSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "postgreSqlSettings"))

    @postgre_sql_settings.setter
    def postgre_sql_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.PostgreSqlSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "postgreSqlSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="redisSettings")
    def redis_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.RedisSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target Redis endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-redissettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.RedisSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "redisSettings"))

    @redis_settings.setter
    def redis_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.RedisSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "redisSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="redshiftSettings")
    def redshift_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.RedshiftSettingsProperty", _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-redshiftsettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.RedshiftSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "redshiftSettings"))

    @redshift_settings.setter
    def redshift_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.RedshiftSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "redshiftSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceIdentifier")
    def resource_identifier(self) -> typing.Optional[builtins.str]:
        '''A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object.

        The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-resourceidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "resourceIdentifier"))

    @resource_identifier.setter
    def resource_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "resourceIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="s3Settings")
    def s3_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.S3SettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target Amazon S3 endpoint.

        For more information about the available settings, see `Extra Connection Attributes When Using Amazon S3 as a Target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-s3settings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.S3SettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "s3Settings"))

    @s3_settings.setter
    def s3_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.S3SettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "s3Settings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serverName")
    def server_name(self) -> typing.Optional[builtins.str]:
        '''The name of the server where the endpoint database resides.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-servername
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "serverName"))

    @server_name.setter
    def server_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "serverName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sslMode")
    def ssl_mode(self) -> typing.Optional[builtins.str]:
        '''The Secure Sockets Layer (SSL) mode to use for the SSL connection. The default is ``none`` .

        .. epigraph::

           When ``engine_name`` is set to S3, then the only allowed value is ``none`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-sslmode
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "sslMode"))

    @ssl_mode.setter
    def ssl_mode(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "sslMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sybaseSettings")
    def sybase_settings(
        self,
    ) -> typing.Optional[typing.Union["CfnEndpoint.SybaseSettingsProperty", _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source and target SAP ASE endpoint.

        For information about other available settings, see `Extra connection attributes when using SAP ASE as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.SAP.html#CHAP_Source.SAP.ConnectionAttrib>`_ and `Extra connection attributes when using SAP ASE as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.SAP.html#CHAP_Target.SAP.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-sybasesettings
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEndpoint.SybaseSettingsProperty", _IResolvable_da3f097b]], jsii.get(self, "sybaseSettings"))

    @sybase_settings.setter
    def sybase_settings(
        self,
        value: typing.Optional[typing.Union["CfnEndpoint.SybaseSettingsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "sybaseSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="username")
    def username(self) -> typing.Optional[builtins.str]:
        '''The user name to be used to log in to the endpoint database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-username
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "username"))

    @username.setter
    def username(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "username", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.DocDbSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
        },
    )
    class DocDbSettingsProperty:
        def __init__(
            self,
            *,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-docdbsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                doc_db_settings_property = dms.CfnEndpoint.DocDbSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-docdbsettings.html#cfn-dms-endpoint-docdbsettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-docdbsettings.html#cfn-dms-endpoint-docdbsettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DocDbSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.DynamoDbSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={"service_access_role_arn": "serviceAccessRoleArn"},
    )
    class DynamoDbSettingsProperty:
        def __init__(
            self,
            *,
            service_access_role_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Provides the Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role used to define an Amazon DynamoDB target endpoint.

            :param service_access_role_arn: The Amazon Resource Name (ARN) used by the service to access the IAM role. The role must allow the ``iam:PassRole`` action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-dynamodbsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                dynamo_db_settings_property = dms.CfnEndpoint.DynamoDbSettingsProperty(
                    service_access_role_arn="serviceAccessRoleArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if service_access_role_arn is not None:
                self._values["service_access_role_arn"] = service_access_role_arn

        @builtins.property
        def service_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) used by the service to access the IAM role.

            The role must allow the ``iam:PassRole`` action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-dynamodbsettings.html#cfn-dms-endpoint-dynamodbsettings-serviceaccessrolearn
            '''
            result = self._values.get("service_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DynamoDbSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.ElasticsearchSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "endpoint_uri": "endpointUri",
            "error_retry_duration": "errorRetryDuration",
            "full_load_error_percentage": "fullLoadErrorPercentage",
            "service_access_role_arn": "serviceAccessRoleArn",
        },
    )
    class ElasticsearchSettingsProperty:
        def __init__(
            self,
            *,
            endpoint_uri: typing.Optional[builtins.str] = None,
            error_retry_duration: typing.Optional[jsii.Number] = None,
            full_load_error_percentage: typing.Optional[jsii.Number] = None,
            service_access_role_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Provides information that defines an OpenSearch endpoint.

            :param endpoint_uri: The endpoint for the OpenSearch cluster. AWS DMS uses HTTPS if a transport protocol (http/https) is not specified.
            :param error_retry_duration: The maximum number of seconds for which DMS retries failed API requests to the OpenSearch cluster.
            :param full_load_error_percentage: The maximum percentage of records that can fail to be written before a full load operation stops. To avoid early failure, this counter is only effective after 1000 records are transferred. OpenSearch also has the concept of error monitoring during the last 10 minutes of an Observation Window. If transfer of all records fail in the last 10 minutes, the full load operation stops.
            :param service_access_role_arn: The Amazon Resource Name (ARN) used by the service to access the IAM role. The role must allow the ``iam:PassRole`` action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-elasticsearchsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                elasticsearch_settings_property = dms.CfnEndpoint.ElasticsearchSettingsProperty(
                    endpoint_uri="endpointUri",
                    error_retry_duration=123,
                    full_load_error_percentage=123,
                    service_access_role_arn="serviceAccessRoleArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if endpoint_uri is not None:
                self._values["endpoint_uri"] = endpoint_uri
            if error_retry_duration is not None:
                self._values["error_retry_duration"] = error_retry_duration
            if full_load_error_percentage is not None:
                self._values["full_load_error_percentage"] = full_load_error_percentage
            if service_access_role_arn is not None:
                self._values["service_access_role_arn"] = service_access_role_arn

        @builtins.property
        def endpoint_uri(self) -> typing.Optional[builtins.str]:
            '''The endpoint for the OpenSearch cluster.

            AWS DMS uses HTTPS if a transport protocol (http/https) is not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-elasticsearchsettings.html#cfn-dms-endpoint-elasticsearchsettings-endpointuri
            '''
            result = self._values.get("endpoint_uri")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def error_retry_duration(self) -> typing.Optional[jsii.Number]:
            '''The maximum number of seconds for which DMS retries failed API requests to the OpenSearch cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-elasticsearchsettings.html#cfn-dms-endpoint-elasticsearchsettings-errorretryduration
            '''
            result = self._values.get("error_retry_duration")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def full_load_error_percentage(self) -> typing.Optional[jsii.Number]:
            '''The maximum percentage of records that can fail to be written before a full load operation stops.

            To avoid early failure, this counter is only effective after 1000 records are transferred. OpenSearch also has the concept of error monitoring during the last 10 minutes of an Observation Window. If transfer of all records fail in the last 10 minutes, the full load operation stops.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-elasticsearchsettings.html#cfn-dms-endpoint-elasticsearchsettings-fullloaderrorpercentage
            '''
            result = self._values.get("full_load_error_percentage")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def service_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) used by the service to access the IAM role.

            The role must allow the ``iam:PassRole`` action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-elasticsearchsettings.html#cfn-dms-endpoint-elasticsearchsettings-serviceaccessrolearn
            '''
            result = self._values.get("service_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ElasticsearchSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.GcpMySQLSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "after_connect_script": "afterConnectScript",
            "clean_source_metadata_on_mismatch": "cleanSourceMetadataOnMismatch",
            "database_name": "databaseName",
            "events_poll_interval": "eventsPollInterval",
            "max_file_size": "maxFileSize",
            "parallel_load_threads": "parallelLoadThreads",
            "password": "password",
            "port": "port",
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
            "server_name": "serverName",
            "server_timezone": "serverTimezone",
            "username": "username",
        },
    )
    class GcpMySQLSettingsProperty:
        def __init__(
            self,
            *,
            after_connect_script: typing.Optional[builtins.str] = None,
            clean_source_metadata_on_mismatch: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            database_name: typing.Optional[builtins.str] = None,
            events_poll_interval: typing.Optional[jsii.Number] = None,
            max_file_size: typing.Optional[jsii.Number] = None,
            parallel_load_threads: typing.Optional[jsii.Number] = None,
            password: typing.Optional[builtins.str] = None,
            port: typing.Optional[jsii.Number] = None,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
            server_name: typing.Optional[builtins.str] = None,
            server_timezone: typing.Optional[builtins.str] = None,
            username: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Settings in JSON format for the source GCP MySQL endpoint.

            :param after_connect_script: Specifies a script to run immediately after AWS DMS connects to the endpoint. The migration task continues running regardless if the SQL statement succeeds or fails. For this parameter, provide the code of the script itself, not the name of a file containing the script.
            :param clean_source_metadata_on_mismatch: Adjusts the behavior of AWS DMS when migrating from an SQL Server source database that is hosted as part of an Always On availability group cluster. If you need AWS DMS to poll all the nodes in the Always On cluster for transaction backups, set this attribute to ``false`` .
            :param database_name: Database name for the endpoint. For a MySQL source or target endpoint, don't explicitly specify the database using the ``DatabaseName`` request parameter on either the ``CreateEndpoint`` or ``ModifyEndpoint`` API call. Specifying ``DatabaseName`` when you create or modify a MySQL endpoint replicates all the task tables to this single database. For MySQL endpoints, you specify the database only when you specify the schema in the table-mapping rules of the AWS DMS task.
            :param events_poll_interval: Specifies how often to check the binary log for new changes/events when the database is idle. The default is five seconds. Example: ``eventsPollInterval=5;`` In the example, AWS DMS checks for changes in the binary logs every five seconds.
            :param max_file_size: Specifies the maximum size (in KB) of any .csv file used to transfer data to a MySQL-compatible database. Example: ``maxFileSize=512``
            :param parallel_load_threads: Improves performance when loading data into the MySQL-compatible target database. Specifies how many threads to use to load the data into the MySQL-compatible target database. Setting a large number of threads can have an adverse effect on database performance, because a separate connection is required for each thread. The default is one. Example: ``parallelLoadThreads=1``
            :param password: Endpoint connection password.
            :param port: ``CfnEndpoint.GcpMySQLSettingsProperty.Port``.
            :param secrets_manager_access_role_arn: The full Amazon Resource Name (ARN) of the IAM role that specifies AWS DMS as the trusted entity and grants the required permissions to access the value in ``SecretsManagerSecret.`` The role must allow the ``iam:PassRole`` action. ``SecretsManagerSecret`` has the value of the AWS Secrets Manager secret that allows access to the MySQL endpoint. .. epigraph:: You can specify one of two sets of values for these permissions. You can specify the values for this setting and ``SecretsManagerSecretId`` . Or you can specify clear-text values for ``UserName`` , ``Password`` , ``ServerName`` , and ``Port`` . You can't specify both. For more information on creating this ``SecretsManagerSecret`` and the ``SecretsManagerAccessRoleArn`` and ``SecretsManagerSecretId`` required to access it, see `Using secrets to access AWS Database Migration Service resources <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#security-iam-secretsmanager>`_ in the AWS Database Migration Service User Guide.
            :param secrets_manager_secret_id: The full ARN, partial ARN, or friendly name of the ``SecretsManagerSecret`` that contains the MySQL endpoint connection details.
            :param server_name: Endpoint TCP port.
            :param server_timezone: Specifies the time zone for the source MySQL database. Example: ``serverTimezone=US/Pacific;`` Note: Do not enclose time zones in single quotes.
            :param username: Endpoint connection user name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                gcp_my_sQLSettings_property = dms.CfnEndpoint.GcpMySQLSettingsProperty(
                    after_connect_script="afterConnectScript",
                    clean_source_metadata_on_mismatch=False,
                    database_name="databaseName",
                    events_poll_interval=123,
                    max_file_size=123,
                    parallel_load_threads=123,
                    password="password",
                    port=123,
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId",
                    server_name="serverName",
                    server_timezone="serverTimezone",
                    username="username"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if after_connect_script is not None:
                self._values["after_connect_script"] = after_connect_script
            if clean_source_metadata_on_mismatch is not None:
                self._values["clean_source_metadata_on_mismatch"] = clean_source_metadata_on_mismatch
            if database_name is not None:
                self._values["database_name"] = database_name
            if events_poll_interval is not None:
                self._values["events_poll_interval"] = events_poll_interval
            if max_file_size is not None:
                self._values["max_file_size"] = max_file_size
            if parallel_load_threads is not None:
                self._values["parallel_load_threads"] = parallel_load_threads
            if password is not None:
                self._values["password"] = password
            if port is not None:
                self._values["port"] = port
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id
            if server_name is not None:
                self._values["server_name"] = server_name
            if server_timezone is not None:
                self._values["server_timezone"] = server_timezone
            if username is not None:
                self._values["username"] = username

        @builtins.property
        def after_connect_script(self) -> typing.Optional[builtins.str]:
            '''Specifies a script to run immediately after AWS DMS connects to the endpoint.

            The migration task continues running regardless if the SQL statement succeeds or fails.

            For this parameter, provide the code of the script itself, not the name of a file containing the script.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-afterconnectscript
            '''
            result = self._values.get("after_connect_script")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def clean_source_metadata_on_mismatch(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Adjusts the behavior of AWS DMS when migrating from an SQL Server source database that is hosted as part of an Always On availability group cluster.

            If you need AWS DMS to poll all the nodes in the Always On cluster for transaction backups, set this attribute to ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-cleansourcemetadataonmismatch
            '''
            result = self._values.get("clean_source_metadata_on_mismatch")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def database_name(self) -> typing.Optional[builtins.str]:
            '''Database name for the endpoint.

            For a MySQL source or target endpoint, don't explicitly specify the database using the ``DatabaseName`` request parameter on either the ``CreateEndpoint`` or ``ModifyEndpoint`` API call. Specifying ``DatabaseName`` when you create or modify a MySQL endpoint replicates all the task tables to this single database. For MySQL endpoints, you specify the database only when you specify the schema in the table-mapping rules of the AWS DMS task.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-databasename
            '''
            result = self._values.get("database_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def events_poll_interval(self) -> typing.Optional[jsii.Number]:
            '''Specifies how often to check the binary log for new changes/events when the database is idle.

            The default is five seconds.

            Example: ``eventsPollInterval=5;``

            In the example, AWS DMS checks for changes in the binary logs every five seconds.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-eventspollinterval
            '''
            result = self._values.get("events_poll_interval")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_file_size(self) -> typing.Optional[jsii.Number]:
            '''Specifies the maximum size (in KB) of any .csv file used to transfer data to a MySQL-compatible database.

            Example: ``maxFileSize=512``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-maxfilesize
            '''
            result = self._values.get("max_file_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def parallel_load_threads(self) -> typing.Optional[jsii.Number]:
            '''Improves performance when loading data into the MySQL-compatible target database.

            Specifies how many threads to use to load the data into the MySQL-compatible target database. Setting a large number of threads can have an adverse effect on database performance, because a separate connection is required for each thread. The default is one.

            Example: ``parallelLoadThreads=1``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-parallelloadthreads
            '''
            result = self._values.get("parallel_load_threads")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def password(self) -> typing.Optional[builtins.str]:
            '''Endpoint connection password.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-password
            '''
            result = self._values.get("password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def port(self) -> typing.Optional[jsii.Number]:
            '''``CfnEndpoint.GcpMySQLSettingsProperty.Port``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-port
            '''
            result = self._values.get("port")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''The full Amazon Resource Name (ARN) of the IAM role that specifies AWS DMS as the trusted entity and grants the required permissions to access the value in ``SecretsManagerSecret.`` The role must allow the ``iam:PassRole`` action. ``SecretsManagerSecret`` has the value of the AWS Secrets Manager secret that allows access to the MySQL endpoint.

            .. epigraph::

               You can specify one of two sets of values for these permissions. You can specify the values for this setting and ``SecretsManagerSecretId`` . Or you can specify clear-text values for ``UserName`` , ``Password`` , ``ServerName`` , and ``Port`` . You can't specify both. For more information on creating this ``SecretsManagerSecret`` and the ``SecretsManagerAccessRoleArn`` and ``SecretsManagerSecretId`` required to access it, see `Using secrets to access AWS Database Migration Service resources <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#security-iam-secretsmanager>`_ in the AWS Database Migration Service User Guide.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''The full ARN, partial ARN, or friendly name of the ``SecretsManagerSecret`` that contains the MySQL endpoint connection details.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def server_name(self) -> typing.Optional[builtins.str]:
            '''Endpoint TCP port.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-servername
            '''
            result = self._values.get("server_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def server_timezone(self) -> typing.Optional[builtins.str]:
            '''Specifies the time zone for the source MySQL database.

            Example: ``serverTimezone=US/Pacific;``

            Note: Do not enclose time zones in single quotes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-servertimezone
            '''
            result = self._values.get("server_timezone")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def username(self) -> typing.Optional[builtins.str]:
            '''Endpoint connection user name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-gcpmysqlsettings.html#cfn-dms-endpoint-gcpmysqlsettings-username
            '''
            result = self._values.get("username")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GcpMySQLSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.IbmDb2SettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
        },
    )
    class IbmDb2SettingsProperty:
        def __init__(
            self,
            *,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-ibmdb2settings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                ibm_db2_settings_property = dms.CfnEndpoint.IbmDb2SettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-ibmdb2settings.html#cfn-dms-endpoint-ibmdb2settings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-ibmdb2settings.html#cfn-dms-endpoint-ibmdb2settings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IbmDb2SettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.KafkaSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "broker": "broker",
            "include_control_details": "includeControlDetails",
            "include_null_and_empty": "includeNullAndEmpty",
            "include_table_alter_operations": "includeTableAlterOperations",
            "include_transaction_details": "includeTransactionDetails",
            "no_hex_prefix": "noHexPrefix",
            "partition_include_schema_table": "partitionIncludeSchemaTable",
            "sasl_password": "saslPassword",
            "sasl_user_name": "saslUserName",
            "security_protocol": "securityProtocol",
            "ssl_ca_certificate_arn": "sslCaCertificateArn",
            "ssl_client_certificate_arn": "sslClientCertificateArn",
            "ssl_client_key_arn": "sslClientKeyArn",
            "ssl_client_key_password": "sslClientKeyPassword",
            "topic": "topic",
        },
    )
    class KafkaSettingsProperty:
        def __init__(
            self,
            *,
            broker: typing.Optional[builtins.str] = None,
            include_control_details: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_null_and_empty: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_table_alter_operations: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_transaction_details: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            no_hex_prefix: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            partition_include_schema_table: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            sasl_password: typing.Optional[builtins.str] = None,
            sasl_user_name: typing.Optional[builtins.str] = None,
            security_protocol: typing.Optional[builtins.str] = None,
            ssl_ca_certificate_arn: typing.Optional[builtins.str] = None,
            ssl_client_certificate_arn: typing.Optional[builtins.str] = None,
            ssl_client_key_arn: typing.Optional[builtins.str] = None,
            ssl_client_key_password: typing.Optional[builtins.str] = None,
            topic: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param broker: Not currently supported by AWS CloudFormation .
            :param include_control_details: Shows detailed control information for table definition, column definition, and table and column changes in the Kafka message output. The default is ``false`` .
            :param include_null_and_empty: Include NULL and empty columns for records migrated to the endpoint. The default is ``false`` .
            :param include_table_alter_operations: Includes any data definition language (DDL) operations that change the table in the control data, such as ``rename-table`` , ``drop-table`` , ``add-column`` , ``drop-column`` , and ``rename-column`` . The default is ``false`` .
            :param include_transaction_details: Provides detailed transaction information from the source database. This information includes a commit timestamp, a log position, and values for ``transaction_id`` , previous ``transaction_id`` , and ``transaction_record_id`` (the record offset within a transaction). The default is ``false`` .
            :param no_hex_prefix: Set this optional parameter to ``true`` to avoid adding a '0x' prefix to raw data in hexadecimal format. For example, by default, AWS DMS adds a '0x' prefix to the LOB column type in hexadecimal format moving from an Oracle source to a Kafka target. Use the ``NoHexPrefix`` endpoint setting to enable migration of RAW data type columns without adding the '0x' prefix.
            :param partition_include_schema_table: Prefixes schema and table names to partition values, when the partition type is ``primary-key-type`` . Doing this increases data distribution among Kafka partitions. For example, suppose that a SysBench schema has thousands of tables and each table has only limited range for a primary key. In this case, the same primary key is sent from thousands of tables to the same partition, which causes throttling. The default is ``false`` .
            :param sasl_password: The secure password you created when you first set up your MSK cluster to validate a client identity and make an encrypted connection between server and client using SASL-SSL authentication.
            :param sasl_user_name: The secure user name you created when you first set up your MSK cluster to validate a client identity and make an encrypted connection between server and client using SASL-SSL authentication.
            :param security_protocol: Set secure connection to a Kafka target endpoint using Transport Layer Security (TLS). Options include ``ssl-encryption`` , ``ssl-authentication`` , and ``sasl-ssl`` . ``sasl-ssl`` requires ``SaslUsername`` and ``SaslPassword`` .
            :param ssl_ca_certificate_arn: The Amazon Resource Name (ARN) for the private certificate authority (CA) cert that AWS DMS uses to securely connect to your Kafka target endpoint.
            :param ssl_client_certificate_arn: The Amazon Resource Name (ARN) of the client certificate used to securely connect to a Kafka target endpoint.
            :param ssl_client_key_arn: The Amazon Resource Name (ARN) for the client private key used to securely connect to a Kafka target endpoint.
            :param ssl_client_key_password: The password for the client private key used to securely connect to a Kafka target endpoint.
            :param topic: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                kafka_settings_property = dms.CfnEndpoint.KafkaSettingsProperty(
                    broker="broker",
                    include_control_details=False,
                    include_null_and_empty=False,
                    include_table_alter_operations=False,
                    include_transaction_details=False,
                    no_hex_prefix=False,
                    partition_include_schema_table=False,
                    sasl_password="saslPassword",
                    sasl_user_name="saslUserName",
                    security_protocol="securityProtocol",
                    ssl_ca_certificate_arn="sslCaCertificateArn",
                    ssl_client_certificate_arn="sslClientCertificateArn",
                    ssl_client_key_arn="sslClientKeyArn",
                    ssl_client_key_password="sslClientKeyPassword",
                    topic="topic"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if broker is not None:
                self._values["broker"] = broker
            if include_control_details is not None:
                self._values["include_control_details"] = include_control_details
            if include_null_and_empty is not None:
                self._values["include_null_and_empty"] = include_null_and_empty
            if include_table_alter_operations is not None:
                self._values["include_table_alter_operations"] = include_table_alter_operations
            if include_transaction_details is not None:
                self._values["include_transaction_details"] = include_transaction_details
            if no_hex_prefix is not None:
                self._values["no_hex_prefix"] = no_hex_prefix
            if partition_include_schema_table is not None:
                self._values["partition_include_schema_table"] = partition_include_schema_table
            if sasl_password is not None:
                self._values["sasl_password"] = sasl_password
            if sasl_user_name is not None:
                self._values["sasl_user_name"] = sasl_user_name
            if security_protocol is not None:
                self._values["security_protocol"] = security_protocol
            if ssl_ca_certificate_arn is not None:
                self._values["ssl_ca_certificate_arn"] = ssl_ca_certificate_arn
            if ssl_client_certificate_arn is not None:
                self._values["ssl_client_certificate_arn"] = ssl_client_certificate_arn
            if ssl_client_key_arn is not None:
                self._values["ssl_client_key_arn"] = ssl_client_key_arn
            if ssl_client_key_password is not None:
                self._values["ssl_client_key_password"] = ssl_client_key_password
            if topic is not None:
                self._values["topic"] = topic

        @builtins.property
        def broker(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-broker
            '''
            result = self._values.get("broker")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def include_control_details(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Shows detailed control information for table definition, column definition, and table and column changes in the Kafka message output.

            The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-includecontroldetails
            '''
            result = self._values.get("include_control_details")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_null_and_empty(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Include NULL and empty columns for records migrated to the endpoint.

            The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-includenullandempty
            '''
            result = self._values.get("include_null_and_empty")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_table_alter_operations(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Includes any data definition language (DDL) operations that change the table in the control data, such as ``rename-table`` , ``drop-table`` , ``add-column`` , ``drop-column`` , and ``rename-column`` .

            The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-includetablealteroperations
            '''
            result = self._values.get("include_table_alter_operations")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_transaction_details(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Provides detailed transaction information from the source database.

            This information includes a commit timestamp, a log position, and values for ``transaction_id`` , previous ``transaction_id`` , and ``transaction_record_id`` (the record offset within a transaction). The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-includetransactiondetails
            '''
            result = self._values.get("include_transaction_details")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def no_hex_prefix(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Set this optional parameter to ``true`` to avoid adding a '0x' prefix to raw data in hexadecimal format.

            For example, by default, AWS DMS adds a '0x' prefix to the LOB column type in hexadecimal format moving from an Oracle source to a Kafka target. Use the ``NoHexPrefix`` endpoint setting to enable migration of RAW data type columns without adding the '0x' prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-nohexprefix
            '''
            result = self._values.get("no_hex_prefix")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def partition_include_schema_table(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Prefixes schema and table names to partition values, when the partition type is ``primary-key-type`` .

            Doing this increases data distribution among Kafka partitions. For example, suppose that a SysBench schema has thousands of tables and each table has only limited range for a primary key. In this case, the same primary key is sent from thousands of tables to the same partition, which causes throttling. The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-partitionincludeschematable
            '''
            result = self._values.get("partition_include_schema_table")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def sasl_password(self) -> typing.Optional[builtins.str]:
            '''The secure password you created when you first set up your MSK cluster to validate a client identity and make an encrypted connection between server and client using SASL-SSL authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-saslpassword
            '''
            result = self._values.get("sasl_password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sasl_user_name(self) -> typing.Optional[builtins.str]:
            '''The secure user name you created when you first set up your MSK cluster to validate a client identity and make an encrypted connection between server and client using SASL-SSL authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-saslusername
            '''
            result = self._values.get("sasl_user_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def security_protocol(self) -> typing.Optional[builtins.str]:
            '''Set secure connection to a Kafka target endpoint using Transport Layer Security (TLS).

            Options include ``ssl-encryption`` , ``ssl-authentication`` , and ``sasl-ssl`` . ``sasl-ssl`` requires ``SaslUsername`` and ``SaslPassword`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-securityprotocol
            '''
            result = self._values.get("security_protocol")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ssl_ca_certificate_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) for the private certificate authority (CA) cert that AWS DMS uses to securely connect to your Kafka target endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-sslcacertificatearn
            '''
            result = self._values.get("ssl_ca_certificate_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ssl_client_certificate_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the client certificate used to securely connect to a Kafka target endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-sslclientcertificatearn
            '''
            result = self._values.get("ssl_client_certificate_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ssl_client_key_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) for the client private key used to securely connect to a Kafka target endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-sslclientkeyarn
            '''
            result = self._values.get("ssl_client_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ssl_client_key_password(self) -> typing.Optional[builtins.str]:
            '''The password for the client private key used to securely connect to a Kafka target endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-sslclientkeypassword
            '''
            result = self._values.get("ssl_client_key_password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def topic(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kafkasettings.html#cfn-dms-endpoint-kafkasettings-topic
            '''
            result = self._values.get("topic")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KafkaSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.KinesisSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "include_control_details": "includeControlDetails",
            "include_null_and_empty": "includeNullAndEmpty",
            "include_table_alter_operations": "includeTableAlterOperations",
            "include_transaction_details": "includeTransactionDetails",
            "message_format": "messageFormat",
            "no_hex_prefix": "noHexPrefix",
            "partition_include_schema_table": "partitionIncludeSchemaTable",
            "service_access_role_arn": "serviceAccessRoleArn",
            "stream_arn": "streamArn",
        },
    )
    class KinesisSettingsProperty:
        def __init__(
            self,
            *,
            include_control_details: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_null_and_empty: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_table_alter_operations: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_transaction_details: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            message_format: typing.Optional[builtins.str] = None,
            no_hex_prefix: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            partition_include_schema_table: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            service_access_role_arn: typing.Optional[builtins.str] = None,
            stream_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation ..

            :param include_control_details: Shows detailed control information for table definition, column definition, and table and column changes in the Kinesis message output. The default is ``false`` .
            :param include_null_and_empty: Include NULL and empty columns for records migrated to the endpoint. The default is ``false`` .
            :param include_table_alter_operations: Includes any data definition language (DDL) operations that change the table in the control data, such as ``rename-table`` , ``drop-table`` , ``add-column`` , ``drop-column`` , and ``rename-column`` . The default is ``false`` .
            :param include_transaction_details: Provides detailed transaction information from the source database. This information includes a commit timestamp, a log position, and values for ``transaction_id`` , previous ``transaction_id`` , and ``transaction_record_id`` (the record offset within a transaction). The default is ``false`` .
            :param message_format: Not currently supported by AWS CloudFormation .
            :param no_hex_prefix: Set this optional parameter to ``true`` to avoid adding a '0x' prefix to raw data in hexadecimal format. For example, by default, AWS DMS adds a '0x' prefix to the LOB column type in hexadecimal format moving from an Oracle source to an Amazon Kinesis target. Use the ``NoHexPrefix`` endpoint setting to enable migration of RAW data type columns without adding the '0x' prefix.
            :param partition_include_schema_table: Prefixes schema and table names to partition values, when the partition type is ``primary-key-type`` . Doing this increases data distribution among Kinesis shards. For example, suppose that a SysBench schema has thousands of tables and each table has only limited range for a primary key. In this case, the same primary key is sent from thousands of tables to the same shard, which causes throttling. The default is ``false`` .
            :param service_access_role_arn: Not currently supported by AWS CloudFormation .
            :param stream_arn: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                kinesis_settings_property = dms.CfnEndpoint.KinesisSettingsProperty(
                    include_control_details=False,
                    include_null_and_empty=False,
                    include_table_alter_operations=False,
                    include_transaction_details=False,
                    message_format="messageFormat",
                    no_hex_prefix=False,
                    partition_include_schema_table=False,
                    service_access_role_arn="serviceAccessRoleArn",
                    stream_arn="streamArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if include_control_details is not None:
                self._values["include_control_details"] = include_control_details
            if include_null_and_empty is not None:
                self._values["include_null_and_empty"] = include_null_and_empty
            if include_table_alter_operations is not None:
                self._values["include_table_alter_operations"] = include_table_alter_operations
            if include_transaction_details is not None:
                self._values["include_transaction_details"] = include_transaction_details
            if message_format is not None:
                self._values["message_format"] = message_format
            if no_hex_prefix is not None:
                self._values["no_hex_prefix"] = no_hex_prefix
            if partition_include_schema_table is not None:
                self._values["partition_include_schema_table"] = partition_include_schema_table
            if service_access_role_arn is not None:
                self._values["service_access_role_arn"] = service_access_role_arn
            if stream_arn is not None:
                self._values["stream_arn"] = stream_arn

        @builtins.property
        def include_control_details(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Shows detailed control information for table definition, column definition, and table and column changes in the Kinesis message output.

            The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-includecontroldetails
            '''
            result = self._values.get("include_control_details")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_null_and_empty(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Include NULL and empty columns for records migrated to the endpoint.

            The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-includenullandempty
            '''
            result = self._values.get("include_null_and_empty")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_table_alter_operations(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Includes any data definition language (DDL) operations that change the table in the control data, such as ``rename-table`` , ``drop-table`` , ``add-column`` , ``drop-column`` , and ``rename-column`` .

            The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-includetablealteroperations
            '''
            result = self._values.get("include_table_alter_operations")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_transaction_details(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Provides detailed transaction information from the source database.

            This information includes a commit timestamp, a log position, and values for ``transaction_id`` , previous ``transaction_id`` , and ``transaction_record_id`` (the record offset within a transaction). The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-includetransactiondetails
            '''
            result = self._values.get("include_transaction_details")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def message_format(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-messageformat
            '''
            result = self._values.get("message_format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def no_hex_prefix(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Set this optional parameter to ``true`` to avoid adding a '0x' prefix to raw data in hexadecimal format.

            For example, by default, AWS DMS adds a '0x' prefix to the LOB column type in hexadecimal format moving from an Oracle source to an Amazon Kinesis target. Use the ``NoHexPrefix`` endpoint setting to enable migration of RAW data type columns without adding the '0x' prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-nohexprefix
            '''
            result = self._values.get("no_hex_prefix")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def partition_include_schema_table(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Prefixes schema and table names to partition values, when the partition type is ``primary-key-type`` .

            Doing this increases data distribution among Kinesis shards. For example, suppose that a SysBench schema has thousands of tables and each table has only limited range for a primary key. In this case, the same primary key is sent from thousands of tables to the same shard, which causes throttling. The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-partitionincludeschematable
            '''
            result = self._values.get("partition_include_schema_table")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def service_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-serviceaccessrolearn
            '''
            result = self._values.get("service_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def stream_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-kinesissettings.html#cfn-dms-endpoint-kinesissettings-streamarn
            '''
            result = self._values.get("stream_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KinesisSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.MicrosoftSqlServerSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
        },
    )
    class MicrosoftSqlServerSettingsProperty:
        def __init__(
            self,
            *,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-microsoftsqlserversettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                microsoft_sql_server_settings_property = dms.CfnEndpoint.MicrosoftSqlServerSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-microsoftsqlserversettings.html#cfn-dms-endpoint-microsoftsqlserversettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-microsoftsqlserversettings.html#cfn-dms-endpoint-microsoftsqlserversettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MicrosoftSqlServerSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.MongoDbSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "auth_mechanism": "authMechanism",
            "auth_source": "authSource",
            "auth_type": "authType",
            "database_name": "databaseName",
            "docs_to_investigate": "docsToInvestigate",
            "extract_doc_id": "extractDocId",
            "nesting_level": "nestingLevel",
            "password": "password",
            "port": "port",
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
            "server_name": "serverName",
            "username": "username",
        },
    )
    class MongoDbSettingsProperty:
        def __init__(
            self,
            *,
            auth_mechanism: typing.Optional[builtins.str] = None,
            auth_source: typing.Optional[builtins.str] = None,
            auth_type: typing.Optional[builtins.str] = None,
            database_name: typing.Optional[builtins.str] = None,
            docs_to_investigate: typing.Optional[builtins.str] = None,
            extract_doc_id: typing.Optional[builtins.str] = None,
            nesting_level: typing.Optional[builtins.str] = None,
            password: typing.Optional[builtins.str] = None,
            port: typing.Optional[jsii.Number] = None,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
            server_name: typing.Optional[builtins.str] = None,
            username: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param auth_mechanism: Not currently supported by AWS CloudFormation .
            :param auth_source: Not currently supported by AWS CloudFormation .
            :param auth_type: Not currently supported by AWS CloudFormation .
            :param database_name: Not currently supported by AWS CloudFormation .
            :param docs_to_investigate: Not currently supported by AWS CloudFormation .
            :param extract_doc_id: Not currently supported by AWS CloudFormation .
            :param nesting_level: Not currently supported by AWS CloudFormation .
            :param password: Not currently supported by AWS CloudFormation .
            :param port: Not currently supported by AWS CloudFormation .
            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .
            :param server_name: Not currently supported by AWS CloudFormation .
            :param username: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                mongo_db_settings_property = dms.CfnEndpoint.MongoDbSettingsProperty(
                    auth_mechanism="authMechanism",
                    auth_source="authSource",
                    auth_type="authType",
                    database_name="databaseName",
                    docs_to_investigate="docsToInvestigate",
                    extract_doc_id="extractDocId",
                    nesting_level="nestingLevel",
                    password="password",
                    port=123,
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId",
                    server_name="serverName",
                    username="username"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if auth_mechanism is not None:
                self._values["auth_mechanism"] = auth_mechanism
            if auth_source is not None:
                self._values["auth_source"] = auth_source
            if auth_type is not None:
                self._values["auth_type"] = auth_type
            if database_name is not None:
                self._values["database_name"] = database_name
            if docs_to_investigate is not None:
                self._values["docs_to_investigate"] = docs_to_investigate
            if extract_doc_id is not None:
                self._values["extract_doc_id"] = extract_doc_id
            if nesting_level is not None:
                self._values["nesting_level"] = nesting_level
            if password is not None:
                self._values["password"] = password
            if port is not None:
                self._values["port"] = port
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id
            if server_name is not None:
                self._values["server_name"] = server_name
            if username is not None:
                self._values["username"] = username

        @builtins.property
        def auth_mechanism(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-authmechanism
            '''
            result = self._values.get("auth_mechanism")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def auth_source(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-authsource
            '''
            result = self._values.get("auth_source")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def auth_type(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-authtype
            '''
            result = self._values.get("auth_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def database_name(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-databasename
            '''
            result = self._values.get("database_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def docs_to_investigate(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-docstoinvestigate
            '''
            result = self._values.get("docs_to_investigate")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def extract_doc_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-extractdocid
            '''
            result = self._values.get("extract_doc_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def nesting_level(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-nestinglevel
            '''
            result = self._values.get("nesting_level")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def password(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-password
            '''
            result = self._values.get("password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def port(self) -> typing.Optional[jsii.Number]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-port
            '''
            result = self._values.get("port")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def server_name(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-servername
            '''
            result = self._values.get("server_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def username(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html#cfn-dms-endpoint-mongodbsettings-username
            '''
            result = self._values.get("username")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MongoDbSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.MySqlSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
        },
    )
    class MySqlSettingsProperty:
        def __init__(
            self,
            *,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mysqlsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                my_sql_settings_property = dms.CfnEndpoint.MySqlSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mysqlsettings.html#cfn-dms-endpoint-mysqlsettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mysqlsettings.html#cfn-dms-endpoint-mysqlsettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MySqlSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.NeptuneSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "error_retry_duration": "errorRetryDuration",
            "iam_auth_enabled": "iamAuthEnabled",
            "max_file_size": "maxFileSize",
            "max_retry_count": "maxRetryCount",
            "s3_bucket_folder": "s3BucketFolder",
            "s3_bucket_name": "s3BucketName",
            "service_access_role_arn": "serviceAccessRoleArn",
        },
    )
    class NeptuneSettingsProperty:
        def __init__(
            self,
            *,
            error_retry_duration: typing.Optional[jsii.Number] = None,
            iam_auth_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            max_file_size: typing.Optional[jsii.Number] = None,
            max_retry_count: typing.Optional[jsii.Number] = None,
            s3_bucket_folder: typing.Optional[builtins.str] = None,
            s3_bucket_name: typing.Optional[builtins.str] = None,
            service_access_role_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Provides information that defines an Amazon Neptune endpoint.

            :param error_retry_duration: The number of milliseconds for AWS DMS to wait to retry a bulk-load of migrated graph data to the Neptune target database before raising an error. The default is 250.
            :param iam_auth_enabled: If you want AWS Identity and Access Management (IAM) authorization enabled for this endpoint, set this parameter to ``true`` . Then attach the appropriate IAM policy document to your service role specified by ``ServiceAccessRoleArn`` . The default is ``false`` .
            :param max_file_size: The maximum size in kilobytes of migrated graph data stored in a .csv file before AWS DMS bulk-loads the data to the Neptune target database. The default is 1,048,576 KB. If the bulk load is successful, AWS DMS clears the bucket, ready to store the next batch of migrated graph data.
            :param max_retry_count: The number of times for AWS DMS to retry a bulk load of migrated graph data to the Neptune target database before raising an error. The default is 5.
            :param s3_bucket_folder: A folder path where you want AWS DMS to store migrated graph data in the S3 bucket specified by ``S3BucketName``.
            :param s3_bucket_name: The name of the Amazon S3 bucket where AWS DMS can temporarily store migrated graph data in .csv files before bulk-loading it to the Neptune target database. AWS DMS maps the SQL source data to graph data before storing it in these .csv files.
            :param service_access_role_arn: The Amazon Resource Name (ARN) of the service role that you created for the Neptune target endpoint. The role must allow the ``iam:PassRole`` action. For more information, see `Creating an IAM Service Role for Accessing Amazon Neptune as a Target <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Neptune.html#CHAP_Target.Neptune.ServiceRole>`_ in the *AWS Database Migration Service User Guide.*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-neptunesettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                neptune_settings_property = dms.CfnEndpoint.NeptuneSettingsProperty(
                    error_retry_duration=123,
                    iam_auth_enabled=False,
                    max_file_size=123,
                    max_retry_count=123,
                    s3_bucket_folder="s3BucketFolder",
                    s3_bucket_name="s3BucketName",
                    service_access_role_arn="serviceAccessRoleArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if error_retry_duration is not None:
                self._values["error_retry_duration"] = error_retry_duration
            if iam_auth_enabled is not None:
                self._values["iam_auth_enabled"] = iam_auth_enabled
            if max_file_size is not None:
                self._values["max_file_size"] = max_file_size
            if max_retry_count is not None:
                self._values["max_retry_count"] = max_retry_count
            if s3_bucket_folder is not None:
                self._values["s3_bucket_folder"] = s3_bucket_folder
            if s3_bucket_name is not None:
                self._values["s3_bucket_name"] = s3_bucket_name
            if service_access_role_arn is not None:
                self._values["service_access_role_arn"] = service_access_role_arn

        @builtins.property
        def error_retry_duration(self) -> typing.Optional[jsii.Number]:
            '''The number of milliseconds for AWS DMS to wait to retry a bulk-load of migrated graph data to the Neptune target database before raising an error.

            The default is 250.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-neptunesettings.html#cfn-dms-endpoint-neptunesettings-errorretryduration
            '''
            result = self._values.get("error_retry_duration")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def iam_auth_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If you want AWS Identity and Access Management (IAM) authorization enabled for this endpoint, set this parameter to ``true`` .

            Then attach the appropriate IAM policy document to your service role specified by ``ServiceAccessRoleArn`` . The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-neptunesettings.html#cfn-dms-endpoint-neptunesettings-iamauthenabled
            '''
            result = self._values.get("iam_auth_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def max_file_size(self) -> typing.Optional[jsii.Number]:
            '''The maximum size in kilobytes of migrated graph data stored in a .csv file before AWS DMS bulk-loads the data to the Neptune target database. The default is 1,048,576 KB. If the bulk load is successful, AWS DMS clears the bucket, ready to store the next batch of migrated graph data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-neptunesettings.html#cfn-dms-endpoint-neptunesettings-maxfilesize
            '''
            result = self._values.get("max_file_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_retry_count(self) -> typing.Optional[jsii.Number]:
            '''The number of times for AWS DMS to retry a bulk load of migrated graph data to the Neptune target database before raising an error.

            The default is 5.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-neptunesettings.html#cfn-dms-endpoint-neptunesettings-maxretrycount
            '''
            result = self._values.get("max_retry_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def s3_bucket_folder(self) -> typing.Optional[builtins.str]:
            '''A folder path where you want AWS DMS to store migrated graph data in the S3 bucket specified by ``S3BucketName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-neptunesettings.html#cfn-dms-endpoint-neptunesettings-s3bucketfolder
            '''
            result = self._values.get("s3_bucket_folder")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3_bucket_name(self) -> typing.Optional[builtins.str]:
            '''The name of the Amazon S3 bucket where AWS DMS can temporarily store migrated graph data in .csv files before bulk-loading it to the Neptune target database. AWS DMS maps the SQL source data to graph data before storing it in these .csv files.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-neptunesettings.html#cfn-dms-endpoint-neptunesettings-s3bucketname
            '''
            result = self._values.get("s3_bucket_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def service_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the service role that you created for the Neptune target endpoint.

            The role must allow the ``iam:PassRole`` action. For more information, see `Creating an IAM Service Role for Accessing Amazon Neptune as a Target <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Neptune.html#CHAP_Target.Neptune.ServiceRole>`_ in the *AWS Database Migration Service User Guide.*

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-neptunesettings.html#cfn-dms-endpoint-neptunesettings-serviceaccessrolearn
            '''
            result = self._values.get("service_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NeptuneSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.OracleSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_oracle_asm_access_role_arn": "secretsManagerOracleAsmAccessRoleArn",
            "secrets_manager_oracle_asm_secret_id": "secretsManagerOracleAsmSecretId",
            "secrets_manager_secret_id": "secretsManagerSecretId",
        },
    )
    class OracleSettingsProperty:
        def __init__(
            self,
            *,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_oracle_asm_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_oracle_asm_secret_id: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_oracle_asm_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_oracle_asm_secret_id: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-oraclesettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                oracle_settings_property = dms.CfnEndpoint.OracleSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_oracle_asm_access_role_arn="secretsManagerOracleAsmAccessRoleArn",
                    secrets_manager_oracle_asm_secret_id="secretsManagerOracleAsmSecretId",
                    secrets_manager_secret_id="secretsManagerSecretId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_oracle_asm_access_role_arn is not None:
                self._values["secrets_manager_oracle_asm_access_role_arn"] = secrets_manager_oracle_asm_access_role_arn
            if secrets_manager_oracle_asm_secret_id is not None:
                self._values["secrets_manager_oracle_asm_secret_id"] = secrets_manager_oracle_asm_secret_id
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-oraclesettings.html#cfn-dms-endpoint-oraclesettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_oracle_asm_access_role_arn(
            self,
        ) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-oraclesettings.html#cfn-dms-endpoint-oraclesettings-secretsmanageroracleasmaccessrolearn
            '''
            result = self._values.get("secrets_manager_oracle_asm_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_oracle_asm_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-oraclesettings.html#cfn-dms-endpoint-oraclesettings-secretsmanageroracleasmsecretid
            '''
            result = self._values.get("secrets_manager_oracle_asm_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-oraclesettings.html#cfn-dms-endpoint-oraclesettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OracleSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.PostgreSqlSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
        },
    )
    class PostgreSqlSettingsProperty:
        def __init__(
            self,
            *,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-postgresqlsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                postgre_sql_settings_property = dms.CfnEndpoint.PostgreSqlSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-postgresqlsettings.html#cfn-dms-endpoint-postgresqlsettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-postgresqlsettings.html#cfn-dms-endpoint-postgresqlsettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PostgreSqlSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.RedisSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "auth_password": "authPassword",
            "auth_type": "authType",
            "auth_user_name": "authUserName",
            "port": "port",
            "server_name": "serverName",
            "ssl_ca_certificate_arn": "sslCaCertificateArn",
            "ssl_security_protocol": "sslSecurityProtocol",
        },
    )
    class RedisSettingsProperty:
        def __init__(
            self,
            *,
            auth_password: typing.Optional[builtins.str] = None,
            auth_type: typing.Optional[builtins.str] = None,
            auth_user_name: typing.Optional[builtins.str] = None,
            port: typing.Optional[jsii.Number] = None,
            server_name: typing.Optional[builtins.str] = None,
            ssl_ca_certificate_arn: typing.Optional[builtins.str] = None,
            ssl_security_protocol: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Provides information that defines a Redis target endpoint.

            :param auth_password: The password provided with the ``auth-role`` and ``auth-token`` options of the ``AuthType`` setting for a Redis target endpoint.
            :param auth_type: The type of authentication to perform when connecting to a Redis target. Options include ``none`` , ``auth-token`` , and ``auth-role`` . The ``auth-token`` option requires an ``AuthPassword`` value to be provided. The ``auth-role`` option requires ``AuthUserName`` and ``AuthPassword`` values to be provided.
            :param auth_user_name: The user name provided with the ``auth-role`` option of the ``AuthType`` setting for a Redis target endpoint.
            :param port: Transmission Control Protocol (TCP) port for the endpoint.
            :param server_name: Fully qualified domain name of the endpoint.
            :param ssl_ca_certificate_arn: The Amazon Resource Name (ARN) for the certificate authority (CA) that DMS uses to connect to your Redis target endpoint.
            :param ssl_security_protocol: The connection to a Redis target endpoint using Transport Layer Security (TLS). Valid values include ``plaintext`` and ``ssl-encryption`` . The default is ``ssl-encryption`` . The ``ssl-encryption`` option makes an encrypted connection. Optionally, you can identify an Amazon Resource Name (ARN) for an SSL certificate authority (CA) using the ``SslCaCertificateArn`` setting. If an ARN isn't given for a CA, DMS uses the Amazon root CA. The ``plaintext`` option doesn't provide Transport Layer Security (TLS) encryption for traffic between endpoint and database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redissettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                redis_settings_property = dms.CfnEndpoint.RedisSettingsProperty(
                    auth_password="authPassword",
                    auth_type="authType",
                    auth_user_name="authUserName",
                    port=123,
                    server_name="serverName",
                    ssl_ca_certificate_arn="sslCaCertificateArn",
                    ssl_security_protocol="sslSecurityProtocol"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if auth_password is not None:
                self._values["auth_password"] = auth_password
            if auth_type is not None:
                self._values["auth_type"] = auth_type
            if auth_user_name is not None:
                self._values["auth_user_name"] = auth_user_name
            if port is not None:
                self._values["port"] = port
            if server_name is not None:
                self._values["server_name"] = server_name
            if ssl_ca_certificate_arn is not None:
                self._values["ssl_ca_certificate_arn"] = ssl_ca_certificate_arn
            if ssl_security_protocol is not None:
                self._values["ssl_security_protocol"] = ssl_security_protocol

        @builtins.property
        def auth_password(self) -> typing.Optional[builtins.str]:
            '''The password provided with the ``auth-role`` and ``auth-token`` options of the ``AuthType`` setting for a Redis target endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redissettings.html#cfn-dms-endpoint-redissettings-authpassword
            '''
            result = self._values.get("auth_password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def auth_type(self) -> typing.Optional[builtins.str]:
            '''The type of authentication to perform when connecting to a Redis target.

            Options include ``none`` , ``auth-token`` , and ``auth-role`` . The ``auth-token`` option requires an ``AuthPassword`` value to be provided. The ``auth-role`` option requires ``AuthUserName`` and ``AuthPassword`` values to be provided.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redissettings.html#cfn-dms-endpoint-redissettings-authtype
            '''
            result = self._values.get("auth_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def auth_user_name(self) -> typing.Optional[builtins.str]:
            '''The user name provided with the ``auth-role`` option of the ``AuthType`` setting for a Redis target endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redissettings.html#cfn-dms-endpoint-redissettings-authusername
            '''
            result = self._values.get("auth_user_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def port(self) -> typing.Optional[jsii.Number]:
            '''Transmission Control Protocol (TCP) port for the endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redissettings.html#cfn-dms-endpoint-redissettings-port
            '''
            result = self._values.get("port")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def server_name(self) -> typing.Optional[builtins.str]:
            '''Fully qualified domain name of the endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redissettings.html#cfn-dms-endpoint-redissettings-servername
            '''
            result = self._values.get("server_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ssl_ca_certificate_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) for the certificate authority (CA) that DMS uses to connect to your Redis target endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redissettings.html#cfn-dms-endpoint-redissettings-sslcacertificatearn
            '''
            result = self._values.get("ssl_ca_certificate_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ssl_security_protocol(self) -> typing.Optional[builtins.str]:
            '''The connection to a Redis target endpoint using Transport Layer Security (TLS).

            Valid values include ``plaintext`` and ``ssl-encryption`` . The default is ``ssl-encryption`` . The ``ssl-encryption`` option makes an encrypted connection. Optionally, you can identify an Amazon Resource Name (ARN) for an SSL certificate authority (CA) using the ``SslCaCertificateArn`` setting. If an ARN isn't given for a CA, DMS uses the Amazon root CA.

            The ``plaintext`` option doesn't provide Transport Layer Security (TLS) encryption for traffic between endpoint and database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redissettings.html#cfn-dms-endpoint-redissettings-sslsecurityprotocol
            '''
            result = self._values.get("ssl_security_protocol")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedisSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.RedshiftSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
        },
    )
    class RedshiftSettingsProperty:
        def __init__(
            self,
            *,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redshiftsettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                redshift_settings_property = dms.CfnEndpoint.RedshiftSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redshiftsettings.html#cfn-dms-endpoint-redshiftsettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-redshiftsettings.html#cfn-dms-endpoint-redshiftsettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedshiftSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.S3SettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "add_column_name": "addColumnName",
            "bucket_folder": "bucketFolder",
            "bucket_name": "bucketName",
            "canned_acl_for_objects": "cannedAclForObjects",
            "cdc_inserts_and_updates": "cdcInsertsAndUpdates",
            "cdc_inserts_only": "cdcInsertsOnly",
            "cdc_max_batch_interval": "cdcMaxBatchInterval",
            "cdc_min_file_size": "cdcMinFileSize",
            "cdc_path": "cdcPath",
            "compression_type": "compressionType",
            "csv_delimiter": "csvDelimiter",
            "csv_no_sup_value": "csvNoSupValue",
            "csv_null_value": "csvNullValue",
            "csv_row_delimiter": "csvRowDelimiter",
            "data_format": "dataFormat",
            "data_page_size": "dataPageSize",
            "date_partition_delimiter": "datePartitionDelimiter",
            "date_partition_enabled": "datePartitionEnabled",
            "date_partition_sequence": "datePartitionSequence",
            "date_partition_timezone": "datePartitionTimezone",
            "dict_page_size_limit": "dictPageSizeLimit",
            "enable_statistics": "enableStatistics",
            "encoding_type": "encodingType",
            "encryption_mode": "encryptionMode",
            "external_table_definition": "externalTableDefinition",
            "ignore_header_rows": "ignoreHeaderRows",
            "include_op_for_full_load": "includeOpForFullLoad",
            "max_file_size": "maxFileSize",
            "parquet_timestamp_in_millisecond": "parquetTimestampInMillisecond",
            "parquet_version": "parquetVersion",
            "preserve_transactions": "preserveTransactions",
            "rfc4180": "rfc4180",
            "row_group_length": "rowGroupLength",
            "server_side_encryption_kms_key_id": "serverSideEncryptionKmsKeyId",
            "service_access_role_arn": "serviceAccessRoleArn",
            "timestamp_column_name": "timestampColumnName",
            "use_csv_no_sup_value": "useCsvNoSupValue",
            "use_task_start_time_for_full_load_timestamp": "useTaskStartTimeForFullLoadTimestamp",
        },
    )
    class S3SettingsProperty:
        def __init__(
            self,
            *,
            add_column_name: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            bucket_folder: typing.Optional[builtins.str] = None,
            bucket_name: typing.Optional[builtins.str] = None,
            canned_acl_for_objects: typing.Optional[builtins.str] = None,
            cdc_inserts_and_updates: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            cdc_inserts_only: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            cdc_max_batch_interval: typing.Optional[jsii.Number] = None,
            cdc_min_file_size: typing.Optional[jsii.Number] = None,
            cdc_path: typing.Optional[builtins.str] = None,
            compression_type: typing.Optional[builtins.str] = None,
            csv_delimiter: typing.Optional[builtins.str] = None,
            csv_no_sup_value: typing.Optional[builtins.str] = None,
            csv_null_value: typing.Optional[builtins.str] = None,
            csv_row_delimiter: typing.Optional[builtins.str] = None,
            data_format: typing.Optional[builtins.str] = None,
            data_page_size: typing.Optional[jsii.Number] = None,
            date_partition_delimiter: typing.Optional[builtins.str] = None,
            date_partition_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            date_partition_sequence: typing.Optional[builtins.str] = None,
            date_partition_timezone: typing.Optional[builtins.str] = None,
            dict_page_size_limit: typing.Optional[jsii.Number] = None,
            enable_statistics: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            encoding_type: typing.Optional[builtins.str] = None,
            encryption_mode: typing.Optional[builtins.str] = None,
            external_table_definition: typing.Optional[builtins.str] = None,
            ignore_header_rows: typing.Optional[jsii.Number] = None,
            include_op_for_full_load: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            max_file_size: typing.Optional[jsii.Number] = None,
            parquet_timestamp_in_millisecond: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            parquet_version: typing.Optional[builtins.str] = None,
            preserve_transactions: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            rfc4180: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            row_group_length: typing.Optional[jsii.Number] = None,
            server_side_encryption_kms_key_id: typing.Optional[builtins.str] = None,
            service_access_role_arn: typing.Optional[builtins.str] = None,
            timestamp_column_name: typing.Optional[builtins.str] = None,
            use_csv_no_sup_value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            use_task_start_time_for_full_load_timestamp: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param add_column_name: An optional parameter that, when set to ``true`` or ``y`` , you can use to add column name information to the .csv output file. The default value is ``false`` . Valid values are ``true`` , ``false`` , ``y`` , and ``n`` .
            :param bucket_folder: Not currently supported by AWS CloudFormation .
            :param bucket_name: Not currently supported by AWS CloudFormation .
            :param canned_acl_for_objects: A value that enables AWS DMS to specify a predefined (canned) access control list for objects created in an Amazon S3 bucket as .csv or .parquet files. For more information about Amazon S3 canned ACLs, see `Canned ACL <https://docs.aws.amazon.com/http://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl>`_ in the *Amazon S3 Developer Guide.*. The default value is NONE. Valid values include NONE, PRIVATE, PUBLIC_READ, PUBLIC_READ_WRITE, AUTHENTICATED_READ, AWS_EXEC_READ, BUCKET_OWNER_READ, and BUCKET_OWNER_FULL_CONTROL.
            :param cdc_inserts_and_updates: A value that enables a change data capture (CDC) load to write INSERT and UPDATE operations to .csv or .parquet (columnar storage) output files. The default setting is ``false`` , but when ``CdcInsertsAndUpdates`` is set to ``true`` or ``y`` , only INSERTs and UPDATEs from the source database are migrated to the .csv or .parquet file. For .csv file format only, how these INSERTs and UPDATEs are recorded depends on the value of the ``IncludeOpForFullLoad`` parameter. If ``IncludeOpForFullLoad`` is set to ``true`` , the first field of every CDC record is set to either ``I`` or ``U`` to indicate INSERT and UPDATE operations at the source. But if ``IncludeOpForFullLoad`` is set to ``false`` , CDC records are written without an indication of INSERT or UPDATE operations at the source. For more information about how these settings work together, see `Indicating Source DB Operations in Migrated S3 Data <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring.InsertOps>`_ in the *AWS Database Migration Service User Guide.* . .. epigraph:: AWS DMS supports the use of the ``CdcInsertsAndUpdates`` parameter in versions 3.3.1 and later. ``CdcInsertsOnly`` and ``CdcInsertsAndUpdates`` can't both be set to ``true`` for the same endpoint. Set either ``CdcInsertsOnly`` or ``CdcInsertsAndUpdates`` to ``true`` for the same endpoint, but not both.
            :param cdc_inserts_only: A value that enables a change data capture (CDC) load to write only INSERT operations to .csv or columnar storage (.parquet) output files. By default (the ``false`` setting), the first field in a .csv or .parquet record contains the letter I (INSERT), U (UPDATE), or D (DELETE). These values indicate whether the row was inserted, updated, or deleted at the source database for a CDC load to the target. If ``CdcInsertsOnly`` is set to ``true`` or ``y`` , only INSERTs from the source database are migrated to the .csv or .parquet file. For .csv format only, how these INSERTs are recorded depends on the value of ``IncludeOpForFullLoad`` . If ``IncludeOpForFullLoad`` is set to ``true`` , the first field of every CDC record is set to I to indicate the INSERT operation at the source. If ``IncludeOpForFullLoad`` is set to ``false`` , every CDC record is written without a first field to indicate the INSERT operation at the source. For more information about how these settings work together, see `Indicating Source DB Operations in Migrated S3 Data <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring.InsertOps>`_ in the *AWS Database Migration Service User Guide.* . .. epigraph:: AWS DMS supports the interaction described preceding between the ``CdcInsertsOnly`` and ``IncludeOpForFullLoad`` parameters in versions 3.1.4 and later. ``CdcInsertsOnly`` and ``CdcInsertsAndUpdates`` can't both be set to ``true`` for the same endpoint. Set either ``CdcInsertsOnly`` or ``CdcInsertsAndUpdates`` to ``true`` for the same endpoint, but not both.
            :param cdc_max_batch_interval: Maximum length of the interval, defined in seconds, after which to output a file to Amazon S3. When ``CdcMaxBatchInterval`` and ``CdcMinFileSize`` are both specified, the file write is triggered by whichever parameter condition is met first within an AWS DMS CloudFormation template. The default value is 60 seconds.
            :param cdc_min_file_size: Minimum file size, defined in megabytes, to reach for a file output to Amazon S3. When ``CdcMinFileSize`` and ``CdcMaxBatchInterval`` are both specified, the file write is triggered by whichever parameter condition is met first within an AWS DMS CloudFormation template. The default value is 32 MB.
            :param cdc_path: Specifies the folder path of CDC files. For an S3 source, this setting is required if a task captures change data; otherwise, it's optional. If ``CdcPath`` is set, AWS DMS reads CDC files from this path and replicates the data changes to the target endpoint. For an S3 target if you set ```PreserveTransactions`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-PreserveTransactions>`_ to ``true`` , AWS DMS verifies that you have set this parameter to a folder path on your S3 target where AWS DMS can save the transaction order for the CDC load. AWS DMS creates this CDC folder path in either your S3 target working directory or the S3 target location specified by ```BucketFolder`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-BucketFolder>`_ and ```BucketName`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-BucketName>`_ . For example, if you specify ``CdcPath`` as ``MyChangedData`` , and you specify ``BucketName`` as ``MyTargetBucket`` but do not specify ``BucketFolder`` , AWS DMS creates the CDC folder path following: ``MyTargetBucket/MyChangedData`` . If you specify the same ``CdcPath`` , and you specify ``BucketName`` as ``MyTargetBucket`` and ``BucketFolder`` as ``MyTargetData`` , AWS DMS creates the CDC folder path following: ``MyTargetBucket/MyTargetData/MyChangedData`` . For more information on CDC including transaction order on an S3 target, see `Capturing data changes (CDC) including transaction order on the S3 target <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.EndpointSettings.CdcPath>`_ . .. epigraph:: This setting is supported in AWS DMS versions 3.4.2 and later.
            :param compression_type: Not currently supported by AWS CloudFormation .
            :param csv_delimiter: Not currently supported by AWS CloudFormation .
            :param csv_no_sup_value: This setting only applies if your Amazon S3 output files during a change data capture (CDC) load are written in .csv format. If ```UseCsvNoSupValue`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-UseCsvNoSupValue>`_ is set to true, specify a string value that you want AWS DMS to use for all columns not included in the supplemental log. If you do not specify a string value, AWS DMS uses the null value for these columns regardless of the ``UseCsvNoSupValue`` setting. .. epigraph:: This setting is supported in AWS DMS versions 3.4.1 and later.
            :param csv_null_value: An optional parameter that specifies how AWS DMS treats null values. While handling the null value, you can use this parameter to pass a user-defined string as null when writing to the target. For example, when target columns are not nullable, you can use this option to differentiate between the empty string value and the null value. So, if you set this parameter value to the empty string ("" or ''), AWS DMS treats the empty string as the null value instead of ``NULL`` . The default value is ``NULL`` . Valid values include any valid string.
            :param csv_row_delimiter: Not currently supported by AWS CloudFormation .
            :param data_format: The format of the data that you want to use for output. You can choose one of the following:. - ``csv`` : This is a row-based file format with comma-separated values (.csv). - ``parquet`` : Apache Parquet (.parquet) is a columnar storage file format that features efficient compression and provides faster query response.
            :param data_page_size: The size of one data page in bytes. This parameter defaults to 1024 * 1024 bytes (1 MiB). This number is used for .parquet file format only.
            :param date_partition_delimiter: Specifies a date separating delimiter to use during folder partitioning. The default value is ``SLASH`` . Use this parameter when ``DatePartitionedEnabled`` is set to ``true`` .
            :param date_partition_enabled: When set to ``true`` , this parameter partitions S3 bucket folders based on transaction commit dates. The default value is ``false`` . For more information about date-based folder partitioning, see `Using date-based folder partitioning <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.DatePartitioning>`_ .
            :param date_partition_sequence: Identifies the sequence of the date format to use during folder partitioning. The default value is ``YYYYMMDD`` . Use this parameter when ``DatePartitionedEnabled`` is set to ``true`` .
            :param date_partition_timezone: When creating an S3 target endpoint, set ``DatePartitionTimezone`` to convert the current UTC time into a specified time zone. The conversion occurs when a date partition folder is created and a CDC filename is generated. The time zone format is Area/Location. Use this parameter when ``DatePartitionedEnabled`` is set to ``true`` , as shown in the following example. ``s3-settings='{"DatePartitionEnabled": true, "DatePartitionSequence": "YYYYMMDDHH", "DatePartitionDelimiter": "SLASH", "DatePartitionTimezone":" *Asia/Seoul* ", "BucketName": "dms-nattarat-test"}'``
            :param dict_page_size_limit: The maximum size of an encoded dictionary page of a column. If the dictionary page exceeds this, this column is stored using an encoding type of ``PLAIN`` . This parameter defaults to 1024 * 1024 bytes (1 MiB), the maximum size of a dictionary page before it reverts to ``PLAIN`` encoding. This size is used for .parquet file format only.
            :param enable_statistics: A value that enables statistics for Parquet pages and row groups. Choose ``true`` to enable statistics, ``false`` to disable. Statistics include ``NULL`` , ``DISTINCT`` , ``MAX`` , and ``MIN`` values. This parameter defaults to ``true`` . This value is used for .parquet file format only.
            :param encoding_type: The type of encoding you are using:. - ``RLE_DICTIONARY`` uses a combination of bit-packing and run-length encoding to store repeated values more efficiently. This is the default. - ``PLAIN`` doesn't use encoding at all. Values are stored as they are. - ``PLAIN_DICTIONARY`` builds a dictionary of the values encountered in a given column. The dictionary is stored in a dictionary page for each column chunk.
            :param encryption_mode: The type of server-side encryption that you want to use for your data. This encryption type is part of the endpoint settings or the extra connections attributes for Amazon S3. You can choose either ``SSE_S3`` (the default) or ``SSE_KMS`` . .. epigraph:: For the ``ModifyEndpoint`` operation, you can change the existing value of the ``EncryptionMode`` parameter from ``SSE_KMS`` to ``SSE_S3`` . But you can’t change the existing value from ``SSE_S3`` to ``SSE_KMS`` . To use ``SSE_S3`` , you need an AWS Identity and Access Management (IAM) role with permission to allow ``"arn:aws:s3:::dms-*"`` to use the following actions: - ``s3:CreateBucket`` - ``s3:ListBucket`` - ``s3:DeleteBucket`` - ``s3:GetBucketLocation`` - ``s3:GetObject`` - ``s3:PutObject`` - ``s3:DeleteObject`` - ``s3:GetObjectVersion`` - ``s3:GetBucketPolicy`` - ``s3:PutBucketPolicy`` - ``s3:DeleteBucketPolicy``
            :param external_table_definition: Not currently supported by AWS CloudFormation .
            :param ignore_header_rows: When this value is set to 1, AWS DMS ignores the first row header in a .csv file. A value of 1 turns on the feature; a value of 0 turns off the feature. The default is 0.
            :param include_op_for_full_load: A value that enables a full load to write INSERT operations to the comma-separated value (.csv) output files only to indicate how the rows were added to the source database. .. epigraph:: AWS DMS supports the ``IncludeOpForFullLoad`` parameter in versions 3.1.4 and later. For full load, records can only be inserted. By default (the ``false`` setting), no information is recorded in these output files for a full load to indicate that the rows were inserted at the source database. If ``IncludeOpForFullLoad`` is set to ``true`` or ``y`` , the INSERT is recorded as an I annotation in the first field of the .csv file. This allows the format of your target records from a full load to be consistent with the target records from a CDC load. .. epigraph:: This setting works together with the ``CdcInsertsOnly`` and the ``CdcInsertsAndUpdates`` parameters for output to .csv files only. For more information about how these settings work together, see `Indicating Source DB Operations in Migrated S3 Data <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring.InsertOps>`_ in the *AWS Database Migration Service User Guide.* .
            :param max_file_size: A value that specifies the maximum size (in KB) of any .csv file to be created while migrating to an S3 target during full load. The default value is 1,048,576 KB (1 GB). Valid values include 1 to 1,048,576.
            :param parquet_timestamp_in_millisecond: A value that specifies the precision of any ``TIMESTAMP`` column values that are written to an Amazon S3 object file in .parquet format. .. epigraph:: AWS DMS supports the ``ParquetTimestampInMillisecond`` parameter in versions 3.1.4 and later. When ``ParquetTimestampInMillisecond`` is set to ``true`` or ``y`` , AWS DMS writes all ``TIMESTAMP`` columns in a .parquet formatted file with millisecond precision. Otherwise, DMS writes them with microsecond precision. Currently, Amazon Athena and AWS Glue can handle only millisecond precision for ``TIMESTAMP`` values. Set this parameter to ``true`` for S3 endpoint object files that are .parquet formatted only if you plan to query or process the data with Athena or AWS Glue . .. epigraph:: AWS DMS writes any ``TIMESTAMP`` column values written to an S3 file in .csv format with microsecond precision. Setting ``ParquetTimestampInMillisecond`` has no effect on the string format of the timestamp column value that is inserted by setting the ``TimestampColumnName`` parameter.
            :param parquet_version: The version of the Apache Parquet format that you want to use: ``parquet_1_0`` (the default) or ``parquet_2_0`` .
            :param preserve_transactions: If set to ``true`` , AWS DMS saves the transaction order for a change data capture (CDC) load on the Amazon S3 target specified by ```CdcPath`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-CdcPath>`_ . For more information, see `Capturing data changes (CDC) including transaction order on the S3 target <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.EndpointSettings.CdcPath>`_ . .. epigraph:: This setting is supported in AWS DMS versions 3.4.2 and later.
            :param rfc4180: For an S3 source, when this value is set to ``true`` or ``y`` , each leading double quotation mark has to be followed by an ending double quotation mark. This formatting complies with RFC 4180. When this value is set to ``false`` or ``n`` , string literals are copied to the target as is. In this case, a delimiter (row or column) signals the end of the field. Thus, you can't use a delimiter as part of the string, because it signals the end of the value. For an S3 target, an optional parameter used to set behavior to comply with RFC 4180 for data migrated to Amazon S3 using .csv file format only. When this value is set to ``true`` or ``y`` using Amazon S3 as a target, if the data has quotation marks or newline characters in it, AWS DMS encloses the entire column with an additional pair of double quotation marks ("). Every quotation mark within the data is repeated twice. The default value is ``true`` . Valid values include ``true`` , ``false`` , ``y`` , and ``n`` .
            :param row_group_length: The number of rows in a row group. A smaller row group size provides faster reads. But as the number of row groups grows, the slower writes become. This parameter defaults to 10,000 rows. This number is used for .parquet file format only. If you choose a value larger than the maximum, ``RowGroupLength`` is set to the max row group length in bytes (64 * 1024 * 1024).
            :param server_side_encryption_kms_key_id: If you are using ``SSE_KMS`` for the ``EncryptionMode`` , provide the AWS KMS key ID. The key that you use needs an attached policy that enables AWS Identity and Access Management (IAM) user permissions and allows use of the key. Here is a CLI example: ``aws dms create-endpoint --endpoint-identifier *value* --endpoint-type target --engine-name s3 --s3-settings ServiceAccessRoleArn= *value* ,BucketFolder= *value* ,BucketName= *value* ,EncryptionMode=SSE_KMS,ServerSideEncryptionKmsKeyId= *value*``
            :param service_access_role_arn: Not currently supported by AWS CloudFormation .
            :param timestamp_column_name: A value that when nonblank causes AWS DMS to add a column with timestamp information to the endpoint data for an Amazon S3 target. .. epigraph:: AWS DMS supports the ``TimestampColumnName`` parameter in versions 3.1.4 and later. DMS includes an additional ``STRING`` column in the .csv or .parquet object files of your migrated data when you set ``TimestampColumnName`` to a nonblank value. For a full load, each row of this timestamp column contains a timestamp for when the data was transferred from the source to the target by DMS. For a change data capture (CDC) load, each row of the timestamp column contains the timestamp for the commit of that row in the source database. The string format for this timestamp column value is ``yyyy-MM-dd HH:mm:ss.SSSSSS`` . By default, the precision of this value is in microseconds. For a CDC load, the rounding of the precision depends on the commit timestamp supported by DMS for the source database. When the ``AddColumnName`` parameter is set to ``true`` , DMS also includes a name for the timestamp column that you set with ``TimestampColumnName`` .
            :param use_csv_no_sup_value: This setting applies if the S3 output files during a change data capture (CDC) load are written in .csv format. If set to ``true`` for columns not included in the supplemental log, AWS DMS uses the value specified by ```CsvNoSupValue`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-CsvNoSupValue>`_ . If not set or set to ``false`` , AWS DMS uses the null value for these columns. .. epigraph:: This setting is supported in AWS DMS versions 3.4.1 and later.
            :param use_task_start_time_for_full_load_timestamp: When set to true, this parameter uses the task start time as the timestamp column value instead of the time data is written to target. For full load, when ``useTaskStartTimeForFullLoadTimestamp`` is set to ``true`` , each row of the timestamp column contains the task start time. For CDC loads, each row of the timestamp column contains the transaction commit time. When ``useTaskStartTimeForFullLoadTimestamp`` is set to ``false`` , the full load timestamp in the timestamp column increments with the time data arrives at the target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                s3_settings_property = dms.CfnEndpoint.S3SettingsProperty(
                    add_column_name=False,
                    bucket_folder="bucketFolder",
                    bucket_name="bucketName",
                    canned_acl_for_objects="cannedAclForObjects",
                    cdc_inserts_and_updates=False,
                    cdc_inserts_only=False,
                    cdc_max_batch_interval=123,
                    cdc_min_file_size=123,
                    cdc_path="cdcPath",
                    compression_type="compressionType",
                    csv_delimiter="csvDelimiter",
                    csv_no_sup_value="csvNoSupValue",
                    csv_null_value="csvNullValue",
                    csv_row_delimiter="csvRowDelimiter",
                    data_format="dataFormat",
                    data_page_size=123,
                    date_partition_delimiter="datePartitionDelimiter",
                    date_partition_enabled=False,
                    date_partition_sequence="datePartitionSequence",
                    date_partition_timezone="datePartitionTimezone",
                    dict_page_size_limit=123,
                    enable_statistics=False,
                    encoding_type="encodingType",
                    encryption_mode="encryptionMode",
                    external_table_definition="externalTableDefinition",
                    ignore_header_rows=123,
                    include_op_for_full_load=False,
                    max_file_size=123,
                    parquet_timestamp_in_millisecond=False,
                    parquet_version="parquetVersion",
                    preserve_transactions=False,
                    rfc4180=False,
                    row_group_length=123,
                    server_side_encryption_kms_key_id="serverSideEncryptionKmsKeyId",
                    service_access_role_arn="serviceAccessRoleArn",
                    timestamp_column_name="timestampColumnName",
                    use_csv_no_sup_value=False,
                    use_task_start_time_for_full_load_timestamp=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if add_column_name is not None:
                self._values["add_column_name"] = add_column_name
            if bucket_folder is not None:
                self._values["bucket_folder"] = bucket_folder
            if bucket_name is not None:
                self._values["bucket_name"] = bucket_name
            if canned_acl_for_objects is not None:
                self._values["canned_acl_for_objects"] = canned_acl_for_objects
            if cdc_inserts_and_updates is not None:
                self._values["cdc_inserts_and_updates"] = cdc_inserts_and_updates
            if cdc_inserts_only is not None:
                self._values["cdc_inserts_only"] = cdc_inserts_only
            if cdc_max_batch_interval is not None:
                self._values["cdc_max_batch_interval"] = cdc_max_batch_interval
            if cdc_min_file_size is not None:
                self._values["cdc_min_file_size"] = cdc_min_file_size
            if cdc_path is not None:
                self._values["cdc_path"] = cdc_path
            if compression_type is not None:
                self._values["compression_type"] = compression_type
            if csv_delimiter is not None:
                self._values["csv_delimiter"] = csv_delimiter
            if csv_no_sup_value is not None:
                self._values["csv_no_sup_value"] = csv_no_sup_value
            if csv_null_value is not None:
                self._values["csv_null_value"] = csv_null_value
            if csv_row_delimiter is not None:
                self._values["csv_row_delimiter"] = csv_row_delimiter
            if data_format is not None:
                self._values["data_format"] = data_format
            if data_page_size is not None:
                self._values["data_page_size"] = data_page_size
            if date_partition_delimiter is not None:
                self._values["date_partition_delimiter"] = date_partition_delimiter
            if date_partition_enabled is not None:
                self._values["date_partition_enabled"] = date_partition_enabled
            if date_partition_sequence is not None:
                self._values["date_partition_sequence"] = date_partition_sequence
            if date_partition_timezone is not None:
                self._values["date_partition_timezone"] = date_partition_timezone
            if dict_page_size_limit is not None:
                self._values["dict_page_size_limit"] = dict_page_size_limit
            if enable_statistics is not None:
                self._values["enable_statistics"] = enable_statistics
            if encoding_type is not None:
                self._values["encoding_type"] = encoding_type
            if encryption_mode is not None:
                self._values["encryption_mode"] = encryption_mode
            if external_table_definition is not None:
                self._values["external_table_definition"] = external_table_definition
            if ignore_header_rows is not None:
                self._values["ignore_header_rows"] = ignore_header_rows
            if include_op_for_full_load is not None:
                self._values["include_op_for_full_load"] = include_op_for_full_load
            if max_file_size is not None:
                self._values["max_file_size"] = max_file_size
            if parquet_timestamp_in_millisecond is not None:
                self._values["parquet_timestamp_in_millisecond"] = parquet_timestamp_in_millisecond
            if parquet_version is not None:
                self._values["parquet_version"] = parquet_version
            if preserve_transactions is not None:
                self._values["preserve_transactions"] = preserve_transactions
            if rfc4180 is not None:
                self._values["rfc4180"] = rfc4180
            if row_group_length is not None:
                self._values["row_group_length"] = row_group_length
            if server_side_encryption_kms_key_id is not None:
                self._values["server_side_encryption_kms_key_id"] = server_side_encryption_kms_key_id
            if service_access_role_arn is not None:
                self._values["service_access_role_arn"] = service_access_role_arn
            if timestamp_column_name is not None:
                self._values["timestamp_column_name"] = timestamp_column_name
            if use_csv_no_sup_value is not None:
                self._values["use_csv_no_sup_value"] = use_csv_no_sup_value
            if use_task_start_time_for_full_load_timestamp is not None:
                self._values["use_task_start_time_for_full_load_timestamp"] = use_task_start_time_for_full_load_timestamp

        @builtins.property
        def add_column_name(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''An optional parameter that, when set to ``true`` or ``y`` , you can use to add column name information to the .csv output file.

            The default value is ``false`` . Valid values are ``true`` , ``false`` , ``y`` , and ``n`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-addcolumnname
            '''
            result = self._values.get("add_column_name")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def bucket_folder(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-bucketfolder
            '''
            result = self._values.get("bucket_folder")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def bucket_name(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-bucketname
            '''
            result = self._values.get("bucket_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def canned_acl_for_objects(self) -> typing.Optional[builtins.str]:
            '''A value that enables AWS DMS to specify a predefined (canned) access control list for objects created in an Amazon S3 bucket as .csv or .parquet files. For more information about Amazon S3 canned ACLs, see `Canned ACL <https://docs.aws.amazon.com/http://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl>`_ in the *Amazon S3 Developer Guide.*.

            The default value is NONE. Valid values include NONE, PRIVATE, PUBLIC_READ, PUBLIC_READ_WRITE, AUTHENTICATED_READ, AWS_EXEC_READ, BUCKET_OWNER_READ, and BUCKET_OWNER_FULL_CONTROL.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-cannedaclforobjects
            '''
            result = self._values.get("canned_acl_for_objects")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def cdc_inserts_and_updates(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A value that enables a change data capture (CDC) load to write INSERT and UPDATE operations to .csv or .parquet (columnar storage) output files. The default setting is ``false`` , but when ``CdcInsertsAndUpdates`` is set to ``true`` or ``y`` , only INSERTs and UPDATEs from the source database are migrated to the .csv or .parquet file.

            For .csv file format only, how these INSERTs and UPDATEs are recorded depends on the value of the ``IncludeOpForFullLoad`` parameter. If ``IncludeOpForFullLoad`` is set to ``true`` , the first field of every CDC record is set to either ``I`` or ``U`` to indicate INSERT and UPDATE operations at the source. But if ``IncludeOpForFullLoad`` is set to ``false`` , CDC records are written without an indication of INSERT or UPDATE operations at the source. For more information about how these settings work together, see `Indicating Source DB Operations in Migrated S3 Data <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring.InsertOps>`_ in the *AWS Database Migration Service User Guide.* .
            .. epigraph::

               AWS DMS supports the use of the ``CdcInsertsAndUpdates`` parameter in versions 3.3.1 and later.

               ``CdcInsertsOnly`` and ``CdcInsertsAndUpdates`` can't both be set to ``true`` for the same endpoint. Set either ``CdcInsertsOnly`` or ``CdcInsertsAndUpdates`` to ``true`` for the same endpoint, but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-cdcinsertsandupdates
            '''
            result = self._values.get("cdc_inserts_and_updates")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def cdc_inserts_only(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A value that enables a change data capture (CDC) load to write only INSERT operations to .csv or columnar storage (.parquet) output files. By default (the ``false`` setting), the first field in a .csv or .parquet record contains the letter I (INSERT), U (UPDATE), or D (DELETE). These values indicate whether the row was inserted, updated, or deleted at the source database for a CDC load to the target.

            If ``CdcInsertsOnly`` is set to ``true`` or ``y`` , only INSERTs from the source database are migrated to the .csv or .parquet file. For .csv format only, how these INSERTs are recorded depends on the value of ``IncludeOpForFullLoad`` . If ``IncludeOpForFullLoad`` is set to ``true`` , the first field of every CDC record is set to I to indicate the INSERT operation at the source. If ``IncludeOpForFullLoad`` is set to ``false`` , every CDC record is written without a first field to indicate the INSERT operation at the source. For more information about how these settings work together, see `Indicating Source DB Operations in Migrated S3 Data <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring.InsertOps>`_ in the *AWS Database Migration Service User Guide.* .
            .. epigraph::

               AWS DMS supports the interaction described preceding between the ``CdcInsertsOnly`` and ``IncludeOpForFullLoad`` parameters in versions 3.1.4 and later.

               ``CdcInsertsOnly`` and ``CdcInsertsAndUpdates`` can't both be set to ``true`` for the same endpoint. Set either ``CdcInsertsOnly`` or ``CdcInsertsAndUpdates`` to ``true`` for the same endpoint, but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-cdcinsertsonly
            '''
            result = self._values.get("cdc_inserts_only")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def cdc_max_batch_interval(self) -> typing.Optional[jsii.Number]:
            '''Maximum length of the interval, defined in seconds, after which to output a file to Amazon S3.

            When ``CdcMaxBatchInterval`` and ``CdcMinFileSize`` are both specified, the file write is triggered by whichever parameter condition is met first within an AWS DMS CloudFormation template.

            The default value is 60 seconds.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-cdcmaxbatchinterval
            '''
            result = self._values.get("cdc_max_batch_interval")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def cdc_min_file_size(self) -> typing.Optional[jsii.Number]:
            '''Minimum file size, defined in megabytes, to reach for a file output to Amazon S3.

            When ``CdcMinFileSize`` and ``CdcMaxBatchInterval`` are both specified, the file write is triggered by whichever parameter condition is met first within an AWS DMS CloudFormation template.

            The default value is 32 MB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-cdcminfilesize
            '''
            result = self._values.get("cdc_min_file_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def cdc_path(self) -> typing.Optional[builtins.str]:
            '''Specifies the folder path of CDC files.

            For an S3 source, this setting is required if a task captures change data; otherwise, it's optional. If ``CdcPath`` is set, AWS DMS reads CDC files from this path and replicates the data changes to the target endpoint. For an S3 target if you set ```PreserveTransactions`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-PreserveTransactions>`_ to ``true`` , AWS DMS verifies that you have set this parameter to a folder path on your S3 target where AWS DMS can save the transaction order for the CDC load. AWS DMS creates this CDC folder path in either your S3 target working directory or the S3 target location specified by ```BucketFolder`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-BucketFolder>`_ and ```BucketName`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-BucketName>`_ .

            For example, if you specify ``CdcPath`` as ``MyChangedData`` , and you specify ``BucketName`` as ``MyTargetBucket`` but do not specify ``BucketFolder`` , AWS DMS creates the CDC folder path following: ``MyTargetBucket/MyChangedData`` .

            If you specify the same ``CdcPath`` , and you specify ``BucketName`` as ``MyTargetBucket`` and ``BucketFolder`` as ``MyTargetData`` , AWS DMS creates the CDC folder path following: ``MyTargetBucket/MyTargetData/MyChangedData`` .

            For more information on CDC including transaction order on an S3 target, see `Capturing data changes (CDC) including transaction order on the S3 target <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.EndpointSettings.CdcPath>`_ .
            .. epigraph::

               This setting is supported in AWS DMS versions 3.4.2 and later.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-cdcpath
            '''
            result = self._values.get("cdc_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def compression_type(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-compressiontype
            '''
            result = self._values.get("compression_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def csv_delimiter(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-csvdelimiter
            '''
            result = self._values.get("csv_delimiter")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def csv_no_sup_value(self) -> typing.Optional[builtins.str]:
            '''This setting only applies if your Amazon S3 output files during a change data capture (CDC) load are written in .csv format. If ```UseCsvNoSupValue`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-UseCsvNoSupValue>`_ is set to true, specify a string value that you want AWS DMS to use for all columns not included in the supplemental log. If you do not specify a string value, AWS DMS uses the null value for these columns regardless of the ``UseCsvNoSupValue`` setting.

            .. epigraph::

               This setting is supported in AWS DMS versions 3.4.1 and later.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-csvnosupvalue
            '''
            result = self._values.get("csv_no_sup_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def csv_null_value(self) -> typing.Optional[builtins.str]:
            '''An optional parameter that specifies how AWS DMS treats null values.

            While handling the null value, you can use this parameter to pass a user-defined string as null when writing to the target. For example, when target columns are not nullable, you can use this option to differentiate between the empty string value and the null value. So, if you set this parameter value to the empty string ("" or ''), AWS DMS treats the empty string as the null value instead of ``NULL`` .

            The default value is ``NULL`` . Valid values include any valid string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-csvnullvalue
            '''
            result = self._values.get("csv_null_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def csv_row_delimiter(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-csvrowdelimiter
            '''
            result = self._values.get("csv_row_delimiter")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def data_format(self) -> typing.Optional[builtins.str]:
            '''The format of the data that you want to use for output. You can choose one of the following:.

            - ``csv`` : This is a row-based file format with comma-separated values (.csv).
            - ``parquet`` : Apache Parquet (.parquet) is a columnar storage file format that features efficient compression and provides faster query response.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-dataformat
            '''
            result = self._values.get("data_format")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def data_page_size(self) -> typing.Optional[jsii.Number]:
            '''The size of one data page in bytes.

            This parameter defaults to 1024 * 1024 bytes (1 MiB). This number is used for .parquet file format only.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-datapagesize
            '''
            result = self._values.get("data_page_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def date_partition_delimiter(self) -> typing.Optional[builtins.str]:
            '''Specifies a date separating delimiter to use during folder partitioning.

            The default value is ``SLASH`` . Use this parameter when ``DatePartitionedEnabled`` is set to ``true`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-datepartitiondelimiter
            '''
            result = self._values.get("date_partition_delimiter")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def date_partition_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When set to ``true`` , this parameter partitions S3 bucket folders based on transaction commit dates.

            The default value is ``false`` . For more information about date-based folder partitioning, see `Using date-based folder partitioning <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.DatePartitioning>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-datepartitionenabled
            '''
            result = self._values.get("date_partition_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def date_partition_sequence(self) -> typing.Optional[builtins.str]:
            '''Identifies the sequence of the date format to use during folder partitioning.

            The default value is ``YYYYMMDD`` . Use this parameter when ``DatePartitionedEnabled`` is set to ``true`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-datepartitionsequence
            '''
            result = self._values.get("date_partition_sequence")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def date_partition_timezone(self) -> typing.Optional[builtins.str]:
            '''When creating an S3 target endpoint, set ``DatePartitionTimezone`` to convert the current UTC time into a specified time zone.

            The conversion occurs when a date partition folder is created and a CDC filename is generated. The time zone format is Area/Location. Use this parameter when ``DatePartitionedEnabled`` is set to ``true`` , as shown in the following example.

            ``s3-settings='{"DatePartitionEnabled": true, "DatePartitionSequence": "YYYYMMDDHH", "DatePartitionDelimiter": "SLASH", "DatePartitionTimezone":" *Asia/Seoul* ", "BucketName": "dms-nattarat-test"}'``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-datepartitiontimezone
            '''
            result = self._values.get("date_partition_timezone")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def dict_page_size_limit(self) -> typing.Optional[jsii.Number]:
            '''The maximum size of an encoded dictionary page of a column.

            If the dictionary page exceeds this, this column is stored using an encoding type of ``PLAIN`` . This parameter defaults to 1024 * 1024 bytes (1 MiB), the maximum size of a dictionary page before it reverts to ``PLAIN`` encoding. This size is used for .parquet file format only.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-dictpagesizelimit
            '''
            result = self._values.get("dict_page_size_limit")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def enable_statistics(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A value that enables statistics for Parquet pages and row groups.

            Choose ``true`` to enable statistics, ``false`` to disable. Statistics include ``NULL`` , ``DISTINCT`` , ``MAX`` , and ``MIN`` values. This parameter defaults to ``true`` . This value is used for .parquet file format only.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-enablestatistics
            '''
            result = self._values.get("enable_statistics")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def encoding_type(self) -> typing.Optional[builtins.str]:
            '''The type of encoding you are using:.

            - ``RLE_DICTIONARY`` uses a combination of bit-packing and run-length encoding to store repeated values more efficiently. This is the default.
            - ``PLAIN`` doesn't use encoding at all. Values are stored as they are.
            - ``PLAIN_DICTIONARY`` builds a dictionary of the values encountered in a given column. The dictionary is stored in a dictionary page for each column chunk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-encodingtype
            '''
            result = self._values.get("encoding_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def encryption_mode(self) -> typing.Optional[builtins.str]:
            '''The type of server-side encryption that you want to use for your data.

            This encryption type is part of the endpoint settings or the extra connections attributes for Amazon S3. You can choose either ``SSE_S3`` (the default) or ``SSE_KMS`` .
            .. epigraph::

               For the ``ModifyEndpoint`` operation, you can change the existing value of the ``EncryptionMode`` parameter from ``SSE_KMS`` to ``SSE_S3`` . But you can’t change the existing value from ``SSE_S3`` to ``SSE_KMS`` .

            To use ``SSE_S3`` , you need an AWS Identity and Access Management (IAM) role with permission to allow ``"arn:aws:s3:::dms-*"`` to use the following actions:

            - ``s3:CreateBucket``
            - ``s3:ListBucket``
            - ``s3:DeleteBucket``
            - ``s3:GetBucketLocation``
            - ``s3:GetObject``
            - ``s3:PutObject``
            - ``s3:DeleteObject``
            - ``s3:GetObjectVersion``
            - ``s3:GetBucketPolicy``
            - ``s3:PutBucketPolicy``
            - ``s3:DeleteBucketPolicy``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-encryptionmode
            '''
            result = self._values.get("encryption_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def external_table_definition(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-externaltabledefinition
            '''
            result = self._values.get("external_table_definition")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def ignore_header_rows(self) -> typing.Optional[jsii.Number]:
            '''When this value is set to 1, AWS DMS ignores the first row header in a .csv file. A value of 1 turns on the feature; a value of 0 turns off the feature.

            The default is 0.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-ignoreheaderrows
            '''
            result = self._values.get("ignore_header_rows")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def include_op_for_full_load(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A value that enables a full load to write INSERT operations to the comma-separated value (.csv) output files only to indicate how the rows were added to the source database.

            .. epigraph::

               AWS DMS supports the ``IncludeOpForFullLoad`` parameter in versions 3.1.4 and later.

            For full load, records can only be inserted. By default (the ``false`` setting), no information is recorded in these output files for a full load to indicate that the rows were inserted at the source database. If ``IncludeOpForFullLoad`` is set to ``true`` or ``y`` , the INSERT is recorded as an I annotation in the first field of the .csv file. This allows the format of your target records from a full load to be consistent with the target records from a CDC load.
            .. epigraph::

               This setting works together with the ``CdcInsertsOnly`` and the ``CdcInsertsAndUpdates`` parameters for output to .csv files only. For more information about how these settings work together, see `Indicating Source DB Operations in Migrated S3 Data <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring.InsertOps>`_ in the *AWS Database Migration Service User Guide.* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-includeopforfullload
            '''
            result = self._values.get("include_op_for_full_load")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def max_file_size(self) -> typing.Optional[jsii.Number]:
            '''A value that specifies the maximum size (in KB) of any .csv file to be created while migrating to an S3 target during full load.

            The default value is 1,048,576 KB (1 GB). Valid values include 1 to 1,048,576.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-maxfilesize
            '''
            result = self._values.get("max_file_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def parquet_timestamp_in_millisecond(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A value that specifies the precision of any ``TIMESTAMP`` column values that are written to an Amazon S3 object file in .parquet format.

            .. epigraph::

               AWS DMS supports the ``ParquetTimestampInMillisecond`` parameter in versions 3.1.4 and later.

            When ``ParquetTimestampInMillisecond`` is set to ``true`` or ``y`` , AWS DMS writes all ``TIMESTAMP`` columns in a .parquet formatted file with millisecond precision. Otherwise, DMS writes them with microsecond precision.

            Currently, Amazon Athena and AWS Glue can handle only millisecond precision for ``TIMESTAMP`` values. Set this parameter to ``true`` for S3 endpoint object files that are .parquet formatted only if you plan to query or process the data with Athena or AWS Glue .
            .. epigraph::

               AWS DMS writes any ``TIMESTAMP`` column values written to an S3 file in .csv format with microsecond precision.

               Setting ``ParquetTimestampInMillisecond`` has no effect on the string format of the timestamp column value that is inserted by setting the ``TimestampColumnName`` parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-parquettimestampinmillisecond
            '''
            result = self._values.get("parquet_timestamp_in_millisecond")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def parquet_version(self) -> typing.Optional[builtins.str]:
            '''The version of the Apache Parquet format that you want to use: ``parquet_1_0`` (the default) or ``parquet_2_0`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-parquetversion
            '''
            result = self._values.get("parquet_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def preserve_transactions(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If set to ``true`` , AWS DMS saves the transaction order for a change data capture (CDC) load on the Amazon S3 target specified by ```CdcPath`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-CdcPath>`_ . For more information, see `Capturing data changes (CDC) including transaction order on the S3 target <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.EndpointSettings.CdcPath>`_ .

            .. epigraph::

               This setting is supported in AWS DMS versions 3.4.2 and later.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-preservetransactions
            '''
            result = self._values.get("preserve_transactions")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def rfc4180(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''For an S3 source, when this value is set to ``true`` or ``y`` , each leading double quotation mark has to be followed by an ending double quotation mark.

            This formatting complies with RFC 4180. When this value is set to ``false`` or ``n`` , string literals are copied to the target as is. In this case, a delimiter (row or column) signals the end of the field. Thus, you can't use a delimiter as part of the string, because it signals the end of the value.

            For an S3 target, an optional parameter used to set behavior to comply with RFC 4180 for data migrated to Amazon S3 using .csv file format only. When this value is set to ``true`` or ``y`` using Amazon S3 as a target, if the data has quotation marks or newline characters in it, AWS DMS encloses the entire column with an additional pair of double quotation marks ("). Every quotation mark within the data is repeated twice.

            The default value is ``true`` . Valid values include ``true`` , ``false`` , ``y`` , and ``n`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-rfc4180
            '''
            result = self._values.get("rfc4180")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def row_group_length(self) -> typing.Optional[jsii.Number]:
            '''The number of rows in a row group.

            A smaller row group size provides faster reads. But as the number of row groups grows, the slower writes become. This parameter defaults to 10,000 rows. This number is used for .parquet file format only.

            If you choose a value larger than the maximum, ``RowGroupLength`` is set to the max row group length in bytes (64 * 1024 * 1024).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-rowgrouplength
            '''
            result = self._values.get("row_group_length")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def server_side_encryption_kms_key_id(self) -> typing.Optional[builtins.str]:
            '''If you are using ``SSE_KMS`` for the ``EncryptionMode`` , provide the AWS KMS key ID.

            The key that you use needs an attached policy that enables AWS Identity and Access Management (IAM) user permissions and allows use of the key.

            Here is a CLI example: ``aws dms create-endpoint --endpoint-identifier *value* --endpoint-type target --engine-name s3 --s3-settings ServiceAccessRoleArn= *value* ,BucketFolder= *value* ,BucketName= *value* ,EncryptionMode=SSE_KMS,ServerSideEncryptionKmsKeyId= *value*``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-serversideencryptionkmskeyid
            '''
            result = self._values.get("server_side_encryption_kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def service_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-serviceaccessrolearn
            '''
            result = self._values.get("service_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def timestamp_column_name(self) -> typing.Optional[builtins.str]:
            '''A value that when nonblank causes AWS DMS to add a column with timestamp information to the endpoint data for an Amazon S3 target.

            .. epigraph::

               AWS DMS supports the ``TimestampColumnName`` parameter in versions 3.1.4 and later.

            DMS includes an additional ``STRING`` column in the .csv or .parquet object files of your migrated data when you set ``TimestampColumnName`` to a nonblank value.

            For a full load, each row of this timestamp column contains a timestamp for when the data was transferred from the source to the target by DMS.

            For a change data capture (CDC) load, each row of the timestamp column contains the timestamp for the commit of that row in the source database.

            The string format for this timestamp column value is ``yyyy-MM-dd HH:mm:ss.SSSSSS`` . By default, the precision of this value is in microseconds. For a CDC load, the rounding of the precision depends on the commit timestamp supported by DMS for the source database.

            When the ``AddColumnName`` parameter is set to ``true`` , DMS also includes a name for the timestamp column that you set with ``TimestampColumnName`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-timestampcolumnname
            '''
            result = self._values.get("timestamp_column_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def use_csv_no_sup_value(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''This setting applies if the S3 output files during a change data capture (CDC) load are written in .csv format. If set to ``true`` for columns not included in the supplemental log, AWS DMS uses the value specified by ```CsvNoSupValue`` <https://docs.aws.amazon.com/dms/latest/APIReference/API_S3Settings.html#DMS-Type-S3Settings-CsvNoSupValue>`_ . If not set or set to ``false`` , AWS DMS uses the null value for these columns.

            .. epigraph::

               This setting is supported in AWS DMS versions 3.4.1 and later.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-usecsvnosupvalue
            '''
            result = self._values.get("use_csv_no_sup_value")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def use_task_start_time_for_full_load_timestamp(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When set to true, this parameter uses the task start time as the timestamp column value instead of the time data is written to target.

            For full load, when ``useTaskStartTimeForFullLoadTimestamp`` is set to ``true`` , each row of the timestamp column contains the task start time. For CDC loads, each row of the timestamp column contains the transaction commit time.

            When ``useTaskStartTimeForFullLoadTimestamp`` is set to ``false`` , the full load timestamp in the timestamp column increments with the time data arrives at the target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html#cfn-dms-endpoint-s3settings-usetaskstarttimeforfullloadtimestamp
            '''
            result = self._values.get("use_task_start_time_for_full_load_timestamp")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3SettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_dms.CfnEndpoint.SybaseSettingsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "secrets_manager_access_role_arn": "secretsManagerAccessRoleArn",
            "secrets_manager_secret_id": "secretsManagerSecretId",
        },
    )
    class SybaseSettingsProperty:
        def __init__(
            self,
            *,
            secrets_manager_access_role_arn: typing.Optional[builtins.str] = None,
            secrets_manager_secret_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Not currently supported by AWS CloudFormation .

            :param secrets_manager_access_role_arn: Not currently supported by AWS CloudFormation .
            :param secrets_manager_secret_id: Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-sybasesettings.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_dms as dms
                
                sybase_settings_property = dms.CfnEndpoint.SybaseSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if secrets_manager_access_role_arn is not None:
                self._values["secrets_manager_access_role_arn"] = secrets_manager_access_role_arn
            if secrets_manager_secret_id is not None:
                self._values["secrets_manager_secret_id"] = secrets_manager_secret_id

        @builtins.property
        def secrets_manager_access_role_arn(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-sybasesettings.html#cfn-dms-endpoint-sybasesettings-secretsmanageraccessrolearn
            '''
            result = self._values.get("secrets_manager_access_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secrets_manager_secret_id(self) -> typing.Optional[builtins.str]:
            '''Not currently supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-sybasesettings.html#cfn-dms-endpoint-sybasesettings-secretsmanagersecretid
            '''
            result = self._values.get("secrets_manager_secret_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SybaseSettingsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_dms.CfnEndpointProps",
    jsii_struct_bases=[],
    name_mapping={
        "endpoint_type": "endpointType",
        "engine_name": "engineName",
        "certificate_arn": "certificateArn",
        "database_name": "databaseName",
        "doc_db_settings": "docDbSettings",
        "dynamo_db_settings": "dynamoDbSettings",
        "elasticsearch_settings": "elasticsearchSettings",
        "endpoint_identifier": "endpointIdentifier",
        "extra_connection_attributes": "extraConnectionAttributes",
        "gcp_my_sql_settings": "gcpMySqlSettings",
        "ibm_db2_settings": "ibmDb2Settings",
        "kafka_settings": "kafkaSettings",
        "kinesis_settings": "kinesisSettings",
        "kms_key_id": "kmsKeyId",
        "microsoft_sql_server_settings": "microsoftSqlServerSettings",
        "mongo_db_settings": "mongoDbSettings",
        "my_sql_settings": "mySqlSettings",
        "neptune_settings": "neptuneSettings",
        "oracle_settings": "oracleSettings",
        "password": "password",
        "port": "port",
        "postgre_sql_settings": "postgreSqlSettings",
        "redis_settings": "redisSettings",
        "redshift_settings": "redshiftSettings",
        "resource_identifier": "resourceIdentifier",
        "s3_settings": "s3Settings",
        "server_name": "serverName",
        "ssl_mode": "sslMode",
        "sybase_settings": "sybaseSettings",
        "tags": "tags",
        "username": "username",
    },
)
class CfnEndpointProps:
    def __init__(
        self,
        *,
        endpoint_type: builtins.str,
        engine_name: builtins.str,
        certificate_arn: typing.Optional[builtins.str] = None,
        database_name: typing.Optional[builtins.str] = None,
        doc_db_settings: typing.Optional[typing.Union[CfnEndpoint.DocDbSettingsProperty, _IResolvable_da3f097b]] = None,
        dynamo_db_settings: typing.Optional[typing.Union[CfnEndpoint.DynamoDbSettingsProperty, _IResolvable_da3f097b]] = None,
        elasticsearch_settings: typing.Optional[typing.Union[CfnEndpoint.ElasticsearchSettingsProperty, _IResolvable_da3f097b]] = None,
        endpoint_identifier: typing.Optional[builtins.str] = None,
        extra_connection_attributes: typing.Optional[builtins.str] = None,
        gcp_my_sql_settings: typing.Optional[typing.Union[CfnEndpoint.GcpMySQLSettingsProperty, _IResolvable_da3f097b]] = None,
        ibm_db2_settings: typing.Optional[typing.Union[CfnEndpoint.IbmDb2SettingsProperty, _IResolvable_da3f097b]] = None,
        kafka_settings: typing.Optional[typing.Union[CfnEndpoint.KafkaSettingsProperty, _IResolvable_da3f097b]] = None,
        kinesis_settings: typing.Optional[typing.Union[CfnEndpoint.KinesisSettingsProperty, _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        microsoft_sql_server_settings: typing.Optional[typing.Union[CfnEndpoint.MicrosoftSqlServerSettingsProperty, _IResolvable_da3f097b]] = None,
        mongo_db_settings: typing.Optional[typing.Union[CfnEndpoint.MongoDbSettingsProperty, _IResolvable_da3f097b]] = None,
        my_sql_settings: typing.Optional[typing.Union[CfnEndpoint.MySqlSettingsProperty, _IResolvable_da3f097b]] = None,
        neptune_settings: typing.Optional[typing.Union[CfnEndpoint.NeptuneSettingsProperty, _IResolvable_da3f097b]] = None,
        oracle_settings: typing.Optional[typing.Union[CfnEndpoint.OracleSettingsProperty, _IResolvable_da3f097b]] = None,
        password: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        postgre_sql_settings: typing.Optional[typing.Union[CfnEndpoint.PostgreSqlSettingsProperty, _IResolvable_da3f097b]] = None,
        redis_settings: typing.Optional[typing.Union[CfnEndpoint.RedisSettingsProperty, _IResolvable_da3f097b]] = None,
        redshift_settings: typing.Optional[typing.Union[CfnEndpoint.RedshiftSettingsProperty, _IResolvable_da3f097b]] = None,
        resource_identifier: typing.Optional[builtins.str] = None,
        s3_settings: typing.Optional[typing.Union[CfnEndpoint.S3SettingsProperty, _IResolvable_da3f097b]] = None,
        server_name: typing.Optional[builtins.str] = None,
        ssl_mode: typing.Optional[builtins.str] = None,
        sybase_settings: typing.Optional[typing.Union[CfnEndpoint.SybaseSettingsProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        username: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnEndpoint``.

        :param endpoint_type: The type of endpoint. Valid values are ``source`` and ``target`` .
        :param engine_name: The type of engine for the endpoint. Valid values, depending on the ``EndpointType`` value, include ``"mysql"`` , ``"oracle"`` , ``"postgres"`` , ``"mariadb"`` , ``"aurora"`` , ``"aurora-postgresql"`` , ``"opensearch"`` , ``"redshift"`` , ``"s3"`` , ``"db2"`` , ``"azuredb"`` , ``"sybase"`` , ``"dynamodb"`` , ``"mongodb"`` , ``"kinesis"`` , ``"kafka"`` , ``"elasticsearch"`` , ``"docdb"`` , ``"sqlserver"`` , and ``"neptune"`` .
        :param certificate_arn: The Amazon Resource Name (ARN) for the certificate.
        :param database_name: The name of the endpoint database. For a MySQL source or target endpoint, do not specify DatabaseName. To migrate to a specific database, use this setting and ``targetDbType`` .
        :param doc_db_settings: Settings in JSON format for the source DocumentDB endpoint. For more information about the available settings, see the configuration properties section in `Using DocumentDB as a Target for AWS Database Migration Service <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.DocumentDB.html>`_ in the *AWS Database Migration Service User Guide.*
        :param dynamo_db_settings: Settings in JSON format for the target Amazon DynamoDB endpoint. For information about other available settings, see `Using Object Mapping to Migrate Data to DynamoDB <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.DynamoDB.html#CHAP_Target.DynamoDB.ObjectMapping>`_ in the *AWS Database Migration Service User Guide.*
        :param elasticsearch_settings: Settings in JSON format for the target OpenSearch endpoint. For more information about the available settings, see `Extra Connection Attributes When Using OpenSearch as a Target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Elasticsearch.html#CHAP_Target.Elasticsearch.Configuration>`_ in the *AWS Database Migration Service User Guide* .
        :param endpoint_identifier: The database endpoint identifier. Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.
        :param extra_connection_attributes: Additional attributes associated with the connection. Each attribute is specified as a name-value pair associated by an equal sign (=). Multiple attributes are separated by a semicolon (;) with no additional white space. For information on the attributes available for connecting your source or target endpoint, see `Working with AWS DMS Endpoints <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Endpoints.html>`_ in the *AWS Database Migration Service User Guide.*
        :param gcp_my_sql_settings: Settings in JSON format for the source GCP MySQL endpoint.
        :param ibm_db2_settings: Not currently supported by AWS CloudFormation .
        :param kafka_settings: Settings in JSON format for the target Apache Kafka endpoint. For more information about the available settings, see `Using object mapping to migrate data to a Kafka topic <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Kafka.html#CHAP_Target.Kafka.ObjectMapping>`_ in the *AWS Database Migration Service User Guide.*
        :param kinesis_settings: Settings in JSON format for the target endpoint for Amazon Kinesis Data Streams. For more information about the available settings, see `Using Amazon Kinesis Data Streams as a Target for AWS Database Migration Service <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Kinesis.html>`_ in the *AWS Database Migration Service User Guide.*
        :param kms_key_id: An AWS KMS key identifier that is used to encrypt the connection parameters for the endpoint. If you don't specify a value for the ``KmsKeyId`` parameter, then AWS DMS uses your default encryption key. AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Region .
        :param microsoft_sql_server_settings: Not currently supported by AWS CloudFormation .
        :param mongo_db_settings: Not currently supported by AWS CloudFormation .
        :param my_sql_settings: Settings in JSON format for the source and target MySQL endpoint. For information about other available settings, see `Extra connection attributes when using MySQL as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.MySQL.html#CHAP_Source.MySQL.ConnectionAttrib>`_ and `Extra connection attributes when using a MySQL-compatible database as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.MySQL.html#CHAP_Target.MySQL.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*
        :param neptune_settings: ``AWS::DMS::Endpoint.NeptuneSettings``.
        :param oracle_settings: Settings in JSON format for the source and target Oracle endpoint. For information about other available settings, see `Extra connection attributes when using Oracle as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.Oracle.html#CHAP_Source.Oracle.ConnectionAttrib>`_ and `Extra connection attributes when using Oracle as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Oracle.html#CHAP_Target.Oracle.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*
        :param password: The password to be used to log in to the endpoint database.
        :param port: The port used by the endpoint database.
        :param postgre_sql_settings: Not currently supported by AWS CloudFormation .
        :param redis_settings: Settings in JSON format for the target Redis endpoint.
        :param redshift_settings: Not currently supported by AWS CloudFormation .
        :param resource_identifier: A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object. The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .
        :param s3_settings: Settings in JSON format for the target Amazon S3 endpoint. For more information about the available settings, see `Extra Connection Attributes When Using Amazon S3 as a Target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring>`_ in the *AWS Database Migration Service User Guide.*
        :param server_name: The name of the server where the endpoint database resides.
        :param ssl_mode: The Secure Sockets Layer (SSL) mode to use for the SSL connection. The default is ``none`` . .. epigraph:: When ``engine_name`` is set to S3, then the only allowed value is ``none`` .
        :param sybase_settings: Settings in JSON format for the source and target SAP ASE endpoint. For information about other available settings, see `Extra connection attributes when using SAP ASE as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.SAP.html#CHAP_Source.SAP.ConnectionAttrib>`_ and `Extra connection attributes when using SAP ASE as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.SAP.html#CHAP_Target.SAP.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*
        :param tags: One or more tags to be assigned to the endpoint.
        :param username: The user name to be used to log in to the endpoint database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_dms as dms
            
            cfn_endpoint_props = dms.CfnEndpointProps(
                endpoint_type="endpointType",
                engine_name="engineName",
            
                # the properties below are optional
                certificate_arn="certificateArn",
                database_name="databaseName",
                doc_db_settings=dms.CfnEndpoint.DocDbSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                ),
                dynamo_db_settings=dms.CfnEndpoint.DynamoDbSettingsProperty(
                    service_access_role_arn="serviceAccessRoleArn"
                ),
                elasticsearch_settings=dms.CfnEndpoint.ElasticsearchSettingsProperty(
                    endpoint_uri="endpointUri",
                    error_retry_duration=123,
                    full_load_error_percentage=123,
                    service_access_role_arn="serviceAccessRoleArn"
                ),
                endpoint_identifier="endpointIdentifier",
                extra_connection_attributes="extraConnectionAttributes",
                gcp_my_sql_settings=dms.CfnEndpoint.GcpMySQLSettingsProperty(
                    after_connect_script="afterConnectScript",
                    clean_source_metadata_on_mismatch=False,
                    database_name="databaseName",
                    events_poll_interval=123,
                    max_file_size=123,
                    parallel_load_threads=123,
                    password="password",
                    port=123,
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId",
                    server_name="serverName",
                    server_timezone="serverTimezone",
                    username="username"
                ),
                ibm_db2_settings=dms.CfnEndpoint.IbmDb2SettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                ),
                kafka_settings=dms.CfnEndpoint.KafkaSettingsProperty(
                    broker="broker",
                    include_control_details=False,
                    include_null_and_empty=False,
                    include_table_alter_operations=False,
                    include_transaction_details=False,
                    no_hex_prefix=False,
                    partition_include_schema_table=False,
                    sasl_password="saslPassword",
                    sasl_user_name="saslUserName",
                    security_protocol="securityProtocol",
                    ssl_ca_certificate_arn="sslCaCertificateArn",
                    ssl_client_certificate_arn="sslClientCertificateArn",
                    ssl_client_key_arn="sslClientKeyArn",
                    ssl_client_key_password="sslClientKeyPassword",
                    topic="topic"
                ),
                kinesis_settings=dms.CfnEndpoint.KinesisSettingsProperty(
                    include_control_details=False,
                    include_null_and_empty=False,
                    include_table_alter_operations=False,
                    include_transaction_details=False,
                    message_format="messageFormat",
                    no_hex_prefix=False,
                    partition_include_schema_table=False,
                    service_access_role_arn="serviceAccessRoleArn",
                    stream_arn="streamArn"
                ),
                kms_key_id="kmsKeyId",
                microsoft_sql_server_settings=dms.CfnEndpoint.MicrosoftSqlServerSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                ),
                mongo_db_settings=dms.CfnEndpoint.MongoDbSettingsProperty(
                    auth_mechanism="authMechanism",
                    auth_source="authSource",
                    auth_type="authType",
                    database_name="databaseName",
                    docs_to_investigate="docsToInvestigate",
                    extract_doc_id="extractDocId",
                    nesting_level="nestingLevel",
                    password="password",
                    port=123,
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId",
                    server_name="serverName",
                    username="username"
                ),
                my_sql_settings=dms.CfnEndpoint.MySqlSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                ),
                neptune_settings=dms.CfnEndpoint.NeptuneSettingsProperty(
                    error_retry_duration=123,
                    iam_auth_enabled=False,
                    max_file_size=123,
                    max_retry_count=123,
                    s3_bucket_folder="s3BucketFolder",
                    s3_bucket_name="s3BucketName",
                    service_access_role_arn="serviceAccessRoleArn"
                ),
                oracle_settings=dms.CfnEndpoint.OracleSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_oracle_asm_access_role_arn="secretsManagerOracleAsmAccessRoleArn",
                    secrets_manager_oracle_asm_secret_id="secretsManagerOracleAsmSecretId",
                    secrets_manager_secret_id="secretsManagerSecretId"
                ),
                password="password",
                port=123,
                postgre_sql_settings=dms.CfnEndpoint.PostgreSqlSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                ),
                redis_settings=dms.CfnEndpoint.RedisSettingsProperty(
                    auth_password="authPassword",
                    auth_type="authType",
                    auth_user_name="authUserName",
                    port=123,
                    server_name="serverName",
                    ssl_ca_certificate_arn="sslCaCertificateArn",
                    ssl_security_protocol="sslSecurityProtocol"
                ),
                redshift_settings=dms.CfnEndpoint.RedshiftSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                ),
                resource_identifier="resourceIdentifier",
                s3_settings=dms.CfnEndpoint.S3SettingsProperty(
                    add_column_name=False,
                    bucket_folder="bucketFolder",
                    bucket_name="bucketName",
                    canned_acl_for_objects="cannedAclForObjects",
                    cdc_inserts_and_updates=False,
                    cdc_inserts_only=False,
                    cdc_max_batch_interval=123,
                    cdc_min_file_size=123,
                    cdc_path="cdcPath",
                    compression_type="compressionType",
                    csv_delimiter="csvDelimiter",
                    csv_no_sup_value="csvNoSupValue",
                    csv_null_value="csvNullValue",
                    csv_row_delimiter="csvRowDelimiter",
                    data_format="dataFormat",
                    data_page_size=123,
                    date_partition_delimiter="datePartitionDelimiter",
                    date_partition_enabled=False,
                    date_partition_sequence="datePartitionSequence",
                    date_partition_timezone="datePartitionTimezone",
                    dict_page_size_limit=123,
                    enable_statistics=False,
                    encoding_type="encodingType",
                    encryption_mode="encryptionMode",
                    external_table_definition="externalTableDefinition",
                    ignore_header_rows=123,
                    include_op_for_full_load=False,
                    max_file_size=123,
                    parquet_timestamp_in_millisecond=False,
                    parquet_version="parquetVersion",
                    preserve_transactions=False,
                    rfc4180=False,
                    row_group_length=123,
                    server_side_encryption_kms_key_id="serverSideEncryptionKmsKeyId",
                    service_access_role_arn="serviceAccessRoleArn",
                    timestamp_column_name="timestampColumnName",
                    use_csv_no_sup_value=False,
                    use_task_start_time_for_full_load_timestamp=False
                ),
                server_name="serverName",
                ssl_mode="sslMode",
                sybase_settings=dms.CfnEndpoint.SybaseSettingsProperty(
                    secrets_manager_access_role_arn="secretsManagerAccessRoleArn",
                    secrets_manager_secret_id="secretsManagerSecretId"
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                username="username"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "endpoint_type": endpoint_type,
            "engine_name": engine_name,
        }
        if certificate_arn is not None:
            self._values["certificate_arn"] = certificate_arn
        if database_name is not None:
            self._values["database_name"] = database_name
        if doc_db_settings is not None:
            self._values["doc_db_settings"] = doc_db_settings
        if dynamo_db_settings is not None:
            self._values["dynamo_db_settings"] = dynamo_db_settings
        if elasticsearch_settings is not None:
            self._values["elasticsearch_settings"] = elasticsearch_settings
        if endpoint_identifier is not None:
            self._values["endpoint_identifier"] = endpoint_identifier
        if extra_connection_attributes is not None:
            self._values["extra_connection_attributes"] = extra_connection_attributes
        if gcp_my_sql_settings is not None:
            self._values["gcp_my_sql_settings"] = gcp_my_sql_settings
        if ibm_db2_settings is not None:
            self._values["ibm_db2_settings"] = ibm_db2_settings
        if kafka_settings is not None:
            self._values["kafka_settings"] = kafka_settings
        if kinesis_settings is not None:
            self._values["kinesis_settings"] = kinesis_settings
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if microsoft_sql_server_settings is not None:
            self._values["microsoft_sql_server_settings"] = microsoft_sql_server_settings
        if mongo_db_settings is not None:
            self._values["mongo_db_settings"] = mongo_db_settings
        if my_sql_settings is not None:
            self._values["my_sql_settings"] = my_sql_settings
        if neptune_settings is not None:
            self._values["neptune_settings"] = neptune_settings
        if oracle_settings is not None:
            self._values["oracle_settings"] = oracle_settings
        if password is not None:
            self._values["password"] = password
        if port is not None:
            self._values["port"] = port
        if postgre_sql_settings is not None:
            self._values["postgre_sql_settings"] = postgre_sql_settings
        if redis_settings is not None:
            self._values["redis_settings"] = redis_settings
        if redshift_settings is not None:
            self._values["redshift_settings"] = redshift_settings
        if resource_identifier is not None:
            self._values["resource_identifier"] = resource_identifier
        if s3_settings is not None:
            self._values["s3_settings"] = s3_settings
        if server_name is not None:
            self._values["server_name"] = server_name
        if ssl_mode is not None:
            self._values["ssl_mode"] = ssl_mode
        if sybase_settings is not None:
            self._values["sybase_settings"] = sybase_settings
        if tags is not None:
            self._values["tags"] = tags
        if username is not None:
            self._values["username"] = username

    @builtins.property
    def endpoint_type(self) -> builtins.str:
        '''The type of endpoint.

        Valid values are ``source`` and ``target`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-endpointtype
        '''
        result = self._values.get("endpoint_type")
        assert result is not None, "Required property 'endpoint_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def engine_name(self) -> builtins.str:
        '''The type of engine for the endpoint.

        Valid values, depending on the ``EndpointType`` value, include ``"mysql"`` , ``"oracle"`` , ``"postgres"`` , ``"mariadb"`` , ``"aurora"`` , ``"aurora-postgresql"`` , ``"opensearch"`` , ``"redshift"`` , ``"s3"`` , ``"db2"`` , ``"azuredb"`` , ``"sybase"`` , ``"dynamodb"`` , ``"mongodb"`` , ``"kinesis"`` , ``"kafka"`` , ``"elasticsearch"`` , ``"docdb"`` , ``"sqlserver"`` , and ``"neptune"`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename
        '''
        result = self._values.get("engine_name")
        assert result is not None, "Required property 'engine_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def certificate_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) for the certificate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-certificatearn
        '''
        result = self._values.get("certificate_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def database_name(self) -> typing.Optional[builtins.str]:
        '''The name of the endpoint database.

        For a MySQL source or target endpoint, do not specify DatabaseName. To migrate to a specific database, use this setting and ``targetDbType`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-databasename
        '''
        result = self._values.get("database_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def doc_db_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.DocDbSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source DocumentDB endpoint.

        For more information about the available settings, see the configuration properties section in `Using DocumentDB as a Target for AWS Database Migration Service <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.DocumentDB.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-docdbsettings
        '''
        result = self._values.get("doc_db_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.DocDbSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def dynamo_db_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.DynamoDbSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target Amazon DynamoDB endpoint.

        For information about other available settings, see `Using Object Mapping to Migrate Data to DynamoDB <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.DynamoDB.html#CHAP_Target.DynamoDB.ObjectMapping>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-dynamodbsettings
        '''
        result = self._values.get("dynamo_db_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.DynamoDbSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def elasticsearch_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.ElasticsearchSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target OpenSearch endpoint.

        For more information about the available settings, see `Extra Connection Attributes When Using OpenSearch as a Target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Elasticsearch.html#CHAP_Target.Elasticsearch.Configuration>`_ in the *AWS Database Migration Service User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-elasticsearchsettings
        '''
        result = self._values.get("elasticsearch_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.ElasticsearchSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def endpoint_identifier(self) -> typing.Optional[builtins.str]:
        '''The database endpoint identifier.

        Identifiers must begin with a letter and must contain only ASCII letters, digits, and hyphens. They can't end with a hyphen, or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-endpointidentifier
        '''
        result = self._values.get("endpoint_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def extra_connection_attributes(self) -> typing.Optional[builtins.str]:
        '''Additional attributes associated with the connection.

        Each attribute is specified as a name-value pair associated by an equal sign (=). Multiple attributes are separated by a semicolon (;) with no additional white space. For information on the attributes available for connecting your source or target endpoint, see `Working with AWS DMS Endpoints <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Endpoints.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-extraconnectionattributes
        '''
        result = self._values.get("extra_connection_attributes")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def gcp_my_sql_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.GcpMySQLSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source GCP MySQL endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-gcpmysqlsettings
        '''
        result = self._values.get("gcp_my_sql_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.GcpMySQLSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def ibm_db2_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.IbmDb2SettingsProperty, _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-ibmdb2settings
        '''
        result = self._values.get("ibm_db2_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.IbmDb2SettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def kafka_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.KafkaSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target Apache Kafka endpoint.

        For more information about the available settings, see `Using object mapping to migrate data to a Kafka topic <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Kafka.html#CHAP_Target.Kafka.ObjectMapping>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-kafkasettings
        '''
        result = self._values.get("kafka_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.KafkaSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def kinesis_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.KinesisSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target endpoint for Amazon Kinesis Data Streams.

        For more information about the available settings, see `Using Amazon Kinesis Data Streams as a Target for AWS Database Migration Service <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Kinesis.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-kinesissettings
        '''
        result = self._values.get("kinesis_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.KinesisSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''An AWS KMS key identifier that is used to encrypt the connection parameters for the endpoint.

        If you don't specify a value for the ``KmsKeyId`` parameter, then AWS DMS uses your default encryption key.

        AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Region .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def microsoft_sql_server_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.MicrosoftSqlServerSettingsProperty, _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-microsoftsqlserversettings
        '''
        result = self._values.get("microsoft_sql_server_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.MicrosoftSqlServerSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def mongo_db_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.MongoDbSettingsProperty, _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-mongodbsettings
        '''
        result = self._values.get("mongo_db_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.MongoDbSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def my_sql_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.MySqlSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source and target MySQL endpoint.

        For information about other available settings, see `Extra connection attributes when using MySQL as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.MySQL.html#CHAP_Source.MySQL.ConnectionAttrib>`_ and `Extra connection attributes when using a MySQL-compatible database as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.MySQL.html#CHAP_Target.MySQL.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-mysqlsettings
        '''
        result = self._values.get("my_sql_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.MySqlSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def neptune_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.NeptuneSettingsProperty, _IResolvable_da3f097b]]:
        '''``AWS::DMS::Endpoint.NeptuneSettings``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-neptunesettings
        '''
        result = self._values.get("neptune_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.NeptuneSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def oracle_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.OracleSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source and target Oracle endpoint.

        For information about other available settings, see `Extra connection attributes when using Oracle as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.Oracle.html#CHAP_Source.Oracle.ConnectionAttrib>`_ and `Extra connection attributes when using Oracle as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.Oracle.html#CHAP_Target.Oracle.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-oraclesettings
        '''
        result = self._values.get("oracle_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.OracleSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def password(self) -> typing.Optional[builtins.str]:
        '''The password to be used to log in to the endpoint database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-password
        '''
        result = self._values.get("password")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port used by the endpoint database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-port
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def postgre_sql_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.PostgreSqlSettingsProperty, _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-postgresqlsettings
        '''
        result = self._values.get("postgre_sql_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.PostgreSqlSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def redis_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.RedisSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target Redis endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-redissettings
        '''
        result = self._values.get("redis_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.RedisSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def redshift_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.RedshiftSettingsProperty, _IResolvable_da3f097b]]:
        '''Not currently supported by AWS CloudFormation .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-redshiftsettings
        '''
        result = self._values.get("redshift_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.RedshiftSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def resource_identifier(self) -> typing.Optional[builtins.str]:
        '''A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object.

        The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-resourceidentifier
        '''
        result = self._values.get("resource_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def s3_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.S3SettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the target Amazon S3 endpoint.

        For more information about the available settings, see `Extra Connection Attributes When Using Amazon S3 as a Target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html#CHAP_Target.S3.Configuring>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-s3settings
        '''
        result = self._values.get("s3_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.S3SettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def server_name(self) -> typing.Optional[builtins.str]:
        '''The name of the server where the endpoint database resides.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-servername
        '''
        result = self._values.get("server_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ssl_mode(self) -> typing.Optional[builtins.str]:
        '''The Secure Sockets Layer (SSL) mode to use for the SSL connection. The default is ``none`` .

        .. epigraph::

           When ``engine_name`` is set to S3, then the only allowed value is ``none`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-sslmode
        '''
        result = self._values.get("ssl_mode")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sybase_settings(
        self,
    ) -> typing.Optional[typing.Union[CfnEndpoint.SybaseSettingsProperty, _IResolvable_da3f097b]]:
        '''Settings in JSON format for the source and target SAP ASE endpoint.

        For information about other available settings, see `Extra connection attributes when using SAP ASE as a source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.SAP.html#CHAP_Source.SAP.ConnectionAttrib>`_ and `Extra connection attributes when using SAP ASE as a target for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.SAP.html#CHAP_Target.SAP.ConnectionAttrib>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-sybasesettings
        '''
        result = self._values.get("sybase_settings")
        return typing.cast(typing.Optional[typing.Union[CfnEndpoint.SybaseSettingsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''One or more tags to be assigned to the endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def username(self) -> typing.Optional[builtins.str]:
        '''The user name to be used to log in to the endpoint database.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-username
        '''
        result = self._values.get("username")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnEndpointProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnEventSubscription(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_dms.CfnEventSubscription",
):
    '''A CloudFormation ``AWS::DMS::EventSubscription``.

    Use the ``AWS::DMS::EventSubscription`` resource to get notifications for AWS Database Migration Service events through the Amazon Simple Notification Service. For more information, see `Using AWS DMS Event Notification <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Events.html>`_ in the *AWS Database Migration Service User Guide.*

    :cloudformationResource: AWS::DMS::EventSubscription
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_dms as dms
        
        cfn_event_subscription = dms.CfnEventSubscription(self, "MyCfnEventSubscription",
            sns_topic_arn="snsTopicArn",
        
            # the properties below are optional
            enabled=False,
            event_categories=["eventCategories"],
            source_ids=["sourceIds"],
            source_type="sourceType",
            subscription_name="subscriptionName",
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
        sns_topic_arn: builtins.str,
        enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        event_categories: typing.Optional[typing.Sequence[builtins.str]] = None,
        source_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        source_type: typing.Optional[builtins.str] = None,
        subscription_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::DMS::EventSubscription``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param sns_topic_arn: The Amazon Resource Name (ARN) of the Amazon SNS topic created for event notification. The ARN is created by Amazon SNS when you create a topic and subscribe to it.
        :param enabled: Indicates whether to activate the subscription. If you don't specify this property, AWS CloudFormation activates the subscription.
        :param event_categories: A list of event categories for a source type that you want to subscribe to. If you don't specify this property, you are notified about all event categories. For more information, see `Working with Events and Notifications <https://docs.aws.amazon.com//dms/latest/userguide/CHAP_Events.html>`_ in the *AWS DMS User Guide* .
        :param source_ids: A list of identifiers for which AWS DMS provides notification events. If you don't specify a value, notifications are provided for all sources. If you specify multiple values, they must be of the same type. For example, if you specify a database instance ID, then all of the other values must be database instance IDs.
        :param source_type: The type of AWS DMS resource that generates the events. For example, if you want to be notified of events generated by a replication instance, you set this parameter to ``replication-instance`` . If this value isn't specified, all events are returned. Valid values: ``replication-instance`` | ``replication-task``
        :param subscription_name: The name of the AWS DMS event notification subscription. This name must be less than 255 characters.
        :param tags: One or more tags to be assigned to the event subscription.
        '''
        props = CfnEventSubscriptionProps(
            sns_topic_arn=sns_topic_arn,
            enabled=enabled,
            event_categories=event_categories,
            source_ids=source_ids,
            source_type=source_type,
            subscription_name=subscription_name,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''One or more tags to be assigned to the event subscription.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snsTopicArn")
    def sns_topic_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the Amazon SNS topic created for event notification.

        The ARN is created by Amazon SNS when you create a topic and subscribe to it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-snstopicarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "snsTopicArn"))

    @sns_topic_arn.setter
    def sns_topic_arn(self, value: builtins.str) -> None:
        jsii.set(self, "snsTopicArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enabled")
    def enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether to activate the subscription.

        If you don't specify this property, AWS CloudFormation activates the subscription.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-enabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enabled"))

    @enabled.setter
    def enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventCategories")
    def event_categories(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of event categories for a source type that you want to subscribe to.

        If you don't specify this property, you are notified about all event categories. For more information, see `Working with Events and Notifications <https://docs.aws.amazon.com//dms/latest/userguide/CHAP_Events.html>`_ in the *AWS DMS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-eventcategories
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "eventCategories"))

    @event_categories.setter
    def event_categories(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "eventCategories", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceIds")
    def source_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of identifiers for which AWS DMS provides notification events.

        If you don't specify a value, notifications are provided for all sources.

        If you specify multiple values, they must be of the same type. For example, if you specify a database instance ID, then all of the other values must be database instance IDs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-sourceids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "sourceIds"))

    @source_ids.setter
    def source_ids(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "sourceIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceType")
    def source_type(self) -> typing.Optional[builtins.str]:
        '''The type of AWS DMS resource that generates the events.

        For example, if you want to be notified of events generated by a replication instance, you set this parameter to ``replication-instance`` . If this value isn't specified, all events are returned.

        Valid values: ``replication-instance`` | ``replication-task``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-sourcetype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "sourceType"))

    @source_type.setter
    def source_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "sourceType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subscriptionName")
    def subscription_name(self) -> typing.Optional[builtins.str]:
        '''The name of the AWS DMS event notification subscription.

        This name must be less than 255 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-subscriptionname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "subscriptionName"))

    @subscription_name.setter
    def subscription_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "subscriptionName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_dms.CfnEventSubscriptionProps",
    jsii_struct_bases=[],
    name_mapping={
        "sns_topic_arn": "snsTopicArn",
        "enabled": "enabled",
        "event_categories": "eventCategories",
        "source_ids": "sourceIds",
        "source_type": "sourceType",
        "subscription_name": "subscriptionName",
        "tags": "tags",
    },
)
class CfnEventSubscriptionProps:
    def __init__(
        self,
        *,
        sns_topic_arn: builtins.str,
        enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        event_categories: typing.Optional[typing.Sequence[builtins.str]] = None,
        source_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        source_type: typing.Optional[builtins.str] = None,
        subscription_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnEventSubscription``.

        :param sns_topic_arn: The Amazon Resource Name (ARN) of the Amazon SNS topic created for event notification. The ARN is created by Amazon SNS when you create a topic and subscribe to it.
        :param enabled: Indicates whether to activate the subscription. If you don't specify this property, AWS CloudFormation activates the subscription.
        :param event_categories: A list of event categories for a source type that you want to subscribe to. If you don't specify this property, you are notified about all event categories. For more information, see `Working with Events and Notifications <https://docs.aws.amazon.com//dms/latest/userguide/CHAP_Events.html>`_ in the *AWS DMS User Guide* .
        :param source_ids: A list of identifiers for which AWS DMS provides notification events. If you don't specify a value, notifications are provided for all sources. If you specify multiple values, they must be of the same type. For example, if you specify a database instance ID, then all of the other values must be database instance IDs.
        :param source_type: The type of AWS DMS resource that generates the events. For example, if you want to be notified of events generated by a replication instance, you set this parameter to ``replication-instance`` . If this value isn't specified, all events are returned. Valid values: ``replication-instance`` | ``replication-task``
        :param subscription_name: The name of the AWS DMS event notification subscription. This name must be less than 255 characters.
        :param tags: One or more tags to be assigned to the event subscription.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_dms as dms
            
            cfn_event_subscription_props = dms.CfnEventSubscriptionProps(
                sns_topic_arn="snsTopicArn",
            
                # the properties below are optional
                enabled=False,
                event_categories=["eventCategories"],
                source_ids=["sourceIds"],
                source_type="sourceType",
                subscription_name="subscriptionName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "sns_topic_arn": sns_topic_arn,
        }
        if enabled is not None:
            self._values["enabled"] = enabled
        if event_categories is not None:
            self._values["event_categories"] = event_categories
        if source_ids is not None:
            self._values["source_ids"] = source_ids
        if source_type is not None:
            self._values["source_type"] = source_type
        if subscription_name is not None:
            self._values["subscription_name"] = subscription_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def sns_topic_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the Amazon SNS topic created for event notification.

        The ARN is created by Amazon SNS when you create a topic and subscribe to it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-snstopicarn
        '''
        result = self._values.get("sns_topic_arn")
        assert result is not None, "Required property 'sns_topic_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether to activate the subscription.

        If you don't specify this property, AWS CloudFormation activates the subscription.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-enabled
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def event_categories(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of event categories for a source type that you want to subscribe to.

        If you don't specify this property, you are notified about all event categories. For more information, see `Working with Events and Notifications <https://docs.aws.amazon.com//dms/latest/userguide/CHAP_Events.html>`_ in the *AWS DMS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-eventcategories
        '''
        result = self._values.get("event_categories")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def source_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of identifiers for which AWS DMS provides notification events.

        If you don't specify a value, notifications are provided for all sources.

        If you specify multiple values, they must be of the same type. For example, if you specify a database instance ID, then all of the other values must be database instance IDs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-sourceids
        '''
        result = self._values.get("source_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def source_type(self) -> typing.Optional[builtins.str]:
        '''The type of AWS DMS resource that generates the events.

        For example, if you want to be notified of events generated by a replication instance, you set this parameter to ``replication-instance`` . If this value isn't specified, all events are returned.

        Valid values: ``replication-instance`` | ``replication-task``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-sourcetype
        '''
        result = self._values.get("source_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def subscription_name(self) -> typing.Optional[builtins.str]:
        '''The name of the AWS DMS event notification subscription.

        This name must be less than 255 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-subscriptionname
        '''
        result = self._values.get("subscription_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''One or more tags to be assigned to the event subscription.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-eventsubscription.html#cfn-dms-eventsubscription-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnEventSubscriptionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnReplicationInstance(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_dms.CfnReplicationInstance",
):
    '''A CloudFormation ``AWS::DMS::ReplicationInstance``.

    The ``AWS::DMS::ReplicationInstance`` resource creates an AWS DMS replication instance.

    :cloudformationResource: AWS::DMS::ReplicationInstance
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_dms as dms
        
        cfn_replication_instance = dms.CfnReplicationInstance(self, "MyCfnReplicationInstance",
            replication_instance_class="replicationInstanceClass",
        
            # the properties below are optional
            allocated_storage=123,
            allow_major_version_upgrade=False,
            auto_minor_version_upgrade=False,
            availability_zone="availabilityZone",
            engine_version="engineVersion",
            kms_key_id="kmsKeyId",
            multi_az=False,
            preferred_maintenance_window="preferredMaintenanceWindow",
            publicly_accessible=False,
            replication_instance_identifier="replicationInstanceIdentifier",
            replication_subnet_group_identifier="replicationSubnetGroupIdentifier",
            resource_identifier="resourceIdentifier",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            vpc_security_group_ids=["vpcSecurityGroupIds"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        replication_instance_class: builtins.str,
        allocated_storage: typing.Optional[jsii.Number] = None,
        allow_major_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        auto_minor_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        availability_zone: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        multi_az: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        publicly_accessible: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        replication_instance_identifier: typing.Optional[builtins.str] = None,
        replication_subnet_group_identifier: typing.Optional[builtins.str] = None,
        resource_identifier: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::DMS::ReplicationInstance``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param replication_instance_class: The compute and memory capacity of the replication instance as defined for the specified replication instance class. For example to specify the instance class dms.c4.large, set this parameter to ``"dms.c4.large"`` . For more information on the settings and capacities for the available replication instance classes, see `Selecting the right AWS DMS replication instance for your migration <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html#CHAP_ReplicationInstance.InDepth>`_ .
        :param allocated_storage: The amount of storage (in gigabytes) to be initially allocated for the replication instance.
        :param allow_major_version_upgrade: Indicates that major version upgrades are allowed. Changing this parameter does not result in an outage, and the change is asynchronously applied as soon as possible. This parameter must be set to ``true`` when specifying a value for the ``EngineVersion`` parameter that is a different major version than the replication instance's current version.
        :param auto_minor_version_upgrade: A value that indicates whether minor engine upgrades are applied automatically to the replication instance during the maintenance window. This parameter defaults to ``true`` . Default: ``true``
        :param availability_zone: The Availability Zone that the replication instance will be created in. The default value is a random, system-chosen Availability Zone in the endpoint's AWS Region , for example: ``us-east-1d``
        :param engine_version: The engine version number of the replication instance. If an engine version number is not specified when a replication instance is created, the default is the latest engine version available.
        :param kms_key_id: An AWS KMS key identifier that is used to encrypt the data on the replication instance. If you don't specify a value for the ``KmsKeyId`` parameter, then AWS DMS uses your default encryption key. AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Region .
        :param multi_az: Specifies whether the replication instance is a Multi-AZ deployment. You can't set the ``AvailabilityZone`` parameter if the Multi-AZ parameter is set to ``true`` .
        :param preferred_maintenance_window: The weekly time range during which system maintenance can occur, in Universal Coordinated Time (UTC). Format: ``ddd:hh24:mi-ddd:hh24:mi`` Default: A 30-minute window selected at random from an 8-hour block of time per AWS Region , occurring on a random day of the week. Valid Days: Mon, Tue, Wed, Thu, Fri, Sat, Sun Constraints: Minimum 30-minute window.
        :param publicly_accessible: Specifies the accessibility options for the replication instance. A value of ``true`` represents an instance with a public IP address. A value of ``false`` represents an instance with a private IP address. The default value is ``true`` .
        :param replication_instance_identifier: The replication instance identifier. This parameter is stored as a lowercase string. Constraints: - Must contain 1-63 alphanumeric characters or hyphens. - First character must be a letter. - Can't end with a hyphen or contain two consecutive hyphens. Example: ``myrepinstance``
        :param replication_subnet_group_identifier: A subnet group to associate with the replication instance.
        :param resource_identifier: A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object. The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .
        :param tags: One or more tags to be assigned to the replication instance.
        :param vpc_security_group_ids: Specifies the VPC security group to be used with the replication instance. The VPC security group must work with the VPC containing the replication instance.
        '''
        props = CfnReplicationInstanceProps(
            replication_instance_class=replication_instance_class,
            allocated_storage=allocated_storage,
            allow_major_version_upgrade=allow_major_version_upgrade,
            auto_minor_version_upgrade=auto_minor_version_upgrade,
            availability_zone=availability_zone,
            engine_version=engine_version,
            kms_key_id=kms_key_id,
            multi_az=multi_az,
            preferred_maintenance_window=preferred_maintenance_window,
            publicly_accessible=publicly_accessible,
            replication_instance_identifier=replication_instance_identifier,
            replication_subnet_group_identifier=replication_subnet_group_identifier,
            resource_identifier=resource_identifier,
            tags=tags,
            vpc_security_group_ids=vpc_security_group_ids,
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
    @jsii.member(jsii_name="attrReplicationInstancePrivateIpAddresses")
    def attr_replication_instance_private_ip_addresses(
        self,
    ) -> typing.List[builtins.str]:
        '''One or more private IP addresses for the replication instance.

        :cloudformationAttribute: ReplicationInstancePrivateIpAddresses
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrReplicationInstancePrivateIpAddresses"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReplicationInstancePublicIpAddresses")
    def attr_replication_instance_public_ip_addresses(
        self,
    ) -> typing.List[builtins.str]:
        '''One or more public IP addresses for the replication instance.

        :cloudformationAttribute: ReplicationInstancePublicIpAddresses
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrReplicationInstancePublicIpAddresses"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''One or more tags to be assigned to the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationInstanceClass")
    def replication_instance_class(self) -> builtins.str:
        '''The compute and memory capacity of the replication instance as defined for the specified replication instance class.

        For example to specify the instance class dms.c4.large, set this parameter to ``"dms.c4.large"`` .

        For more information on the settings and capacities for the available replication instance classes, see `Selecting the right AWS DMS replication instance for your migration <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html#CHAP_ReplicationInstance.InDepth>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-replicationinstanceclass
        '''
        return typing.cast(builtins.str, jsii.get(self, "replicationInstanceClass"))

    @replication_instance_class.setter
    def replication_instance_class(self, value: builtins.str) -> None:
        jsii.set(self, "replicationInstanceClass", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allocatedStorage")
    def allocated_storage(self) -> typing.Optional[jsii.Number]:
        '''The amount of storage (in gigabytes) to be initially allocated for the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-allocatedstorage
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "allocatedStorage"))

    @allocated_storage.setter
    def allocated_storage(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "allocatedStorage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allowMajorVersionUpgrade")
    def allow_major_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates that major version upgrades are allowed.

        Changing this parameter does not result in an outage, and the change is asynchronously applied as soon as possible.

        This parameter must be set to ``true`` when specifying a value for the ``EngineVersion`` parameter that is a different major version than the replication instance's current version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-allowmajorversionupgrade
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "allowMajorVersionUpgrade"))

    @allow_major_version_upgrade.setter
    def allow_major_version_upgrade(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "allowMajorVersionUpgrade", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoMinorVersionUpgrade")
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''A value that indicates whether minor engine upgrades are applied automatically to the replication instance during the maintenance window.

        This parameter defaults to ``true`` .

        Default: ``true``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-autominorversionupgrade
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "autoMinorVersionUpgrade"))

    @auto_minor_version_upgrade.setter
    def auto_minor_version_upgrade(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "autoMinorVersionUpgrade", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="availabilityZone")
    def availability_zone(self) -> typing.Optional[builtins.str]:
        '''The Availability Zone that the replication instance will be created in.

        The default value is a random, system-chosen Availability Zone in the endpoint's AWS Region , for example: ``us-east-1d``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-availabilityzone
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "availabilityZone"))

    @availability_zone.setter
    def availability_zone(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "availabilityZone", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineVersion")
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The engine version number of the replication instance.

        If an engine version number is not specified when a replication instance is created, the default is the latest engine version available.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-engineversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "engineVersion"))

    @engine_version.setter
    def engine_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "engineVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''An AWS KMS key identifier that is used to encrypt the data on the replication instance.

        If you don't specify a value for the ``KmsKeyId`` parameter, then AWS DMS uses your default encryption key.

        AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Region .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="multiAz")
    def multi_az(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the replication instance is a Multi-AZ deployment.

        You can't set the ``AvailabilityZone`` parameter if the Multi-AZ parameter is set to ``true`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-multiaz
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "multiAz"))

    @multi_az.setter
    def multi_az(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "multiAz", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredMaintenanceWindow")
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''The weekly time range during which system maintenance can occur, in Universal Coordinated Time (UTC).

        Format: ``ddd:hh24:mi-ddd:hh24:mi``

        Default: A 30-minute window selected at random from an 8-hour block of time per AWS Region , occurring on a random day of the week.

        Valid Days: Mon, Tue, Wed, Thu, Fri, Sat, Sun

        Constraints: Minimum 30-minute window.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-preferredmaintenancewindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preferredMaintenanceWindow"))

    @preferred_maintenance_window.setter
    def preferred_maintenance_window(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "preferredMaintenanceWindow", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publiclyAccessible")
    def publicly_accessible(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies the accessibility options for the replication instance.

        A value of ``true`` represents an instance with a public IP address. A value of ``false`` represents an instance with a private IP address. The default value is ``true`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-publiclyaccessible
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "publiclyAccessible"))

    @publicly_accessible.setter
    def publicly_accessible(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "publiclyAccessible", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationInstanceIdentifier")
    def replication_instance_identifier(self) -> typing.Optional[builtins.str]:
        '''The replication instance identifier. This parameter is stored as a lowercase string.

        Constraints:

        - Must contain 1-63 alphanumeric characters or hyphens.
        - First character must be a letter.
        - Can't end with a hyphen or contain two consecutive hyphens.

        Example: ``myrepinstance``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-replicationinstanceidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "replicationInstanceIdentifier"))

    @replication_instance_identifier.setter
    def replication_instance_identifier(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "replicationInstanceIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationSubnetGroupIdentifier")
    def replication_subnet_group_identifier(self) -> typing.Optional[builtins.str]:
        '''A subnet group to associate with the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-replicationsubnetgroupidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "replicationSubnetGroupIdentifier"))

    @replication_subnet_group_identifier.setter
    def replication_subnet_group_identifier(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "replicationSubnetGroupIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceIdentifier")
    def resource_identifier(self) -> typing.Optional[builtins.str]:
        '''A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object.

        The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-resourceidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "resourceIdentifier"))

    @resource_identifier.setter
    def resource_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "resourceIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcSecurityGroupIds")
    def vpc_security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specifies the VPC security group to be used with the replication instance.

        The VPC security group must work with the VPC containing the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-vpcsecuritygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "vpcSecurityGroupIds"))

    @vpc_security_group_ids.setter
    def vpc_security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "vpcSecurityGroupIds", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_dms.CfnReplicationInstanceProps",
    jsii_struct_bases=[],
    name_mapping={
        "replication_instance_class": "replicationInstanceClass",
        "allocated_storage": "allocatedStorage",
        "allow_major_version_upgrade": "allowMajorVersionUpgrade",
        "auto_minor_version_upgrade": "autoMinorVersionUpgrade",
        "availability_zone": "availabilityZone",
        "engine_version": "engineVersion",
        "kms_key_id": "kmsKeyId",
        "multi_az": "multiAz",
        "preferred_maintenance_window": "preferredMaintenanceWindow",
        "publicly_accessible": "publiclyAccessible",
        "replication_instance_identifier": "replicationInstanceIdentifier",
        "replication_subnet_group_identifier": "replicationSubnetGroupIdentifier",
        "resource_identifier": "resourceIdentifier",
        "tags": "tags",
        "vpc_security_group_ids": "vpcSecurityGroupIds",
    },
)
class CfnReplicationInstanceProps:
    def __init__(
        self,
        *,
        replication_instance_class: builtins.str,
        allocated_storage: typing.Optional[jsii.Number] = None,
        allow_major_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        auto_minor_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        availability_zone: typing.Optional[builtins.str] = None,
        engine_version: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        multi_az: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        publicly_accessible: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        replication_instance_identifier: typing.Optional[builtins.str] = None,
        replication_subnet_group_identifier: typing.Optional[builtins.str] = None,
        resource_identifier: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnReplicationInstance``.

        :param replication_instance_class: The compute and memory capacity of the replication instance as defined for the specified replication instance class. For example to specify the instance class dms.c4.large, set this parameter to ``"dms.c4.large"`` . For more information on the settings and capacities for the available replication instance classes, see `Selecting the right AWS DMS replication instance for your migration <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html#CHAP_ReplicationInstance.InDepth>`_ .
        :param allocated_storage: The amount of storage (in gigabytes) to be initially allocated for the replication instance.
        :param allow_major_version_upgrade: Indicates that major version upgrades are allowed. Changing this parameter does not result in an outage, and the change is asynchronously applied as soon as possible. This parameter must be set to ``true`` when specifying a value for the ``EngineVersion`` parameter that is a different major version than the replication instance's current version.
        :param auto_minor_version_upgrade: A value that indicates whether minor engine upgrades are applied automatically to the replication instance during the maintenance window. This parameter defaults to ``true`` . Default: ``true``
        :param availability_zone: The Availability Zone that the replication instance will be created in. The default value is a random, system-chosen Availability Zone in the endpoint's AWS Region , for example: ``us-east-1d``
        :param engine_version: The engine version number of the replication instance. If an engine version number is not specified when a replication instance is created, the default is the latest engine version available.
        :param kms_key_id: An AWS KMS key identifier that is used to encrypt the data on the replication instance. If you don't specify a value for the ``KmsKeyId`` parameter, then AWS DMS uses your default encryption key. AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Region .
        :param multi_az: Specifies whether the replication instance is a Multi-AZ deployment. You can't set the ``AvailabilityZone`` parameter if the Multi-AZ parameter is set to ``true`` .
        :param preferred_maintenance_window: The weekly time range during which system maintenance can occur, in Universal Coordinated Time (UTC). Format: ``ddd:hh24:mi-ddd:hh24:mi`` Default: A 30-minute window selected at random from an 8-hour block of time per AWS Region , occurring on a random day of the week. Valid Days: Mon, Tue, Wed, Thu, Fri, Sat, Sun Constraints: Minimum 30-minute window.
        :param publicly_accessible: Specifies the accessibility options for the replication instance. A value of ``true`` represents an instance with a public IP address. A value of ``false`` represents an instance with a private IP address. The default value is ``true`` .
        :param replication_instance_identifier: The replication instance identifier. This parameter is stored as a lowercase string. Constraints: - Must contain 1-63 alphanumeric characters or hyphens. - First character must be a letter. - Can't end with a hyphen or contain two consecutive hyphens. Example: ``myrepinstance``
        :param replication_subnet_group_identifier: A subnet group to associate with the replication instance.
        :param resource_identifier: A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object. The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .
        :param tags: One or more tags to be assigned to the replication instance.
        :param vpc_security_group_ids: Specifies the VPC security group to be used with the replication instance. The VPC security group must work with the VPC containing the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_dms as dms
            
            cfn_replication_instance_props = dms.CfnReplicationInstanceProps(
                replication_instance_class="replicationInstanceClass",
            
                # the properties below are optional
                allocated_storage=123,
                allow_major_version_upgrade=False,
                auto_minor_version_upgrade=False,
                availability_zone="availabilityZone",
                engine_version="engineVersion",
                kms_key_id="kmsKeyId",
                multi_az=False,
                preferred_maintenance_window="preferredMaintenanceWindow",
                publicly_accessible=False,
                replication_instance_identifier="replicationInstanceIdentifier",
                replication_subnet_group_identifier="replicationSubnetGroupIdentifier",
                resource_identifier="resourceIdentifier",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                vpc_security_group_ids=["vpcSecurityGroupIds"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "replication_instance_class": replication_instance_class,
        }
        if allocated_storage is not None:
            self._values["allocated_storage"] = allocated_storage
        if allow_major_version_upgrade is not None:
            self._values["allow_major_version_upgrade"] = allow_major_version_upgrade
        if auto_minor_version_upgrade is not None:
            self._values["auto_minor_version_upgrade"] = auto_minor_version_upgrade
        if availability_zone is not None:
            self._values["availability_zone"] = availability_zone
        if engine_version is not None:
            self._values["engine_version"] = engine_version
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if multi_az is not None:
            self._values["multi_az"] = multi_az
        if preferred_maintenance_window is not None:
            self._values["preferred_maintenance_window"] = preferred_maintenance_window
        if publicly_accessible is not None:
            self._values["publicly_accessible"] = publicly_accessible
        if replication_instance_identifier is not None:
            self._values["replication_instance_identifier"] = replication_instance_identifier
        if replication_subnet_group_identifier is not None:
            self._values["replication_subnet_group_identifier"] = replication_subnet_group_identifier
        if resource_identifier is not None:
            self._values["resource_identifier"] = resource_identifier
        if tags is not None:
            self._values["tags"] = tags
        if vpc_security_group_ids is not None:
            self._values["vpc_security_group_ids"] = vpc_security_group_ids

    @builtins.property
    def replication_instance_class(self) -> builtins.str:
        '''The compute and memory capacity of the replication instance as defined for the specified replication instance class.

        For example to specify the instance class dms.c4.large, set this parameter to ``"dms.c4.large"`` .

        For more information on the settings and capacities for the available replication instance classes, see `Selecting the right AWS DMS replication instance for your migration <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html#CHAP_ReplicationInstance.InDepth>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-replicationinstanceclass
        '''
        result = self._values.get("replication_instance_class")
        assert result is not None, "Required property 'replication_instance_class' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def allocated_storage(self) -> typing.Optional[jsii.Number]:
        '''The amount of storage (in gigabytes) to be initially allocated for the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-allocatedstorage
        '''
        result = self._values.get("allocated_storage")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def allow_major_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates that major version upgrades are allowed.

        Changing this parameter does not result in an outage, and the change is asynchronously applied as soon as possible.

        This parameter must be set to ``true`` when specifying a value for the ``EngineVersion`` parameter that is a different major version than the replication instance's current version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-allowmajorversionupgrade
        '''
        result = self._values.get("allow_major_version_upgrade")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''A value that indicates whether minor engine upgrades are applied automatically to the replication instance during the maintenance window.

        This parameter defaults to ``true`` .

        Default: ``true``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-autominorversionupgrade
        '''
        result = self._values.get("auto_minor_version_upgrade")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def availability_zone(self) -> typing.Optional[builtins.str]:
        '''The Availability Zone that the replication instance will be created in.

        The default value is a random, system-chosen Availability Zone in the endpoint's AWS Region , for example: ``us-east-1d``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-availabilityzone
        '''
        result = self._values.get("availability_zone")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The engine version number of the replication instance.

        If an engine version number is not specified when a replication instance is created, the default is the latest engine version available.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-engineversion
        '''
        result = self._values.get("engine_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''An AWS KMS key identifier that is used to encrypt the data on the replication instance.

        If you don't specify a value for the ``KmsKeyId`` parameter, then AWS DMS uses your default encryption key.

        AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Region .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def multi_az(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the replication instance is a Multi-AZ deployment.

        You can't set the ``AvailabilityZone`` parameter if the Multi-AZ parameter is set to ``true`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-multiaz
        '''
        result = self._values.get("multi_az")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''The weekly time range during which system maintenance can occur, in Universal Coordinated Time (UTC).

        Format: ``ddd:hh24:mi-ddd:hh24:mi``

        Default: A 30-minute window selected at random from an 8-hour block of time per AWS Region , occurring on a random day of the week.

        Valid Days: Mon, Tue, Wed, Thu, Fri, Sat, Sun

        Constraints: Minimum 30-minute window.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-preferredmaintenancewindow
        '''
        result = self._values.get("preferred_maintenance_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def publicly_accessible(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies the accessibility options for the replication instance.

        A value of ``true`` represents an instance with a public IP address. A value of ``false`` represents an instance with a private IP address. The default value is ``true`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-publiclyaccessible
        '''
        result = self._values.get("publicly_accessible")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def replication_instance_identifier(self) -> typing.Optional[builtins.str]:
        '''The replication instance identifier. This parameter is stored as a lowercase string.

        Constraints:

        - Must contain 1-63 alphanumeric characters or hyphens.
        - First character must be a letter.
        - Can't end with a hyphen or contain two consecutive hyphens.

        Example: ``myrepinstance``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-replicationinstanceidentifier
        '''
        result = self._values.get("replication_instance_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def replication_subnet_group_identifier(self) -> typing.Optional[builtins.str]:
        '''A subnet group to associate with the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-replicationsubnetgroupidentifier
        '''
        result = self._values.get("replication_subnet_group_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def resource_identifier(self) -> typing.Optional[builtins.str]:
        '''A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object.

        The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-resourceidentifier
        '''
        result = self._values.get("resource_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''One or more tags to be assigned to the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def vpc_security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specifies the VPC security group to be used with the replication instance.

        The VPC security group must work with the VPC containing the replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-vpcsecuritygroupids
        '''
        result = self._values.get("vpc_security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnReplicationInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnReplicationSubnetGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_dms.CfnReplicationSubnetGroup",
):
    '''A CloudFormation ``AWS::DMS::ReplicationSubnetGroup``.

    The ``AWS::DMS::ReplicationSubnetGroup`` resource creates an AWS DMS replication subnet group. Subnet groups must contain at least two subnets in two different Availability Zones in the same region.
    .. epigraph::

       Resource creation will fail if the ``dms-vpc-role`` IAM role doesn't already exist. For more information, see `Creating the IAM Roles to Use With the AWS CLI and AWS DMS API <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.APIRole.html>`_ in the *AWS Database Migration Service User Guide.*

    :cloudformationResource: AWS::DMS::ReplicationSubnetGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_dms as dms
        
        cfn_replication_subnet_group = dms.CfnReplicationSubnetGroup(self, "MyCfnReplicationSubnetGroup",
            replication_subnet_group_description="replicationSubnetGroupDescription",
            subnet_ids=["subnetIds"],
        
            # the properties below are optional
            replication_subnet_group_identifier="replicationSubnetGroupIdentifier",
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
        replication_subnet_group_description: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        replication_subnet_group_identifier: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::DMS::ReplicationSubnetGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param replication_subnet_group_description: The description for the subnet group.
        :param subnet_ids: One or more subnet IDs to be assigned to the subnet group.
        :param replication_subnet_group_identifier: The identifier for the replication subnet group. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the identifier.
        :param tags: One or more tags to be assigned to the subnet group.
        '''
        props = CfnReplicationSubnetGroupProps(
            replication_subnet_group_description=replication_subnet_group_description,
            subnet_ids=subnet_ids,
            replication_subnet_group_identifier=replication_subnet_group_identifier,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''One or more tags to be assigned to the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html#cfn-dms-replicationsubnetgroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationSubnetGroupDescription")
    def replication_subnet_group_description(self) -> builtins.str:
        '''The description for the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html#cfn-dms-replicationsubnetgroup-replicationsubnetgroupdescription
        '''
        return typing.cast(builtins.str, jsii.get(self, "replicationSubnetGroupDescription"))

    @replication_subnet_group_description.setter
    def replication_subnet_group_description(self, value: builtins.str) -> None:
        jsii.set(self, "replicationSubnetGroupDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetIds")
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''One or more subnet IDs to be assigned to the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html#cfn-dms-replicationsubnetgroup-subnetids
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "subnetIds"))

    @subnet_ids.setter
    def subnet_ids(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "subnetIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationSubnetGroupIdentifier")
    def replication_subnet_group_identifier(self) -> typing.Optional[builtins.str]:
        '''The identifier for the replication subnet group.

        If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the identifier.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html#cfn-dms-replicationsubnetgroup-replicationsubnetgroupidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "replicationSubnetGroupIdentifier"))

    @replication_subnet_group_identifier.setter
    def replication_subnet_group_identifier(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "replicationSubnetGroupIdentifier", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_dms.CfnReplicationSubnetGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "replication_subnet_group_description": "replicationSubnetGroupDescription",
        "subnet_ids": "subnetIds",
        "replication_subnet_group_identifier": "replicationSubnetGroupIdentifier",
        "tags": "tags",
    },
)
class CfnReplicationSubnetGroupProps:
    def __init__(
        self,
        *,
        replication_subnet_group_description: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        replication_subnet_group_identifier: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnReplicationSubnetGroup``.

        :param replication_subnet_group_description: The description for the subnet group.
        :param subnet_ids: One or more subnet IDs to be assigned to the subnet group.
        :param replication_subnet_group_identifier: The identifier for the replication subnet group. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the identifier.
        :param tags: One or more tags to be assigned to the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_dms as dms
            
            cfn_replication_subnet_group_props = dms.CfnReplicationSubnetGroupProps(
                replication_subnet_group_description="replicationSubnetGroupDescription",
                subnet_ids=["subnetIds"],
            
                # the properties below are optional
                replication_subnet_group_identifier="replicationSubnetGroupIdentifier",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "replication_subnet_group_description": replication_subnet_group_description,
            "subnet_ids": subnet_ids,
        }
        if replication_subnet_group_identifier is not None:
            self._values["replication_subnet_group_identifier"] = replication_subnet_group_identifier
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def replication_subnet_group_description(self) -> builtins.str:
        '''The description for the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html#cfn-dms-replicationsubnetgroup-replicationsubnetgroupdescription
        '''
        result = self._values.get("replication_subnet_group_description")
        assert result is not None, "Required property 'replication_subnet_group_description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''One or more subnet IDs to be assigned to the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html#cfn-dms-replicationsubnetgroup-subnetids
        '''
        result = self._values.get("subnet_ids")
        assert result is not None, "Required property 'subnet_ids' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def replication_subnet_group_identifier(self) -> typing.Optional[builtins.str]:
        '''The identifier for the replication subnet group.

        If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the identifier.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html#cfn-dms-replicationsubnetgroup-replicationsubnetgroupidentifier
        '''
        result = self._values.get("replication_subnet_group_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''One or more tags to be assigned to the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationsubnetgroup.html#cfn-dms-replicationsubnetgroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnReplicationSubnetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnReplicationTask(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_dms.CfnReplicationTask",
):
    '''A CloudFormation ``AWS::DMS::ReplicationTask``.

    The ``AWS::DMS::ReplicationTask`` resource creates an AWS DMS replication task.

    :cloudformationResource: AWS::DMS::ReplicationTask
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_dms as dms
        
        cfn_replication_task = dms.CfnReplicationTask(self, "MyCfnReplicationTask",
            migration_type="migrationType",
            replication_instance_arn="replicationInstanceArn",
            source_endpoint_arn="sourceEndpointArn",
            table_mappings="tableMappings",
            target_endpoint_arn="targetEndpointArn",
        
            # the properties below are optional
            cdc_start_position="cdcStartPosition",
            cdc_start_time=123,
            cdc_stop_position="cdcStopPosition",
            replication_task_identifier="replicationTaskIdentifier",
            replication_task_settings="replicationTaskSettings",
            resource_identifier="resourceIdentifier",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            task_data="taskData"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        migration_type: builtins.str,
        replication_instance_arn: builtins.str,
        source_endpoint_arn: builtins.str,
        table_mappings: builtins.str,
        target_endpoint_arn: builtins.str,
        cdc_start_position: typing.Optional[builtins.str] = None,
        cdc_start_time: typing.Optional[jsii.Number] = None,
        cdc_stop_position: typing.Optional[builtins.str] = None,
        replication_task_identifier: typing.Optional[builtins.str] = None,
        replication_task_settings: typing.Optional[builtins.str] = None,
        resource_identifier: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        task_data: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::DMS::ReplicationTask``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param migration_type: The migration type. Valid values: ``full-load`` | ``cdc`` | ``full-load-and-cdc``
        :param replication_instance_arn: The Amazon Resource Name (ARN) of a replication instance.
        :param source_endpoint_arn: An Amazon Resource Name (ARN) that uniquely identifies the source endpoint.
        :param table_mappings: The table mappings for the task, in JSON format. For more information, see `Using Table Mapping to Specify Task Settings <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TableMapping.html>`_ in the *AWS Database Migration Service User Guide.*
        :param target_endpoint_arn: An Amazon Resource Name (ARN) that uniquely identifies the target endpoint.
        :param cdc_start_position: Indicates when you want a change data capture (CDC) operation to start. Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error. The value can be in date, checkpoint, or LSN/SCN format. Date Example: --cdc-start-position “2018-03-08T12:12:12” Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93" LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373” .. epigraph:: When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the ``slotName`` extra connection attribute to the name of this logical replication slot. For more information, see `Extra Connection Attributes When Using PostgreSQL as a Source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib>`_ .
        :param cdc_start_time: Indicates the start time for a change data capture (CDC) operation.
        :param cdc_stop_position: Indicates when you want a change data capture (CDC) operation to stop. The value can be either server time or commit time. Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12” Commit time example: --cdc-stop-position “commit_time: 2018-02-09T12:12:12 “
        :param replication_task_identifier: An identifier for the replication task. Constraints: - Must contain 1-255 alphanumeric characters or hyphens. - First character must be a letter. - Cannot end with a hyphen or contain two consecutive hyphens.
        :param replication_task_settings: Overall settings for the task, in JSON format. For more information, see `Specifying Task Settings for AWS Database Migration Service Tasks <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TaskSettings.html>`_ in the *AWS Database Migration Service User Guide.*
        :param resource_identifier: A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object. The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .
        :param tags: One or more tags to be assigned to the replication task.
        :param task_data: ``AWS::DMS::ReplicationTask.TaskData``.
        '''
        props = CfnReplicationTaskProps(
            migration_type=migration_type,
            replication_instance_arn=replication_instance_arn,
            source_endpoint_arn=source_endpoint_arn,
            table_mappings=table_mappings,
            target_endpoint_arn=target_endpoint_arn,
            cdc_start_position=cdc_start_position,
            cdc_start_time=cdc_start_time,
            cdc_stop_position=cdc_stop_position,
            replication_task_identifier=replication_task_identifier,
            replication_task_settings=replication_task_settings,
            resource_identifier=resource_identifier,
            tags=tags,
            task_data=task_data,
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
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''One or more tags to be assigned to the replication task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="migrationType")
    def migration_type(self) -> builtins.str:
        '''The migration type.

        Valid values: ``full-load`` | ``cdc`` | ``full-load-and-cdc``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-migrationtype
        '''
        return typing.cast(builtins.str, jsii.get(self, "migrationType"))

    @migration_type.setter
    def migration_type(self, value: builtins.str) -> None:
        jsii.set(self, "migrationType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationInstanceArn")
    def replication_instance_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of a replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-replicationinstancearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "replicationInstanceArn"))

    @replication_instance_arn.setter
    def replication_instance_arn(self, value: builtins.str) -> None:
        jsii.set(self, "replicationInstanceArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceEndpointArn")
    def source_endpoint_arn(self) -> builtins.str:
        '''An Amazon Resource Name (ARN) that uniquely identifies the source endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-sourceendpointarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "sourceEndpointArn"))

    @source_endpoint_arn.setter
    def source_endpoint_arn(self, value: builtins.str) -> None:
        jsii.set(self, "sourceEndpointArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tableMappings")
    def table_mappings(self) -> builtins.str:
        '''The table mappings for the task, in JSON format.

        For more information, see `Using Table Mapping to Specify Task Settings <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TableMapping.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-tablemappings
        '''
        return typing.cast(builtins.str, jsii.get(self, "tableMappings"))

    @table_mappings.setter
    def table_mappings(self, value: builtins.str) -> None:
        jsii.set(self, "tableMappings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetEndpointArn")
    def target_endpoint_arn(self) -> builtins.str:
        '''An Amazon Resource Name (ARN) that uniquely identifies the target endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-targetendpointarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "targetEndpointArn"))

    @target_endpoint_arn.setter
    def target_endpoint_arn(self, value: builtins.str) -> None:
        jsii.set(self, "targetEndpointArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cdcStartPosition")
    def cdc_start_position(self) -> typing.Optional[builtins.str]:
        '''Indicates when you want a change data capture (CDC) operation to start.

        Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error.

        The value can be in date, checkpoint, or LSN/SCN format.

        Date Example: --cdc-start-position “2018-03-08T12:12:12”

        Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93"

        LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373”
        .. epigraph::

           When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the ``slotName`` extra connection attribute to the name of this logical replication slot. For more information, see `Extra Connection Attributes When Using PostgreSQL as a Source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-cdcstartposition
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cdcStartPosition"))

    @cdc_start_position.setter
    def cdc_start_position(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cdcStartPosition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cdcStartTime")
    def cdc_start_time(self) -> typing.Optional[jsii.Number]:
        '''Indicates the start time for a change data capture (CDC) operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-cdcstarttime
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "cdcStartTime"))

    @cdc_start_time.setter
    def cdc_start_time(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "cdcStartTime", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cdcStopPosition")
    def cdc_stop_position(self) -> typing.Optional[builtins.str]:
        '''Indicates when you want a change data capture (CDC) operation to stop.

        The value can be either server time or commit time.

        Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12”

        Commit time example: --cdc-stop-position “commit_time: 2018-02-09T12:12:12 “

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-cdcstopposition
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cdcStopPosition"))

    @cdc_stop_position.setter
    def cdc_stop_position(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cdcStopPosition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationTaskIdentifier")
    def replication_task_identifier(self) -> typing.Optional[builtins.str]:
        '''An identifier for the replication task.

        Constraints:

        - Must contain 1-255 alphanumeric characters or hyphens.
        - First character must be a letter.
        - Cannot end with a hyphen or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-replicationtaskidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "replicationTaskIdentifier"))

    @replication_task_identifier.setter
    def replication_task_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "replicationTaskIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationTaskSettings")
    def replication_task_settings(self) -> typing.Optional[builtins.str]:
        '''Overall settings for the task, in JSON format.

        For more information, see `Specifying Task Settings for AWS Database Migration Service Tasks <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TaskSettings.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-replicationtasksettings
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "replicationTaskSettings"))

    @replication_task_settings.setter
    def replication_task_settings(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "replicationTaskSettings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceIdentifier")
    def resource_identifier(self) -> typing.Optional[builtins.str]:
        '''A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object.

        The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-resourceidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "resourceIdentifier"))

    @resource_identifier.setter
    def resource_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "resourceIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="taskData")
    def task_data(self) -> typing.Optional[builtins.str]:
        '''``AWS::DMS::ReplicationTask.TaskData``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-taskdata
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "taskData"))

    @task_data.setter
    def task_data(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "taskData", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_dms.CfnReplicationTaskProps",
    jsii_struct_bases=[],
    name_mapping={
        "migration_type": "migrationType",
        "replication_instance_arn": "replicationInstanceArn",
        "source_endpoint_arn": "sourceEndpointArn",
        "table_mappings": "tableMappings",
        "target_endpoint_arn": "targetEndpointArn",
        "cdc_start_position": "cdcStartPosition",
        "cdc_start_time": "cdcStartTime",
        "cdc_stop_position": "cdcStopPosition",
        "replication_task_identifier": "replicationTaskIdentifier",
        "replication_task_settings": "replicationTaskSettings",
        "resource_identifier": "resourceIdentifier",
        "tags": "tags",
        "task_data": "taskData",
    },
)
class CfnReplicationTaskProps:
    def __init__(
        self,
        *,
        migration_type: builtins.str,
        replication_instance_arn: builtins.str,
        source_endpoint_arn: builtins.str,
        table_mappings: builtins.str,
        target_endpoint_arn: builtins.str,
        cdc_start_position: typing.Optional[builtins.str] = None,
        cdc_start_time: typing.Optional[jsii.Number] = None,
        cdc_stop_position: typing.Optional[builtins.str] = None,
        replication_task_identifier: typing.Optional[builtins.str] = None,
        replication_task_settings: typing.Optional[builtins.str] = None,
        resource_identifier: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        task_data: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnReplicationTask``.

        :param migration_type: The migration type. Valid values: ``full-load`` | ``cdc`` | ``full-load-and-cdc``
        :param replication_instance_arn: The Amazon Resource Name (ARN) of a replication instance.
        :param source_endpoint_arn: An Amazon Resource Name (ARN) that uniquely identifies the source endpoint.
        :param table_mappings: The table mappings for the task, in JSON format. For more information, see `Using Table Mapping to Specify Task Settings <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TableMapping.html>`_ in the *AWS Database Migration Service User Guide.*
        :param target_endpoint_arn: An Amazon Resource Name (ARN) that uniquely identifies the target endpoint.
        :param cdc_start_position: Indicates when you want a change data capture (CDC) operation to start. Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error. The value can be in date, checkpoint, or LSN/SCN format. Date Example: --cdc-start-position “2018-03-08T12:12:12” Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93" LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373” .. epigraph:: When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the ``slotName`` extra connection attribute to the name of this logical replication slot. For more information, see `Extra Connection Attributes When Using PostgreSQL as a Source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib>`_ .
        :param cdc_start_time: Indicates the start time for a change data capture (CDC) operation.
        :param cdc_stop_position: Indicates when you want a change data capture (CDC) operation to stop. The value can be either server time or commit time. Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12” Commit time example: --cdc-stop-position “commit_time: 2018-02-09T12:12:12 “
        :param replication_task_identifier: An identifier for the replication task. Constraints: - Must contain 1-255 alphanumeric characters or hyphens. - First character must be a letter. - Cannot end with a hyphen or contain two consecutive hyphens.
        :param replication_task_settings: Overall settings for the task, in JSON format. For more information, see `Specifying Task Settings for AWS Database Migration Service Tasks <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TaskSettings.html>`_ in the *AWS Database Migration Service User Guide.*
        :param resource_identifier: A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object. The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .
        :param tags: One or more tags to be assigned to the replication task.
        :param task_data: ``AWS::DMS::ReplicationTask.TaskData``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_dms as dms
            
            cfn_replication_task_props = dms.CfnReplicationTaskProps(
                migration_type="migrationType",
                replication_instance_arn="replicationInstanceArn",
                source_endpoint_arn="sourceEndpointArn",
                table_mappings="tableMappings",
                target_endpoint_arn="targetEndpointArn",
            
                # the properties below are optional
                cdc_start_position="cdcStartPosition",
                cdc_start_time=123,
                cdc_stop_position="cdcStopPosition",
                replication_task_identifier="replicationTaskIdentifier",
                replication_task_settings="replicationTaskSettings",
                resource_identifier="resourceIdentifier",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                task_data="taskData"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "migration_type": migration_type,
            "replication_instance_arn": replication_instance_arn,
            "source_endpoint_arn": source_endpoint_arn,
            "table_mappings": table_mappings,
            "target_endpoint_arn": target_endpoint_arn,
        }
        if cdc_start_position is not None:
            self._values["cdc_start_position"] = cdc_start_position
        if cdc_start_time is not None:
            self._values["cdc_start_time"] = cdc_start_time
        if cdc_stop_position is not None:
            self._values["cdc_stop_position"] = cdc_stop_position
        if replication_task_identifier is not None:
            self._values["replication_task_identifier"] = replication_task_identifier
        if replication_task_settings is not None:
            self._values["replication_task_settings"] = replication_task_settings
        if resource_identifier is not None:
            self._values["resource_identifier"] = resource_identifier
        if tags is not None:
            self._values["tags"] = tags
        if task_data is not None:
            self._values["task_data"] = task_data

    @builtins.property
    def migration_type(self) -> builtins.str:
        '''The migration type.

        Valid values: ``full-load`` | ``cdc`` | ``full-load-and-cdc``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-migrationtype
        '''
        result = self._values.get("migration_type")
        assert result is not None, "Required property 'migration_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def replication_instance_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of a replication instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-replicationinstancearn
        '''
        result = self._values.get("replication_instance_arn")
        assert result is not None, "Required property 'replication_instance_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def source_endpoint_arn(self) -> builtins.str:
        '''An Amazon Resource Name (ARN) that uniquely identifies the source endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-sourceendpointarn
        '''
        result = self._values.get("source_endpoint_arn")
        assert result is not None, "Required property 'source_endpoint_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def table_mappings(self) -> builtins.str:
        '''The table mappings for the task, in JSON format.

        For more information, see `Using Table Mapping to Specify Task Settings <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TableMapping.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-tablemappings
        '''
        result = self._values.get("table_mappings")
        assert result is not None, "Required property 'table_mappings' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def target_endpoint_arn(self) -> builtins.str:
        '''An Amazon Resource Name (ARN) that uniquely identifies the target endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-targetendpointarn
        '''
        result = self._values.get("target_endpoint_arn")
        assert result is not None, "Required property 'target_endpoint_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cdc_start_position(self) -> typing.Optional[builtins.str]:
        '''Indicates when you want a change data capture (CDC) operation to start.

        Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error.

        The value can be in date, checkpoint, or LSN/SCN format.

        Date Example: --cdc-start-position “2018-03-08T12:12:12”

        Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93"

        LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373”
        .. epigraph::

           When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the ``slotName`` extra connection attribute to the name of this logical replication slot. For more information, see `Extra Connection Attributes When Using PostgreSQL as a Source for AWS DMS <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-cdcstartposition
        '''
        result = self._values.get("cdc_start_position")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cdc_start_time(self) -> typing.Optional[jsii.Number]:
        '''Indicates the start time for a change data capture (CDC) operation.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-cdcstarttime
        '''
        result = self._values.get("cdc_start_time")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def cdc_stop_position(self) -> typing.Optional[builtins.str]:
        '''Indicates when you want a change data capture (CDC) operation to stop.

        The value can be either server time or commit time.

        Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12”

        Commit time example: --cdc-stop-position “commit_time: 2018-02-09T12:12:12 “

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-cdcstopposition
        '''
        result = self._values.get("cdc_stop_position")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def replication_task_identifier(self) -> typing.Optional[builtins.str]:
        '''An identifier for the replication task.

        Constraints:

        - Must contain 1-255 alphanumeric characters or hyphens.
        - First character must be a letter.
        - Cannot end with a hyphen or contain two consecutive hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-replicationtaskidentifier
        '''
        result = self._values.get("replication_task_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def replication_task_settings(self) -> typing.Optional[builtins.str]:
        '''Overall settings for the task, in JSON format.

        For more information, see `Specifying Task Settings for AWS Database Migration Service Tasks <https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.CustomizingTasks.TaskSettings.html>`_ in the *AWS Database Migration Service User Guide.*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-replicationtasksettings
        '''
        result = self._values.get("replication_task_settings")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def resource_identifier(self) -> typing.Optional[builtins.str]:
        '''A friendly name for the resource identifier at the end of the ``EndpointArn`` response parameter that is returned in the created ``Endpoint`` object.

        The value for this parameter can have up to 31 characters. It can contain only ASCII letters, digits, and hyphen ('-'). Also, it can't end with a hyphen or contain two consecutive hyphens, and can only begin with a letter, such as ``Example-App-ARN1`` . For example, this value might result in the ``EndpointArn`` value ``arn:aws:dms:eu-west-1:012345678901:rep:Example-App-ARN1`` . If you don't specify a ``ResourceIdentifier`` value, AWS DMS generates a default identifier value for the end of ``EndpointArn`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-resourceidentifier
        '''
        result = self._values.get("resource_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''One or more tags to be assigned to the replication task.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def task_data(self) -> typing.Optional[builtins.str]:
        '''``AWS::DMS::ReplicationTask.TaskData``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationtask.html#cfn-dms-replicationtask-taskdata
        '''
        result = self._values.get("task_data")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnReplicationTaskProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnCertificate",
    "CfnCertificateProps",
    "CfnEndpoint",
    "CfnEndpointProps",
    "CfnEventSubscription",
    "CfnEventSubscriptionProps",
    "CfnReplicationInstance",
    "CfnReplicationInstanceProps",
    "CfnReplicationSubnetGroup",
    "CfnReplicationSubnetGroupProps",
    "CfnReplicationTask",
    "CfnReplicationTaskProps",
]

publication.publish()
