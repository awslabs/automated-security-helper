'''
# AWS::Cassandra Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_cassandra as cassandra
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-cassandra-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Cassandra](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Cassandra.html).

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
class CfnKeyspace(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cassandra.CfnKeyspace",
):
    '''A CloudFormation ``AWS::Cassandra::Keyspace``.

    The ``AWS::Cassandra::Keyspace`` resource allows you to create a new keyspace in Amazon Keyspaces (for Apache Cassandra). For more information, see `Create a keyspace and a table <https://docs.aws.amazon.com/keyspaces/latest/devguide/getting-started.ddl.html>`_ in the *Amazon Keyspaces Developer Guide* .

    :cloudformationResource: AWS::Cassandra::Keyspace
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-keyspace.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cassandra as cassandra
        
        cfn_keyspace = cassandra.CfnKeyspace(self, "MyCfnKeyspace",
            keyspace_name="keyspaceName",
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
        keyspace_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Cassandra::Keyspace``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param keyspace_name: The name of the keyspace to be created. The keyspace name is case sensitive. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the keyspace name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . *Length constraints:* Minimum length of 3. Maximum length of 255. *Pattern:* ``^[a-zA-Z0-9][a-zA-Z0-9_]{1,47}$``
        :param tags: A list of key-value pair tags to be attached to the resource.
        '''
        props = CfnKeyspaceProps(keyspace_name=keyspace_name, tags=tags)

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
        '''A list of key-value pair tags to be attached to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-keyspace.html#cfn-cassandra-keyspace-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="keyspaceName")
    def keyspace_name(self) -> typing.Optional[builtins.str]:
        '''The name of the keyspace to be created.

        The keyspace name is case sensitive. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the keyspace name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .

        *Length constraints:* Minimum length of 3. Maximum length of 255.

        *Pattern:* ``^[a-zA-Z0-9][a-zA-Z0-9_]{1,47}$``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-keyspace.html#cfn-cassandra-keyspace-keyspacename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "keyspaceName"))

    @keyspace_name.setter
    def keyspace_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "keyspaceName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cassandra.CfnKeyspaceProps",
    jsii_struct_bases=[],
    name_mapping={"keyspace_name": "keyspaceName", "tags": "tags"},
)
class CfnKeyspaceProps:
    def __init__(
        self,
        *,
        keyspace_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnKeyspace``.

        :param keyspace_name: The name of the keyspace to be created. The keyspace name is case sensitive. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the keyspace name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . *Length constraints:* Minimum length of 3. Maximum length of 255. *Pattern:* ``^[a-zA-Z0-9][a-zA-Z0-9_]{1,47}$``
        :param tags: A list of key-value pair tags to be attached to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-keyspace.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cassandra as cassandra
            
            cfn_keyspace_props = cassandra.CfnKeyspaceProps(
                keyspace_name="keyspaceName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if keyspace_name is not None:
            self._values["keyspace_name"] = keyspace_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def keyspace_name(self) -> typing.Optional[builtins.str]:
        '''The name of the keyspace to be created.

        The keyspace name is case sensitive. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the keyspace name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .

        *Length constraints:* Minimum length of 3. Maximum length of 255.

        *Pattern:* ``^[a-zA-Z0-9][a-zA-Z0-9_]{1,47}$``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-keyspace.html#cfn-cassandra-keyspace-keyspacename
        '''
        result = self._values.get("keyspace_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of key-value pair tags to be attached to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-keyspace.html#cfn-cassandra-keyspace-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnKeyspaceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTable(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cassandra.CfnTable",
):
    '''A CloudFormation ``AWS::Cassandra::Table``.

    The ``AWS::Cassandra::Table`` resource allows you to create a new table in Amazon Keyspaces (for Apache Cassandra). For more information, see `Create a keyspace and a table <https://docs.aws.amazon.com/keyspaces/latest/devguide/getting-started.ddl.html>`_ in the *Amazon Keyspaces Developer Guide* .

    :cloudformationResource: AWS::Cassandra::Table
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cassandra as cassandra
        
        cfn_table = cassandra.CfnTable(self, "MyCfnTable",
            keyspace_name="keyspaceName",
            partition_key_columns=[cassandra.CfnTable.ColumnProperty(
                column_name="columnName",
                column_type="columnType"
            )],
        
            # the properties below are optional
            billing_mode=cassandra.CfnTable.BillingModeProperty(
                mode="mode",
        
                # the properties below are optional
                provisioned_throughput=cassandra.CfnTable.ProvisionedThroughputProperty(
                    read_capacity_units=123,
                    write_capacity_units=123
                )
            ),
            clustering_key_columns=[cassandra.CfnTable.ClusteringKeyColumnProperty(
                column=cassandra.CfnTable.ColumnProperty(
                    column_name="columnName",
                    column_type="columnType"
                ),
        
                # the properties below are optional
                order_by="orderBy"
            )],
            default_time_to_live=123,
            encryption_specification=cassandra.CfnTable.EncryptionSpecificationProperty(
                encryption_type="encryptionType",
        
                # the properties below are optional
                kms_key_identifier="kmsKeyIdentifier"
            ),
            point_in_time_recovery_enabled=False,
            regular_columns=[cassandra.CfnTable.ColumnProperty(
                column_name="columnName",
                column_type="columnType"
            )],
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
        keyspace_name: builtins.str,
        partition_key_columns: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]],
        billing_mode: typing.Optional[typing.Union["CfnTable.BillingModeProperty", _IResolvable_da3f097b]] = None,
        clustering_key_columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTable.ClusteringKeyColumnProperty", _IResolvable_da3f097b]]]] = None,
        default_time_to_live: typing.Optional[jsii.Number] = None,
        encryption_specification: typing.Optional[typing.Union["CfnTable.EncryptionSpecificationProperty", _IResolvable_da3f097b]] = None,
        point_in_time_recovery_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        regular_columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]] = None,
        table_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Cassandra::Table``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param keyspace_name: The name of the keyspace in which to create the table. The keyspace must already exist.
        :param partition_key_columns: One or more columns that uniquely identify every row in the table. Every table must have a partition key.
        :param billing_mode: The billing mode for the table, which determines how you'll be charged for reads and writes:. - *On-demand mode* (default) - You pay based on the actual reads and writes your application performs. - *Provisioned mode* - Lets you specify the number of reads and writes per second that you need for your application. If you don't specify a value for this property, then the table will use on-demand mode.
        :param clustering_key_columns: One or more columns that determine how the table data is sorted.
        :param default_time_to_live: The default Time To Live (TTL) value for all rows in a table in seconds. The maximum configurable value is 630,720,000 seconds, which is the equivalent of 20 years. By default, the TTL value for a table is 0, which means data does not expire. For more information, see `Setting the default TTL value for a table <https://docs.aws.amazon.com/keyspaces/latest/devguide/TTL-how-it-works.html#ttl-howitworks_default_ttl>`_ in the *Amazon Keyspaces Developer Guide* .
        :param encryption_specification: The encryption at rest options for the table. - *AWS owned key* (default) - The key is owned by Amazon Keyspaces. - *Customer managed key* - The key is stored in your account and is created, owned, and managed by you. .. epigraph:: If you choose encryption with a customer managed key, you must specify a valid customer managed KMS key with permissions granted to Amazon Keyspaces. For more information, see `Encryption at rest in Amazon Keyspaces <https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html>`_ in the *Amazon Keyspaces Developer Guide* .
        :param point_in_time_recovery_enabled: Specifies if point-in-time recovery is enabled or disabled for the table. The options are ``PointInTimeRecoveryEnabled=true`` and ``PointInTimeRecoveryEnabled=false`` . If not specified, the default is ``PointInTimeRecoveryEnabled=false`` .
        :param regular_columns: One or more columns that are not part of the primary key - that is, columns that are *not* defined as partition key columns or clustering key columns. You can add regular columns to existing tables by adding them to the template.
        :param table_name: The name of the table to be created. The table name is case sensitive. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the table name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. *Length constraints:* Minimum length of 3. Maximum length of 255. *Pattern:* ``^[a-zA-Z0-9][a-zA-Z0-9_]{1,47}$``
        :param tags: A list of key-value pair tags to be attached to the resource.
        '''
        props = CfnTableProps(
            keyspace_name=keyspace_name,
            partition_key_columns=partition_key_columns,
            billing_mode=billing_mode,
            clustering_key_columns=clustering_key_columns,
            default_time_to_live=default_time_to_live,
            encryption_specification=encryption_specification,
            point_in_time_recovery_enabled=point_in_time_recovery_enabled,
            regular_columns=regular_columns,
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
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A list of key-value pair tags to be attached to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="keyspaceName")
    def keyspace_name(self) -> builtins.str:
        '''The name of the keyspace in which to create the table.

        The keyspace must already exist.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-keyspacename
        '''
        return typing.cast(builtins.str, jsii.get(self, "keyspaceName"))

    @keyspace_name.setter
    def keyspace_name(self, value: builtins.str) -> None:
        jsii.set(self, "keyspaceName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="partitionKeyColumns")
    def partition_key_columns(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]:
        '''One or more columns that uniquely identify every row in the table.

        Every table must have a partition key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-partitionkeycolumns
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]], jsii.get(self, "partitionKeyColumns"))

    @partition_key_columns.setter
    def partition_key_columns(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "partitionKeyColumns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="billingMode")
    def billing_mode(
        self,
    ) -> typing.Optional[typing.Union["CfnTable.BillingModeProperty", _IResolvable_da3f097b]]:
        '''The billing mode for the table, which determines how you'll be charged for reads and writes:.

        - *On-demand mode* (default) - You pay based on the actual reads and writes your application performs.
        - *Provisioned mode* - Lets you specify the number of reads and writes per second that you need for your application.

        If you don't specify a value for this property, then the table will use on-demand mode.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-billingmode
        '''
        return typing.cast(typing.Optional[typing.Union["CfnTable.BillingModeProperty", _IResolvable_da3f097b]], jsii.get(self, "billingMode"))

    @billing_mode.setter
    def billing_mode(
        self,
        value: typing.Optional[typing.Union["CfnTable.BillingModeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "billingMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusteringKeyColumns")
    def clustering_key_columns(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ClusteringKeyColumnProperty", _IResolvable_da3f097b]]]]:
        '''One or more columns that determine how the table data is sorted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-clusteringkeycolumns
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ClusteringKeyColumnProperty", _IResolvable_da3f097b]]]], jsii.get(self, "clusteringKeyColumns"))

    @clustering_key_columns.setter
    def clustering_key_columns(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ClusteringKeyColumnProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "clusteringKeyColumns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultTimeToLive")
    def default_time_to_live(self) -> typing.Optional[jsii.Number]:
        '''The default Time To Live (TTL) value for all rows in a table in seconds.

        The maximum configurable value is 630,720,000 seconds, which is the equivalent of 20 years. By default, the TTL value for a table is 0, which means data does not expire.

        For more information, see `Setting the default TTL value for a table <https://docs.aws.amazon.com/keyspaces/latest/devguide/TTL-how-it-works.html#ttl-howitworks_default_ttl>`_ in the *Amazon Keyspaces Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-defaulttimetolive
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "defaultTimeToLive"))

    @default_time_to_live.setter
    def default_time_to_live(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "defaultTimeToLive", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionSpecification")
    def encryption_specification(
        self,
    ) -> typing.Optional[typing.Union["CfnTable.EncryptionSpecificationProperty", _IResolvable_da3f097b]]:
        '''The encryption at rest options for the table.

        - *AWS owned key* (default) - The key is owned by Amazon Keyspaces.
        - *Customer managed key* - The key is stored in your account and is created, owned, and managed by you.

        .. epigraph::

           If you choose encryption with a customer managed key, you must specify a valid customer managed KMS key with permissions granted to Amazon Keyspaces.

        For more information, see `Encryption at rest in Amazon Keyspaces <https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html>`_ in the *Amazon Keyspaces Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-encryptionspecification
        '''
        return typing.cast(typing.Optional[typing.Union["CfnTable.EncryptionSpecificationProperty", _IResolvable_da3f097b]], jsii.get(self, "encryptionSpecification"))

    @encryption_specification.setter
    def encryption_specification(
        self,
        value: typing.Optional[typing.Union["CfnTable.EncryptionSpecificationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "encryptionSpecification", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="pointInTimeRecoveryEnabled")
    def point_in_time_recovery_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies if point-in-time recovery is enabled or disabled for the table.

        The options are ``PointInTimeRecoveryEnabled=true`` and ``PointInTimeRecoveryEnabled=false`` . If not specified, the default is ``PointInTimeRecoveryEnabled=false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-pointintimerecoveryenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "pointInTimeRecoveryEnabled"))

    @point_in_time_recovery_enabled.setter
    def point_in_time_recovery_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "pointInTimeRecoveryEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="regularColumns")
    def regular_columns(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]]:
        '''One or more columns that are not part of the primary key - that is, columns that are *not* defined as partition key columns or clustering key columns.

        You can add regular columns to existing tables by adding them to the template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-regularcolumns
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]], jsii.get(self, "regularColumns"))

    @regular_columns.setter
    def regular_columns(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "regularColumns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tableName")
    def table_name(self) -> typing.Optional[builtins.str]:
        '''The name of the table to be created.

        The table name is case sensitive. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the table name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        *Length constraints:* Minimum length of 3. Maximum length of 255.

        *Pattern:* ``^[a-zA-Z0-9][a-zA-Z0-9_]{1,47}$``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-tablename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "tableName"))

    @table_name.setter
    def table_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "tableName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cassandra.CfnTable.BillingModeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "mode": "mode",
            "provisioned_throughput": "provisionedThroughput",
        },
    )
    class BillingModeProperty:
        def __init__(
            self,
            *,
            mode: builtins.str,
            provisioned_throughput: typing.Optional[typing.Union["CfnTable.ProvisionedThroughputProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Determines the billing mode for the table - On-demand or provisioned.

            :param mode: The billing mode for the table:. - On-demand mode - ``ON_DEMAND`` - Provisioned mode - ``PROVISIONED`` .. epigraph:: If you choose ``PROVISIONED`` mode, then you also need to specify provisioned throughput (read and write capacity) for the table. Valid values: ``ON_DEMAND`` | ``PROVISIONED``
            :param provisioned_throughput: The provisioned read capacity and write capacity for the table. For more information, see `Provisioned throughput capacity mode <https://docs.aws.amazon.com/keyspaces/latest/devguide/ReadWriteCapacityMode.html#ReadWriteCapacityMode.Provisioned>`_ in the *Amazon Keyspaces Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-billingmode.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cassandra as cassandra
                
                billing_mode_property = cassandra.CfnTable.BillingModeProperty(
                    mode="mode",
                
                    # the properties below are optional
                    provisioned_throughput=cassandra.CfnTable.ProvisionedThroughputProperty(
                        read_capacity_units=123,
                        write_capacity_units=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "mode": mode,
            }
            if provisioned_throughput is not None:
                self._values["provisioned_throughput"] = provisioned_throughput

        @builtins.property
        def mode(self) -> builtins.str:
            '''The billing mode for the table:.

            - On-demand mode - ``ON_DEMAND``
            - Provisioned mode - ``PROVISIONED``

            .. epigraph::

               If you choose ``PROVISIONED`` mode, then you also need to specify provisioned throughput (read and write capacity) for the table.

            Valid values: ``ON_DEMAND`` | ``PROVISIONED``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-billingmode.html#cfn-cassandra-table-billingmode-mode
            '''
            result = self._values.get("mode")
            assert result is not None, "Required property 'mode' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def provisioned_throughput(
            self,
        ) -> typing.Optional[typing.Union["CfnTable.ProvisionedThroughputProperty", _IResolvable_da3f097b]]:
            '''The provisioned read capacity and write capacity for the table.

            For more information, see `Provisioned throughput capacity mode <https://docs.aws.amazon.com/keyspaces/latest/devguide/ReadWriteCapacityMode.html#ReadWriteCapacityMode.Provisioned>`_ in the *Amazon Keyspaces Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-billingmode.html#cfn-cassandra-table-billingmode-provisionedthroughput
            '''
            result = self._values.get("provisioned_throughput")
            return typing.cast(typing.Optional[typing.Union["CfnTable.ProvisionedThroughputProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BillingModeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cassandra.CfnTable.ClusteringKeyColumnProperty",
        jsii_struct_bases=[],
        name_mapping={"column": "column", "order_by": "orderBy"},
    )
    class ClusteringKeyColumnProperty:
        def __init__(
            self,
            *,
            column: typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b],
            order_by: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Defines an individual column within the clustering key.

            :param column: The name and data type of this clustering key column.
            :param order_by: The order in which this column's data is stored:. - ``ASC`` (default) - The column's data is stored in ascending order. - ``DESC`` - The column's data is stored in descending order.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-clusteringkeycolumn.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cassandra as cassandra
                
                clustering_key_column_property = cassandra.CfnTable.ClusteringKeyColumnProperty(
                    column=cassandra.CfnTable.ColumnProperty(
                        column_name="columnName",
                        column_type="columnType"
                    ),
                
                    # the properties below are optional
                    order_by="orderBy"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "column": column,
            }
            if order_by is not None:
                self._values["order_by"] = order_by

        @builtins.property
        def column(
            self,
        ) -> typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b]:
            '''The name and data type of this clustering key column.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-clusteringkeycolumn.html#cfn-cassandra-table-clusteringkeycolumn-column
            '''
            result = self._values.get("column")
            assert result is not None, "Required property 'column' is missing"
            return typing.cast(typing.Union["CfnTable.ColumnProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def order_by(self) -> typing.Optional[builtins.str]:
            '''The order in which this column's data is stored:.

            - ``ASC`` (default) - The column's data is stored in ascending order.
            - ``DESC`` - The column's data is stored in descending order.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-clusteringkeycolumn.html#cfn-cassandra-table-clusteringkeycolumn-orderby
            '''
            result = self._values.get("order_by")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ClusteringKeyColumnProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cassandra.CfnTable.ColumnProperty",
        jsii_struct_bases=[],
        name_mapping={"column_name": "columnName", "column_type": "columnType"},
    )
    class ColumnProperty:
        def __init__(
            self,
            *,
            column_name: builtins.str,
            column_type: builtins.str,
        ) -> None:
            '''The name and data type of an individual column in a table.

            :param column_name: The name of the column. For more information, see `Identifiers <https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html#cql.elements.identifier>`_ in the *Amazon Keyspaces Developer Guide* .
            :param column_type: The data type of the column. For more information, see `Data types <https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html#cql.data-types>`_ in the *Amazon Keyspaces Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-column.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cassandra as cassandra
                
                column_property = cassandra.CfnTable.ColumnProperty(
                    column_name="columnName",
                    column_type="columnType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "column_name": column_name,
                "column_type": column_type,
            }

        @builtins.property
        def column_name(self) -> builtins.str:
            '''The name of the column.

            For more information, see `Identifiers <https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html#cql.elements.identifier>`_ in the *Amazon Keyspaces Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-column.html#cfn-cassandra-table-column-columnname
            '''
            result = self._values.get("column_name")
            assert result is not None, "Required property 'column_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def column_type(self) -> builtins.str:
            '''The data type of the column.

            For more information, see `Data types <https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html#cql.data-types>`_ in the *Amazon Keyspaces Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-column.html#cfn-cassandra-table-column-columntype
            '''
            result = self._values.get("column_type")
            assert result is not None, "Required property 'column_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cassandra.CfnTable.EncryptionSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encryption_type": "encryptionType",
            "kms_key_identifier": "kmsKeyIdentifier",
        },
    )
    class EncryptionSpecificationProperty:
        def __init__(
            self,
            *,
            encryption_type: builtins.str,
            kms_key_identifier: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the encryption at rest option selected for the table.

            :param encryption_type: The encryption at rest options for the table. - *AWS owned key* (default) - ``AWS_OWNED_KMS_KEY`` - *Customer managed key* - ``CUSTOMER_MANAGED_KMS_KEY`` .. epigraph:: If you choose ``CUSTOMER_MANAGED_KMS_KEY`` , a ``kms_key_identifier`` in the format of a key ARN is required. Valid values: ``CUSTOMER_MANAGED_KMS_KEY`` | ``AWS_OWNED_KMS_KEY`` .
            :param kms_key_identifier: Requires a ``kms_key_identifier`` in the format of a key ARN.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-encryptionspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cassandra as cassandra
                
                encryption_specification_property = cassandra.CfnTable.EncryptionSpecificationProperty(
                    encryption_type="encryptionType",
                
                    # the properties below are optional
                    kms_key_identifier="kmsKeyIdentifier"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "encryption_type": encryption_type,
            }
            if kms_key_identifier is not None:
                self._values["kms_key_identifier"] = kms_key_identifier

        @builtins.property
        def encryption_type(self) -> builtins.str:
            '''The encryption at rest options for the table.

            - *AWS owned key* (default) - ``AWS_OWNED_KMS_KEY``
            - *Customer managed key* - ``CUSTOMER_MANAGED_KMS_KEY``

            .. epigraph::

               If you choose ``CUSTOMER_MANAGED_KMS_KEY`` , a ``kms_key_identifier`` in the format of a key ARN is required.

            Valid values: ``CUSTOMER_MANAGED_KMS_KEY`` | ``AWS_OWNED_KMS_KEY`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-encryptionspecification.html#cfn-cassandra-table-encryptionspecification-encryptiontype
            '''
            result = self._values.get("encryption_type")
            assert result is not None, "Required property 'encryption_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_key_identifier(self) -> typing.Optional[builtins.str]:
            '''Requires a ``kms_key_identifier`` in the format of a key ARN.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-encryptionspecification.html#cfn-cassandra-table-encryptionspecification-kmskeyidentifier
            '''
            result = self._values.get("kms_key_identifier")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cassandra.CfnTable.ProvisionedThroughputProperty",
        jsii_struct_bases=[],
        name_mapping={
            "read_capacity_units": "readCapacityUnits",
            "write_capacity_units": "writeCapacityUnits",
        },
    )
    class ProvisionedThroughputProperty:
        def __init__(
            self,
            *,
            read_capacity_units: jsii.Number,
            write_capacity_units: jsii.Number,
        ) -> None:
            '''The provisioned throughput for the table, which consists of ``ReadCapacityUnits`` and ``WriteCapacityUnits`` .

            :param read_capacity_units: The amount of read capacity that's provisioned for the table. For more information, see `Read/write capacity mode <https://docs.aws.amazon.com/keyspaces/latest/devguide/ReadWriteCapacityMode.html>`_ in the *Amazon Keyspaces Developer Guide* .
            :param write_capacity_units: The amount of write capacity that's provisioned for the table. For more information, see `Read/write capacity mode <https://docs.aws.amazon.com/keyspaces/latest/devguide/ReadWriteCapacityMode.html>`_ in the *Amazon Keyspaces Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-provisionedthroughput.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cassandra as cassandra
                
                provisioned_throughput_property = cassandra.CfnTable.ProvisionedThroughputProperty(
                    read_capacity_units=123,
                    write_capacity_units=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "read_capacity_units": read_capacity_units,
                "write_capacity_units": write_capacity_units,
            }

        @builtins.property
        def read_capacity_units(self) -> jsii.Number:
            '''The amount of read capacity that's provisioned for the table.

            For more information, see `Read/write capacity mode <https://docs.aws.amazon.com/keyspaces/latest/devguide/ReadWriteCapacityMode.html>`_ in the *Amazon Keyspaces Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-provisionedthroughput.html#cfn-cassandra-table-provisionedthroughput-readcapacityunits
            '''
            result = self._values.get("read_capacity_units")
            assert result is not None, "Required property 'read_capacity_units' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def write_capacity_units(self) -> jsii.Number:
            '''The amount of write capacity that's provisioned for the table.

            For more information, see `Read/write capacity mode <https://docs.aws.amazon.com/keyspaces/latest/devguide/ReadWriteCapacityMode.html>`_ in the *Amazon Keyspaces Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cassandra-table-provisionedthroughput.html#cfn-cassandra-table-provisionedthroughput-writecapacityunits
            '''
            result = self._values.get("write_capacity_units")
            assert result is not None, "Required property 'write_capacity_units' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ProvisionedThroughputProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cassandra.CfnTableProps",
    jsii_struct_bases=[],
    name_mapping={
        "keyspace_name": "keyspaceName",
        "partition_key_columns": "partitionKeyColumns",
        "billing_mode": "billingMode",
        "clustering_key_columns": "clusteringKeyColumns",
        "default_time_to_live": "defaultTimeToLive",
        "encryption_specification": "encryptionSpecification",
        "point_in_time_recovery_enabled": "pointInTimeRecoveryEnabled",
        "regular_columns": "regularColumns",
        "table_name": "tableName",
        "tags": "tags",
    },
)
class CfnTableProps:
    def __init__(
        self,
        *,
        keyspace_name: builtins.str,
        partition_key_columns: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTable.ColumnProperty, _IResolvable_da3f097b]]],
        billing_mode: typing.Optional[typing.Union[CfnTable.BillingModeProperty, _IResolvable_da3f097b]] = None,
        clustering_key_columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTable.ClusteringKeyColumnProperty, _IResolvable_da3f097b]]]] = None,
        default_time_to_live: typing.Optional[jsii.Number] = None,
        encryption_specification: typing.Optional[typing.Union[CfnTable.EncryptionSpecificationProperty, _IResolvable_da3f097b]] = None,
        point_in_time_recovery_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        regular_columns: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTable.ColumnProperty, _IResolvable_da3f097b]]]] = None,
        table_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnTable``.

        :param keyspace_name: The name of the keyspace in which to create the table. The keyspace must already exist.
        :param partition_key_columns: One or more columns that uniquely identify every row in the table. Every table must have a partition key.
        :param billing_mode: The billing mode for the table, which determines how you'll be charged for reads and writes:. - *On-demand mode* (default) - You pay based on the actual reads and writes your application performs. - *Provisioned mode* - Lets you specify the number of reads and writes per second that you need for your application. If you don't specify a value for this property, then the table will use on-demand mode.
        :param clustering_key_columns: One or more columns that determine how the table data is sorted.
        :param default_time_to_live: The default Time To Live (TTL) value for all rows in a table in seconds. The maximum configurable value is 630,720,000 seconds, which is the equivalent of 20 years. By default, the TTL value for a table is 0, which means data does not expire. For more information, see `Setting the default TTL value for a table <https://docs.aws.amazon.com/keyspaces/latest/devguide/TTL-how-it-works.html#ttl-howitworks_default_ttl>`_ in the *Amazon Keyspaces Developer Guide* .
        :param encryption_specification: The encryption at rest options for the table. - *AWS owned key* (default) - The key is owned by Amazon Keyspaces. - *Customer managed key* - The key is stored in your account and is created, owned, and managed by you. .. epigraph:: If you choose encryption with a customer managed key, you must specify a valid customer managed KMS key with permissions granted to Amazon Keyspaces. For more information, see `Encryption at rest in Amazon Keyspaces <https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html>`_ in the *Amazon Keyspaces Developer Guide* .
        :param point_in_time_recovery_enabled: Specifies if point-in-time recovery is enabled or disabled for the table. The options are ``PointInTimeRecoveryEnabled=true`` and ``PointInTimeRecoveryEnabled=false`` . If not specified, the default is ``PointInTimeRecoveryEnabled=false`` .
        :param regular_columns: One or more columns that are not part of the primary key - that is, columns that are *not* defined as partition key columns or clustering key columns. You can add regular columns to existing tables by adding them to the template.
        :param table_name: The name of the table to be created. The table name is case sensitive. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the table name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. *Length constraints:* Minimum length of 3. Maximum length of 255. *Pattern:* ``^[a-zA-Z0-9][a-zA-Z0-9_]{1,47}$``
        :param tags: A list of key-value pair tags to be attached to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cassandra as cassandra
            
            cfn_table_props = cassandra.CfnTableProps(
                keyspace_name="keyspaceName",
                partition_key_columns=[cassandra.CfnTable.ColumnProperty(
                    column_name="columnName",
                    column_type="columnType"
                )],
            
                # the properties below are optional
                billing_mode=cassandra.CfnTable.BillingModeProperty(
                    mode="mode",
            
                    # the properties below are optional
                    provisioned_throughput=cassandra.CfnTable.ProvisionedThroughputProperty(
                        read_capacity_units=123,
                        write_capacity_units=123
                    )
                ),
                clustering_key_columns=[cassandra.CfnTable.ClusteringKeyColumnProperty(
                    column=cassandra.CfnTable.ColumnProperty(
                        column_name="columnName",
                        column_type="columnType"
                    ),
            
                    # the properties below are optional
                    order_by="orderBy"
                )],
                default_time_to_live=123,
                encryption_specification=cassandra.CfnTable.EncryptionSpecificationProperty(
                    encryption_type="encryptionType",
            
                    # the properties below are optional
                    kms_key_identifier="kmsKeyIdentifier"
                ),
                point_in_time_recovery_enabled=False,
                regular_columns=[cassandra.CfnTable.ColumnProperty(
                    column_name="columnName",
                    column_type="columnType"
                )],
                table_name="tableName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "keyspace_name": keyspace_name,
            "partition_key_columns": partition_key_columns,
        }
        if billing_mode is not None:
            self._values["billing_mode"] = billing_mode
        if clustering_key_columns is not None:
            self._values["clustering_key_columns"] = clustering_key_columns
        if default_time_to_live is not None:
            self._values["default_time_to_live"] = default_time_to_live
        if encryption_specification is not None:
            self._values["encryption_specification"] = encryption_specification
        if point_in_time_recovery_enabled is not None:
            self._values["point_in_time_recovery_enabled"] = point_in_time_recovery_enabled
        if regular_columns is not None:
            self._values["regular_columns"] = regular_columns
        if table_name is not None:
            self._values["table_name"] = table_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def keyspace_name(self) -> builtins.str:
        '''The name of the keyspace in which to create the table.

        The keyspace must already exist.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-keyspacename
        '''
        result = self._values.get("keyspace_name")
        assert result is not None, "Required property 'keyspace_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def partition_key_columns(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTable.ColumnProperty, _IResolvable_da3f097b]]]:
        '''One or more columns that uniquely identify every row in the table.

        Every table must have a partition key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-partitionkeycolumns
        '''
        result = self._values.get("partition_key_columns")
        assert result is not None, "Required property 'partition_key_columns' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTable.ColumnProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def billing_mode(
        self,
    ) -> typing.Optional[typing.Union[CfnTable.BillingModeProperty, _IResolvable_da3f097b]]:
        '''The billing mode for the table, which determines how you'll be charged for reads and writes:.

        - *On-demand mode* (default) - You pay based on the actual reads and writes your application performs.
        - *Provisioned mode* - Lets you specify the number of reads and writes per second that you need for your application.

        If you don't specify a value for this property, then the table will use on-demand mode.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-billingmode
        '''
        result = self._values.get("billing_mode")
        return typing.cast(typing.Optional[typing.Union[CfnTable.BillingModeProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def clustering_key_columns(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTable.ClusteringKeyColumnProperty, _IResolvable_da3f097b]]]]:
        '''One or more columns that determine how the table data is sorted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-clusteringkeycolumns
        '''
        result = self._values.get("clustering_key_columns")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTable.ClusteringKeyColumnProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def default_time_to_live(self) -> typing.Optional[jsii.Number]:
        '''The default Time To Live (TTL) value for all rows in a table in seconds.

        The maximum configurable value is 630,720,000 seconds, which is the equivalent of 20 years. By default, the TTL value for a table is 0, which means data does not expire.

        For more information, see `Setting the default TTL value for a table <https://docs.aws.amazon.com/keyspaces/latest/devguide/TTL-how-it-works.html#ttl-howitworks_default_ttl>`_ in the *Amazon Keyspaces Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-defaulttimetolive
        '''
        result = self._values.get("default_time_to_live")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def encryption_specification(
        self,
    ) -> typing.Optional[typing.Union[CfnTable.EncryptionSpecificationProperty, _IResolvable_da3f097b]]:
        '''The encryption at rest options for the table.

        - *AWS owned key* (default) - The key is owned by Amazon Keyspaces.
        - *Customer managed key* - The key is stored in your account and is created, owned, and managed by you.

        .. epigraph::

           If you choose encryption with a customer managed key, you must specify a valid customer managed KMS key with permissions granted to Amazon Keyspaces.

        For more information, see `Encryption at rest in Amazon Keyspaces <https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html>`_ in the *Amazon Keyspaces Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-encryptionspecification
        '''
        result = self._values.get("encryption_specification")
        return typing.cast(typing.Optional[typing.Union[CfnTable.EncryptionSpecificationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def point_in_time_recovery_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies if point-in-time recovery is enabled or disabled for the table.

        The options are ``PointInTimeRecoveryEnabled=true`` and ``PointInTimeRecoveryEnabled=false`` . If not specified, the default is ``PointInTimeRecoveryEnabled=false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-pointintimerecoveryenabled
        '''
        result = self._values.get("point_in_time_recovery_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def regular_columns(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTable.ColumnProperty, _IResolvable_da3f097b]]]]:
        '''One or more columns that are not part of the primary key - that is, columns that are *not* defined as partition key columns or clustering key columns.

        You can add regular columns to existing tables by adding them to the template.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-regularcolumns
        '''
        result = self._values.get("regular_columns")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTable.ColumnProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def table_name(self) -> typing.Optional[builtins.str]:
        '''The name of the table to be created.

        The table name is case sensitive. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the table name. For more information, see `Name type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        *Length constraints:* Minimum length of 3. Maximum length of 255.

        *Pattern:* ``^[a-zA-Z0-9][a-zA-Z0-9_]{1,47}$``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-tablename
        '''
        result = self._values.get("table_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of key-value pair tags to be attached to the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cassandra-table.html#cfn-cassandra-table-tags
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
    "CfnKeyspace",
    "CfnKeyspaceProps",
    "CfnTable",
    "CfnTableProps",
]

publication.publish()
