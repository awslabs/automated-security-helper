'''
# Amazon DocumentDB Construct Library

## Starting a Clustered Database

To set up a clustered DocumentDB database, define a `DatabaseCluster`. You must
always launch a database in a VPC. Use the `vpcSubnets` attribute to control whether
your instances will be launched privately or publicly:

```python
# vpc: ec2.Vpc

cluster = docdb.DatabaseCluster(self, "Database",
    master_user=docdb.Login(
        username="myuser",  # NOTE: 'admin' is reserved by DocumentDB
        exclude_characters="\"@/:",  # optional, defaults to the set "\"@/" and is also used for eventually created rotations
        secret_name="/myapp/mydocdb/masteruser"
    ),
    instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc_subnets=ec2.SubnetSelection(
        subnet_type=ec2.SubnetType.PUBLIC
    ),
    vpc=vpc
)
```

By default, the master password will be generated and stored in AWS Secrets Manager with auto-generated description.

Your cluster will be empty by default.

## Connecting

To control who can access the cluster, use the `.connections` attribute. DocumentDB databases have a default port, so
you don't need to specify the port:

```python
# cluster: docdb.DatabaseCluster

cluster.connections.allow_default_port_from_any_ipv4("Open to the world")
```

The endpoints to access your database cluster will be available as the `.clusterEndpoint` and `.clusterReadEndpoint`
attributes:

```python
# cluster: docdb.DatabaseCluster

write_address = cluster.cluster_endpoint.socket_address
```

If you have existing security groups you would like to add to the cluster, use the `addSecurityGroups` method. Security
groups added in this way will not be managed by the `Connections` object of the cluster.

```python
# vpc: ec2.Vpc
# cluster: docdb.DatabaseCluster


security_group = ec2.SecurityGroup(self, "SecurityGroup",
    vpc=vpc
)
cluster.add_security_groups(security_group)
```

## Deletion protection

Deletion protection can be enabled on an Amazon DocumentDB cluster to prevent accidental deletion of the cluster:

```python
# vpc: ec2.Vpc

cluster = docdb.DatabaseCluster(self, "Database",
    master_user=docdb.Login(
        username="myuser"
    ),
    instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc_subnets=ec2.SubnetSelection(
        subnet_type=ec2.SubnetType.PUBLIC
    ),
    vpc=vpc,
    deletion_protection=True
)
```

## Rotating credentials

When the master password is generated and stored in AWS Secrets Manager, it can be rotated automatically:

```python
# cluster: docdb.DatabaseCluster

cluster.add_rotation_single_user()
```

```python
cluster = docdb.DatabaseCluster(stack, "Database",
    master_user=cdk.aws_docdb.Login(
        username="docdb"
    ),
    instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc=vpc,
    removal_policy=cdk.RemovalPolicy.DESTROY
)

cluster.add_rotation_single_user()
```

The multi user rotation scheme is also available:

```python
import aws_cdk.aws_secretsmanager as secretsmanager

# my_imported_secret: secretsmanager.Secret
# cluster: docdb.DatabaseCluster


cluster.add_rotation_multi_user("MyUser",
    secret=my_imported_secret
)
```

It's also possible to create user credentials together with the cluster and add rotation:

```python
# cluster: docdb.DatabaseCluster

my_user_secret = docdb.DatabaseSecret(self, "MyUserSecret",
    username="myuser",
    master_secret=cluster.secret
)
my_user_secret_attached = my_user_secret.attach(cluster) # Adds DB connections information in the secret

cluster.add_rotation_multi_user("MyUser",  # Add rotation using the multi user scheme
    secret=my_user_secret_attached)
```

**Note**: This user must be created manually in the database using the master credentials.
The rotation will start as soon as this user exists.

See also [@aws-cdk/aws-secretsmanager](https://github.com/aws/aws-cdk/blob/master/packages/%40aws-cdk/aws-secretsmanager/README.md) for credentials rotation of existing clusters.

## Audit and profiler Logs

Sending audit or profiler needs to be configured in two places:

1. Check / create the needed options in your ParameterGroup for [audit](https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html#event-auditing-enabling-auditing) and
   [profiler](https://docs.aws.amazon.com/documentdb/latest/developerguide/profiling.html#profiling.enable-profiling) logs.
2. Enable the corresponding option(s) when creating the `DatabaseCluster`:

```python
import aws_cdk.aws_iam as iam
import aws_cdk.aws_logs as logs

# my_logs_publishing_role: iam.Role
# vpc: ec2.Vpc


cluster = docdb.DatabaseCluster(self, "Database",
    master_user=docdb.Login(
        username="myuser"
    ),
    instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpc_subnets=ec2.SubnetSelection(
        subnet_type=ec2.SubnetType.PUBLIC
    ),
    vpc=vpc,
    export_profiler_logs_to_cloud_watch=True,  # Enable sending profiler logs
    export_audit_logs_to_cloud_watch=True,  # Enable sending audit logs
    cloud_watch_logs_retention=logs.RetentionDays.THREE_MONTHS,  # Optional - default is to never expire logs
    cloud_watch_logs_retention_role=my_logs_publishing_role
)
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
    SecretValue as _SecretValue_3dd0ddae,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_ec2 import (
    Connections as _Connections_0f31fce8,
    IConnectable as _IConnectable_10015a05,
    ISecurityGroup as _ISecurityGroup_acf8a799,
    IVpc as _IVpc_f30d5663,
    InstanceType as _InstanceType_f64915b9,
    SubnetSelection as _SubnetSelection_e57d76df,
)
from ..aws_iam import IRole as _IRole_235f5d8e
from ..aws_kms import IKey as _IKey_5f11635f
from ..aws_logs import RetentionDays as _RetentionDays_070f99f0
from ..aws_secretsmanager import (
    ISecret as _ISecret_6e020e6a,
    ISecretAttachmentTarget as _ISecretAttachmentTarget_123e2df9,
    Secret as _Secret_50778576,
    SecretAttachmentTargetProps as _SecretAttachmentTargetProps_9ec7949d,
    SecretRotation as _SecretRotation_38c354d9,
)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.BackupProps",
    jsii_struct_bases=[],
    name_mapping={"retention": "retention", "preferred_window": "preferredWindow"},
)
class BackupProps:
    def __init__(
        self,
        *,
        retention: _Duration_4839e8c3,
        preferred_window: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Backup configuration for DocumentDB databases.

        :param retention: How many days to retain the backup.
        :param preferred_window: A daily time range in 24-hours UTC format in which backups preferably execute. Must be at least 30 minutes long. Example: '01:00-02:00' Default: - a 30-minute window selected at random from an 8-hour block of time for each AWS Region. To see the time blocks available, see https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshots.html#backup-restore.backup-window

        :default:

        - The retention period for automated backups is 1 day.
        The preferred backup window will be a 30-minute window selected at random
        from an 8-hour block of time for each AWS Region.

        :see: https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshots.html#backup-restore.backup-window
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_docdb as docdb
            
            backup_props = docdb.BackupProps(
                retention=cdk.Duration.minutes(30),
            
                # the properties below are optional
                preferred_window="preferredWindow"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "retention": retention,
        }
        if preferred_window is not None:
            self._values["preferred_window"] = preferred_window

    @builtins.property
    def retention(self) -> _Duration_4839e8c3:
        '''How many days to retain the backup.'''
        result = self._values.get("retention")
        assert result is not None, "Required property 'retention' is missing"
        return typing.cast(_Duration_4839e8c3, result)

    @builtins.property
    def preferred_window(self) -> typing.Optional[builtins.str]:
        '''A daily time range in 24-hours UTC format in which backups preferably execute.

        Must be at least 30 minutes long.

        Example: '01:00-02:00'

        :default:

        - a 30-minute window selected at random from an 8-hour block of
        time for each AWS Region. To see the time blocks available, see
        https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshots.html#backup-restore.backup-window
        '''
        result = self._values.get("preferred_window")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BackupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDBCluster(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_docdb.CfnDBCluster",
):
    '''A CloudFormation ``AWS::DocDB::DBCluster``.

    The ``AWS::DocDB::DBCluster`` Amazon DocumentDB (with MongoDB compatibility) resource describes a DBCluster. Amazon DocumentDB is a fully managed, MongoDB-compatible document database engine. For more information, see `DBCluster <https://docs.aws.amazon.com/documentdb/latest/developerguide/API_DBCluster.html>`_ in the *Amazon DocumentDB Developer Guide* .

    :cloudformationResource: AWS::DocDB::DBCluster
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_docdb as docdb
        
        cfn_dBCluster = docdb.CfnDBCluster(self, "MyCfnDBCluster",
            availability_zones=["availabilityZones"],
            backup_retention_period=123,
            copy_tags_to_snapshot=False,
            db_cluster_identifier="dbClusterIdentifier",
            db_cluster_parameter_group_name="dbClusterParameterGroupName",
            db_subnet_group_name="dbSubnetGroupName",
            deletion_protection=False,
            enable_cloudwatch_logs_exports=["enableCloudwatchLogsExports"],
            engine_version="engineVersion",
            kms_key_id="kmsKeyId",
            master_username="masterUsername",
            master_user_password="masterUserPassword",
            port=123,
            preferred_backup_window="preferredBackupWindow",
            preferred_maintenance_window="preferredMaintenanceWindow",
            snapshot_identifier="snapshotIdentifier",
            storage_encrypted=False,
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
        availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
        backup_retention_period: typing.Optional[jsii.Number] = None,
        copy_tags_to_snapshot: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        db_cluster_identifier: typing.Optional[builtins.str] = None,
        db_cluster_parameter_group_name: typing.Optional[builtins.str] = None,
        db_subnet_group_name: typing.Optional[builtins.str] = None,
        deletion_protection: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        enable_cloudwatch_logs_exports: typing.Optional[typing.Sequence[builtins.str]] = None,
        engine_version: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        master_username: typing.Optional[builtins.str] = None,
        master_user_password: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        preferred_backup_window: typing.Optional[builtins.str] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        snapshot_identifier: typing.Optional[builtins.str] = None,
        storage_encrypted: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::DocDB::DBCluster``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param availability_zones: A list of Amazon EC2 Availability Zones that instances in the cluster can be created in.
        :param backup_retention_period: The number of days for which automated backups are retained. You must specify a minimum value of 1. Default: 1 Constraints: - Must be a value from 1 to 35.
        :param copy_tags_to_snapshot: ``AWS::DocDB::DBCluster.CopyTagsToSnapshot``.
        :param db_cluster_identifier: The cluster identifier. This parameter is stored as a lowercase string. Constraints: - Must contain from 1 to 63 letters, numbers, or hyphens. - The first character must be a letter. - Cannot end with a hyphen or contain two consecutive hyphens. Example: ``my-cluster``
        :param db_cluster_parameter_group_name: The name of the cluster parameter group to associate with this cluster.
        :param db_subnet_group_name: A subnet group to associate with this cluster. Constraints: Must match the name of an existing ``DBSubnetGroup`` . Must not be default. Example: ``mySubnetgroup``
        :param deletion_protection: Protects clusters from being accidentally deleted. If enabled, the cluster cannot be deleted unless it is modified and ``DeletionProtection`` is disabled.
        :param enable_cloudwatch_logs_exports: The list of log types that need to be enabled for exporting to Amazon CloudWatch Logs. You can enable audit logs or profiler logs. For more information, see `Auditing Amazon DocumentDB Events <https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html>`_ and `Profiling Amazon DocumentDB Operations <https://docs.aws.amazon.com/documentdb/latest/developerguide/profiling.html>`_ .
        :param engine_version: The version number of the database engine to use. The ``--engine-version`` will default to the latest major engine version. For production workloads, we recommend explicitly declaring this parameter with the intended major engine version.
        :param kms_key_id: The AWS KMS key identifier for an encrypted cluster. The AWS KMS key identifier is the Amazon Resource Name (ARN) for the AWS KMS encryption key. If you are creating a cluster using the same AWS account that owns the AWS KMS encryption key that is used to encrypt the new cluster, you can use the AWS KMS key alias instead of the ARN for the AWS KMS encryption key. If an encryption key is not specified in ``KmsKeyId`` : - If the ``StorageEncrypted`` parameter is ``true`` , Amazon DocumentDB uses your default encryption key. AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Regions .
        :param master_username: The name of the master user for the cluster. Constraints: - Must be from 1 to 63 letters or numbers. - The first character must be a letter. - Cannot be a reserved word for the chosen database engine.
        :param master_user_password: The password for the master database user. This password can contain any printable ASCII character except forward slash (/), double quote ("), or the "at" symbol (@). Constraints: Must contain from 8 to 100 characters.
        :param port: Specifies the port that the database engine is listening on.
        :param preferred_backup_window: The daily time range during which automated backups are created if automated backups are enabled using the ``BackupRetentionPeriod`` parameter. The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region . Constraints: - Must be in the format ``hh24:mi-hh24:mi`` . - Must be in Universal Coordinated Time (UTC). - Must not conflict with the preferred maintenance window. - Must be at least 30 minutes.
        :param preferred_maintenance_window: The weekly time range during which system maintenance can occur, in Universal Coordinated Time (UTC). Format: ``ddd:hh24:mi-ddd:hh24:mi`` The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region , occurring on a random day of the week. Valid days: Mon, Tue, Wed, Thu, Fri, Sat, Sun Constraints: Minimum 30-minute window.
        :param snapshot_identifier: The identifier for the snapshot or cluster snapshot to restore from. You can use either the name or the Amazon Resource Name (ARN) to specify a cluster snapshot. However, you can use only the ARN to specify a snapshot. Constraints: - Must match the identifier of an existing snapshot.
        :param storage_encrypted: Specifies whether the cluster is encrypted.
        :param tags: The tags to be assigned to the cluster.
        :param vpc_security_group_ids: A list of EC2 VPC security groups to associate with this cluster.
        '''
        props = CfnDBClusterProps(
            availability_zones=availability_zones,
            backup_retention_period=backup_retention_period,
            copy_tags_to_snapshot=copy_tags_to_snapshot,
            db_cluster_identifier=db_cluster_identifier,
            db_cluster_parameter_group_name=db_cluster_parameter_group_name,
            db_subnet_group_name=db_subnet_group_name,
            deletion_protection=deletion_protection,
            enable_cloudwatch_logs_exports=enable_cloudwatch_logs_exports,
            engine_version=engine_version,
            kms_key_id=kms_key_id,
            master_username=master_username,
            master_user_password=master_user_password,
            port=port,
            preferred_backup_window=preferred_backup_window,
            preferred_maintenance_window=preferred_maintenance_window,
            snapshot_identifier=snapshot_identifier,
            storage_encrypted=storage_encrypted,
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
    @jsii.member(jsii_name="attrClusterResourceId")
    def attr_cluster_resource_id(self) -> builtins.str:
        '''The resource id for the cluster;

        for example: ``cluster-ABCD1234EFGH5678IJKL90MNOP`` . The cluster ID uniquely identifies the cluster and is used in things like IAM authentication policies.

        :cloudformationAttribute: ClusterResourceId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrClusterResourceId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEndpoint")
    def attr_endpoint(self) -> builtins.str:
        '''The connection endpoint for the cluster, such as ``sample-cluster.cluster-cozrlsfrcjoc.us-east-1.docdb.amazonaws.com`` .

        :cloudformationAttribute: Endpoint
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPort")
    def attr_port(self) -> builtins.str:
        '''The port number on which the cluster accepts connections.

        For example: ``27017`` .

        :cloudformationAttribute: Port
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrReadEndpoint")
    def attr_read_endpoint(self) -> builtins.str:
        '''The reader endpoint for the cluster.

        For example: ``sample-cluster.cluster-ro-cozrlsfrcjoc.us-east-1.docdb.amazonaws.com`` .

        :cloudformationAttribute: ReadEndpoint
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrReadEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to be assigned to the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="availabilityZones")
    def availability_zones(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Amazon EC2 Availability Zones that instances in the cluster can be created in.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-availabilityzones
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "availabilityZones"))

    @availability_zones.setter
    def availability_zones(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "availabilityZones", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupRetentionPeriod")
    def backup_retention_period(self) -> typing.Optional[jsii.Number]:
        '''The number of days for which automated backups are retained. You must specify a minimum value of 1.

        Default: 1

        Constraints:

        - Must be a value from 1 to 35.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-backupretentionperiod
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "backupRetentionPeriod"))

    @backup_retention_period.setter
    def backup_retention_period(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "backupRetentionPeriod", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="copyTagsToSnapshot")
    def copy_tags_to_snapshot(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::DocDB::DBCluster.CopyTagsToSnapshot``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-copytagstosnapshot
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "copyTagsToSnapshot"))

    @copy_tags_to_snapshot.setter
    def copy_tags_to_snapshot(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "copyTagsToSnapshot", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbClusterIdentifier")
    def db_cluster_identifier(self) -> typing.Optional[builtins.str]:
        '''The cluster identifier. This parameter is stored as a lowercase string.

        Constraints:

        - Must contain from 1 to 63 letters, numbers, or hyphens.
        - The first character must be a letter.
        - Cannot end with a hyphen or contain two consecutive hyphens.

        Example: ``my-cluster``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-dbclusteridentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dbClusterIdentifier"))

    @db_cluster_identifier.setter
    def db_cluster_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dbClusterIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbClusterParameterGroupName")
    def db_cluster_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the cluster parameter group to associate with this cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-dbclusterparametergroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dbClusterParameterGroupName"))

    @db_cluster_parameter_group_name.setter
    def db_cluster_parameter_group_name(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "dbClusterParameterGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbSubnetGroupName")
    def db_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''A subnet group to associate with this cluster.

        Constraints: Must match the name of an existing ``DBSubnetGroup`` . Must not be default.

        Example: ``mySubnetgroup``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-dbsubnetgroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dbSubnetGroupName"))

    @db_subnet_group_name.setter
    def db_subnet_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dbSubnetGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deletionProtection")
    def deletion_protection(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Protects clusters from being accidentally deleted.

        If enabled, the cluster cannot be deleted unless it is modified and ``DeletionProtection`` is disabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-deletionprotection
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "deletionProtection"))

    @deletion_protection.setter
    def deletion_protection(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "deletionProtection", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableCloudwatchLogsExports")
    def enable_cloudwatch_logs_exports(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of log types that need to be enabled for exporting to Amazon CloudWatch Logs.

        You can enable audit logs or profiler logs. For more information, see `Auditing Amazon DocumentDB Events <https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html>`_ and `Profiling Amazon DocumentDB Operations <https://docs.aws.amazon.com/documentdb/latest/developerguide/profiling.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-enablecloudwatchlogsexports
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "enableCloudwatchLogsExports"))

    @enable_cloudwatch_logs_exports.setter
    def enable_cloudwatch_logs_exports(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "enableCloudwatchLogsExports", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="engineVersion")
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The version number of the database engine to use.

        The ``--engine-version`` will default to the latest major engine version. For production workloads, we recommend explicitly declaring this parameter with the intended major engine version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-engineversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "engineVersion"))

    @engine_version.setter
    def engine_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "engineVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The AWS KMS key identifier for an encrypted cluster.

        The AWS KMS key identifier is the Amazon Resource Name (ARN) for the AWS KMS encryption key. If you are creating a cluster using the same AWS account that owns the AWS KMS encryption key that is used to encrypt the new cluster, you can use the AWS KMS key alias instead of the ARN for the AWS KMS encryption key.

        If an encryption key is not specified in ``KmsKeyId`` :

        - If the ``StorageEncrypted`` parameter is ``true`` , Amazon DocumentDB uses your default encryption key.

        AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Regions .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="masterUsername")
    def master_username(self) -> typing.Optional[builtins.str]:
        '''The name of the master user for the cluster.

        Constraints:

        - Must be from 1 to 63 letters or numbers.
        - The first character must be a letter.
        - Cannot be a reserved word for the chosen database engine.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-masterusername
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "masterUsername"))

    @master_username.setter
    def master_username(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "masterUsername", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="masterUserPassword")
    def master_user_password(self) -> typing.Optional[builtins.str]:
        '''The password for the master database user.

        This password can contain any printable ASCII character except forward slash (/), double quote ("), or the "at" symbol (@).

        Constraints: Must contain from 8 to 100 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-masteruserpassword
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "masterUserPassword"))

    @master_user_password.setter
    def master_user_password(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "masterUserPassword", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="port")
    def port(self) -> typing.Optional[jsii.Number]:
        '''Specifies the port that the database engine is listening on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-port
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "port"))

    @port.setter
    def port(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "port", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredBackupWindow")
    def preferred_backup_window(self) -> typing.Optional[builtins.str]:
        '''The daily time range during which automated backups are created if automated backups are enabled using the ``BackupRetentionPeriod`` parameter.

        The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region .

        Constraints:

        - Must be in the format ``hh24:mi-hh24:mi`` .
        - Must be in Universal Coordinated Time (UTC).
        - Must not conflict with the preferred maintenance window.
        - Must be at least 30 minutes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-preferredbackupwindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preferredBackupWindow"))

    @preferred_backup_window.setter
    def preferred_backup_window(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "preferredBackupWindow", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredMaintenanceWindow")
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''The weekly time range during which system maintenance can occur, in Universal Coordinated Time (UTC).

        Format: ``ddd:hh24:mi-ddd:hh24:mi``

        The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region , occurring on a random day of the week.

        Valid days: Mon, Tue, Wed, Thu, Fri, Sat, Sun

        Constraints: Minimum 30-minute window.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-preferredmaintenancewindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preferredMaintenanceWindow"))

    @preferred_maintenance_window.setter
    def preferred_maintenance_window(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "preferredMaintenanceWindow", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotIdentifier")
    def snapshot_identifier(self) -> typing.Optional[builtins.str]:
        '''The identifier for the snapshot or cluster snapshot to restore from.

        You can use either the name or the Amazon Resource Name (ARN) to specify a cluster snapshot. However, you can use only the ARN to specify a snapshot.

        Constraints:

        - Must match the identifier of an existing snapshot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-snapshotidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "snapshotIdentifier"))

    @snapshot_identifier.setter
    def snapshot_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "snapshotIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="storageEncrypted")
    def storage_encrypted(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the cluster is encrypted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "storageEncrypted"))

    @storage_encrypted.setter
    def storage_encrypted(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "storageEncrypted", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcSecurityGroupIds")
    def vpc_security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of EC2 VPC security groups to associate with this cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-vpcsecuritygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "vpcSecurityGroupIds"))

    @vpc_security_group_ids.setter
    def vpc_security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "vpcSecurityGroupIds", value)


@jsii.implements(_IInspectable_c2943556)
class CfnDBClusterParameterGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_docdb.CfnDBClusterParameterGroup",
):
    '''A CloudFormation ``AWS::DocDB::DBClusterParameterGroup``.

    The ``AWS::DocDB::DBClusterParameterGroup`` Amazon DocumentDB (with MongoDB compatibility) resource describes a DBClusterParameterGroup. For more information, see `DBClusterParameterGroup <https://docs.aws.amazon.com/documentdb/latest/developerguide/API_DBClusterParameterGroup.html>`_ in the *Amazon DocumentDB Developer Guide* .

    Parameters in a cluster parameter group apply to all of the instances in a cluster.

    A cluster parameter group is initially created with the default parameters for the database engine used by instances in the cluster. To provide custom values for any of the parameters, you must modify the group after you create it. After you create a DB cluster parameter group, you must associate it with your cluster. For the new cluster parameter group and associated settings to take effect, you must then reboot the DB instances in the cluster without failover.
    .. epigraph::

       After you create a cluster parameter group, you should wait at least 5 minutes before creating your first cluster that uses that cluster parameter group as the default parameter group. This allows Amazon DocumentDB to fully complete the create action before the cluster parameter group is used as the default for a new cluster. This step is especially important for parameters that are critical when creating the default database for a cluster, such as the character set for the default database defined by the ``character_set_database`` parameter.

    :cloudformationResource: AWS::DocDB::DBClusterParameterGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_docdb as docdb
        
        # parameters: Any
        
        cfn_dBCluster_parameter_group = docdb.CfnDBClusterParameterGroup(self, "MyCfnDBClusterParameterGroup",
            description="description",
            family="family",
            parameters=parameters,
        
            # the properties below are optional
            name="name",
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
        description: builtins.str,
        family: builtins.str,
        parameters: typing.Any,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::DocDB::DBClusterParameterGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: The description for the cluster parameter group.
        :param family: The cluster parameter group family name.
        :param parameters: Provides a list of parameters for the cluster parameter group.
        :param name: The name of the DB cluster parameter group. Constraints: - Must not match the name of an existing ``DBClusterParameterGroup`` . .. epigraph:: This value is stored as a lowercase string.
        :param tags: The tags to be assigned to the cluster parameter group.
        '''
        props = CfnDBClusterParameterGroupProps(
            description=description,
            family=family,
            parameters=parameters,
            name=name,
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
        '''The tags to be assigned to the cluster parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> builtins.str:
        '''The description for the cluster parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-description
        '''
        return typing.cast(builtins.str, jsii.get(self, "description"))

    @description.setter
    def description(self, value: builtins.str) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="family")
    def family(self) -> builtins.str:
        '''The cluster parameter group family name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-family
        '''
        return typing.cast(builtins.str, jsii.get(self, "family"))

    @family.setter
    def family(self, value: builtins.str) -> None:
        jsii.set(self, "family", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parameters")
    def parameters(self) -> typing.Any:
        '''Provides a list of parameters for the cluster parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-parameters
        '''
        return typing.cast(typing.Any, jsii.get(self, "parameters"))

    @parameters.setter
    def parameters(self, value: typing.Any) -> None:
        jsii.set(self, "parameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the DB cluster parameter group.

        Constraints:

        - Must not match the name of an existing ``DBClusterParameterGroup`` .

        .. epigraph::

           This value is stored as a lowercase string.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.CfnDBClusterParameterGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "family": "family",
        "parameters": "parameters",
        "name": "name",
        "tags": "tags",
    },
)
class CfnDBClusterParameterGroupProps:
    def __init__(
        self,
        *,
        description: builtins.str,
        family: builtins.str,
        parameters: typing.Any,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDBClusterParameterGroup``.

        :param description: The description for the cluster parameter group.
        :param family: The cluster parameter group family name.
        :param parameters: Provides a list of parameters for the cluster parameter group.
        :param name: The name of the DB cluster parameter group. Constraints: - Must not match the name of an existing ``DBClusterParameterGroup`` . .. epigraph:: This value is stored as a lowercase string.
        :param tags: The tags to be assigned to the cluster parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_docdb as docdb
            
            # parameters: Any
            
            cfn_dBCluster_parameter_group_props = docdb.CfnDBClusterParameterGroupProps(
                description="description",
                family="family",
                parameters=parameters,
            
                # the properties below are optional
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "description": description,
            "family": family,
            "parameters": parameters,
        }
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def description(self) -> builtins.str:
        '''The description for the cluster parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-description
        '''
        result = self._values.get("description")
        assert result is not None, "Required property 'description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def family(self) -> builtins.str:
        '''The cluster parameter group family name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-family
        '''
        result = self._values.get("family")
        assert result is not None, "Required property 'family' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def parameters(self) -> typing.Any:
        '''Provides a list of parameters for the cluster parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-parameters
        '''
        result = self._values.get("parameters")
        assert result is not None, "Required property 'parameters' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the DB cluster parameter group.

        Constraints:

        - Must not match the name of an existing ``DBClusterParameterGroup`` .

        .. epigraph::

           This value is stored as a lowercase string.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to be assigned to the cluster parameter group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDBClusterParameterGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.CfnDBClusterProps",
    jsii_struct_bases=[],
    name_mapping={
        "availability_zones": "availabilityZones",
        "backup_retention_period": "backupRetentionPeriod",
        "copy_tags_to_snapshot": "copyTagsToSnapshot",
        "db_cluster_identifier": "dbClusterIdentifier",
        "db_cluster_parameter_group_name": "dbClusterParameterGroupName",
        "db_subnet_group_name": "dbSubnetGroupName",
        "deletion_protection": "deletionProtection",
        "enable_cloudwatch_logs_exports": "enableCloudwatchLogsExports",
        "engine_version": "engineVersion",
        "kms_key_id": "kmsKeyId",
        "master_username": "masterUsername",
        "master_user_password": "masterUserPassword",
        "port": "port",
        "preferred_backup_window": "preferredBackupWindow",
        "preferred_maintenance_window": "preferredMaintenanceWindow",
        "snapshot_identifier": "snapshotIdentifier",
        "storage_encrypted": "storageEncrypted",
        "tags": "tags",
        "vpc_security_group_ids": "vpcSecurityGroupIds",
    },
)
class CfnDBClusterProps:
    def __init__(
        self,
        *,
        availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
        backup_retention_period: typing.Optional[jsii.Number] = None,
        copy_tags_to_snapshot: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        db_cluster_identifier: typing.Optional[builtins.str] = None,
        db_cluster_parameter_group_name: typing.Optional[builtins.str] = None,
        db_subnet_group_name: typing.Optional[builtins.str] = None,
        deletion_protection: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        enable_cloudwatch_logs_exports: typing.Optional[typing.Sequence[builtins.str]] = None,
        engine_version: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        master_username: typing.Optional[builtins.str] = None,
        master_user_password: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        preferred_backup_window: typing.Optional[builtins.str] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        snapshot_identifier: typing.Optional[builtins.str] = None,
        storage_encrypted: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDBCluster``.

        :param availability_zones: A list of Amazon EC2 Availability Zones that instances in the cluster can be created in.
        :param backup_retention_period: The number of days for which automated backups are retained. You must specify a minimum value of 1. Default: 1 Constraints: - Must be a value from 1 to 35.
        :param copy_tags_to_snapshot: ``AWS::DocDB::DBCluster.CopyTagsToSnapshot``.
        :param db_cluster_identifier: The cluster identifier. This parameter is stored as a lowercase string. Constraints: - Must contain from 1 to 63 letters, numbers, or hyphens. - The first character must be a letter. - Cannot end with a hyphen or contain two consecutive hyphens. Example: ``my-cluster``
        :param db_cluster_parameter_group_name: The name of the cluster parameter group to associate with this cluster.
        :param db_subnet_group_name: A subnet group to associate with this cluster. Constraints: Must match the name of an existing ``DBSubnetGroup`` . Must not be default. Example: ``mySubnetgroup``
        :param deletion_protection: Protects clusters from being accidentally deleted. If enabled, the cluster cannot be deleted unless it is modified and ``DeletionProtection`` is disabled.
        :param enable_cloudwatch_logs_exports: The list of log types that need to be enabled for exporting to Amazon CloudWatch Logs. You can enable audit logs or profiler logs. For more information, see `Auditing Amazon DocumentDB Events <https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html>`_ and `Profiling Amazon DocumentDB Operations <https://docs.aws.amazon.com/documentdb/latest/developerguide/profiling.html>`_ .
        :param engine_version: The version number of the database engine to use. The ``--engine-version`` will default to the latest major engine version. For production workloads, we recommend explicitly declaring this parameter with the intended major engine version.
        :param kms_key_id: The AWS KMS key identifier for an encrypted cluster. The AWS KMS key identifier is the Amazon Resource Name (ARN) for the AWS KMS encryption key. If you are creating a cluster using the same AWS account that owns the AWS KMS encryption key that is used to encrypt the new cluster, you can use the AWS KMS key alias instead of the ARN for the AWS KMS encryption key. If an encryption key is not specified in ``KmsKeyId`` : - If the ``StorageEncrypted`` parameter is ``true`` , Amazon DocumentDB uses your default encryption key. AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Regions .
        :param master_username: The name of the master user for the cluster. Constraints: - Must be from 1 to 63 letters or numbers. - The first character must be a letter. - Cannot be a reserved word for the chosen database engine.
        :param master_user_password: The password for the master database user. This password can contain any printable ASCII character except forward slash (/), double quote ("), or the "at" symbol (@). Constraints: Must contain from 8 to 100 characters.
        :param port: Specifies the port that the database engine is listening on.
        :param preferred_backup_window: The daily time range during which automated backups are created if automated backups are enabled using the ``BackupRetentionPeriod`` parameter. The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region . Constraints: - Must be in the format ``hh24:mi-hh24:mi`` . - Must be in Universal Coordinated Time (UTC). - Must not conflict with the preferred maintenance window. - Must be at least 30 minutes.
        :param preferred_maintenance_window: The weekly time range during which system maintenance can occur, in Universal Coordinated Time (UTC). Format: ``ddd:hh24:mi-ddd:hh24:mi`` The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region , occurring on a random day of the week. Valid days: Mon, Tue, Wed, Thu, Fri, Sat, Sun Constraints: Minimum 30-minute window.
        :param snapshot_identifier: The identifier for the snapshot or cluster snapshot to restore from. You can use either the name or the Amazon Resource Name (ARN) to specify a cluster snapshot. However, you can use only the ARN to specify a snapshot. Constraints: - Must match the identifier of an existing snapshot.
        :param storage_encrypted: Specifies whether the cluster is encrypted.
        :param tags: The tags to be assigned to the cluster.
        :param vpc_security_group_ids: A list of EC2 VPC security groups to associate with this cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_docdb as docdb
            
            cfn_dBCluster_props = docdb.CfnDBClusterProps(
                availability_zones=["availabilityZones"],
                backup_retention_period=123,
                copy_tags_to_snapshot=False,
                db_cluster_identifier="dbClusterIdentifier",
                db_cluster_parameter_group_name="dbClusterParameterGroupName",
                db_subnet_group_name="dbSubnetGroupName",
                deletion_protection=False,
                enable_cloudwatch_logs_exports=["enableCloudwatchLogsExports"],
                engine_version="engineVersion",
                kms_key_id="kmsKeyId",
                master_username="masterUsername",
                master_user_password="masterUserPassword",
                port=123,
                preferred_backup_window="preferredBackupWindow",
                preferred_maintenance_window="preferredMaintenanceWindow",
                snapshot_identifier="snapshotIdentifier",
                storage_encrypted=False,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                vpc_security_group_ids=["vpcSecurityGroupIds"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if availability_zones is not None:
            self._values["availability_zones"] = availability_zones
        if backup_retention_period is not None:
            self._values["backup_retention_period"] = backup_retention_period
        if copy_tags_to_snapshot is not None:
            self._values["copy_tags_to_snapshot"] = copy_tags_to_snapshot
        if db_cluster_identifier is not None:
            self._values["db_cluster_identifier"] = db_cluster_identifier
        if db_cluster_parameter_group_name is not None:
            self._values["db_cluster_parameter_group_name"] = db_cluster_parameter_group_name
        if db_subnet_group_name is not None:
            self._values["db_subnet_group_name"] = db_subnet_group_name
        if deletion_protection is not None:
            self._values["deletion_protection"] = deletion_protection
        if enable_cloudwatch_logs_exports is not None:
            self._values["enable_cloudwatch_logs_exports"] = enable_cloudwatch_logs_exports
        if engine_version is not None:
            self._values["engine_version"] = engine_version
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if master_username is not None:
            self._values["master_username"] = master_username
        if master_user_password is not None:
            self._values["master_user_password"] = master_user_password
        if port is not None:
            self._values["port"] = port
        if preferred_backup_window is not None:
            self._values["preferred_backup_window"] = preferred_backup_window
        if preferred_maintenance_window is not None:
            self._values["preferred_maintenance_window"] = preferred_maintenance_window
        if snapshot_identifier is not None:
            self._values["snapshot_identifier"] = snapshot_identifier
        if storage_encrypted is not None:
            self._values["storage_encrypted"] = storage_encrypted
        if tags is not None:
            self._values["tags"] = tags
        if vpc_security_group_ids is not None:
            self._values["vpc_security_group_ids"] = vpc_security_group_ids

    @builtins.property
    def availability_zones(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Amazon EC2 Availability Zones that instances in the cluster can be created in.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-availabilityzones
        '''
        result = self._values.get("availability_zones")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def backup_retention_period(self) -> typing.Optional[jsii.Number]:
        '''The number of days for which automated backups are retained. You must specify a minimum value of 1.

        Default: 1

        Constraints:

        - Must be a value from 1 to 35.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-backupretentionperiod
        '''
        result = self._values.get("backup_retention_period")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def copy_tags_to_snapshot(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''``AWS::DocDB::DBCluster.CopyTagsToSnapshot``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-copytagstosnapshot
        '''
        result = self._values.get("copy_tags_to_snapshot")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def db_cluster_identifier(self) -> typing.Optional[builtins.str]:
        '''The cluster identifier. This parameter is stored as a lowercase string.

        Constraints:

        - Must contain from 1 to 63 letters, numbers, or hyphens.
        - The first character must be a letter.
        - Cannot end with a hyphen or contain two consecutive hyphens.

        Example: ``my-cluster``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-dbclusteridentifier
        '''
        result = self._values.get("db_cluster_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def db_cluster_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the cluster parameter group to associate with this cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-dbclusterparametergroupname
        '''
        result = self._values.get("db_cluster_parameter_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def db_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''A subnet group to associate with this cluster.

        Constraints: Must match the name of an existing ``DBSubnetGroup`` . Must not be default.

        Example: ``mySubnetgroup``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-dbsubnetgroupname
        '''
        result = self._values.get("db_subnet_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def deletion_protection(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Protects clusters from being accidentally deleted.

        If enabled, the cluster cannot be deleted unless it is modified and ``DeletionProtection`` is disabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-deletionprotection
        '''
        result = self._values.get("deletion_protection")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def enable_cloudwatch_logs_exports(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of log types that need to be enabled for exporting to Amazon CloudWatch Logs.

        You can enable audit logs or profiler logs. For more information, see `Auditing Amazon DocumentDB Events <https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html>`_ and `Profiling Amazon DocumentDB Operations <https://docs.aws.amazon.com/documentdb/latest/developerguide/profiling.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-enablecloudwatchlogsexports
        '''
        result = self._values.get("enable_cloudwatch_logs_exports")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''The version number of the database engine to use.

        The ``--engine-version`` will default to the latest major engine version. For production workloads, we recommend explicitly declaring this parameter with the intended major engine version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-engineversion
        '''
        result = self._values.get("engine_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The AWS KMS key identifier for an encrypted cluster.

        The AWS KMS key identifier is the Amazon Resource Name (ARN) for the AWS KMS encryption key. If you are creating a cluster using the same AWS account that owns the AWS KMS encryption key that is used to encrypt the new cluster, you can use the AWS KMS key alias instead of the ARN for the AWS KMS encryption key.

        If an encryption key is not specified in ``KmsKeyId`` :

        - If the ``StorageEncrypted`` parameter is ``true`` , Amazon DocumentDB uses your default encryption key.

        AWS KMS creates the default encryption key for your AWS account . Your AWS account has a different default encryption key for each AWS Regions .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def master_username(self) -> typing.Optional[builtins.str]:
        '''The name of the master user for the cluster.

        Constraints:

        - Must be from 1 to 63 letters or numbers.
        - The first character must be a letter.
        - Cannot be a reserved word for the chosen database engine.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-masterusername
        '''
        result = self._values.get("master_username")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def master_user_password(self) -> typing.Optional[builtins.str]:
        '''The password for the master database user.

        This password can contain any printable ASCII character except forward slash (/), double quote ("), or the "at" symbol (@).

        Constraints: Must contain from 8 to 100 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-masteruserpassword
        '''
        result = self._values.get("master_user_password")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''Specifies the port that the database engine is listening on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-port
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def preferred_backup_window(self) -> typing.Optional[builtins.str]:
        '''The daily time range during which automated backups are created if automated backups are enabled using the ``BackupRetentionPeriod`` parameter.

        The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region .

        Constraints:

        - Must be in the format ``hh24:mi-hh24:mi`` .
        - Must be in Universal Coordinated Time (UTC).
        - Must not conflict with the preferred maintenance window.
        - Must be at least 30 minutes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-preferredbackupwindow
        '''
        result = self._values.get("preferred_backup_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''The weekly time range during which system maintenance can occur, in Universal Coordinated Time (UTC).

        Format: ``ddd:hh24:mi-ddd:hh24:mi``

        The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region , occurring on a random day of the week.

        Valid days: Mon, Tue, Wed, Thu, Fri, Sat, Sun

        Constraints: Minimum 30-minute window.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-preferredmaintenancewindow
        '''
        result = self._values.get("preferred_maintenance_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def snapshot_identifier(self) -> typing.Optional[builtins.str]:
        '''The identifier for the snapshot or cluster snapshot to restore from.

        You can use either the name or the Amazon Resource Name (ARN) to specify a cluster snapshot. However, you can use only the ARN to specify a snapshot.

        Constraints:

        - Must match the identifier of an existing snapshot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-snapshotidentifier
        '''
        result = self._values.get("snapshot_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def storage_encrypted(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the cluster is encrypted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted
        '''
        result = self._values.get("storage_encrypted")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to be assigned to the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def vpc_security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of EC2 VPC security groups to associate with this cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-vpcsecuritygroupids
        '''
        result = self._values.get("vpc_security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDBClusterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDBInstance(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_docdb.CfnDBInstance",
):
    '''A CloudFormation ``AWS::DocDB::DBInstance``.

    The ``AWS::DocDB::DBInstance`` Amazon DocumentDB (with MongoDB compatibility) resource describes a DBInstance. For more information, see `DBInstance <https://docs.aws.amazon.com/documentdb/latest/developerguide/API_DBInstance.html>`_ in the *Amazon DocumentDB Developer Guide* .

    :cloudformationResource: AWS::DocDB::DBInstance
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_docdb as docdb
        
        cfn_dBInstance = docdb.CfnDBInstance(self, "MyCfnDBInstance",
            db_cluster_identifier="dbClusterIdentifier",
            db_instance_class="dbInstanceClass",
        
            # the properties below are optional
            auto_minor_version_upgrade=False,
            availability_zone="availabilityZone",
            db_instance_identifier="dbInstanceIdentifier",
            preferred_maintenance_window="preferredMaintenanceWindow",
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
        db_cluster_identifier: builtins.str,
        db_instance_class: builtins.str,
        auto_minor_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        availability_zone: typing.Optional[builtins.str] = None,
        db_instance_identifier: typing.Optional[builtins.str] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::DocDB::DBInstance``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param db_cluster_identifier: The identifier of the cluster that the instance will belong to.
        :param db_instance_class: The compute and memory capacity of the instance; for example, ``db.m4.large`` . If you change the class of an instance there can be some interruption in the cluster's service.
        :param auto_minor_version_upgrade: This parameter does not apply to Amazon DocumentDB. Amazon DocumentDB does not perform minor version upgrades regardless of the value set. Default: ``false``
        :param availability_zone: The Amazon EC2 Availability Zone that the instance is created in. Default: A random, system-chosen Availability Zone in the endpoint's AWS Region . Example: ``us-east-1d``
        :param db_instance_identifier: The instance identifier. This parameter is stored as a lowercase string. Constraints: - Must contain from 1 to 63 letters, numbers, or hyphens. - The first character must be a letter. - Cannot end with a hyphen or contain two consecutive hyphens. Example: ``mydbinstance``
        :param preferred_maintenance_window: The time range each week during which system maintenance can occur, in Universal Coordinated Time (UTC). Format: ``ddd:hh24:mi-ddd:hh24:mi`` The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region , occurring on a random day of the week. Valid days: Mon, Tue, Wed, Thu, Fri, Sat, Sun Constraints: Minimum 30-minute window.
        :param tags: The tags to be assigned to the instance. You can assign up to 10 tags to an instance.
        '''
        props = CfnDBInstanceProps(
            db_cluster_identifier=db_cluster_identifier,
            db_instance_class=db_instance_class,
            auto_minor_version_upgrade=auto_minor_version_upgrade,
            availability_zone=availability_zone,
            db_instance_identifier=db_instance_identifier,
            preferred_maintenance_window=preferred_maintenance_window,
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
    @jsii.member(jsii_name="attrEndpoint")
    def attr_endpoint(self) -> builtins.str:
        '''The connection endpoint for the instance.

        For example: ``sample-cluster.cluster-abcdefghijkl.us-east-1.docdb.amazonaws.com`` .

        :cloudformationAttribute: Endpoint
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPort")
    def attr_port(self) -> builtins.str:
        '''The port number on which the database accepts connections, such as ``27017`` .

        :cloudformationAttribute: Port
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to be assigned to the instance.

        You can assign up to 10 tags to an instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbClusterIdentifier")
    def db_cluster_identifier(self) -> builtins.str:
        '''The identifier of the cluster that the instance will belong to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-dbclusteridentifier
        '''
        return typing.cast(builtins.str, jsii.get(self, "dbClusterIdentifier"))

    @db_cluster_identifier.setter
    def db_cluster_identifier(self, value: builtins.str) -> None:
        jsii.set(self, "dbClusterIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbInstanceClass")
    def db_instance_class(self) -> builtins.str:
        '''The compute and memory capacity of the instance;

        for example, ``db.m4.large`` . If you change the class of an instance there can be some interruption in the cluster's service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-dbinstanceclass
        '''
        return typing.cast(builtins.str, jsii.get(self, "dbInstanceClass"))

    @db_instance_class.setter
    def db_instance_class(self, value: builtins.str) -> None:
        jsii.set(self, "dbInstanceClass", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoMinorVersionUpgrade")
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''This parameter does not apply to Amazon DocumentDB.

        Amazon DocumentDB does not perform minor version upgrades regardless of the value set.

        Default: ``false``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-autominorversionupgrade
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
        '''The Amazon EC2 Availability Zone that the instance is created in.

        Default: A random, system-chosen Availability Zone in the endpoint's AWS Region .

        Example: ``us-east-1d``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-availabilityzone
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "availabilityZone"))

    @availability_zone.setter
    def availability_zone(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "availabilityZone", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbInstanceIdentifier")
    def db_instance_identifier(self) -> typing.Optional[builtins.str]:
        '''The instance identifier. This parameter is stored as a lowercase string.

        Constraints:

        - Must contain from 1 to 63 letters, numbers, or hyphens.
        - The first character must be a letter.
        - Cannot end with a hyphen or contain two consecutive hyphens.

        Example: ``mydbinstance``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-dbinstanceidentifier
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dbInstanceIdentifier"))

    @db_instance_identifier.setter
    def db_instance_identifier(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dbInstanceIdentifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preferredMaintenanceWindow")
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''The time range each week during which system maintenance can occur, in Universal Coordinated Time (UTC).

        Format: ``ddd:hh24:mi-ddd:hh24:mi``

        The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region , occurring on a random day of the week.

        Valid days: Mon, Tue, Wed, Thu, Fri, Sat, Sun

        Constraints: Minimum 30-minute window.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-preferredmaintenancewindow
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preferredMaintenanceWindow"))

    @preferred_maintenance_window.setter
    def preferred_maintenance_window(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "preferredMaintenanceWindow", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.CfnDBInstanceProps",
    jsii_struct_bases=[],
    name_mapping={
        "db_cluster_identifier": "dbClusterIdentifier",
        "db_instance_class": "dbInstanceClass",
        "auto_minor_version_upgrade": "autoMinorVersionUpgrade",
        "availability_zone": "availabilityZone",
        "db_instance_identifier": "dbInstanceIdentifier",
        "preferred_maintenance_window": "preferredMaintenanceWindow",
        "tags": "tags",
    },
)
class CfnDBInstanceProps:
    def __init__(
        self,
        *,
        db_cluster_identifier: builtins.str,
        db_instance_class: builtins.str,
        auto_minor_version_upgrade: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        availability_zone: typing.Optional[builtins.str] = None,
        db_instance_identifier: typing.Optional[builtins.str] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDBInstance``.

        :param db_cluster_identifier: The identifier of the cluster that the instance will belong to.
        :param db_instance_class: The compute and memory capacity of the instance; for example, ``db.m4.large`` . If you change the class of an instance there can be some interruption in the cluster's service.
        :param auto_minor_version_upgrade: This parameter does not apply to Amazon DocumentDB. Amazon DocumentDB does not perform minor version upgrades regardless of the value set. Default: ``false``
        :param availability_zone: The Amazon EC2 Availability Zone that the instance is created in. Default: A random, system-chosen Availability Zone in the endpoint's AWS Region . Example: ``us-east-1d``
        :param db_instance_identifier: The instance identifier. This parameter is stored as a lowercase string. Constraints: - Must contain from 1 to 63 letters, numbers, or hyphens. - The first character must be a letter. - Cannot end with a hyphen or contain two consecutive hyphens. Example: ``mydbinstance``
        :param preferred_maintenance_window: The time range each week during which system maintenance can occur, in Universal Coordinated Time (UTC). Format: ``ddd:hh24:mi-ddd:hh24:mi`` The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region , occurring on a random day of the week. Valid days: Mon, Tue, Wed, Thu, Fri, Sat, Sun Constraints: Minimum 30-minute window.
        :param tags: The tags to be assigned to the instance. You can assign up to 10 tags to an instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_docdb as docdb
            
            cfn_dBInstance_props = docdb.CfnDBInstanceProps(
                db_cluster_identifier="dbClusterIdentifier",
                db_instance_class="dbInstanceClass",
            
                # the properties below are optional
                auto_minor_version_upgrade=False,
                availability_zone="availabilityZone",
                db_instance_identifier="dbInstanceIdentifier",
                preferred_maintenance_window="preferredMaintenanceWindow",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "db_cluster_identifier": db_cluster_identifier,
            "db_instance_class": db_instance_class,
        }
        if auto_minor_version_upgrade is not None:
            self._values["auto_minor_version_upgrade"] = auto_minor_version_upgrade
        if availability_zone is not None:
            self._values["availability_zone"] = availability_zone
        if db_instance_identifier is not None:
            self._values["db_instance_identifier"] = db_instance_identifier
        if preferred_maintenance_window is not None:
            self._values["preferred_maintenance_window"] = preferred_maintenance_window
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def db_cluster_identifier(self) -> builtins.str:
        '''The identifier of the cluster that the instance will belong to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-dbclusteridentifier
        '''
        result = self._values.get("db_cluster_identifier")
        assert result is not None, "Required property 'db_cluster_identifier' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def db_instance_class(self) -> builtins.str:
        '''The compute and memory capacity of the instance;

        for example, ``db.m4.large`` . If you change the class of an instance there can be some interruption in the cluster's service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-dbinstanceclass
        '''
        result = self._values.get("db_instance_class")
        assert result is not None, "Required property 'db_instance_class' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auto_minor_version_upgrade(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''This parameter does not apply to Amazon DocumentDB.

        Amazon DocumentDB does not perform minor version upgrades regardless of the value set.

        Default: ``false``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-autominorversionupgrade
        '''
        result = self._values.get("auto_minor_version_upgrade")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def availability_zone(self) -> typing.Optional[builtins.str]:
        '''The Amazon EC2 Availability Zone that the instance is created in.

        Default: A random, system-chosen Availability Zone in the endpoint's AWS Region .

        Example: ``us-east-1d``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-availabilityzone
        '''
        result = self._values.get("availability_zone")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def db_instance_identifier(self) -> typing.Optional[builtins.str]:
        '''The instance identifier. This parameter is stored as a lowercase string.

        Constraints:

        - Must contain from 1 to 63 letters, numbers, or hyphens.
        - The first character must be a letter.
        - Cannot end with a hyphen or contain two consecutive hyphens.

        Example: ``mydbinstance``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-dbinstanceidentifier
        '''
        result = self._values.get("db_instance_identifier")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''The time range each week during which system maintenance can occur, in Universal Coordinated Time (UTC).

        Format: ``ddd:hh24:mi-ddd:hh24:mi``

        The default is a 30-minute window selected at random from an 8-hour block of time for each AWS Region , occurring on a random day of the week.

        Valid days: Mon, Tue, Wed, Thu, Fri, Sat, Sun

        Constraints: Minimum 30-minute window.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-preferredmaintenancewindow
        '''
        result = self._values.get("preferred_maintenance_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to be assigned to the instance.

        You can assign up to 10 tags to an instance.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbinstance.html#cfn-docdb-dbinstance-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDBInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDBSubnetGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_docdb.CfnDBSubnetGroup",
):
    '''A CloudFormation ``AWS::DocDB::DBSubnetGroup``.

    The ``AWS::DocDB::DBSubnetGroup`` Amazon DocumentDB (with MongoDB compatibility) resource describes a DBSubnetGroup. subnet groups must contain at least one subnet in at least two Availability Zones in the AWS Region . For more information, see `DBSubnetGroup <https://docs.aws.amazon.com/documentdb/latest/developerguide/API_DBSubnetGroup.html>`_ in the *Amazon DocumentDB Developer Guide* .

    :cloudformationResource: AWS::DocDB::DBSubnetGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_docdb as docdb
        
        cfn_dBSubnet_group = docdb.CfnDBSubnetGroup(self, "MyCfnDBSubnetGroup",
            db_subnet_group_description="dbSubnetGroupDescription",
            subnet_ids=["subnetIds"],
        
            # the properties below are optional
            db_subnet_group_name="dbSubnetGroupName",
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
        db_subnet_group_description: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        db_subnet_group_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::DocDB::DBSubnetGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param db_subnet_group_description: The description for the subnet group.
        :param subnet_ids: The Amazon EC2 subnet IDs for the subnet group.
        :param db_subnet_group_name: The name for the subnet group. This value is stored as a lowercase string. Constraints: Must contain no more than 255 letters, numbers, periods, underscores, spaces, or hyphens. Must not be default. Example: ``mySubnetgroup``
        :param tags: The tags to be assigned to the subnet group.
        '''
        props = CfnDBSubnetGroupProps(
            db_subnet_group_description=db_subnet_group_description,
            subnet_ids=subnet_ids,
            db_subnet_group_name=db_subnet_group_name,
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
        '''The tags to be assigned to the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html#cfn-docdb-dbsubnetgroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbSubnetGroupDescription")
    def db_subnet_group_description(self) -> builtins.str:
        '''The description for the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html#cfn-docdb-dbsubnetgroup-dbsubnetgroupdescription
        '''
        return typing.cast(builtins.str, jsii.get(self, "dbSubnetGroupDescription"))

    @db_subnet_group_description.setter
    def db_subnet_group_description(self, value: builtins.str) -> None:
        jsii.set(self, "dbSubnetGroupDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetIds")
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''The Amazon EC2 subnet IDs for the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html#cfn-docdb-dbsubnetgroup-subnetids
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "subnetIds"))

    @subnet_ids.setter
    def subnet_ids(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "subnetIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbSubnetGroupName")
    def db_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''The name for the subnet group. This value is stored as a lowercase string.

        Constraints: Must contain no more than 255 letters, numbers, periods, underscores, spaces, or hyphens. Must not be default.

        Example: ``mySubnetgroup``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html#cfn-docdb-dbsubnetgroup-dbsubnetgroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dbSubnetGroupName"))

    @db_subnet_group_name.setter
    def db_subnet_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dbSubnetGroupName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.CfnDBSubnetGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "db_subnet_group_description": "dbSubnetGroupDescription",
        "subnet_ids": "subnetIds",
        "db_subnet_group_name": "dbSubnetGroupName",
        "tags": "tags",
    },
)
class CfnDBSubnetGroupProps:
    def __init__(
        self,
        *,
        db_subnet_group_description: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        db_subnet_group_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDBSubnetGroup``.

        :param db_subnet_group_description: The description for the subnet group.
        :param subnet_ids: The Amazon EC2 subnet IDs for the subnet group.
        :param db_subnet_group_name: The name for the subnet group. This value is stored as a lowercase string. Constraints: Must contain no more than 255 letters, numbers, periods, underscores, spaces, or hyphens. Must not be default. Example: ``mySubnetgroup``
        :param tags: The tags to be assigned to the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_docdb as docdb
            
            cfn_dBSubnet_group_props = docdb.CfnDBSubnetGroupProps(
                db_subnet_group_description="dbSubnetGroupDescription",
                subnet_ids=["subnetIds"],
            
                # the properties below are optional
                db_subnet_group_name="dbSubnetGroupName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "db_subnet_group_description": db_subnet_group_description,
            "subnet_ids": subnet_ids,
        }
        if db_subnet_group_name is not None:
            self._values["db_subnet_group_name"] = db_subnet_group_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def db_subnet_group_description(self) -> builtins.str:
        '''The description for the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html#cfn-docdb-dbsubnetgroup-dbsubnetgroupdescription
        '''
        result = self._values.get("db_subnet_group_description")
        assert result is not None, "Required property 'db_subnet_group_description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''The Amazon EC2 subnet IDs for the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html#cfn-docdb-dbsubnetgroup-subnetids
        '''
        result = self._values.get("subnet_ids")
        assert result is not None, "Required property 'subnet_ids' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def db_subnet_group_name(self) -> typing.Optional[builtins.str]:
        '''The name for the subnet group. This value is stored as a lowercase string.

        Constraints: Must contain no more than 255 letters, numbers, periods, underscores, spaces, or hyphens. Must not be default.

        Example: ``mySubnetgroup``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html#cfn-docdb-dbsubnetgroup-dbsubnetgroupname
        '''
        result = self._values.get("db_subnet_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to be assigned to the subnet group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html#cfn-docdb-dbsubnetgroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDBSubnetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.ClusterParameterGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "family": "family",
        "parameters": "parameters",
        "db_cluster_parameter_group_name": "dbClusterParameterGroupName",
        "description": "description",
    },
)
class ClusterParameterGroupProps:
    def __init__(
        self,
        *,
        family: builtins.str,
        parameters: typing.Mapping[builtins.str, builtins.str],
        db_cluster_parameter_group_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for a cluster parameter group.

        :param family: Database family of this parameter group.
        :param parameters: The parameters in this parameter group.
        :param db_cluster_parameter_group_name: The name of the cluster parameter group. Default: A CDK generated name for the cluster parameter group
        :param description: Description for this parameter group. Default: a CDK generated description

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_docdb as docdb
            
            cluster_parameter_group_props = docdb.ClusterParameterGroupProps(
                family="family",
                parameters={
                    "parameters_key": "parameters"
                },
            
                # the properties below are optional
                db_cluster_parameter_group_name="dbClusterParameterGroupName",
                description="description"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "family": family,
            "parameters": parameters,
        }
        if db_cluster_parameter_group_name is not None:
            self._values["db_cluster_parameter_group_name"] = db_cluster_parameter_group_name
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def family(self) -> builtins.str:
        '''Database family of this parameter group.'''
        result = self._values.get("family")
        assert result is not None, "Required property 'family' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def parameters(self) -> typing.Mapping[builtins.str, builtins.str]:
        '''The parameters in this parameter group.'''
        result = self._values.get("parameters")
        assert result is not None, "Required property 'parameters' is missing"
        return typing.cast(typing.Mapping[builtins.str, builtins.str], result)

    @builtins.property
    def db_cluster_parameter_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the cluster parameter group.

        :default: A CDK generated name for the cluster parameter group
        '''
        result = self._values.get("db_cluster_parameter_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''Description for this parameter group.

        :default: a CDK generated description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterParameterGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.DatabaseClusterAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "cluster_endpoint_address": "clusterEndpointAddress",
        "cluster_identifier": "clusterIdentifier",
        "instance_endpoint_addresses": "instanceEndpointAddresses",
        "instance_identifiers": "instanceIdentifiers",
        "port": "port",
        "reader_endpoint_address": "readerEndpointAddress",
        "security_group": "securityGroup",
    },
)
class DatabaseClusterAttributes:
    def __init__(
        self,
        *,
        cluster_endpoint_address: builtins.str,
        cluster_identifier: builtins.str,
        instance_endpoint_addresses: typing.Sequence[builtins.str],
        instance_identifiers: typing.Sequence[builtins.str],
        port: jsii.Number,
        reader_endpoint_address: builtins.str,
        security_group: _ISecurityGroup_acf8a799,
    ) -> None:
        '''Properties that describe an existing cluster instance.

        :param cluster_endpoint_address: Cluster endpoint address.
        :param cluster_identifier: Identifier for the cluster.
        :param instance_endpoint_addresses: Endpoint addresses of individual instances.
        :param instance_identifiers: Identifier for the instances.
        :param port: The database port.
        :param reader_endpoint_address: Reader endpoint address.
        :param security_group: The security group of the database cluster.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_docdb as docdb
            from aws_cdk import aws_ec2 as ec2
            
            # security_group: ec2.SecurityGroup
            
            database_cluster_attributes = docdb.DatabaseClusterAttributes(
                cluster_endpoint_address="clusterEndpointAddress",
                cluster_identifier="clusterIdentifier",
                instance_endpoint_addresses=["instanceEndpointAddresses"],
                instance_identifiers=["instanceIdentifiers"],
                port=123,
                reader_endpoint_address="readerEndpointAddress",
                security_group=security_group
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster_endpoint_address": cluster_endpoint_address,
            "cluster_identifier": cluster_identifier,
            "instance_endpoint_addresses": instance_endpoint_addresses,
            "instance_identifiers": instance_identifiers,
            "port": port,
            "reader_endpoint_address": reader_endpoint_address,
            "security_group": security_group,
        }

    @builtins.property
    def cluster_endpoint_address(self) -> builtins.str:
        '''Cluster endpoint address.'''
        result = self._values.get("cluster_endpoint_address")
        assert result is not None, "Required property 'cluster_endpoint_address' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cluster_identifier(self) -> builtins.str:
        '''Identifier for the cluster.'''
        result = self._values.get("cluster_identifier")
        assert result is not None, "Required property 'cluster_identifier' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_endpoint_addresses(self) -> typing.List[builtins.str]:
        '''Endpoint addresses of individual instances.'''
        result = self._values.get("instance_endpoint_addresses")
        assert result is not None, "Required property 'instance_endpoint_addresses' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def instance_identifiers(self) -> typing.List[builtins.str]:
        '''Identifier for the instances.'''
        result = self._values.get("instance_identifiers")
        assert result is not None, "Required property 'instance_identifiers' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def port(self) -> jsii.Number:
        '''The database port.'''
        result = self._values.get("port")
        assert result is not None, "Required property 'port' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def reader_endpoint_address(self) -> builtins.str:
        '''Reader endpoint address.'''
        result = self._values.get("reader_endpoint_address")
        assert result is not None, "Required property 'reader_endpoint_address' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def security_group(self) -> _ISecurityGroup_acf8a799:
        '''The security group of the database cluster.'''
        result = self._values.get("security_group")
        assert result is not None, "Required property 'security_group' is missing"
        return typing.cast(_ISecurityGroup_acf8a799, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DatabaseClusterAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.DatabaseClusterProps",
    jsii_struct_bases=[],
    name_mapping={
        "instance_type": "instanceType",
        "master_user": "masterUser",
        "vpc": "vpc",
        "backup": "backup",
        "cloud_watch_logs_retention": "cloudWatchLogsRetention",
        "cloud_watch_logs_retention_role": "cloudWatchLogsRetentionRole",
        "db_cluster_name": "dbClusterName",
        "deletion_protection": "deletionProtection",
        "engine_version": "engineVersion",
        "export_audit_logs_to_cloud_watch": "exportAuditLogsToCloudWatch",
        "export_profiler_logs_to_cloud_watch": "exportProfilerLogsToCloudWatch",
        "instance_identifier_base": "instanceIdentifierBase",
        "instances": "instances",
        "kms_key": "kmsKey",
        "parameter_group": "parameterGroup",
        "port": "port",
        "preferred_maintenance_window": "preferredMaintenanceWindow",
        "removal_policy": "removalPolicy",
        "security_group": "securityGroup",
        "storage_encrypted": "storageEncrypted",
        "vpc_subnets": "vpcSubnets",
    },
)
class DatabaseClusterProps:
    def __init__(
        self,
        *,
        instance_type: _InstanceType_f64915b9,
        master_user: "Login",
        vpc: _IVpc_f30d5663,
        backup: typing.Optional[BackupProps] = None,
        cloud_watch_logs_retention: typing.Optional[_RetentionDays_070f99f0] = None,
        cloud_watch_logs_retention_role: typing.Optional[_IRole_235f5d8e] = None,
        db_cluster_name: typing.Optional[builtins.str] = None,
        deletion_protection: typing.Optional[builtins.bool] = None,
        engine_version: typing.Optional[builtins.str] = None,
        export_audit_logs_to_cloud_watch: typing.Optional[builtins.bool] = None,
        export_profiler_logs_to_cloud_watch: typing.Optional[builtins.bool] = None,
        instance_identifier_base: typing.Optional[builtins.str] = None,
        instances: typing.Optional[jsii.Number] = None,
        kms_key: typing.Optional[_IKey_5f11635f] = None,
        parameter_group: typing.Optional["IClusterParameterGroup"] = None,
        port: typing.Optional[jsii.Number] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        storage_encrypted: typing.Optional[builtins.bool] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''Properties for a new database cluster.

        :param instance_type: What type of instance to start for the replicas.
        :param master_user: Username and password for the administrative user.
        :param vpc: What subnets to run the DocumentDB instances in. Must be at least 2 subnets in two different AZs.
        :param backup: Backup settings. Default: - Backup retention period for automated backups is 1 day. Backup preferred window is set to a 30-minute window selected at random from an 8-hour block of time for each AWS Region, occurring on a random day of the week.
        :param cloud_watch_logs_retention: The number of days log events are kept in CloudWatch Logs. When updating this property, unsetting it doesn't remove the log retention policy. To remove the retention policy, set the value to ``Infinity``. Default: - logs never expire
        :param cloud_watch_logs_retention_role: The IAM role for the Lambda function associated with the custom resource that sets the retention policy. Default: - a new role is created.
        :param db_cluster_name: An optional identifier for the cluster. Default: - A name is automatically generated.
        :param deletion_protection: Specifies whether this cluster can be deleted. If deletionProtection is enabled, the cluster cannot be deleted unless it is modified and deletionProtection is disabled. deletionProtection protects clusters from being accidentally deleted. Default: - false
        :param engine_version: What version of the database to start. Default: - The default engine version.
        :param export_audit_logs_to_cloud_watch: Whether the audit logs should be exported to CloudWatch. Note that you also have to configure the audit log export in the Cluster's Parameter Group. Default: false
        :param export_profiler_logs_to_cloud_watch: Whether the profiler logs should be exported to CloudWatch. Note that you also have to configure the profiler log export in the Cluster's Parameter Group. Default: false
        :param instance_identifier_base: Base identifier for instances. Every replica is named by appending the replica number to this string, 1-based. Default: - ``dbClusterName`` is used with the word "Instance" appended. If ``dbClusterName`` is not provided, the identifier is automatically generated.
        :param instances: Number of DocDB compute instances. Default: 1
        :param kms_key: The KMS key for storage encryption. Default: - default master key.
        :param parameter_group: The DB parameter group to associate with the instance. Default: no parameter group
        :param port: The port the DocumentDB cluster will listen on. Default: DatabaseCluster.DEFAULT_PORT
        :param preferred_maintenance_window: A weekly time range in which maintenance should preferably execute. Must be at least 30 minutes long. Example: 'tue:04:17-tue:04:47' Default: - 30-minute window selected at random from an 8-hour block of time for each AWS Region, occurring on a random day of the week.
        :param removal_policy: The removal policy to apply when the cluster and its instances are removed or replaced during a stack update, or when the stack is deleted. This removal policy also applies to the implicit security group created for the cluster if one is not supplied as a parameter. Default: - Retain cluster.
        :param security_group: Security group. Default: a new security group is created.
        :param storage_encrypted: Whether to enable storage encryption. Default: true
        :param vpc_subnets: Where to place the instances within the VPC. Default: private subnets

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            
            cluster = docdb.DatabaseCluster(self, "Database",
                master_user=docdb.Login(
                    username="myuser",  # NOTE: 'admin' is reserved by DocumentDB
                    exclude_characters="\"@/:",  # optional, defaults to the set "\"@/" and is also used for eventually created rotations
                    secret_name="/myapp/mydocdb/masteruser"
                ),
                instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PUBLIC
                ),
                vpc=vpc
            )
        '''
        if isinstance(master_user, dict):
            master_user = Login(**master_user)
        if isinstance(backup, dict):
            backup = BackupProps(**backup)
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        self._values: typing.Dict[str, typing.Any] = {
            "instance_type": instance_type,
            "master_user": master_user,
            "vpc": vpc,
        }
        if backup is not None:
            self._values["backup"] = backup
        if cloud_watch_logs_retention is not None:
            self._values["cloud_watch_logs_retention"] = cloud_watch_logs_retention
        if cloud_watch_logs_retention_role is not None:
            self._values["cloud_watch_logs_retention_role"] = cloud_watch_logs_retention_role
        if db_cluster_name is not None:
            self._values["db_cluster_name"] = db_cluster_name
        if deletion_protection is not None:
            self._values["deletion_protection"] = deletion_protection
        if engine_version is not None:
            self._values["engine_version"] = engine_version
        if export_audit_logs_to_cloud_watch is not None:
            self._values["export_audit_logs_to_cloud_watch"] = export_audit_logs_to_cloud_watch
        if export_profiler_logs_to_cloud_watch is not None:
            self._values["export_profiler_logs_to_cloud_watch"] = export_profiler_logs_to_cloud_watch
        if instance_identifier_base is not None:
            self._values["instance_identifier_base"] = instance_identifier_base
        if instances is not None:
            self._values["instances"] = instances
        if kms_key is not None:
            self._values["kms_key"] = kms_key
        if parameter_group is not None:
            self._values["parameter_group"] = parameter_group
        if port is not None:
            self._values["port"] = port
        if preferred_maintenance_window is not None:
            self._values["preferred_maintenance_window"] = preferred_maintenance_window
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if security_group is not None:
            self._values["security_group"] = security_group
        if storage_encrypted is not None:
            self._values["storage_encrypted"] = storage_encrypted
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets

    @builtins.property
    def instance_type(self) -> _InstanceType_f64915b9:
        '''What type of instance to start for the replicas.'''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(_InstanceType_f64915b9, result)

    @builtins.property
    def master_user(self) -> "Login":
        '''Username and password for the administrative user.'''
        result = self._values.get("master_user")
        assert result is not None, "Required property 'master_user' is missing"
        return typing.cast("Login", result)

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''What subnets to run the DocumentDB instances in.

        Must be at least 2 subnets in two different AZs.
        '''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    @builtins.property
    def backup(self) -> typing.Optional[BackupProps]:
        '''Backup settings.

        :default:

        - Backup retention period for automated backups is 1 day.
        Backup preferred window is set to a 30-minute window selected at random from an
        8-hour block of time for each AWS Region, occurring on a random day of the week.

        :see: https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshots.html#backup-restore.backup-window
        '''
        result = self._values.get("backup")
        return typing.cast(typing.Optional[BackupProps], result)

    @builtins.property
    def cloud_watch_logs_retention(self) -> typing.Optional[_RetentionDays_070f99f0]:
        '''The number of days log events are kept in CloudWatch Logs.

        When updating
        this property, unsetting it doesn't remove the log retention policy. To
        remove the retention policy, set the value to ``Infinity``.

        :default: - logs never expire
        '''
        result = self._values.get("cloud_watch_logs_retention")
        return typing.cast(typing.Optional[_RetentionDays_070f99f0], result)

    @builtins.property
    def cloud_watch_logs_retention_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The IAM role for the Lambda function associated with the custom resource that sets the retention policy.

        :default: - a new role is created.
        '''
        result = self._values.get("cloud_watch_logs_retention_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def db_cluster_name(self) -> typing.Optional[builtins.str]:
        '''An optional identifier for the cluster.

        :default: - A name is automatically generated.
        '''
        result = self._values.get("db_cluster_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def deletion_protection(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether this cluster can be deleted.

        If deletionProtection is
        enabled, the cluster cannot be deleted unless it is modified and
        deletionProtection is disabled. deletionProtection protects clusters from
        being accidentally deleted.

        :default: - false
        '''
        result = self._values.get("deletion_protection")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def engine_version(self) -> typing.Optional[builtins.str]:
        '''What version of the database to start.

        :default: - The default engine version.
        '''
        result = self._values.get("engine_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def export_audit_logs_to_cloud_watch(self) -> typing.Optional[builtins.bool]:
        '''Whether the audit logs should be exported to CloudWatch.

        Note that you also have to configure the audit log export in the Cluster's Parameter Group.

        :default: false

        :see: https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html#event-auditing-enabling-auditing
        '''
        result = self._values.get("export_audit_logs_to_cloud_watch")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def export_profiler_logs_to_cloud_watch(self) -> typing.Optional[builtins.bool]:
        '''Whether the profiler logs should be exported to CloudWatch.

        Note that you also have to configure the profiler log export in the Cluster's Parameter Group.

        :default: false

        :see: https://docs.aws.amazon.com/documentdb/latest/developerguide/profiling.html#profiling.enable-profiling
        '''
        result = self._values.get("export_profiler_logs_to_cloud_watch")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def instance_identifier_base(self) -> typing.Optional[builtins.str]:
        '''Base identifier for instances.

        Every replica is named by appending the replica number to this string, 1-based.

        :default:

        - ``dbClusterName`` is used with the word "Instance" appended. If ``dbClusterName`` is not provided, the
        identifier is automatically generated.
        '''
        result = self._values.get("instance_identifier_base")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def instances(self) -> typing.Optional[jsii.Number]:
        '''Number of DocDB compute instances.

        :default: 1
        '''
        result = self._values.get("instances")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def kms_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The KMS key for storage encryption.

        :default: - default master key.
        '''
        result = self._values.get("kms_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def parameter_group(self) -> typing.Optional["IClusterParameterGroup"]:
        '''The DB parameter group to associate with the instance.

        :default: no parameter group
        '''
        result = self._values.get("parameter_group")
        return typing.cast(typing.Optional["IClusterParameterGroup"], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port the DocumentDB cluster will listen on.

        :default: DatabaseCluster.DEFAULT_PORT
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''A weekly time range in which maintenance should preferably execute.

        Must be at least 30 minutes long.

        Example: 'tue:04:17-tue:04:47'

        :default:

        - 30-minute window selected at random from an 8-hour block of time for
        each AWS Region, occurring on a random day of the week.

        :see: https://docs.aws.amazon.com/documentdb/latest/developerguide/db-instance-maintain.html#maintenance-window
        '''
        result = self._values.get("preferred_maintenance_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''The removal policy to apply when the cluster and its instances are removed or replaced during a stack update, or when the stack is deleted.

        This
        removal policy also applies to the implicit security group created for the
        cluster if one is not supplied as a parameter.

        :default: - Retain cluster.
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security group.

        :default: a new security group is created.
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def storage_encrypted(self) -> typing.Optional[builtins.bool]:
        '''Whether to enable storage encryption.

        :default: true
        '''
        result = self._values.get("storage_encrypted")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Where to place the instances within the VPC.

        :default: private subnets
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DatabaseClusterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.DatabaseInstanceAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "instance_endpoint_address": "instanceEndpointAddress",
        "instance_identifier": "instanceIdentifier",
        "port": "port",
    },
)
class DatabaseInstanceAttributes:
    def __init__(
        self,
        *,
        instance_endpoint_address: builtins.str,
        instance_identifier: builtins.str,
        port: jsii.Number,
    ) -> None:
        '''Properties that describe an existing instance.

        :param instance_endpoint_address: The endpoint address.
        :param instance_identifier: The instance identifier.
        :param port: The database port.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_docdb as docdb
            
            database_instance_attributes = docdb.DatabaseInstanceAttributes(
                instance_endpoint_address="instanceEndpointAddress",
                instance_identifier="instanceIdentifier",
                port=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "instance_endpoint_address": instance_endpoint_address,
            "instance_identifier": instance_identifier,
            "port": port,
        }

    @builtins.property
    def instance_endpoint_address(self) -> builtins.str:
        '''The endpoint address.'''
        result = self._values.get("instance_endpoint_address")
        assert result is not None, "Required property 'instance_endpoint_address' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_identifier(self) -> builtins.str:
        '''The instance identifier.'''
        result = self._values.get("instance_identifier")
        assert result is not None, "Required property 'instance_identifier' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def port(self) -> jsii.Number:
        '''The database port.'''
        result = self._values.get("port")
        assert result is not None, "Required property 'port' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DatabaseInstanceAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.DatabaseInstanceProps",
    jsii_struct_bases=[],
    name_mapping={
        "cluster": "cluster",
        "instance_type": "instanceType",
        "auto_minor_version_upgrade": "autoMinorVersionUpgrade",
        "availability_zone": "availabilityZone",
        "db_instance_name": "dbInstanceName",
        "preferred_maintenance_window": "preferredMaintenanceWindow",
        "removal_policy": "removalPolicy",
    },
)
class DatabaseInstanceProps:
    def __init__(
        self,
        *,
        cluster: "IDatabaseCluster",
        instance_type: _InstanceType_f64915b9,
        auto_minor_version_upgrade: typing.Optional[builtins.bool] = None,
        availability_zone: typing.Optional[builtins.str] = None,
        db_instance_name: typing.Optional[builtins.str] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
    ) -> None:
        '''Construction properties for a DatabaseInstanceNew.

        :param cluster: The DocumentDB database cluster the instance should launch into.
        :param instance_type: The name of the compute and memory capacity classes.
        :param auto_minor_version_upgrade: Indicates that minor engine upgrades are applied automatically to the DB instance during the maintenance window. Default: true
        :param availability_zone: The name of the Availability Zone where the DB instance will be located. Default: - no preference
        :param db_instance_name: A name for the DB instance. If you specify a name, AWS CloudFormation converts it to lowercase. Default: - a CloudFormation generated name
        :param preferred_maintenance_window: The weekly time range (in UTC) during which system maintenance can occur. Format: ``ddd:hh24:mi-ddd:hh24:mi`` Constraint: Minimum 30-minute window Default: - a 30-minute window selected at random from an 8-hour block of time for each AWS Region, occurring on a random day of the week. To see the time blocks available, see https://docs.aws.amazon.com/documentdb/latest/developerguide/db-instance-maintain.html#maintenance-window
        :param removal_policy: The CloudFormation policy to apply when the instance is removed from the stack or replaced during an update. Default: RemovalPolicy.Retain

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_docdb as docdb
            from aws_cdk import aws_ec2 as ec2
            
            # database_cluster: docdb.DatabaseCluster
            # instance_type: ec2.InstanceType
            
            database_instance_props = docdb.DatabaseInstanceProps(
                cluster=database_cluster,
                instance_type=instance_type,
            
                # the properties below are optional
                auto_minor_version_upgrade=False,
                availability_zone="availabilityZone",
                db_instance_name="dbInstanceName",
                preferred_maintenance_window="preferredMaintenanceWindow",
                removal_policy=cdk.RemovalPolicy.DESTROY
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster": cluster,
            "instance_type": instance_type,
        }
        if auto_minor_version_upgrade is not None:
            self._values["auto_minor_version_upgrade"] = auto_minor_version_upgrade
        if availability_zone is not None:
            self._values["availability_zone"] = availability_zone
        if db_instance_name is not None:
            self._values["db_instance_name"] = db_instance_name
        if preferred_maintenance_window is not None:
            self._values["preferred_maintenance_window"] = preferred_maintenance_window
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy

    @builtins.property
    def cluster(self) -> "IDatabaseCluster":
        '''The DocumentDB database cluster the instance should launch into.'''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast("IDatabaseCluster", result)

    @builtins.property
    def instance_type(self) -> _InstanceType_f64915b9:
        '''The name of the compute and memory capacity classes.'''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(_InstanceType_f64915b9, result)

    @builtins.property
    def auto_minor_version_upgrade(self) -> typing.Optional[builtins.bool]:
        '''Indicates that minor engine upgrades are applied automatically to the DB instance during the maintenance window.

        :default: true
        '''
        result = self._values.get("auto_minor_version_upgrade")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def availability_zone(self) -> typing.Optional[builtins.str]:
        '''The name of the Availability Zone where the DB instance will be located.

        :default: - no preference
        '''
        result = self._values.get("availability_zone")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def db_instance_name(self) -> typing.Optional[builtins.str]:
        '''A name for the DB instance.

        If you specify a name, AWS CloudFormation
        converts it to lowercase.

        :default: - a CloudFormation generated name
        '''
        result = self._values.get("db_instance_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def preferred_maintenance_window(self) -> typing.Optional[builtins.str]:
        '''The weekly time range (in UTC) during which system maintenance can occur.

        Format: ``ddd:hh24:mi-ddd:hh24:mi``
        Constraint: Minimum 30-minute window

        :default:

        - a 30-minute window selected at random from an 8-hour block of
        time for each AWS Region, occurring on a random day of the week. To see
        the time blocks available, see https://docs.aws.amazon.com/documentdb/latest/developerguide/db-instance-maintain.html#maintenance-window
        '''
        result = self._values.get("preferred_maintenance_window")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''The CloudFormation policy to apply when the instance is removed from the stack or replaced during an update.

        :default: RemovalPolicy.Retain
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DatabaseInstanceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class DatabaseSecret(
    _Secret_50778576,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_docdb.DatabaseSecret",
):
    '''A database secret.

    :exampleMetadata: infused
    :resource: AWS::SecretsManager::Secret

    Example::

        # cluster: docdb.DatabaseCluster
        
        my_user_secret = docdb.DatabaseSecret(self, "MyUserSecret",
            username="myuser",
            master_secret=cluster.secret
        )
        my_user_secret_attached = my_user_secret.attach(cluster) # Adds DB connections information in the secret
        
        cluster.add_rotation_multi_user("MyUser",  # Add rotation using the multi user scheme
            secret=my_user_secret_attached)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        username: builtins.str,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        exclude_characters: typing.Optional[builtins.str] = None,
        master_secret: typing.Optional[_ISecret_6e020e6a] = None,
        secret_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param username: The username.
        :param encryption_key: The KMS key to use to encrypt the secret. Default: default master key
        :param exclude_characters: Characters to not include in the generated password. Default: ""
        :param master_secret: The master secret which will be used to rotate this secret. Default: - no master secret information will be included
        :param secret_name: The physical name of the secret. Default: Secretsmanager will generate a physical name for the secret
        '''
        props = DatabaseSecretProps(
            username=username,
            encryption_key=encryption_key,
            exclude_characters=exclude_characters,
            master_secret=master_secret,
            secret_name=secret_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.DatabaseSecretProps",
    jsii_struct_bases=[],
    name_mapping={
        "username": "username",
        "encryption_key": "encryptionKey",
        "exclude_characters": "excludeCharacters",
        "master_secret": "masterSecret",
        "secret_name": "secretName",
    },
)
class DatabaseSecretProps:
    def __init__(
        self,
        *,
        username: builtins.str,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        exclude_characters: typing.Optional[builtins.str] = None,
        master_secret: typing.Optional[_ISecret_6e020e6a] = None,
        secret_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Construction properties for a DatabaseSecret.

        :param username: The username.
        :param encryption_key: The KMS key to use to encrypt the secret. Default: default master key
        :param exclude_characters: Characters to not include in the generated password. Default: ""
        :param master_secret: The master secret which will be used to rotate this secret. Default: - no master secret information will be included
        :param secret_name: The physical name of the secret. Default: Secretsmanager will generate a physical name for the secret

        :exampleMetadata: infused

        Example::

            # cluster: docdb.DatabaseCluster
            
            my_user_secret = docdb.DatabaseSecret(self, "MyUserSecret",
                username="myuser",
                master_secret=cluster.secret
            )
            my_user_secret_attached = my_user_secret.attach(cluster) # Adds DB connections information in the secret
            
            cluster.add_rotation_multi_user("MyUser",  # Add rotation using the multi user scheme
                secret=my_user_secret_attached)
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "username": username,
        }
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if exclude_characters is not None:
            self._values["exclude_characters"] = exclude_characters
        if master_secret is not None:
            self._values["master_secret"] = master_secret
        if secret_name is not None:
            self._values["secret_name"] = secret_name

    @builtins.property
    def username(self) -> builtins.str:
        '''The username.'''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The KMS key to use to encrypt the secret.

        :default: default master key
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def exclude_characters(self) -> typing.Optional[builtins.str]:
        '''Characters to not include in the generated password.

        :default: ""

        :: /"
        '''
        result = self._values.get("exclude_characters")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def master_secret(self) -> typing.Optional[_ISecret_6e020e6a]:
        '''The master secret which will be used to rotate this secret.

        :default: - no master secret information will be included
        '''
        result = self._values.get("master_secret")
        return typing.cast(typing.Optional[_ISecret_6e020e6a], result)

    @builtins.property
    def secret_name(self) -> typing.Optional[builtins.str]:
        '''The physical name of the secret.

        :default: Secretsmanager will generate a physical name for the secret
        '''
        result = self._values.get("secret_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DatabaseSecretProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Endpoint(metaclass=jsii.JSIIMeta, jsii_type="aws-cdk-lib.aws_docdb.Endpoint"):
    '''Connection endpoint of a database cluster or instance.

    Consists of a combination of hostname and port.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_docdb as docdb
        
        endpoint = docdb.Endpoint("address", 123)
    '''

    def __init__(self, address: builtins.str, port: jsii.Number) -> None:
        '''Constructs an Endpoint instance.

        :param address: - The hostname or address of the endpoint.
        :param port: - The port number of the endpoint.
        '''
        jsii.create(self.__class__, self, [address, port])

    @jsii.member(jsii_name="portAsString")
    def port_as_string(self) -> builtins.str:
        '''Returns the port number as a string representation that can be used for embedding within other strings.

        This is intended to deal with CDK's token system. Numeric CDK tokens are not expanded when their string
        representation is embedded in a string. This function returns the port either as an unresolved string token or
        as a resolved string representation of the port value.

        :return: An (un)resolved string representation of the endpoint's port number
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "portAsString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostname")
    def hostname(self) -> builtins.str:
        '''The hostname of the endpoint.'''
        return typing.cast(builtins.str, jsii.get(self, "hostname"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="port")
    def port(self) -> jsii.Number:
        '''The port number of the endpoint.

        This can potentially be a CDK token. If you need to embed the port in a string (e.g. instance user data script),
        use {@link Endpoint.portAsString}.
        '''
        return typing.cast(jsii.Number, jsii.get(self, "port"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="socketAddress")
    def socket_address(self) -> builtins.str:
        '''The combination of ``HOSTNAME:PORT`` for this endpoint.'''
        return typing.cast(builtins.str, jsii.get(self, "socketAddress"))


@jsii.interface(jsii_type="aws-cdk-lib.aws_docdb.IClusterParameterGroup")
class IClusterParameterGroup(_IResource_c80c4260, typing_extensions.Protocol):
    '''A parameter group.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parameterGroupName")
    def parameter_group_name(self) -> builtins.str:
        '''The name of this parameter group.'''
        ...


class _IClusterParameterGroupProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A parameter group.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_docdb.IClusterParameterGroup"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parameterGroupName")
    def parameter_group_name(self) -> builtins.str:
        '''The name of this parameter group.'''
        return typing.cast(builtins.str, jsii.get(self, "parameterGroupName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IClusterParameterGroup).__jsii_proxy_class__ = lambda : _IClusterParameterGroupProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_docdb.IDatabaseCluster")
class IDatabaseCluster(
    _IResource_c80c4260,
    _IConnectable_10015a05,
    _ISecretAttachmentTarget_123e2df9,
    typing_extensions.Protocol,
):
    '''Create a clustered database with a given number of instances.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEndpoint")
    def cluster_endpoint(self) -> Endpoint:
        '''The endpoint to use for read/write operations.

        :attribute: Endpoint,Port
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterIdentifier")
    def cluster_identifier(self) -> builtins.str:
        '''Identifier of the cluster.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterReadEndpoint")
    def cluster_read_endpoint(self) -> Endpoint:
        '''Endpoint to use for load-balanced read-only operations.

        :attribute: ReadEndpoint
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceEndpoints")
    def instance_endpoints(self) -> typing.List[Endpoint]:
        '''Endpoints which address each individual replica.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceIdentifiers")
    def instance_identifiers(self) -> typing.List[builtins.str]:
        '''Identifiers of the replicas.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroupId")
    def security_group_id(self) -> builtins.str:
        '''The security group for this database cluster.'''
        ...


class _IDatabaseClusterProxy(
    jsii.proxy_for(_IResource_c80c4260), # type: ignore[misc]
    jsii.proxy_for(_IConnectable_10015a05), # type: ignore[misc]
    jsii.proxy_for(_ISecretAttachmentTarget_123e2df9), # type: ignore[misc]
):
    '''Create a clustered database with a given number of instances.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_docdb.IDatabaseCluster"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEndpoint")
    def cluster_endpoint(self) -> Endpoint:
        '''The endpoint to use for read/write operations.

        :attribute: Endpoint,Port
        '''
        return typing.cast(Endpoint, jsii.get(self, "clusterEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterIdentifier")
    def cluster_identifier(self) -> builtins.str:
        '''Identifier of the cluster.'''
        return typing.cast(builtins.str, jsii.get(self, "clusterIdentifier"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterReadEndpoint")
    def cluster_read_endpoint(self) -> Endpoint:
        '''Endpoint to use for load-balanced read-only operations.

        :attribute: ReadEndpoint
        '''
        return typing.cast(Endpoint, jsii.get(self, "clusterReadEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceEndpoints")
    def instance_endpoints(self) -> typing.List[Endpoint]:
        '''Endpoints which address each individual replica.'''
        return typing.cast(typing.List[Endpoint], jsii.get(self, "instanceEndpoints"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceIdentifiers")
    def instance_identifiers(self) -> typing.List[builtins.str]:
        '''Identifiers of the replicas.'''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "instanceIdentifiers"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroupId")
    def security_group_id(self) -> builtins.str:
        '''The security group for this database cluster.'''
        return typing.cast(builtins.str, jsii.get(self, "securityGroupId"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IDatabaseCluster).__jsii_proxy_class__ = lambda : _IDatabaseClusterProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_docdb.IDatabaseInstance")
class IDatabaseInstance(_IResource_c80c4260, typing_extensions.Protocol):
    '''A database instance.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbInstanceEndpointAddress")
    def db_instance_endpoint_address(self) -> builtins.str:
        '''The instance endpoint address.

        :attribute: Endpoint
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbInstanceEndpointPort")
    def db_instance_endpoint_port(self) -> builtins.str:
        '''The instance endpoint port.

        :attribute: Port
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceArn")
    def instance_arn(self) -> builtins.str:
        '''The instance arn.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceEndpoint")
    def instance_endpoint(self) -> Endpoint:
        '''The instance endpoint.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceIdentifier")
    def instance_identifier(self) -> builtins.str:
        '''The instance identifier.'''
        ...


class _IDatabaseInstanceProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A database instance.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_docdb.IDatabaseInstance"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbInstanceEndpointAddress")
    def db_instance_endpoint_address(self) -> builtins.str:
        '''The instance endpoint address.

        :attribute: Endpoint
        '''
        return typing.cast(builtins.str, jsii.get(self, "dbInstanceEndpointAddress"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbInstanceEndpointPort")
    def db_instance_endpoint_port(self) -> builtins.str:
        '''The instance endpoint port.

        :attribute: Port
        '''
        return typing.cast(builtins.str, jsii.get(self, "dbInstanceEndpointPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceArn")
    def instance_arn(self) -> builtins.str:
        '''The instance arn.'''
        return typing.cast(builtins.str, jsii.get(self, "instanceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceEndpoint")
    def instance_endpoint(self) -> Endpoint:
        '''The instance endpoint.'''
        return typing.cast(Endpoint, jsii.get(self, "instanceEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceIdentifier")
    def instance_identifier(self) -> builtins.str:
        '''The instance identifier.'''
        return typing.cast(builtins.str, jsii.get(self, "instanceIdentifier"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IDatabaseInstance).__jsii_proxy_class__ = lambda : _IDatabaseInstanceProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.Login",
    jsii_struct_bases=[],
    name_mapping={
        "username": "username",
        "exclude_characters": "excludeCharacters",
        "kms_key": "kmsKey",
        "password": "password",
        "secret_name": "secretName",
    },
)
class Login:
    def __init__(
        self,
        *,
        username: builtins.str,
        exclude_characters: typing.Optional[builtins.str] = None,
        kms_key: typing.Optional[_IKey_5f11635f] = None,
        password: typing.Optional[_SecretValue_3dd0ddae] = None,
        secret_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Login credentials for a database cluster.

        :param username: Username.
        :param exclude_characters: Specifies characters to not include in generated passwords. Default: ""
        :param kms_key: KMS encryption key to encrypt the generated secret. Default: default master key
        :param password: Password. Do not put passwords in your CDK code directly. Default: a Secrets Manager generated password
        :param secret_name: The physical name of the secret, that will be generated. Default: Secretsmanager will generate a physical name for the secret

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            
            cluster = docdb.DatabaseCluster(self, "Database",
                master_user=docdb.Login(
                    username="myuser",  # NOTE: 'admin' is reserved by DocumentDB
                    exclude_characters="\"@/:",  # optional, defaults to the set "\"@/" and is also used for eventually created rotations
                    secret_name="/myapp/mydocdb/masteruser"
                ),
                instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PUBLIC
                ),
                vpc=vpc
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "username": username,
        }
        if exclude_characters is not None:
            self._values["exclude_characters"] = exclude_characters
        if kms_key is not None:
            self._values["kms_key"] = kms_key
        if password is not None:
            self._values["password"] = password
        if secret_name is not None:
            self._values["secret_name"] = secret_name

    @builtins.property
    def username(self) -> builtins.str:
        '''Username.'''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def exclude_characters(self) -> typing.Optional[builtins.str]:
        '''Specifies characters to not include in generated passwords.

        :default: ""

        :: /"
        '''
        result = self._values.get("exclude_characters")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''KMS encryption key to encrypt the generated secret.

        :default: default master key
        '''
        result = self._values.get("kms_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def password(self) -> typing.Optional[_SecretValue_3dd0ddae]:
        '''Password.

        Do not put passwords in your CDK code directly.

        :default: a Secrets Manager generated password
        '''
        result = self._values.get("password")
        return typing.cast(typing.Optional[_SecretValue_3dd0ddae], result)

    @builtins.property
    def secret_name(self) -> typing.Optional[builtins.str]:
        '''The physical name of the secret, that will be generated.

        :default: Secretsmanager will generate a physical name for the secret
        '''
        result = self._values.get("secret_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "Login(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_docdb.RotationMultiUserOptions",
    jsii_struct_bases=[],
    name_mapping={"secret": "secret", "automatically_after": "automaticallyAfter"},
)
class RotationMultiUserOptions:
    def __init__(
        self,
        *,
        secret: _ISecret_6e020e6a,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Options to add the multi user rotation.

        :param secret: The secret to rotate. It must be a JSON string with the following format:: { "engine": <required: must be set to 'mongo'>, "host": <required: instance host name>, "username": <required: username>, "password": <required: password>, "dbname": <optional: database name>, "port": <optional: if not specified, default port 27017 will be used>, "masterarn": <required: the arn of the master secret which will be used to create users/change passwords> "ssl": <optional: if not specified, defaults to false. This must be true if being used for DocumentDB rotations where the cluster has TLS enabled> }
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_secretsmanager as secretsmanager
            
            # my_imported_secret: secretsmanager.Secret
            # cluster: docdb.DatabaseCluster
            
            
            cluster.add_rotation_multi_user("MyUser",
                secret=my_imported_secret
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "secret": secret,
        }
        if automatically_after is not None:
            self._values["automatically_after"] = automatically_after

    @builtins.property
    def secret(self) -> _ISecret_6e020e6a:
        '''The secret to rotate.

        It must be a JSON string with the following format::

           {
              "engine": <required: must be set to 'mongo'>,
              "host": <required: instance host name>,
              "username": <required: username>,
              "password": <required: password>,
              "dbname": <optional: database name>,
              "port": <optional: if not specified, default port 27017 will be used>,
              "masterarn": <required: the arn of the master secret which will be used to create users/change passwords>
              "ssl": <optional: if not specified, defaults to false. This must be true if being used for DocumentDB rotations
                     where the cluster has TLS enabled>
           }
        '''
        result = self._values.get("secret")
        assert result is not None, "Required property 'secret' is missing"
        return typing.cast(_ISecret_6e020e6a, result)

    @builtins.property
    def automatically_after(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation.

        :default: Duration.days(30)
        '''
        result = self._values.get("automatically_after")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RotationMultiUserOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IClusterParameterGroup)
class ClusterParameterGroup(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_docdb.ClusterParameterGroup",
):
    '''A cluster parameter group.

    :resource: AWS::DocDB::DBClusterParameterGroup
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_docdb as docdb
        
        cluster_parameter_group = docdb.ClusterParameterGroup(self, "MyClusterParameterGroup",
            family="family",
            parameters={
                "parameters_key": "parameters"
            },
        
            # the properties below are optional
            db_cluster_parameter_group_name="dbClusterParameterGroupName",
            description="description"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        family: builtins.str,
        parameters: typing.Mapping[builtins.str, builtins.str],
        db_cluster_parameter_group_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param family: Database family of this parameter group.
        :param parameters: The parameters in this parameter group.
        :param db_cluster_parameter_group_name: The name of the cluster parameter group. Default: A CDK generated name for the cluster parameter group
        :param description: Description for this parameter group. Default: a CDK generated description
        '''
        props = ClusterParameterGroupProps(
            family=family,
            parameters=parameters,
            db_cluster_parameter_group_name=db_cluster_parameter_group_name,
            description=description,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromParameterGroupName") # type: ignore[misc]
    @builtins.classmethod
    def from_parameter_group_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        parameter_group_name: builtins.str,
    ) -> IClusterParameterGroup:
        '''Imports a parameter group.

        :param scope: -
        :param id: -
        :param parameter_group_name: -
        '''
        return typing.cast(IClusterParameterGroup, jsii.sinvoke(cls, "fromParameterGroupName", [scope, id, parameter_group_name]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parameterGroupName")
    def parameter_group_name(self) -> builtins.str:
        '''The name of the parameter group.'''
        return typing.cast(builtins.str, jsii.get(self, "parameterGroupName"))


@jsii.implements(IDatabaseCluster)
class DatabaseCluster(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_docdb.DatabaseCluster",
):
    '''Create a clustered database with a given number of instances.

    :exampleMetadata: infused
    :resource: AWS::DocDB::DBCluster

    Example::

        # vpc: ec2.Vpc
        
        cluster = docdb.DatabaseCluster(self, "Database",
            master_user=docdb.Login(
                username="myuser",  # NOTE: 'admin' is reserved by DocumentDB
                exclude_characters="\"@/:",  # optional, defaults to the set "\"@/" and is also used for eventually created rotations
                secret_name="/myapp/mydocdb/masteruser"
            ),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC
            ),
            vpc=vpc
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instance_type: _InstanceType_f64915b9,
        master_user: Login,
        vpc: _IVpc_f30d5663,
        backup: typing.Optional[BackupProps] = None,
        cloud_watch_logs_retention: typing.Optional[_RetentionDays_070f99f0] = None,
        cloud_watch_logs_retention_role: typing.Optional[_IRole_235f5d8e] = None,
        db_cluster_name: typing.Optional[builtins.str] = None,
        deletion_protection: typing.Optional[builtins.bool] = None,
        engine_version: typing.Optional[builtins.str] = None,
        export_audit_logs_to_cloud_watch: typing.Optional[builtins.bool] = None,
        export_profiler_logs_to_cloud_watch: typing.Optional[builtins.bool] = None,
        instance_identifier_base: typing.Optional[builtins.str] = None,
        instances: typing.Optional[jsii.Number] = None,
        kms_key: typing.Optional[_IKey_5f11635f] = None,
        parameter_group: typing.Optional[IClusterParameterGroup] = None,
        port: typing.Optional[jsii.Number] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        storage_encrypted: typing.Optional[builtins.bool] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param instance_type: What type of instance to start for the replicas.
        :param master_user: Username and password for the administrative user.
        :param vpc: What subnets to run the DocumentDB instances in. Must be at least 2 subnets in two different AZs.
        :param backup: Backup settings. Default: - Backup retention period for automated backups is 1 day. Backup preferred window is set to a 30-minute window selected at random from an 8-hour block of time for each AWS Region, occurring on a random day of the week.
        :param cloud_watch_logs_retention: The number of days log events are kept in CloudWatch Logs. When updating this property, unsetting it doesn't remove the log retention policy. To remove the retention policy, set the value to ``Infinity``. Default: - logs never expire
        :param cloud_watch_logs_retention_role: The IAM role for the Lambda function associated with the custom resource that sets the retention policy. Default: - a new role is created.
        :param db_cluster_name: An optional identifier for the cluster. Default: - A name is automatically generated.
        :param deletion_protection: Specifies whether this cluster can be deleted. If deletionProtection is enabled, the cluster cannot be deleted unless it is modified and deletionProtection is disabled. deletionProtection protects clusters from being accidentally deleted. Default: - false
        :param engine_version: What version of the database to start. Default: - The default engine version.
        :param export_audit_logs_to_cloud_watch: Whether the audit logs should be exported to CloudWatch. Note that you also have to configure the audit log export in the Cluster's Parameter Group. Default: false
        :param export_profiler_logs_to_cloud_watch: Whether the profiler logs should be exported to CloudWatch. Note that you also have to configure the profiler log export in the Cluster's Parameter Group. Default: false
        :param instance_identifier_base: Base identifier for instances. Every replica is named by appending the replica number to this string, 1-based. Default: - ``dbClusterName`` is used with the word "Instance" appended. If ``dbClusterName`` is not provided, the identifier is automatically generated.
        :param instances: Number of DocDB compute instances. Default: 1
        :param kms_key: The KMS key for storage encryption. Default: - default master key.
        :param parameter_group: The DB parameter group to associate with the instance. Default: no parameter group
        :param port: The port the DocumentDB cluster will listen on. Default: DatabaseCluster.DEFAULT_PORT
        :param preferred_maintenance_window: A weekly time range in which maintenance should preferably execute. Must be at least 30 minutes long. Example: 'tue:04:17-tue:04:47' Default: - 30-minute window selected at random from an 8-hour block of time for each AWS Region, occurring on a random day of the week.
        :param removal_policy: The removal policy to apply when the cluster and its instances are removed or replaced during a stack update, or when the stack is deleted. This removal policy also applies to the implicit security group created for the cluster if one is not supplied as a parameter. Default: - Retain cluster.
        :param security_group: Security group. Default: a new security group is created.
        :param storage_encrypted: Whether to enable storage encryption. Default: true
        :param vpc_subnets: Where to place the instances within the VPC. Default: private subnets
        '''
        props = DatabaseClusterProps(
            instance_type=instance_type,
            master_user=master_user,
            vpc=vpc,
            backup=backup,
            cloud_watch_logs_retention=cloud_watch_logs_retention,
            cloud_watch_logs_retention_role=cloud_watch_logs_retention_role,
            db_cluster_name=db_cluster_name,
            deletion_protection=deletion_protection,
            engine_version=engine_version,
            export_audit_logs_to_cloud_watch=export_audit_logs_to_cloud_watch,
            export_profiler_logs_to_cloud_watch=export_profiler_logs_to_cloud_watch,
            instance_identifier_base=instance_identifier_base,
            instances=instances,
            kms_key=kms_key,
            parameter_group=parameter_group,
            port=port,
            preferred_maintenance_window=preferred_maintenance_window,
            removal_policy=removal_policy,
            security_group=security_group,
            storage_encrypted=storage_encrypted,
            vpc_subnets=vpc_subnets,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromDatabaseClusterAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_database_cluster_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster_endpoint_address: builtins.str,
        cluster_identifier: builtins.str,
        instance_endpoint_addresses: typing.Sequence[builtins.str],
        instance_identifiers: typing.Sequence[builtins.str],
        port: jsii.Number,
        reader_endpoint_address: builtins.str,
        security_group: _ISecurityGroup_acf8a799,
    ) -> IDatabaseCluster:
        '''Import an existing DatabaseCluster from properties.

        :param scope: -
        :param id: -
        :param cluster_endpoint_address: Cluster endpoint address.
        :param cluster_identifier: Identifier for the cluster.
        :param instance_endpoint_addresses: Endpoint addresses of individual instances.
        :param instance_identifiers: Identifier for the instances.
        :param port: The database port.
        :param reader_endpoint_address: Reader endpoint address.
        :param security_group: The security group of the database cluster.
        '''
        attrs = DatabaseClusterAttributes(
            cluster_endpoint_address=cluster_endpoint_address,
            cluster_identifier=cluster_identifier,
            instance_endpoint_addresses=instance_endpoint_addresses,
            instance_identifiers=instance_identifiers,
            port=port,
            reader_endpoint_address=reader_endpoint_address,
            security_group=security_group,
        )

        return typing.cast(IDatabaseCluster, jsii.sinvoke(cls, "fromDatabaseClusterAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="addRotationMultiUser")
    def add_rotation_multi_user(
        self,
        id: builtins.str,
        *,
        secret: _ISecret_6e020e6a,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
    ) -> _SecretRotation_38c354d9:
        '''Adds the multi user rotation to this cluster.

        :param id: -
        :param secret: The secret to rotate. It must be a JSON string with the following format:: { "engine": <required: must be set to 'mongo'>, "host": <required: instance host name>, "username": <required: username>, "password": <required: password>, "dbname": <optional: database name>, "port": <optional: if not specified, default port 27017 will be used>, "masterarn": <required: the arn of the master secret which will be used to create users/change passwords> "ssl": <optional: if not specified, defaults to false. This must be true if being used for DocumentDB rotations where the cluster has TLS enabled> }
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        '''
        options = RotationMultiUserOptions(
            secret=secret, automatically_after=automatically_after
        )

        return typing.cast(_SecretRotation_38c354d9, jsii.invoke(self, "addRotationMultiUser", [id, options]))

    @jsii.member(jsii_name="addRotationSingleUser")
    def add_rotation_single_user(
        self,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
    ) -> _SecretRotation_38c354d9:
        '''Adds the single user rotation of the master password to this cluster.

        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation.
        '''
        return typing.cast(_SecretRotation_38c354d9, jsii.invoke(self, "addRotationSingleUser", [automatically_after]))

    @jsii.member(jsii_name="addSecurityGroups")
    def add_security_groups(self, *security_groups: _ISecurityGroup_acf8a799) -> None:
        '''Adds security groups to this cluster.

        :param security_groups: The security groups to add.
        '''
        return typing.cast(None, jsii.invoke(self, "addSecurityGroups", [*security_groups]))

    @jsii.member(jsii_name="asSecretAttachmentTarget")
    def as_secret_attachment_target(self) -> _SecretAttachmentTargetProps_9ec7949d:
        '''Renders the secret attachment target specifications.'''
        return typing.cast(_SecretAttachmentTargetProps_9ec7949d, jsii.invoke(self, "asSecretAttachmentTarget", []))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="DEFAULT_NUM_INSTANCES")
    def DEFAULT_NUM_INSTANCES(cls) -> jsii.Number:
        '''The default number of instances in the DocDB cluster if none are specified.'''
        return typing.cast(jsii.Number, jsii.sget(cls, "DEFAULT_NUM_INSTANCES"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="DEFAULT_PORT")
    def DEFAULT_PORT(cls) -> jsii.Number:
        '''The default port Document DB listens on.'''
        return typing.cast(jsii.Number, jsii.sget(cls, "DEFAULT_PORT"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEndpoint")
    def cluster_endpoint(self) -> Endpoint:
        '''The endpoint to use for read/write operations.'''
        return typing.cast(Endpoint, jsii.get(self, "clusterEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterIdentifier")
    def cluster_identifier(self) -> builtins.str:
        '''Identifier of the cluster.'''
        return typing.cast(builtins.str, jsii.get(self, "clusterIdentifier"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterReadEndpoint")
    def cluster_read_endpoint(self) -> Endpoint:
        '''Endpoint to use for load-balanced read-only operations.'''
        return typing.cast(Endpoint, jsii.get(self, "clusterReadEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterResourceIdentifier")
    def cluster_resource_identifier(self) -> builtins.str:
        '''The resource id for the cluster;

        for example: cluster-ABCD1234EFGH5678IJKL90MNOP. The cluster ID uniquely
        identifies the cluster and is used in things like IAM authentication policies.

        :attribute: ClusterResourceId
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterResourceIdentifier"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''The connections object to implement IConnectable.'''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceEndpoints")
    def instance_endpoints(self) -> typing.List[Endpoint]:
        '''Endpoints which address each individual replica.'''
        return typing.cast(typing.List[Endpoint], jsii.get(self, "instanceEndpoints"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceIdentifiers")
    def instance_identifiers(self) -> typing.List[builtins.str]:
        '''Identifiers of the replicas.'''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "instanceIdentifiers"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroupId")
    def security_group_id(self) -> builtins.str:
        '''Security group identifier of this database.'''
        return typing.cast(builtins.str, jsii.get(self, "securityGroupId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secret")
    def secret(self) -> typing.Optional[_ISecret_6e020e6a]:
        '''The secret attached to this cluster.'''
        return typing.cast(typing.Optional[_ISecret_6e020e6a], jsii.get(self, "secret"))


@jsii.implements(IDatabaseInstance)
class DatabaseInstance(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_docdb.DatabaseInstance",
):
    '''A database instance.

    :resource: AWS::DocDB::DBInstance
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_docdb as docdb
        from aws_cdk import aws_ec2 as ec2
        
        # database_cluster: docdb.DatabaseCluster
        # instance_type: ec2.InstanceType
        
        database_instance = docdb.DatabaseInstance(self, "MyDatabaseInstance",
            cluster=database_cluster,
            instance_type=instance_type,
        
            # the properties below are optional
            auto_minor_version_upgrade=False,
            availability_zone="availabilityZone",
            db_instance_name="dbInstanceName",
            preferred_maintenance_window="preferredMaintenanceWindow",
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: IDatabaseCluster,
        instance_type: _InstanceType_f64915b9,
        auto_minor_version_upgrade: typing.Optional[builtins.bool] = None,
        availability_zone: typing.Optional[builtins.str] = None,
        db_instance_name: typing.Optional[builtins.str] = None,
        preferred_maintenance_window: typing.Optional[builtins.str] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: The DocumentDB database cluster the instance should launch into.
        :param instance_type: The name of the compute and memory capacity classes.
        :param auto_minor_version_upgrade: Indicates that minor engine upgrades are applied automatically to the DB instance during the maintenance window. Default: true
        :param availability_zone: The name of the Availability Zone where the DB instance will be located. Default: - no preference
        :param db_instance_name: A name for the DB instance. If you specify a name, AWS CloudFormation converts it to lowercase. Default: - a CloudFormation generated name
        :param preferred_maintenance_window: The weekly time range (in UTC) during which system maintenance can occur. Format: ``ddd:hh24:mi-ddd:hh24:mi`` Constraint: Minimum 30-minute window Default: - a 30-minute window selected at random from an 8-hour block of time for each AWS Region, occurring on a random day of the week. To see the time blocks available, see https://docs.aws.amazon.com/documentdb/latest/developerguide/db-instance-maintain.html#maintenance-window
        :param removal_policy: The CloudFormation policy to apply when the instance is removed from the stack or replaced during an update. Default: RemovalPolicy.Retain
        '''
        props = DatabaseInstanceProps(
            cluster=cluster,
            instance_type=instance_type,
            auto_minor_version_upgrade=auto_minor_version_upgrade,
            availability_zone=availability_zone,
            db_instance_name=db_instance_name,
            preferred_maintenance_window=preferred_maintenance_window,
            removal_policy=removal_policy,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromDatabaseInstanceAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_database_instance_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instance_endpoint_address: builtins.str,
        instance_identifier: builtins.str,
        port: jsii.Number,
    ) -> IDatabaseInstance:
        '''Import an existing database instance.

        :param scope: -
        :param id: -
        :param instance_endpoint_address: The endpoint address.
        :param instance_identifier: The instance identifier.
        :param port: The database port.
        '''
        attrs = DatabaseInstanceAttributes(
            instance_endpoint_address=instance_endpoint_address,
            instance_identifier=instance_identifier,
            port=port,
        )

        return typing.cast(IDatabaseInstance, jsii.sinvoke(cls, "fromDatabaseInstanceAttributes", [scope, id, attrs]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cluster")
    def cluster(self) -> IDatabaseCluster:
        '''The instance's database cluster.'''
        return typing.cast(IDatabaseCluster, jsii.get(self, "cluster"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbInstanceEndpointAddress")
    def db_instance_endpoint_address(self) -> builtins.str:
        '''The instance endpoint address.

        :inheritdoc: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "dbInstanceEndpointAddress"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dbInstanceEndpointPort")
    def db_instance_endpoint_port(self) -> builtins.str:
        '''The instance endpoint port.

        :inheritdoc: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "dbInstanceEndpointPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceArn")
    def instance_arn(self) -> builtins.str:
        '''The instance arn.'''
        return typing.cast(builtins.str, jsii.get(self, "instanceArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceEndpoint")
    def instance_endpoint(self) -> Endpoint:
        '''The instance endpoint.

        :inheritdoc: true
        '''
        return typing.cast(Endpoint, jsii.get(self, "instanceEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceIdentifier")
    def instance_identifier(self) -> builtins.str:
        '''The instance identifier.

        :inheritdoc: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceIdentifier"))


__all__ = [
    "BackupProps",
    "CfnDBCluster",
    "CfnDBClusterParameterGroup",
    "CfnDBClusterParameterGroupProps",
    "CfnDBClusterProps",
    "CfnDBInstance",
    "CfnDBInstanceProps",
    "CfnDBSubnetGroup",
    "CfnDBSubnetGroupProps",
    "ClusterParameterGroup",
    "ClusterParameterGroupProps",
    "DatabaseCluster",
    "DatabaseClusterAttributes",
    "DatabaseClusterProps",
    "DatabaseInstance",
    "DatabaseInstanceAttributes",
    "DatabaseInstanceProps",
    "DatabaseSecret",
    "DatabaseSecretProps",
    "Endpoint",
    "IClusterParameterGroup",
    "IDatabaseCluster",
    "IDatabaseInstance",
    "Login",
    "RotationMultiUserOptions",
]

publication.publish()
