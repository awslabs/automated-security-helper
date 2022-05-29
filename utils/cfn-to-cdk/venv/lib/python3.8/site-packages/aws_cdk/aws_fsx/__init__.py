'''
# Amazon FSx Construct Library

[Amazon FSx](https://docs.aws.amazon.com/fsx/?id=docs_gateway) provides fully managed third-party file systems with the
native compatibility and feature sets for workloads such as Microsoft Windows–based storage, high-performance computing,
machine learning, and electronic design automation.

Amazon FSx supports two file system types: [Lustre](https://docs.aws.amazon.com/fsx/latest/LustreGuide/index.html) and
[Windows](https://docs.aws.amazon.com/fsx/latest/WindowsGuide/index.html) File Server.

## FSx for Lustre

Amazon FSx for Lustre makes it easy and cost-effective to launch and run the popular, high-performance Lustre file
system. You use Lustre for workloads where speed matters, such as machine learning, high performance computing (HPC),
video processing, and financial modeling.

The open-source Lustre file system is designed for applications that require fast storage—where you want your storage
to keep up with your compute. Lustre was built to solve the problem of quickly and cheaply processing the world's
ever-growing datasets. It's a widely used file system designed for the fastest computers in the world. It provides
submillisecond latencies, up to hundreds of GBps of throughput, and up to millions of IOPS. For more information on
Lustre, see the [Lustre website](http://lustre.org/).

As a fully managed service, Amazon FSx makes it easier for you to use Lustre for workloads where storage speed matters.
Amazon FSx for Lustre eliminates the traditional complexity of setting up and managing Lustre file systems, enabling
you to spin up and run a battle-tested high-performance file system in minutes. It also provides multiple deployment
options so you can optimize cost for your needs.

Amazon FSx for Lustre is POSIX-compliant, so you can use your current Linux-based applications without having to make
any changes. Amazon FSx for Lustre provides a native file system interface and works as any file system does with your
Linux operating system. It also provides read-after-write consistency and supports file locking.

### Installation

Import to your project:

```python
import aws_cdk.aws_fsx as fsx
```

### Basic Usage

Setup required properties and create:

```python
# vpc: ec2.Vpc


file_system = fsx.LustreFileSystem(self, "FsxLustreFileSystem",
    lustre_configuration=fsx.LustreConfiguration(deployment_type=fsx.LustreDeploymentType.SCRATCH_2),
    storage_capacity_gi_b=1200,
    vpc=vpc,
    vpc_subnet=vpc.private_subnets[0]
)
```

### Connecting

To control who can access the file system, use the `.connections` attribute. FSx has a fixed default port, so you don't
need to specify the port. This example allows an EC2 instance to connect to a file system:

```python
# file_system: fsx.LustreFileSystem
# instance: ec2.Instance


file_system.connections.allow_default_port_from(instance)
```

### Mounting

The LustreFileSystem Construct exposes both the DNS name of the file system as well as its mount name, which can be
used to mount the file system on an EC2 instance. The following example shows how to bring up a file system and EC2
instance, and then use User Data to mount the file system on the instance at start-up:

```python
import aws_cdk.aws_iam as iam

# vpc: ec2.Vpc

lustre_configuration = {
    "deployment_type": fsx.LustreDeploymentType.SCRATCH_2
}

fs = fsx.LustreFileSystem(self, "FsxLustreFileSystem",
    lustre_configuration=lustre_configuration,
    storage_capacity_gi_b=1200,
    vpc=vpc,
    vpc_subnet=vpc.private_subnets[0]
)

inst = ec2.Instance(self, "inst",
    instance_type=ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.LARGE),
    machine_image=ec2.AmazonLinuxImage(
        generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
    ),
    vpc=vpc,
    vpc_subnets=ec2.SubnetSelection(
        subnet_type=ec2.SubnetType.PUBLIC
    )
)
fs.connections.allow_default_port_from(inst)

# Need to give the instance access to read information about FSx to determine the file system's mount name.
inst.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonFSxReadOnlyAccess"))

mount_path = "/mnt/fsx"
dns_name = fs.dns_name
mount_name = fs.mount_name

inst.user_data.add_commands("set -eux", "yum update -y", "amazon-linux-extras install -y lustre2.10", f"mkdir -p {mountPath}", f"chmod 777 {mountPath}", f"chown ec2-user:ec2-user {mountPath}", f"echo \"{dnsName}@tcp:/{mountName} {mountPath} lustre defaults,noatime,flock,_netdev 0 0\" >> /etc/fstab", "mount -a")
```

### Importing

An FSx for Lustre file system can be imported with `fromLustreFileSystemAttributes(stack, id, attributes)`. The
following example lays out how you could import the SecurityGroup a file system belongs to, use that to import the file
system, and then also import the VPC the file system is in and add an EC2 instance to it, giving it access to the file
system.

```python
sg = ec2.SecurityGroup.from_security_group_id(self, "FsxSecurityGroup", "{SECURITY-GROUP-ID}")
fs = fsx.LustreFileSystem.from_lustre_file_system_attributes(self, "FsxLustreFileSystem",
    dns_name="{FILE-SYSTEM-DNS-NAME}",
    file_system_id="{FILE-SYSTEM-ID}",
    security_group=sg
)

vpc = ec2.Vpc.from_vpc_attributes(self, "Vpc",
    availability_zones=["us-west-2a", "us-west-2b"],
    public_subnet_ids=["{US-WEST-2A-SUBNET-ID}", "{US-WEST-2B-SUBNET-ID}"],
    vpc_id="{VPC-ID}"
)

inst = ec2.Instance(self, "inst",
    instance_type=ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.LARGE),
    machine_image=ec2.AmazonLinuxImage(
        generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
    ),
    vpc=vpc,
    vpc_subnets=ec2.SubnetSelection(
        subnet_type=ec2.SubnetType.PUBLIC
    )
)

fs.connections.allow_default_port_from(inst)
```

## FSx for Windows File Server

The L2 construct for the FSx for Windows File Server has not yet been implemented. To instantiate an FSx for Windows
file system, the L1 constructs can be used as defined by CloudFormation.
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
    RemovalPolicy as _RemovalPolicy_9f93c814,
    Resource as _Resource_45bc6135,
    ResourceProps as _ResourceProps_15a65b4e,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_ec2 import (
    Connections as _Connections_0f31fce8,
    IConnectable as _IConnectable_10015a05,
    ISecurityGroup as _ISecurityGroup_acf8a799,
    ISubnet as _ISubnet_d57d1229,
    IVpc as _IVpc_f30d5663,
)
from ..aws_kms import IKey as _IKey_5f11635f


@jsii.implements(_IInspectable_c2943556)
class CfnFileSystem(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem",
):
    '''A CloudFormation ``AWS::FSx::FileSystem``.

    The ``AWS::FSx::FileSystem`` resource is an Amazon FSx resource type that creates an Amazon FSx file system. You can create any of the following supported file system types:

    - Amazon FSx for Lustre
    - Amazon FSx for NetApp ONTAP
    - Amazon FSx for OpenZFS
    - Amazon FSx for Windows File Server

    :cloudformationResource: AWS::FSx::FileSystem
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_fsx as fsx
        
        cfn_file_system = fsx.CfnFileSystem(self, "MyCfnFileSystem",
            file_system_type="fileSystemType",
            subnet_ids=["subnetIds"],
        
            # the properties below are optional
            backup_id="backupId",
            file_system_type_version="fileSystemTypeVersion",
            kms_key_id="kmsKeyId",
            lustre_configuration=fsx.CfnFileSystem.LustreConfigurationProperty(
                auto_import_policy="autoImportPolicy",
                automatic_backup_retention_days=123,
                copy_tags_to_backups=False,
                daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                data_compression_type="dataCompressionType",
                deployment_type="deploymentType",
                drive_cache_type="driveCacheType",
                export_path="exportPath",
                imported_file_chunk_size=123,
                import_path="importPath",
                per_unit_storage_throughput=123,
                weekly_maintenance_start_time="weeklyMaintenanceStartTime"
            ),
            ontap_configuration=fsx.CfnFileSystem.OntapConfigurationProperty(
                deployment_type="deploymentType",
        
                # the properties below are optional
                automatic_backup_retention_days=123,
                daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                disk_iops_configuration=fsx.CfnFileSystem.DiskIopsConfigurationProperty(
                    iops=123,
                    mode="mode"
                ),
                endpoint_ip_address_range="endpointIpAddressRange",
                fsx_admin_password="fsxAdminPassword",
                preferred_subnet_id="preferredSubnetId",
                route_table_ids=["routeTableIds"],
                throughput_capacity=123,
                weekly_maintenance_start_time="weeklyMaintenanceStartTime"
            ),
            open_zfs_configuration=fsx.CfnFileSystem.OpenZFSConfigurationProperty(
                deployment_type="deploymentType",
        
                # the properties below are optional
                automatic_backup_retention_days=123,
                copy_tags_to_backups=False,
                copy_tags_to_volumes=False,
                daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                disk_iops_configuration=fsx.CfnFileSystem.DiskIopsConfigurationProperty(
                    iops=123,
                    mode="mode"
                ),
                root_volume_configuration=fsx.CfnFileSystem.RootVolumeConfigurationProperty(
                    copy_tags_to_snapshots=False,
                    data_compression_type="dataCompressionType",
                    nfs_exports=[fsx.CfnFileSystem.NfsExportsProperty(
                        client_configurations=[fsx.CfnFileSystem.ClientConfigurationsProperty(
                            clients="clients",
                            options=["options"]
                        )]
                    )],
                    read_only=False,
                    user_and_group_quotas=[fsx.CfnFileSystem.UserAndGroupQuotasProperty(
                        id=123,
                        storage_capacity_quota_gi_b=123,
                        type="type"
                    )]
                ),
                throughput_capacity=123,
                weekly_maintenance_start_time="weeklyMaintenanceStartTime"
            ),
            security_group_ids=["securityGroupIds"],
            storage_capacity=123,
            storage_type="storageType",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            windows_configuration=fsx.CfnFileSystem.WindowsConfigurationProperty(
                throughput_capacity=123,
        
                # the properties below are optional
                active_directory_id="activeDirectoryId",
                aliases=["aliases"],
                audit_log_configuration=fsx.CfnFileSystem.AuditLogConfigurationProperty(
                    file_access_audit_log_level="fileAccessAuditLogLevel",
                    file_share_access_audit_log_level="fileShareAccessAuditLogLevel",
        
                    # the properties below are optional
                    audit_log_destination="auditLogDestination"
                ),
                automatic_backup_retention_days=123,
                copy_tags_to_backups=False,
                daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                deployment_type="deploymentType",
                preferred_subnet_id="preferredSubnetId",
                self_managed_active_directory_configuration=fsx.CfnFileSystem.SelfManagedActiveDirectoryConfigurationProperty(
                    dns_ips=["dnsIps"],
                    domain_name="domainName",
                    file_system_administrators_group="fileSystemAdministratorsGroup",
                    organizational_unit_distinguished_name="organizationalUnitDistinguishedName",
                    password="password",
                    user_name="userName"
                ),
                weekly_maintenance_start_time="weeklyMaintenanceStartTime"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        file_system_type: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        backup_id: typing.Optional[builtins.str] = None,
        file_system_type_version: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        lustre_configuration: typing.Optional[typing.Union["CfnFileSystem.LustreConfigurationProperty", _IResolvable_da3f097b]] = None,
        ontap_configuration: typing.Optional[typing.Union["CfnFileSystem.OntapConfigurationProperty", _IResolvable_da3f097b]] = None,
        open_zfs_configuration: typing.Optional[typing.Union["CfnFileSystem.OpenZFSConfigurationProperty", _IResolvable_da3f097b]] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        storage_capacity: typing.Optional[jsii.Number] = None,
        storage_type: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        windows_configuration: typing.Optional[typing.Union["CfnFileSystem.WindowsConfigurationProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::FSx::FileSystem``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param file_system_type: The type of Amazon FSx file system, which can be ``LUSTRE`` , ``WINDOWS`` , ``ONTAP`` , or ``OPENZFS`` .
        :param subnet_ids: Specifies the IDs of the subnets that the file system will be accessible from. For Windows and ONTAP ``MULTI_AZ_1`` deployment types,provide exactly two subnet IDs, one for the preferred file server and one for the standby file server. You specify one of these subnets as the preferred subnet using the ``WindowsConfiguration > PreferredSubnetID`` or ``OntapConfiguration > PreferredSubnetID`` properties. For more information about Multi-AZ file system configuration, see `Availability and durability: Single-AZ and Multi-AZ file systems <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/high-availability-multiAZ.html>`_ in the *Amazon FSx for Windows User Guide* and `Availability and durability <https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/high-availability-multiAZ.html>`_ in the *Amazon FSx for ONTAP User Guide* . For Windows ``SINGLE_AZ_1`` and ``SINGLE_AZ_2`` and all Lustre deployment types, provide exactly one subnet ID. The file server is launched in that subnet's Availability Zone.
        :param backup_id: The ID of the source backup. Specifies the backup that you are copying.
        :param file_system_type_version: (Optional) For FSx for Lustre file systems, sets the Lustre version for the file system that you're creating. Valid values are ``2.10`` and ``2.12`` : - 2.10 is supported by the Scratch and Persistent_1 Lustre deployment types. - 2.12 is supported by all Lustre deployment types. ``2.12`` is required when setting FSx for Lustre ``DeploymentType`` to ``PERSISTENT_2`` . Default value = ``2.10`` , except when ``DeploymentType`` is set to ``PERSISTENT_2`` , then the default is ``2.12`` . .. epigraph:: If you set ``FileSystemTypeVersion`` to ``2.10`` for a ``PERSISTENT_2`` Lustre deployment type, the ``CreateFileSystem`` operation fails.
        :param kms_key_id: The ID of the AWS Key Management Service ( AWS KMS ) key used to encrypt the file system's data for Amazon FSx for Windows File Server file systems, Amazon FSx for NetApp ONTAP file systems, and ``PERSISTENT`` Amazon FSx for Lustre file systems at rest. If this ID isn't specified, the Amazon FSx-managed key for your account is used. The scratch Amazon FSx for Lustre file systems are always encrypted at rest using the Amazon FSx-managed key for your account. For more information, see `Encrypt <https://docs.aws.amazon.com//kms/latest/APIReference/API_Encrypt.html>`_ in the *AWS Key Management Service API Reference* .
        :param lustre_configuration: The Lustre configuration for the file system being created. .. epigraph:: The following parameters are not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository. - ``AutoImportPolicy`` - ``ExportPath`` - ``ImportedChunkSize`` - ``ImportPath``
        :param ontap_configuration: The ONTAP configuration properties of the FSx for ONTAP file system that you are creating.
        :param open_zfs_configuration: The OpenZFS configuration properties for the file system that you are creating.
        :param security_group_ids: A list of IDs specifying the security groups to apply to all network interfaces created for file system access. This list isn't returned in later requests to describe the file system.
        :param storage_capacity: Sets the storage capacity of the file system that you're creating. ``StorageCapacity`` is required if you are creating a new file system. Do not include ``StorageCapacity`` if you are creating a file system from a backup. For Lustre file systems:
        :param storage_type: Sets the storage type for the file system that you're creating. Valid values are ``SSD`` and ``HDD`` . - Set to ``SSD`` to use solid state drive storage. SSD is supported on all Windows, Lustre, ONTAP, and OpenZFS deployment types. - Set to ``HDD`` to use hard disk drive storage. HDD is supported on ``SINGLE_AZ_2`` and ``MULTI_AZ_1`` Windows file system deployment types, and on ``PERSISTENT`` Lustre file system deployment types. Default value is ``SSD`` . For more information, see `Storage type options <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/optimize-fsx-costs.html#storage-type-options>`_ in the *FSx for Windows File Server User Guide* and `Multiple storage options <https://docs.aws.amazon.com/fsx/latest/LustreGuide/what-is.html#storage-options>`_ in the *FSx for Lustre User Guide* .
        :param tags: The tags to associate with the file system. For more information, see `Tagging your Amazon EC2 resources <https://docs.aws.amazon.com//AWSEC2/latest/UserGuide/Using_Tags.html>`_ in the *Amazon EC2 User Guide* .
        :param windows_configuration: The configuration object for the Microsoft Windows file system you are creating. This value is required if ``FileSystemType`` is set to ``WINDOWS`` .
        '''
        props = CfnFileSystemProps(
            file_system_type=file_system_type,
            subnet_ids=subnet_ids,
            backup_id=backup_id,
            file_system_type_version=file_system_type_version,
            kms_key_id=kms_key_id,
            lustre_configuration=lustre_configuration,
            ontap_configuration=ontap_configuration,
            open_zfs_configuration=open_zfs_configuration,
            security_group_ids=security_group_ids,
            storage_capacity=storage_capacity,
            storage_type=storage_type,
            tags=tags,
            windows_configuration=windows_configuration,
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
    @jsii.member(jsii_name="attrDnsName")
    def attr_dns_name(self) -> builtins.str:
        '''Returns the FSx for Windows file system's DNSName.

        Example: ``amznfsxp1honlek.corp.example.com``

        :cloudformationAttribute: DNSName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDnsName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLustreMountName")
    def attr_lustre_mount_name(self) -> builtins.str:
        '''Returns the file system's LustreMountName.

        Example for SCRATCH_1 deployment types: This value is always ``fsx`` .

        Example for SCRATCH_2 and PERSISTENT deployment types: ``2p3fhbmv``

        :cloudformationAttribute: LustreMountName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLustreMountName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRootVolumeId")
    def attr_root_volume_id(self) -> builtins.str:
        '''Returns the root volume ID of the FSx for OpenZFS file system.

        Example: ``fsvol-0123456789abcdefa``

        :cloudformationAttribute: RootVolumeId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRootVolumeId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to associate with the file system.

        For more information, see `Tagging your Amazon EC2 resources <https://docs.aws.amazon.com//AWSEC2/latest/UserGuide/Using_Tags.html>`_ in the *Amazon EC2 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fileSystemType")
    def file_system_type(self) -> builtins.str:
        '''The type of Amazon FSx file system, which can be ``LUSTRE`` , ``WINDOWS`` , ``ONTAP`` , or ``OPENZFS`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-filesystemtype
        '''
        return typing.cast(builtins.str, jsii.get(self, "fileSystemType"))

    @file_system_type.setter
    def file_system_type(self, value: builtins.str) -> None:
        jsii.set(self, "fileSystemType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetIds")
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''Specifies the IDs of the subnets that the file system will be accessible from.

        For Windows and ONTAP ``MULTI_AZ_1`` deployment types,provide exactly two subnet IDs, one for the preferred file server and one for the standby file server. You specify one of these subnets as the preferred subnet using the ``WindowsConfiguration > PreferredSubnetID`` or ``OntapConfiguration > PreferredSubnetID`` properties. For more information about Multi-AZ file system configuration, see `Availability and durability: Single-AZ and Multi-AZ file systems <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/high-availability-multiAZ.html>`_ in the *Amazon FSx for Windows User Guide* and `Availability and durability <https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/high-availability-multiAZ.html>`_ in the *Amazon FSx for ONTAP User Guide* .

        For Windows ``SINGLE_AZ_1`` and ``SINGLE_AZ_2`` and all Lustre deployment types, provide exactly one subnet ID. The file server is launched in that subnet's Availability Zone.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-subnetids
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "subnetIds"))

    @subnet_ids.setter
    def subnet_ids(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "subnetIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupId")
    def backup_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the source backup.

        Specifies the backup that you are copying.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-backupid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "backupId"))

    @backup_id.setter
    def backup_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "backupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fileSystemTypeVersion")
    def file_system_type_version(self) -> typing.Optional[builtins.str]:
        '''(Optional) For FSx for Lustre file systems, sets the Lustre version for the file system that you're creating.

        Valid values are ``2.10`` and ``2.12`` :

        - 2.10 is supported by the Scratch and Persistent_1 Lustre deployment types.
        - 2.12 is supported by all Lustre deployment types. ``2.12`` is required when setting FSx for Lustre ``DeploymentType`` to ``PERSISTENT_2`` .

        Default value = ``2.10`` , except when ``DeploymentType`` is set to ``PERSISTENT_2`` , then the default is ``2.12`` .
        .. epigraph::

           If you set ``FileSystemTypeVersion`` to ``2.10`` for a ``PERSISTENT_2`` Lustre deployment type, the ``CreateFileSystem`` operation fails.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-filesystemtypeversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "fileSystemTypeVersion"))

    @file_system_type_version.setter
    def file_system_type_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "fileSystemTypeVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the AWS Key Management Service ( AWS KMS ) key used to encrypt the file system's data for Amazon FSx for Windows File Server file systems, Amazon FSx for NetApp ONTAP file systems, and ``PERSISTENT`` Amazon FSx for Lustre file systems at rest.

        If this ID isn't specified, the Amazon FSx-managed key for your account is used. The scratch Amazon FSx for Lustre file systems are always encrypted at rest using the Amazon FSx-managed key for your account. For more information, see `Encrypt <https://docs.aws.amazon.com//kms/latest/APIReference/API_Encrypt.html>`_ in the *AWS Key Management Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lustreConfiguration")
    def lustre_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnFileSystem.LustreConfigurationProperty", _IResolvable_da3f097b]]:
        '''The Lustre configuration for the file system being created.

        .. epigraph::

           The following parameters are not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.

           - ``AutoImportPolicy``
           - ``ExportPath``
           - ``ImportedChunkSize``
           - ``ImportPath``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-lustreconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFileSystem.LustreConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "lustreConfiguration"))

    @lustre_configuration.setter
    def lustre_configuration(
        self,
        value: typing.Optional[typing.Union["CfnFileSystem.LustreConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "lustreConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ontapConfiguration")
    def ontap_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnFileSystem.OntapConfigurationProperty", _IResolvable_da3f097b]]:
        '''The ONTAP configuration properties of the FSx for ONTAP file system that you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-ontapconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFileSystem.OntapConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "ontapConfiguration"))

    @ontap_configuration.setter
    def ontap_configuration(
        self,
        value: typing.Optional[typing.Union["CfnFileSystem.OntapConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ontapConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openZfsConfiguration")
    def open_zfs_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnFileSystem.OpenZFSConfigurationProperty", _IResolvable_da3f097b]]:
        '''The OpenZFS configuration properties for the file system that you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-openzfsconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFileSystem.OpenZFSConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "openZfsConfiguration"))

    @open_zfs_configuration.setter
    def open_zfs_configuration(
        self,
        value: typing.Optional[typing.Union["CfnFileSystem.OpenZFSConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "openZfsConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroupIds")
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of IDs specifying the security groups to apply to all network interfaces created for file system access.

        This list isn't returned in later requests to describe the file system.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-securitygroupids
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "securityGroupIds"))

    @security_group_ids.setter
    def security_group_ids(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "securityGroupIds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="storageCapacity")
    def storage_capacity(self) -> typing.Optional[jsii.Number]:
        '''Sets the storage capacity of the file system that you're creating.

        ``StorageCapacity`` is required if you are creating a new file system. Do not include ``StorageCapacity`` if you are creating a file system from a backup.

        For Lustre file systems:

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-storagecapacity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "storageCapacity"))

    @storage_capacity.setter
    def storage_capacity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "storageCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="storageType")
    def storage_type(self) -> typing.Optional[builtins.str]:
        '''Sets the storage type for the file system that you're creating. Valid values are ``SSD`` and ``HDD`` .

        - Set to ``SSD`` to use solid state drive storage. SSD is supported on all Windows, Lustre, ONTAP, and OpenZFS deployment types.
        - Set to ``HDD`` to use hard disk drive storage. HDD is supported on ``SINGLE_AZ_2`` and ``MULTI_AZ_1`` Windows file system deployment types, and on ``PERSISTENT`` Lustre file system deployment types.

        Default value is ``SSD`` . For more information, see `Storage type options <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/optimize-fsx-costs.html#storage-type-options>`_ in the *FSx for Windows File Server User Guide* and `Multiple storage options <https://docs.aws.amazon.com/fsx/latest/LustreGuide/what-is.html#storage-options>`_ in the *FSx for Lustre User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-storagetype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "storageType"))

    @storage_type.setter
    def storage_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "storageType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="windowsConfiguration")
    def windows_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnFileSystem.WindowsConfigurationProperty", _IResolvable_da3f097b]]:
        '''The configuration object for the Microsoft Windows file system you are creating.

        This value is required if ``FileSystemType`` is set to ``WINDOWS`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-windowsconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnFileSystem.WindowsConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "windowsConfiguration"))

    @windows_configuration.setter
    def windows_configuration(
        self,
        value: typing.Optional[typing.Union["CfnFileSystem.WindowsConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "windowsConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.AuditLogConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "file_access_audit_log_level": "fileAccessAuditLogLevel",
            "file_share_access_audit_log_level": "fileShareAccessAuditLogLevel",
            "audit_log_destination": "auditLogDestination",
        },
    )
    class AuditLogConfigurationProperty:
        def __init__(
            self,
            *,
            file_access_audit_log_level: builtins.str,
            file_share_access_audit_log_level: builtins.str,
            audit_log_destination: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration that Amazon FSx for Windows File Server uses to audit and log user accesses of files, folders, and file shares on the Amazon FSx for Windows File Server file system.

            :param file_access_audit_log_level: Sets which attempt type is logged by Amazon FSx for file and folder accesses. - ``SUCCESS_ONLY`` - only successful attempts to access files or folders are logged. - ``FAILURE_ONLY`` - only failed attempts to access files or folders are logged. - ``SUCCESS_AND_FAILURE`` - both successful attempts and failed attempts to access files or folders are logged. - ``DISABLED`` - access auditing of files and folders is turned off.
            :param file_share_access_audit_log_level: Sets which attempt type is logged by Amazon FSx for file share accesses. - ``SUCCESS_ONLY`` - only successful attempts to access file shares are logged. - ``FAILURE_ONLY`` - only failed attempts to access file shares are logged. - ``SUCCESS_AND_FAILURE`` - both successful attempts and failed attempts to access file shares are logged. - ``DISABLED`` - access auditing of file shares is turned off.
            :param audit_log_destination: The Amazon Resource Name (ARN) for the destination of the audit logs. The destination can be any Amazon CloudWatch Logs log group ARN or Amazon Kinesis Data Firehose delivery stream ARN. The name of the Amazon CloudWatch Logs log group must begin with the ``/aws/fsx`` prefix. The name of the Amazon Kinesis Data Firehouse delivery stream must begin with the ``aws-fsx`` prefix. The destination ARN (either CloudWatch Logs log group or Kinesis Data Firehose delivery stream) must be in the same AWS partition, AWS Region , and AWS account as your Amazon FSx file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-auditlogconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                audit_log_configuration_property = fsx.CfnFileSystem.AuditLogConfigurationProperty(
                    file_access_audit_log_level="fileAccessAuditLogLevel",
                    file_share_access_audit_log_level="fileShareAccessAuditLogLevel",
                
                    # the properties below are optional
                    audit_log_destination="auditLogDestination"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "file_access_audit_log_level": file_access_audit_log_level,
                "file_share_access_audit_log_level": file_share_access_audit_log_level,
            }
            if audit_log_destination is not None:
                self._values["audit_log_destination"] = audit_log_destination

        @builtins.property
        def file_access_audit_log_level(self) -> builtins.str:
            '''Sets which attempt type is logged by Amazon FSx for file and folder accesses.

            - ``SUCCESS_ONLY`` - only successful attempts to access files or folders are logged.
            - ``FAILURE_ONLY`` - only failed attempts to access files or folders are logged.
            - ``SUCCESS_AND_FAILURE`` - both successful attempts and failed attempts to access files or folders are logged.
            - ``DISABLED`` - access auditing of files and folders is turned off.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-auditlogconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-auditlogconfiguration-fileaccessauditloglevel
            '''
            result = self._values.get("file_access_audit_log_level")
            assert result is not None, "Required property 'file_access_audit_log_level' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def file_share_access_audit_log_level(self) -> builtins.str:
            '''Sets which attempt type is logged by Amazon FSx for file share accesses.

            - ``SUCCESS_ONLY`` - only successful attempts to access file shares are logged.
            - ``FAILURE_ONLY`` - only failed attempts to access file shares are logged.
            - ``SUCCESS_AND_FAILURE`` - both successful attempts and failed attempts to access file shares are logged.
            - ``DISABLED`` - access auditing of file shares is turned off.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-auditlogconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-auditlogconfiguration-fileshareaccessauditloglevel
            '''
            result = self._values.get("file_share_access_audit_log_level")
            assert result is not None, "Required property 'file_share_access_audit_log_level' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def audit_log_destination(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) for the destination of the audit logs.

            The destination can be any Amazon CloudWatch Logs log group ARN or Amazon Kinesis Data Firehose delivery stream ARN.

            The name of the Amazon CloudWatch Logs log group must begin with the ``/aws/fsx`` prefix. The name of the Amazon Kinesis Data Firehouse delivery stream must begin with the ``aws-fsx`` prefix.

            The destination ARN (either CloudWatch Logs log group or Kinesis Data Firehose delivery stream) must be in the same AWS partition, AWS Region , and AWS account as your Amazon FSx file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-auditlogconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-auditlogconfiguration-auditlogdestination
            '''
            result = self._values.get("audit_log_destination")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuditLogConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.ClientConfigurationsProperty",
        jsii_struct_bases=[],
        name_mapping={"clients": "clients", "options": "options"},
    )
    class ClientConfigurationsProperty:
        def __init__(
            self,
            *,
            clients: typing.Optional[builtins.str] = None,
            options: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Specifies who can mount the file system and the options that can be used while mounting the file system.

            :param clients: A value that specifies who can mount the file system. You can provide a wildcard character ( ``*`` ), an IP address ( ``0.0.0.0`` ), or a CIDR address ( ``192.0.2.0/24`` . By default, Amazon FSx uses the wildcard character when specifying the client.
            :param options: The options to use when mounting the file system. For a list of options that you can use with Network File System (NFS), see the `exports(5) - Linux man page <https://docs.aws.amazon.com/https://linux.die.net/man/5/exports>`_ . When choosing your options, consider the following: - ``crossmount`` is used by default. If you don't specify ``crossmount`` when changing the client configuration, you won't be able to see or access snapshots in your file system's snapshot directory. - ``sync`` is used by default. If you instead specify ``async`` , the system acknowledges writes before writing to disk. If the system crashes before the writes are finished, you lose the unwritten data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports-clientconfigurations.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                client_configurations_property = fsx.CfnFileSystem.ClientConfigurationsProperty(
                    clients="clients",
                    options=["options"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if clients is not None:
                self._values["clients"] = clients
            if options is not None:
                self._values["options"] = options

        @builtins.property
        def clients(self) -> typing.Optional[builtins.str]:
            '''A value that specifies who can mount the file system.

            You can provide a wildcard character ( ``*`` ), an IP address ( ``0.0.0.0`` ), or a CIDR address ( ``192.0.2.0/24`` . By default, Amazon FSx uses the wildcard character when specifying the client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports-clientconfigurations.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports-clientconfigurations-clients
            '''
            result = self._values.get("clients")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def options(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The options to use when mounting the file system.

            For a list of options that you can use with Network File System (NFS), see the `exports(5) - Linux man page <https://docs.aws.amazon.com/https://linux.die.net/man/5/exports>`_ . When choosing your options, consider the following:

            - ``crossmount`` is used by default. If you don't specify ``crossmount`` when changing the client configuration, you won't be able to see or access snapshots in your file system's snapshot directory.
            - ``sync`` is used by default. If you instead specify ``async`` , the system acknowledges writes before writing to disk. If the system crashes before the writes are finished, you lose the unwritten data.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports-clientconfigurations.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports-clientconfigurations-options
            '''
            result = self._values.get("options")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ClientConfigurationsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.DiskIopsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"iops": "iops", "mode": "mode"},
    )
    class DiskIopsConfigurationProperty:
        def __init__(
            self,
            *,
            iops: typing.Optional[jsii.Number] = None,
            mode: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The SSD IOPS (input/output operations per second) configuration for an Amazon FSx for NetApp ONTAP or Amazon FSx for OpenZFS file system.

            The default is 3 IOPS per GB of storage capacity, but you can provision additional IOPS per GB of storage. The configuration consists of the total number of provisioned SSD IOPS and how the amount was provisioned (by the customer or by the system).

            :param iops: The total number of SSD IOPS provisioned for the file system.
            :param mode: Specifies whether the number of IOPS for the file system is using the system default ( ``AUTOMATIC`` ) or was provisioned by the customer ( ``USER_PROVISIONED`` ).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-diskiopsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                disk_iops_configuration_property = fsx.CfnFileSystem.DiskIopsConfigurationProperty(
                    iops=123,
                    mode="mode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if iops is not None:
                self._values["iops"] = iops
            if mode is not None:
                self._values["mode"] = mode

        @builtins.property
        def iops(self) -> typing.Optional[jsii.Number]:
            '''The total number of SSD IOPS provisioned for the file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-diskiopsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-diskiopsconfiguration-iops
            '''
            result = self._values.get("iops")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def mode(self) -> typing.Optional[builtins.str]:
            '''Specifies whether the number of IOPS for the file system is using the system default ( ``AUTOMATIC`` ) or was provisioned by the customer ( ``USER_PROVISIONED`` ).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-diskiopsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-diskiopsconfiguration-mode
            '''
            result = self._values.get("mode")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DiskIopsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.LustreConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "auto_import_policy": "autoImportPolicy",
            "automatic_backup_retention_days": "automaticBackupRetentionDays",
            "copy_tags_to_backups": "copyTagsToBackups",
            "daily_automatic_backup_start_time": "dailyAutomaticBackupStartTime",
            "data_compression_type": "dataCompressionType",
            "deployment_type": "deploymentType",
            "drive_cache_type": "driveCacheType",
            "export_path": "exportPath",
            "imported_file_chunk_size": "importedFileChunkSize",
            "import_path": "importPath",
            "per_unit_storage_throughput": "perUnitStorageThroughput",
            "weekly_maintenance_start_time": "weeklyMaintenanceStartTime",
        },
    )
    class LustreConfigurationProperty:
        def __init__(
            self,
            *,
            auto_import_policy: typing.Optional[builtins.str] = None,
            automatic_backup_retention_days: typing.Optional[jsii.Number] = None,
            copy_tags_to_backups: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            daily_automatic_backup_start_time: typing.Optional[builtins.str] = None,
            data_compression_type: typing.Optional[builtins.str] = None,
            deployment_type: typing.Optional[builtins.str] = None,
            drive_cache_type: typing.Optional[builtins.str] = None,
            export_path: typing.Optional[builtins.str] = None,
            imported_file_chunk_size: typing.Optional[jsii.Number] = None,
            import_path: typing.Optional[builtins.str] = None,
            per_unit_storage_throughput: typing.Optional[jsii.Number] = None,
            weekly_maintenance_start_time: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration for the Amazon FSx for Lustre file system.

            :param auto_import_policy: (Optional) Available with ``Scratch`` and ``Persistent_1`` deployment types. When you create your file system, your existing S3 objects appear as file and directory listings. Use this property to choose how Amazon FSx keeps your file and directory listings up to date as you add or modify objects in your linked S3 bucket. ``AutoImportPolicy`` can have the following values: - ``NONE`` - (Default) AutoImport is off. Amazon FSx only updates file and directory listings from the linked S3 bucket when the file system is created. FSx does not update file and directory listings for any new or changed objects after choosing this option. - ``NEW`` - AutoImport is on. Amazon FSx automatically imports directory listings of any new objects added to the linked S3 bucket that do not currently exist in the FSx file system. - ``NEW_CHANGED`` - AutoImport is on. Amazon FSx automatically imports file and directory listings of any new objects added to the S3 bucket and any existing objects that are changed in the S3 bucket after you choose this option. - ``NEW_CHANGED_DELETED`` - AutoImport is on. Amazon FSx automatically imports file and directory listings of any new objects added to the S3 bucket, any existing objects that are changed in the S3 bucket, and any objects that were deleted in the S3 bucket. For more information, see `Automatically import updates from your S3 bucket <https://docs.aws.amazon.com/fsx/latest/LustreGuide/autoimport-data-repo.html>`_ . .. epigraph:: This parameter is not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.
            :param automatic_backup_retention_days: The number of days to retain automatic backups. Setting this to 0 disables automatic backups. You can retain automatic backups for a maximum of 90 days. The default is 0. Only valid for use with ``PERSISTENT_1`` deployment types. For more information, see `Working with backups <https://docs.aws.amazon.com/fsx/latest/LustreGuide/using-backups-fsx.html>`_ in the *Amazon FSx for Lustre User Guide* . (Default = 0)
            :param copy_tags_to_backups: A Boolean flag indicating whether tags for the file system should be copied to backups. This value defaults to false. If it's set to true, all tags for the file system are copied to all automatic and user-initiated backups where the user doesn't specify tags. If this value is true, and you specify one or more tags, only the specified tags are copied to backups. If you specify one or more tags when creating a user-initiated backup, no tags are copied from the file system, regardless of this value. Only valid for use with ``PERSISTENT_1`` deployment types.
            :param daily_automatic_backup_start_time: A recurring daily time, in the format ``HH:MM`` . ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour. For example, ``05:00`` specifies 5 AM daily. Only valid for use with ``PERSISTENT_1`` deployment types.
            :param data_compression_type: Sets the data compression configuration for the file system. ``DataCompressionType`` can have the following values:. - ``NONE`` - (Default) Data compression is turned off when the file system is created. - ``LZ4`` - Data compression is turned on with the LZ4 algorithm. For more information, see `Lustre data compression <https://docs.aws.amazon.com/fsx/latest/LustreGuide/data-compression.html>`_ in the *Amazon FSx for Lustre User Guide* .
            :param deployment_type: (Optional) Choose ``SCRATCH_1`` and ``SCRATCH_2`` deployment types when you need temporary storage and shorter-term processing of data. The ``SCRATCH_2`` deployment type provides in-transit encryption of data and higher burst throughput capacity than ``SCRATCH_1`` . Choose ``PERSISTENT_1`` for longer-term storage and for throughput-focused workloads that aren’t latency-sensitive. ``PERSISTENT_1`` supports encryption of data in transit, and is available in all AWS Regions in which FSx for Lustre is available. Choose ``PERSISTENT_2`` for longer-term storage and for latency-sensitive workloads that require the highest levels of IOPS/throughput. ``PERSISTENT_2`` supports SSD storage, and offers higher ``PerUnitStorageThroughput`` (up to 1000 MB/s/TiB). ``PERSISTENT_2`` is available in a limited number of AWS Regions . For more information, and an up-to-date list of AWS Regions in which ``PERSISTENT_2`` is available, see `File system deployment options for FSx for Lustre <https://docs.aws.amazon.com/fsx/latest/LustreGuide/using-fsx-lustre.html#lustre-deployment-types>`_ in the *Amazon FSx for Lustre User Guide* . .. epigraph:: If you choose ``PERSISTENT_2`` , and you set ``FileSystemTypeVersion`` to ``2.10`` , the ``CreateFileSystem`` operation fails. Encryption of data in transit is automatically turned on when you access ``SCRATCH_2`` , ``PERSISTENT_1`` and ``PERSISTENT_2`` file systems from Amazon EC2 instances that [support automatic encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/data- protection.html) in the AWS Regions where they are available. For more information about encryption in transit for FSx for Lustre file systems, see `Encrypting data in transit <https://docs.aws.amazon.com/fsx/latest/LustreGuide/encryption-in-transit-fsxl.html>`_ in the *Amazon FSx for Lustre User Guide* . (Default = ``SCRATCH_1`` )
            :param drive_cache_type: The type of drive cache used by ``PERSISTENT_1`` file systems that are provisioned with HDD storage devices. This parameter is required when storage type is HDD. Set this property to ``READ`` to improve the performance for frequently accessed files by caching up to 20% of the total storage capacity of the file system. This parameter is required when ``StorageType`` is set to ``HDD`` .
            :param export_path: (Optional) Available with ``Scratch`` and ``Persistent_1`` deployment types. Specifies the path in the Amazon S3 bucket where the root of your Amazon FSx file system is exported. The path must use the same Amazon S3 bucket as specified in ImportPath. You can provide an optional prefix to which new and changed data is to be exported from your Amazon FSx for Lustre file system. If an ``ExportPath`` value is not provided, Amazon FSx sets a default export path, ``s3://import-bucket/FSxLustre[creation-timestamp]`` . The timestamp is in UTC format, for example ``s3://import-bucket/FSxLustre20181105T222312Z`` . The Amazon S3 export bucket must be the same as the import bucket specified by ``ImportPath`` . If you specify only a bucket name, such as ``s3://import-bucket`` , you get a 1:1 mapping of file system objects to S3 bucket objects. This mapping means that the input data in S3 is overwritten on export. If you provide a custom prefix in the export path, such as ``s3://import-bucket/[custom-optional-prefix]`` , Amazon FSx exports the contents of your file system to that export prefix in the Amazon S3 bucket. .. epigraph:: This parameter is not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.
            :param imported_file_chunk_size: (Optional) For files imported from a data repository, this value determines the stripe count and maximum amount of data per file (in MiB) stored on a single physical disk. The maximum number of disks that a single file can be striped across is limited by the total number of disks that make up the file system. The default chunk size is 1,024 MiB (1 GiB) and can go as high as 512,000 MiB (500 GiB). Amazon S3 objects have a maximum size of 5 TB. This parameter is not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.
            :param import_path: (Optional) The path to the Amazon S3 bucket (including the optional prefix) that you're using as the data repository for your Amazon FSx for Lustre file system. The root of your FSx for Lustre file system will be mapped to the root of the Amazon S3 bucket you select. An example is ``s3://import-bucket/optional-prefix`` . If you specify a prefix after the Amazon S3 bucket name, only object keys with that prefix are loaded into the file system. This parameter is not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.
            :param per_unit_storage_throughput: Required with ``PERSISTENT_1`` and ``PERSISTENT_2`` deployment types, provisions the amount of read and write throughput for each 1 tebibyte (TiB) of file system storage capacity, in MB/s/TiB. File system throughput capacity is calculated by multiplying ﬁle system storage capacity (TiB) by the ``PerUnitStorageThroughput`` (MB/s/TiB). For a 2.4-TiB ﬁle system, provisioning 50 MB/s/TiB of ``PerUnitStorageThroughput`` yields 120 MB/s of ﬁle system throughput. You pay for the amount of throughput that you provision. Valid values: - For ``PERSISTENT_1`` SSD storage: 50, 100, 200 MB/s/TiB. - For ``PERSISTENT_1`` HDD storage: 12, 40 MB/s/TiB. - For ``PERSISTENT_2`` SSD storage: 125, 250, 500, 1000 MB/s/TiB.
            :param weekly_maintenance_start_time: (Optional) The preferred start time to perform weekly maintenance, formatted d:HH:MM in the UTC time zone, where d is the weekday number, from 1 through 7, beginning with Monday and ending with Sunday.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                lustre_configuration_property = fsx.CfnFileSystem.LustreConfigurationProperty(
                    auto_import_policy="autoImportPolicy",
                    automatic_backup_retention_days=123,
                    copy_tags_to_backups=False,
                    daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                    data_compression_type="dataCompressionType",
                    deployment_type="deploymentType",
                    drive_cache_type="driveCacheType",
                    export_path="exportPath",
                    imported_file_chunk_size=123,
                    import_path="importPath",
                    per_unit_storage_throughput=123,
                    weekly_maintenance_start_time="weeklyMaintenanceStartTime"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if auto_import_policy is not None:
                self._values["auto_import_policy"] = auto_import_policy
            if automatic_backup_retention_days is not None:
                self._values["automatic_backup_retention_days"] = automatic_backup_retention_days
            if copy_tags_to_backups is not None:
                self._values["copy_tags_to_backups"] = copy_tags_to_backups
            if daily_automatic_backup_start_time is not None:
                self._values["daily_automatic_backup_start_time"] = daily_automatic_backup_start_time
            if data_compression_type is not None:
                self._values["data_compression_type"] = data_compression_type
            if deployment_type is not None:
                self._values["deployment_type"] = deployment_type
            if drive_cache_type is not None:
                self._values["drive_cache_type"] = drive_cache_type
            if export_path is not None:
                self._values["export_path"] = export_path
            if imported_file_chunk_size is not None:
                self._values["imported_file_chunk_size"] = imported_file_chunk_size
            if import_path is not None:
                self._values["import_path"] = import_path
            if per_unit_storage_throughput is not None:
                self._values["per_unit_storage_throughput"] = per_unit_storage_throughput
            if weekly_maintenance_start_time is not None:
                self._values["weekly_maintenance_start_time"] = weekly_maintenance_start_time

        @builtins.property
        def auto_import_policy(self) -> typing.Optional[builtins.str]:
            '''(Optional) Available with ``Scratch`` and ``Persistent_1`` deployment types.

            When you create your file system, your existing S3 objects appear as file and directory listings. Use this property to choose how Amazon FSx keeps your file and directory listings up to date as you add or modify objects in your linked S3 bucket. ``AutoImportPolicy`` can have the following values:

            - ``NONE`` - (Default) AutoImport is off. Amazon FSx only updates file and directory listings from the linked S3 bucket when the file system is created. FSx does not update file and directory listings for any new or changed objects after choosing this option.
            - ``NEW`` - AutoImport is on. Amazon FSx automatically imports directory listings of any new objects added to the linked S3 bucket that do not currently exist in the FSx file system.
            - ``NEW_CHANGED`` - AutoImport is on. Amazon FSx automatically imports file and directory listings of any new objects added to the S3 bucket and any existing objects that are changed in the S3 bucket after you choose this option.
            - ``NEW_CHANGED_DELETED`` - AutoImport is on. Amazon FSx automatically imports file and directory listings of any new objects added to the S3 bucket, any existing objects that are changed in the S3 bucket, and any objects that were deleted in the S3 bucket.

            For more information, see `Automatically import updates from your S3 bucket <https://docs.aws.amazon.com/fsx/latest/LustreGuide/autoimport-data-repo.html>`_ .
            .. epigraph::

               This parameter is not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-autoimportpolicy
            '''
            result = self._values.get("auto_import_policy")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def automatic_backup_retention_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days to retain automatic backups.

            Setting this to 0 disables automatic backups. You can retain automatic backups for a maximum of 90 days. The default is 0. Only valid for use with ``PERSISTENT_1`` deployment types. For more information, see `Working with backups <https://docs.aws.amazon.com/fsx/latest/LustreGuide/using-backups-fsx.html>`_ in the *Amazon FSx for Lustre User Guide* . (Default = 0)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-automaticbackupretentiondays
            '''
            result = self._values.get("automatic_backup_retention_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def copy_tags_to_backups(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A Boolean flag indicating whether tags for the file system should be copied to backups.

            This value defaults to false. If it's set to true, all tags for the file system are copied to all automatic and user-initiated backups where the user doesn't specify tags. If this value is true, and you specify one or more tags, only the specified tags are copied to backups. If you specify one or more tags when creating a user-initiated backup, no tags are copied from the file system, regardless of this value. Only valid for use with ``PERSISTENT_1`` deployment types.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-copytagstobackups
            '''
            result = self._values.get("copy_tags_to_backups")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def daily_automatic_backup_start_time(self) -> typing.Optional[builtins.str]:
            '''A recurring daily time, in the format ``HH:MM`` .

            ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour. For example, ``05:00`` specifies 5 AM daily. Only valid for use with ``PERSISTENT_1`` deployment types.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-dailyautomaticbackupstarttime
            '''
            result = self._values.get("daily_automatic_backup_start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def data_compression_type(self) -> typing.Optional[builtins.str]:
            '''Sets the data compression configuration for the file system. ``DataCompressionType`` can have the following values:.

            - ``NONE`` - (Default) Data compression is turned off when the file system is created.
            - ``LZ4`` - Data compression is turned on with the LZ4 algorithm.

            For more information, see `Lustre data compression <https://docs.aws.amazon.com/fsx/latest/LustreGuide/data-compression.html>`_ in the *Amazon FSx for Lustre User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-datacompressiontype
            '''
            result = self._values.get("data_compression_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def deployment_type(self) -> typing.Optional[builtins.str]:
            '''(Optional) Choose ``SCRATCH_1`` and ``SCRATCH_2`` deployment types when you need temporary storage and shorter-term processing of data.

            The ``SCRATCH_2`` deployment type provides in-transit encryption of data and higher burst throughput capacity than ``SCRATCH_1`` .

            Choose ``PERSISTENT_1`` for longer-term storage and for throughput-focused workloads that aren’t latency-sensitive. ``PERSISTENT_1`` supports encryption of data in transit, and is available in all AWS Regions in which FSx for Lustre is available.

            Choose ``PERSISTENT_2`` for longer-term storage and for latency-sensitive workloads that require the highest levels of IOPS/throughput. ``PERSISTENT_2`` supports SSD storage, and offers higher ``PerUnitStorageThroughput`` (up to 1000 MB/s/TiB). ``PERSISTENT_2`` is available in a limited number of AWS Regions . For more information, and an up-to-date list of AWS Regions in which ``PERSISTENT_2`` is available, see `File system deployment options for FSx for Lustre <https://docs.aws.amazon.com/fsx/latest/LustreGuide/using-fsx-lustre.html#lustre-deployment-types>`_ in the *Amazon FSx for Lustre User Guide* .
            .. epigraph::

               If you choose ``PERSISTENT_2`` , and you set ``FileSystemTypeVersion`` to ``2.10`` , the ``CreateFileSystem`` operation fails.

            Encryption of data in transit is automatically turned on when you access ``SCRATCH_2`` , ``PERSISTENT_1`` and ``PERSISTENT_2`` file systems from Amazon EC2 instances that [support automatic encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/data-                 protection.html) in the AWS Regions where they are available. For more information about encryption in transit for FSx for Lustre file systems, see `Encrypting data in transit <https://docs.aws.amazon.com/fsx/latest/LustreGuide/encryption-in-transit-fsxl.html>`_ in the *Amazon FSx for Lustre User Guide* .

            (Default = ``SCRATCH_1`` )

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-deploymenttype
            '''
            result = self._values.get("deployment_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def drive_cache_type(self) -> typing.Optional[builtins.str]:
            '''The type of drive cache used by ``PERSISTENT_1`` file systems that are provisioned with HDD storage devices.

            This parameter is required when storage type is HDD. Set this property to ``READ`` to improve the performance for frequently accessed files by caching up to 20% of the total storage capacity of the file system.

            This parameter is required when ``StorageType`` is set to ``HDD`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-drivecachetype
            '''
            result = self._values.get("drive_cache_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def export_path(self) -> typing.Optional[builtins.str]:
            '''(Optional) Available with ``Scratch`` and ``Persistent_1`` deployment types.

            Specifies the path in the Amazon S3 bucket where the root of your Amazon FSx file system is exported. The path must use the same Amazon S3 bucket as specified in ImportPath. You can provide an optional prefix to which new and changed data is to be exported from your Amazon FSx for Lustre file system. If an ``ExportPath`` value is not provided, Amazon FSx sets a default export path, ``s3://import-bucket/FSxLustre[creation-timestamp]`` . The timestamp is in UTC format, for example ``s3://import-bucket/FSxLustre20181105T222312Z`` .

            The Amazon S3 export bucket must be the same as the import bucket specified by ``ImportPath`` . If you specify only a bucket name, such as ``s3://import-bucket`` , you get a 1:1 mapping of file system objects to S3 bucket objects. This mapping means that the input data in S3 is overwritten on export. If you provide a custom prefix in the export path, such as ``s3://import-bucket/[custom-optional-prefix]`` , Amazon FSx exports the contents of your file system to that export prefix in the Amazon S3 bucket.
            .. epigraph::

               This parameter is not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-exportpath
            '''
            result = self._values.get("export_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def imported_file_chunk_size(self) -> typing.Optional[jsii.Number]:
            '''(Optional) For files imported from a data repository, this value determines the stripe count and maximum amount of data per file (in MiB) stored on a single physical disk.

            The maximum number of disks that a single file can be striped across is limited by the total number of disks that make up the file system.

            The default chunk size is 1,024 MiB (1 GiB) and can go as high as 512,000 MiB (500 GiB). Amazon S3 objects have a maximum size of 5 TB.

            This parameter is not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-importedfilechunksize
            '''
            result = self._values.get("imported_file_chunk_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def import_path(self) -> typing.Optional[builtins.str]:
            '''(Optional) The path to the Amazon S3 bucket (including the optional prefix) that you're using as the data repository for your Amazon FSx for Lustre file system.

            The root of your FSx for Lustre file system will be mapped to the root of the Amazon S3 bucket you select. An example is ``s3://import-bucket/optional-prefix`` . If you specify a prefix after the Amazon S3 bucket name, only object keys with that prefix are loaded into the file system.

            This parameter is not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-importpath
            '''
            result = self._values.get("import_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def per_unit_storage_throughput(self) -> typing.Optional[jsii.Number]:
            '''Required with ``PERSISTENT_1`` and ``PERSISTENT_2`` deployment types, provisions the amount of read and write throughput for each 1 tebibyte (TiB) of file system storage capacity, in MB/s/TiB.

            File system throughput capacity is calculated by multiplying ﬁle system storage capacity (TiB) by the ``PerUnitStorageThroughput`` (MB/s/TiB). For a 2.4-TiB ﬁle system, provisioning 50 MB/s/TiB of ``PerUnitStorageThroughput`` yields 120 MB/s of ﬁle system throughput. You pay for the amount of throughput that you provision.

            Valid values:

            - For ``PERSISTENT_1`` SSD storage: 50, 100, 200 MB/s/TiB.
            - For ``PERSISTENT_1`` HDD storage: 12, 40 MB/s/TiB.
            - For ``PERSISTENT_2`` SSD storage: 125, 250, 500, 1000 MB/s/TiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-perunitstoragethroughput
            '''
            result = self._values.get("per_unit_storage_throughput")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def weekly_maintenance_start_time(self) -> typing.Optional[builtins.str]:
            '''(Optional) The preferred start time to perform weekly maintenance, formatted d:HH:MM in the UTC time zone, where d is the weekday number, from 1 through 7, beginning with Monday and ending with Sunday.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html#cfn-fsx-filesystem-lustreconfiguration-weeklymaintenancestarttime
            '''
            result = self._values.get("weekly_maintenance_start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LustreConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.NfsExportsProperty",
        jsii_struct_bases=[],
        name_mapping={"client_configurations": "clientConfigurations"},
    )
    class NfsExportsProperty:
        def __init__(
            self,
            *,
            client_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFileSystem.ClientConfigurationsProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The configuration object for mounting a file system.

            :param client_configurations: A list of configuration objects that contain the client and options for mounting the OpenZFS file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                nfs_exports_property = fsx.CfnFileSystem.NfsExportsProperty(
                    client_configurations=[fsx.CfnFileSystem.ClientConfigurationsProperty(
                        clients="clients",
                        options=["options"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if client_configurations is not None:
                self._values["client_configurations"] = client_configurations

        @builtins.property
        def client_configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFileSystem.ClientConfigurationsProperty", _IResolvable_da3f097b]]]]:
            '''A list of configuration objects that contain the client and options for mounting the OpenZFS file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports-clientconfigurations
            '''
            result = self._values.get("client_configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFileSystem.ClientConfigurationsProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NfsExportsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.OntapConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "deployment_type": "deploymentType",
            "automatic_backup_retention_days": "automaticBackupRetentionDays",
            "daily_automatic_backup_start_time": "dailyAutomaticBackupStartTime",
            "disk_iops_configuration": "diskIopsConfiguration",
            "endpoint_ip_address_range": "endpointIpAddressRange",
            "fsx_admin_password": "fsxAdminPassword",
            "preferred_subnet_id": "preferredSubnetId",
            "route_table_ids": "routeTableIds",
            "throughput_capacity": "throughputCapacity",
            "weekly_maintenance_start_time": "weeklyMaintenanceStartTime",
        },
    )
    class OntapConfigurationProperty:
        def __init__(
            self,
            *,
            deployment_type: builtins.str,
            automatic_backup_retention_days: typing.Optional[jsii.Number] = None,
            daily_automatic_backup_start_time: typing.Optional[builtins.str] = None,
            disk_iops_configuration: typing.Optional[typing.Union["CfnFileSystem.DiskIopsConfigurationProperty", _IResolvable_da3f097b]] = None,
            endpoint_ip_address_range: typing.Optional[builtins.str] = None,
            fsx_admin_password: typing.Optional[builtins.str] = None,
            preferred_subnet_id: typing.Optional[builtins.str] = None,
            route_table_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            throughput_capacity: typing.Optional[jsii.Number] = None,
            weekly_maintenance_start_time: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration for this FSx for ONTAP file system.

            :param deployment_type: Specifies the FSx for ONTAP file system deployment type to use in creating the file system. ``MULTI_AZ_1`` is the supported ONTAP deployment type.
            :param automatic_backup_retention_days: The number of days to retain automatic backups. Setting this property to ``0`` disables automatic backups. You can retain automatic backups for a maximum of 90 days. The default is ``0`` .
            :param daily_automatic_backup_start_time: A recurring daily time, in the format ``HH:MM`` . ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour. For example, ``05:00`` specifies 5 AM daily.
            :param disk_iops_configuration: The SSD IOPS configuration for the FSx for ONTAP file system.
            :param endpoint_ip_address_range: Specifies the IP address range in which the endpoints to access your file system will be created. By default, Amazon FSx selects an unused IP address range for you from the 198.19.* range.
            :param fsx_admin_password: The ONTAP administrative password for the ``fsxadmin`` user with which you administer your file system using the NetApp ONTAP CLI and REST API.
            :param preferred_subnet_id: Required when ``DeploymentType`` is set to ``MULTI_AZ_1`` . This specifies the subnet in which you want the preferred file server to be located.
            :param route_table_ids: Specifies the virtual private cloud (VPC) route tables in which your file system's endpoints will be created. You should specify all VPC route tables associated with the subnets in which your clients are located. By default, Amazon FSx selects your VPC's default route table.
            :param throughput_capacity: Sets the throughput capacity for the file system that you're creating. Valid values are 128, 256, 512, 1024, and 2048 MBps.
            :param weekly_maintenance_start_time: A recurring weekly time, in the format ``D:HH:MM`` . ``D`` is the day of the week, for which 1 represents Monday and 7 represents Sunday. For further details, see `the ISO-8601 spec as described on Wikipedia <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/ISO_week_date>`_ . ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour. For example, ``1:05:00`` specifies maintenance at 5 AM Monday.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                ontap_configuration_property = fsx.CfnFileSystem.OntapConfigurationProperty(
                    deployment_type="deploymentType",
                
                    # the properties below are optional
                    automatic_backup_retention_days=123,
                    daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                    disk_iops_configuration=fsx.CfnFileSystem.DiskIopsConfigurationProperty(
                        iops=123,
                        mode="mode"
                    ),
                    endpoint_ip_address_range="endpointIpAddressRange",
                    fsx_admin_password="fsxAdminPassword",
                    preferred_subnet_id="preferredSubnetId",
                    route_table_ids=["routeTableIds"],
                    throughput_capacity=123,
                    weekly_maintenance_start_time="weeklyMaintenanceStartTime"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "deployment_type": deployment_type,
            }
            if automatic_backup_retention_days is not None:
                self._values["automatic_backup_retention_days"] = automatic_backup_retention_days
            if daily_automatic_backup_start_time is not None:
                self._values["daily_automatic_backup_start_time"] = daily_automatic_backup_start_time
            if disk_iops_configuration is not None:
                self._values["disk_iops_configuration"] = disk_iops_configuration
            if endpoint_ip_address_range is not None:
                self._values["endpoint_ip_address_range"] = endpoint_ip_address_range
            if fsx_admin_password is not None:
                self._values["fsx_admin_password"] = fsx_admin_password
            if preferred_subnet_id is not None:
                self._values["preferred_subnet_id"] = preferred_subnet_id
            if route_table_ids is not None:
                self._values["route_table_ids"] = route_table_ids
            if throughput_capacity is not None:
                self._values["throughput_capacity"] = throughput_capacity
            if weekly_maintenance_start_time is not None:
                self._values["weekly_maintenance_start_time"] = weekly_maintenance_start_time

        @builtins.property
        def deployment_type(self) -> builtins.str:
            '''Specifies the FSx for ONTAP file system deployment type to use in creating the file system.

            ``MULTI_AZ_1`` is the supported ONTAP deployment type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-deploymenttype
            '''
            result = self._values.get("deployment_type")
            assert result is not None, "Required property 'deployment_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def automatic_backup_retention_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days to retain automatic backups.

            Setting this property to ``0`` disables automatic backups. You can retain automatic backups for a maximum of 90 days. The default is ``0`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-automaticbackupretentiondays
            '''
            result = self._values.get("automatic_backup_retention_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def daily_automatic_backup_start_time(self) -> typing.Optional[builtins.str]:
            '''A recurring daily time, in the format ``HH:MM`` .

            ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour. For example, ``05:00`` specifies 5 AM daily.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-dailyautomaticbackupstarttime
            '''
            result = self._values.get("daily_automatic_backup_start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def disk_iops_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnFileSystem.DiskIopsConfigurationProperty", _IResolvable_da3f097b]]:
            '''The SSD IOPS configuration for the FSx for ONTAP file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-diskiopsconfiguration
            '''
            result = self._values.get("disk_iops_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnFileSystem.DiskIopsConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def endpoint_ip_address_range(self) -> typing.Optional[builtins.str]:
            '''Specifies the IP address range in which the endpoints to access your file system will be created.

            By default, Amazon FSx selects an unused IP address range for you from the 198.19.* range.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-endpointipaddressrange
            '''
            result = self._values.get("endpoint_ip_address_range")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def fsx_admin_password(self) -> typing.Optional[builtins.str]:
            '''The ONTAP administrative password for the ``fsxadmin`` user with which you administer your file system using the NetApp ONTAP CLI and REST API.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-fsxadminpassword
            '''
            result = self._values.get("fsx_admin_password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def preferred_subnet_id(self) -> typing.Optional[builtins.str]:
            '''Required when ``DeploymentType`` is set to ``MULTI_AZ_1`` .

            This specifies the subnet in which you want the preferred file server to be located.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-preferredsubnetid
            '''
            result = self._values.get("preferred_subnet_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def route_table_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Specifies the virtual private cloud (VPC) route tables in which your file system's endpoints will be created.

            You should specify all VPC route tables associated with the subnets in which your clients are located. By default, Amazon FSx selects your VPC's default route table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-routetableids
            '''
            result = self._values.get("route_table_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def throughput_capacity(self) -> typing.Optional[jsii.Number]:
            '''Sets the throughput capacity for the file system that you're creating.

            Valid values are 128, 256, 512, 1024, and 2048 MBps.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-throughputcapacity
            '''
            result = self._values.get("throughput_capacity")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def weekly_maintenance_start_time(self) -> typing.Optional[builtins.str]:
            '''A recurring weekly time, in the format ``D:HH:MM`` .

            ``D`` is the day of the week, for which 1 represents Monday and 7 represents Sunday. For further details, see `the ISO-8601 spec as described on Wikipedia <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/ISO_week_date>`_ .

            ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour.

            For example, ``1:05:00`` specifies maintenance at 5 AM Monday.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-ontapconfiguration.html#cfn-fsx-filesystem-ontapconfiguration-weeklymaintenancestarttime
            '''
            result = self._values.get("weekly_maintenance_start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OntapConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.OpenZFSConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "deployment_type": "deploymentType",
            "automatic_backup_retention_days": "automaticBackupRetentionDays",
            "copy_tags_to_backups": "copyTagsToBackups",
            "copy_tags_to_volumes": "copyTagsToVolumes",
            "daily_automatic_backup_start_time": "dailyAutomaticBackupStartTime",
            "disk_iops_configuration": "diskIopsConfiguration",
            "root_volume_configuration": "rootVolumeConfiguration",
            "throughput_capacity": "throughputCapacity",
            "weekly_maintenance_start_time": "weeklyMaintenanceStartTime",
        },
    )
    class OpenZFSConfigurationProperty:
        def __init__(
            self,
            *,
            deployment_type: builtins.str,
            automatic_backup_retention_days: typing.Optional[jsii.Number] = None,
            copy_tags_to_backups: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            copy_tags_to_volumes: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            daily_automatic_backup_start_time: typing.Optional[builtins.str] = None,
            disk_iops_configuration: typing.Optional[typing.Union["CfnFileSystem.DiskIopsConfigurationProperty", _IResolvable_da3f097b]] = None,
            root_volume_configuration: typing.Optional[typing.Union["CfnFileSystem.RootVolumeConfigurationProperty", _IResolvable_da3f097b]] = None,
            throughput_capacity: typing.Optional[jsii.Number] = None,
            weekly_maintenance_start_time: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The OpenZFS configuration for the file system that's being created.

            :param deployment_type: Specifies the file system deployment type. Amazon FSx for OpenZFS supports ``SINGLE_AZ_1`` . ``SINGLE_AZ_1`` is a file system configured for a single Availability Zone (AZ) of redundancy.
            :param automatic_backup_retention_days: The number of days to retain automatic backups. Setting this property to ``0`` disables automatic backups. You can retain automatic backups for a maximum of 90 days. The default is ``0`` .
            :param copy_tags_to_backups: A Boolean value indicating whether tags for the file system should be copied to backups. This value defaults to ``false`` . If it's set to ``true`` , all tags for the file system are copied to all automatic and user-initiated backups where the user doesn't specify tags. If this value is ``true`` , and you specify one or more tags, only the specified tags are copied to backups. If you specify one or more tags when creating a user-initiated backup, no tags are copied from the file system, regardless of this value.
            :param copy_tags_to_volumes: A Boolean value indicating whether tags for the volume should be copied to snapshots. This value defaults to ``false`` . If it's set to ``true`` , all tags for the volume are copied to snapshots where the user doesn't specify tags. If this value is ``true`` , and you specify one or more tags, only the specified tags are copied to snapshots. If you specify one or more tags when creating the snapshot, no tags are copied from the volume, regardless of this value.
            :param daily_automatic_backup_start_time: A recurring daily time, in the format ``HH:MM`` . ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour. For example, ``05:00`` specifies 5 AM daily.
            :param disk_iops_configuration: The SSD IOPS (input/output operations per second) configuration for an Amazon FSx for NetApp ONTAP or Amazon FSx for OpenZFS file system. The default is 3 IOPS per GB of storage capacity, but you can provision additional IOPS per GB of storage. The configuration consists of the total number of provisioned SSD IOPS and how the amount was provisioned (by the customer or by the system).
            :param root_volume_configuration: The configuration Amazon FSx uses when creating the root value of the Amazon FSx for OpenZFS file system. All volumes are children of the root volume.
            :param throughput_capacity: Specifies the throughput of an Amazon FSx for OpenZFS file system, measured in megabytes per second (MB/s). Valid values are 64, 128, 256, 512, 1024, 2048, 3072, or 4096 MB/s. You pay for additional throughput capacity that you provision.
            :param weekly_maintenance_start_time: A recurring weekly time, in the format ``D:HH:MM`` . ``D`` is the day of the week, for which 1 represents Monday and 7 represents Sunday. For further details, see `the ISO-8601 spec as described on Wikipedia <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/ISO_week_date>`_ . ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour. For example, ``1:05:00`` specifies maintenance at 5 AM Monday.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                open_zFSConfiguration_property = fsx.CfnFileSystem.OpenZFSConfigurationProperty(
                    deployment_type="deploymentType",
                
                    # the properties below are optional
                    automatic_backup_retention_days=123,
                    copy_tags_to_backups=False,
                    copy_tags_to_volumes=False,
                    daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                    disk_iops_configuration=fsx.CfnFileSystem.DiskIopsConfigurationProperty(
                        iops=123,
                        mode="mode"
                    ),
                    root_volume_configuration=fsx.CfnFileSystem.RootVolumeConfigurationProperty(
                        copy_tags_to_snapshots=False,
                        data_compression_type="dataCompressionType",
                        nfs_exports=[fsx.CfnFileSystem.NfsExportsProperty(
                            client_configurations=[fsx.CfnFileSystem.ClientConfigurationsProperty(
                                clients="clients",
                                options=["options"]
                            )]
                        )],
                        read_only=False,
                        user_and_group_quotas=[fsx.CfnFileSystem.UserAndGroupQuotasProperty(
                            id=123,
                            storage_capacity_quota_gi_b=123,
                            type="type"
                        )]
                    ),
                    throughput_capacity=123,
                    weekly_maintenance_start_time="weeklyMaintenanceStartTime"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "deployment_type": deployment_type,
            }
            if automatic_backup_retention_days is not None:
                self._values["automatic_backup_retention_days"] = automatic_backup_retention_days
            if copy_tags_to_backups is not None:
                self._values["copy_tags_to_backups"] = copy_tags_to_backups
            if copy_tags_to_volumes is not None:
                self._values["copy_tags_to_volumes"] = copy_tags_to_volumes
            if daily_automatic_backup_start_time is not None:
                self._values["daily_automatic_backup_start_time"] = daily_automatic_backup_start_time
            if disk_iops_configuration is not None:
                self._values["disk_iops_configuration"] = disk_iops_configuration
            if root_volume_configuration is not None:
                self._values["root_volume_configuration"] = root_volume_configuration
            if throughput_capacity is not None:
                self._values["throughput_capacity"] = throughput_capacity
            if weekly_maintenance_start_time is not None:
                self._values["weekly_maintenance_start_time"] = weekly_maintenance_start_time

        @builtins.property
        def deployment_type(self) -> builtins.str:
            '''Specifies the file system deployment type.

            Amazon FSx for OpenZFS supports ``SINGLE_AZ_1`` . ``SINGLE_AZ_1`` is a file system configured for a single Availability Zone (AZ) of redundancy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-deploymenttype
            '''
            result = self._values.get("deployment_type")
            assert result is not None, "Required property 'deployment_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def automatic_backup_retention_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days to retain automatic backups.

            Setting this property to ``0`` disables automatic backups. You can retain automatic backups for a maximum of 90 days. The default is ``0`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-automaticbackupretentiondays
            '''
            result = self._values.get("automatic_backup_retention_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def copy_tags_to_backups(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A Boolean value indicating whether tags for the file system should be copied to backups.

            This value defaults to ``false`` . If it's set to ``true`` , all tags for the file system are copied to all automatic and user-initiated backups where the user doesn't specify tags. If this value is ``true`` , and you specify one or more tags, only the specified tags are copied to backups. If you specify one or more tags when creating a user-initiated backup, no tags are copied from the file system, regardless of this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-copytagstobackups
            '''
            result = self._values.get("copy_tags_to_backups")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def copy_tags_to_volumes(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A Boolean value indicating whether tags for the volume should be copied to snapshots.

            This value defaults to ``false`` . If it's set to ``true`` , all tags for the volume are copied to snapshots where the user doesn't specify tags. If this value is ``true`` , and you specify one or more tags, only the specified tags are copied to snapshots. If you specify one or more tags when creating the snapshot, no tags are copied from the volume, regardless of this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-copytagstovolumes
            '''
            result = self._values.get("copy_tags_to_volumes")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def daily_automatic_backup_start_time(self) -> typing.Optional[builtins.str]:
            '''A recurring daily time, in the format ``HH:MM`` .

            ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour. For example, ``05:00`` specifies 5 AM daily.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-dailyautomaticbackupstarttime
            '''
            result = self._values.get("daily_automatic_backup_start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def disk_iops_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnFileSystem.DiskIopsConfigurationProperty", _IResolvable_da3f097b]]:
            '''The SSD IOPS (input/output operations per second) configuration for an Amazon FSx for NetApp ONTAP or Amazon FSx for OpenZFS file system.

            The default is 3 IOPS per GB of storage capacity, but you can provision additional IOPS per GB of storage. The configuration consists of the total number of provisioned SSD IOPS and how the amount was provisioned (by the customer or by the system).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-diskiopsconfiguration
            '''
            result = self._values.get("disk_iops_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnFileSystem.DiskIopsConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def root_volume_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnFileSystem.RootVolumeConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration Amazon FSx uses when creating the root value of the Amazon FSx for OpenZFS file system.

            All volumes are children of the root volume.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration
            '''
            result = self._values.get("root_volume_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnFileSystem.RootVolumeConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def throughput_capacity(self) -> typing.Optional[jsii.Number]:
            '''Specifies the throughput of an Amazon FSx for OpenZFS file system, measured in megabytes per second (MB/s).

            Valid values are 64, 128, 256, 512, 1024, 2048, 3072, or 4096 MB/s. You pay for additional throughput capacity that you provision.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-throughputcapacity
            '''
            result = self._values.get("throughput_capacity")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def weekly_maintenance_start_time(self) -> typing.Optional[builtins.str]:
            '''A recurring weekly time, in the format ``D:HH:MM`` .

            ``D`` is the day of the week, for which 1 represents Monday and 7 represents Sunday. For further details, see `the ISO-8601 spec as described on Wikipedia <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/ISO_week_date>`_ .

            ``HH`` is the zero-padded hour of the day (0-23), and ``MM`` is the zero-padded minute of the hour.

            For example, ``1:05:00`` specifies maintenance at 5 AM Monday.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-weeklymaintenancestarttime
            '''
            result = self._values.get("weekly_maintenance_start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OpenZFSConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.RootVolumeConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "copy_tags_to_snapshots": "copyTagsToSnapshots",
            "data_compression_type": "dataCompressionType",
            "nfs_exports": "nfsExports",
            "read_only": "readOnly",
            "user_and_group_quotas": "userAndGroupQuotas",
        },
    )
    class RootVolumeConfigurationProperty:
        def __init__(
            self,
            *,
            copy_tags_to_snapshots: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            data_compression_type: typing.Optional[builtins.str] = None,
            nfs_exports: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFileSystem.NfsExportsProperty", _IResolvable_da3f097b]]]] = None,
            read_only: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            user_and_group_quotas: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFileSystem.UserAndGroupQuotasProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The configuration of an Amazon FSx for OpenZFS root volume.

            :param copy_tags_to_snapshots: A Boolean value indicating whether tags for the volume should be copied to snapshots. This value defaults to ``false`` . If it's set to ``true`` , all tags for the volume are copied to snapshots where the user doesn't specify tags. If this value is ``true`` and you specify one or more tags, only the specified tags are copied to snapshots. If you specify one or more tags when creating the snapshot, no tags are copied from the volume, regardless of this value.
            :param data_compression_type: Specifies the method used to compress the data on the volume. Unless the compression type is specified, volumes inherit the ``DataCompressionType`` value of their parent volume. - ``NONE`` - Doesn't compress the data on the volume. - ``ZSTD`` - Compresses the data in the volume using the ZStandard (ZSTD) compression algorithm. This algorithm reduces the amount of space used on your volume and has very little impact on compute resources.
            :param nfs_exports: The configuration object for mounting a file system.
            :param read_only: A Boolean value indicating whether the volume is read-only. Setting this value to ``true`` can be useful after you have completed changes to a volume and no longer want changes to occur.
            :param user_and_group_quotas: An object specifying how much storage users or groups can use on the volume.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                root_volume_configuration_property = fsx.CfnFileSystem.RootVolumeConfigurationProperty(
                    copy_tags_to_snapshots=False,
                    data_compression_type="dataCompressionType",
                    nfs_exports=[fsx.CfnFileSystem.NfsExportsProperty(
                        client_configurations=[fsx.CfnFileSystem.ClientConfigurationsProperty(
                            clients="clients",
                            options=["options"]
                        )]
                    )],
                    read_only=False,
                    user_and_group_quotas=[fsx.CfnFileSystem.UserAndGroupQuotasProperty(
                        id=123,
                        storage_capacity_quota_gi_b=123,
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if copy_tags_to_snapshots is not None:
                self._values["copy_tags_to_snapshots"] = copy_tags_to_snapshots
            if data_compression_type is not None:
                self._values["data_compression_type"] = data_compression_type
            if nfs_exports is not None:
                self._values["nfs_exports"] = nfs_exports
            if read_only is not None:
                self._values["read_only"] = read_only
            if user_and_group_quotas is not None:
                self._values["user_and_group_quotas"] = user_and_group_quotas

        @builtins.property
        def copy_tags_to_snapshots(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A Boolean value indicating whether tags for the volume should be copied to snapshots.

            This value defaults to ``false`` . If it's set to ``true`` , all tags for the volume are copied to snapshots where the user doesn't specify tags. If this value is ``true`` and you specify one or more tags, only the specified tags are copied to snapshots. If you specify one or more tags when creating the snapshot, no tags are copied from the volume, regardless of this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-copytagstosnapshots
            '''
            result = self._values.get("copy_tags_to_snapshots")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def data_compression_type(self) -> typing.Optional[builtins.str]:
            '''Specifies the method used to compress the data on the volume.

            Unless the compression type is specified, volumes inherit the ``DataCompressionType`` value of their parent volume.

            - ``NONE`` - Doesn't compress the data on the volume.
            - ``ZSTD`` - Compresses the data in the volume using the ZStandard (ZSTD) compression algorithm. This algorithm reduces the amount of space used on your volume and has very little impact on compute resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-datacompressiontype
            '''
            result = self._values.get("data_compression_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def nfs_exports(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFileSystem.NfsExportsProperty", _IResolvable_da3f097b]]]]:
            '''The configuration object for mounting a file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-nfsexports
            '''
            result = self._values.get("nfs_exports")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFileSystem.NfsExportsProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def read_only(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A Boolean value indicating whether the volume is read-only.

            Setting this value to ``true`` can be useful after you have completed changes to a volume and no longer want changes to occur.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-readonly
            '''
            result = self._values.get("read_only")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def user_and_group_quotas(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFileSystem.UserAndGroupQuotasProperty", _IResolvable_da3f097b]]]]:
            '''An object specifying how much storage users or groups can use on the volume.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-userandgroupquotas
            '''
            result = self._values.get("user_and_group_quotas")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFileSystem.UserAndGroupQuotasProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RootVolumeConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.SelfManagedActiveDirectoryConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "dns_ips": "dnsIps",
            "domain_name": "domainName",
            "file_system_administrators_group": "fileSystemAdministratorsGroup",
            "organizational_unit_distinguished_name": "organizationalUnitDistinguishedName",
            "password": "password",
            "user_name": "userName",
        },
    )
    class SelfManagedActiveDirectoryConfigurationProperty:
        def __init__(
            self,
            *,
            dns_ips: typing.Optional[typing.Sequence[builtins.str]] = None,
            domain_name: typing.Optional[builtins.str] = None,
            file_system_administrators_group: typing.Optional[builtins.str] = None,
            organizational_unit_distinguished_name: typing.Optional[builtins.str] = None,
            password: typing.Optional[builtins.str] = None,
            user_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration that Amazon FSx uses to join a FSx for Windows File Server file system or an ONTAP storage virtual machine (SVM) to a self-managed (including on-premises) Microsoft Active Directory (AD) directory.

            For more information, see `Using Amazon FSx with your self-managed Microsoft Active Directory <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/self-managed-AD.html>`_ or `Managing SVMs <https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/managing-svms.html>`_ .

            :param dns_ips: A list of up to three IP addresses of DNS servers or domain controllers in the self-managed AD directory.
            :param domain_name: The fully qualified domain name of the self-managed AD directory, such as ``corp.example.com`` .
            :param file_system_administrators_group: (Optional) The name of the domain group whose members are granted administrative privileges for the file system. Administrative privileges include taking ownership of files and folders, setting audit controls (audit ACLs) on files and folders, and administering the file system remotely by using the FSx Remote PowerShell. The group that you specify must already exist in your domain. If you don't provide one, your AD domain's Domain Admins group is used.
            :param organizational_unit_distinguished_name: (Optional) The fully qualified distinguished name of the organizational unit within your self-managed AD directory. Amazon FSx only accepts OU as the direct parent of the file system. An example is ``OU=FSx,DC=yourdomain,DC=corp,DC=com`` . To learn more, see `RFC 2253 <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc2253>`_ . If none is provided, the FSx file system is created in the default location of your self-managed AD directory. .. epigraph:: Only Organizational Unit (OU) objects can be the direct parent of the file system that you're creating.
            :param password: The password for the service account on your self-managed AD domain that Amazon FSx will use to join to your AD domain. We strongly suggest that you follow best practices and *do not* embed passwords in your CFN templates. The recommended approach is to use AWS Secrets Manager to store your passwords. You can retrieve them for use in your templates using the ``secretsmanager`` dynamic reference. There are additional costs associated with using AWS Secrets Manager . To learn more, see `Secrets Manager secrets <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ in the *AWS CloudFormation User Guide* . Alternatively, you can use the ``NoEcho`` property to obfuscate the password parameter value. For more information, see `Do Not Embed Credentials in Your Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html#creds>`_ in the *AWS CloudFormation User Guide* .
            :param user_name: The user name for the service account on your self-managed AD domain that Amazon FSx will use to join to your AD domain. This account must have the permission to join computers to the domain in the organizational unit provided in ``OrganizationalUnitDistinguishedName`` , or in the default location of your AD domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                self_managed_active_directory_configuration_property = fsx.CfnFileSystem.SelfManagedActiveDirectoryConfigurationProperty(
                    dns_ips=["dnsIps"],
                    domain_name="domainName",
                    file_system_administrators_group="fileSystemAdministratorsGroup",
                    organizational_unit_distinguished_name="organizationalUnitDistinguishedName",
                    password="password",
                    user_name="userName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if dns_ips is not None:
                self._values["dns_ips"] = dns_ips
            if domain_name is not None:
                self._values["domain_name"] = domain_name
            if file_system_administrators_group is not None:
                self._values["file_system_administrators_group"] = file_system_administrators_group
            if organizational_unit_distinguished_name is not None:
                self._values["organizational_unit_distinguished_name"] = organizational_unit_distinguished_name
            if password is not None:
                self._values["password"] = password
            if user_name is not None:
                self._values["user_name"] = user_name

        @builtins.property
        def dns_ips(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of up to three IP addresses of DNS servers or domain controllers in the self-managed AD directory.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration-dnsips
            '''
            result = self._values.get("dns_ips")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def domain_name(self) -> typing.Optional[builtins.str]:
            '''The fully qualified domain name of the self-managed AD directory, such as ``corp.example.com`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration-domainname
            '''
            result = self._values.get("domain_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def file_system_administrators_group(self) -> typing.Optional[builtins.str]:
            '''(Optional) The name of the domain group whose members are granted administrative privileges for the file system.

            Administrative privileges include taking ownership of files and folders, setting audit controls (audit ACLs) on files and folders, and administering the file system remotely by using the FSx Remote PowerShell. The group that you specify must already exist in your domain. If you don't provide one, your AD domain's Domain Admins group is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration-filesystemadministratorsgroup
            '''
            result = self._values.get("file_system_administrators_group")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def organizational_unit_distinguished_name(
            self,
        ) -> typing.Optional[builtins.str]:
            '''(Optional) The fully qualified distinguished name of the organizational unit within your self-managed AD directory.

            Amazon FSx only accepts OU as the direct parent of the file system. An example is ``OU=FSx,DC=yourdomain,DC=corp,DC=com`` . To learn more, see `RFC 2253 <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc2253>`_ . If none is provided, the FSx file system is created in the default location of your self-managed AD directory.
            .. epigraph::

               Only Organizational Unit (OU) objects can be the direct parent of the file system that you're creating.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration-organizationalunitdistinguishedname
            '''
            result = self._values.get("organizational_unit_distinguished_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def password(self) -> typing.Optional[builtins.str]:
            '''The password for the service account on your self-managed AD domain that Amazon FSx will use to join to your AD domain.

            We strongly suggest that you follow best practices and *do not* embed passwords in your CFN templates.

            The recommended approach is to use AWS Secrets Manager to store your passwords. You can retrieve them for use in your templates using the ``secretsmanager`` dynamic reference. There are additional costs associated with using AWS Secrets Manager . To learn more, see `Secrets Manager secrets <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ in the *AWS CloudFormation User Guide* .

            Alternatively, you can use the ``NoEcho`` property to obfuscate the password parameter value. For more information, see `Do Not Embed Credentials in Your Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html#creds>`_ in the *AWS CloudFormation User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration-password
            '''
            result = self._values.get("password")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def user_name(self) -> typing.Optional[builtins.str]:
            '''The user name for the service account on your self-managed AD domain that Amazon FSx will use to join to your AD domain.

            This account must have the permission to join computers to the domain in the organizational unit provided in ``OrganizationalUnitDistinguishedName`` , or in the default location of your AD domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration-username
            '''
            result = self._values.get("user_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SelfManagedActiveDirectoryConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.UserAndGroupQuotasProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "storage_capacity_quota_gib": "storageCapacityQuotaGiB",
            "type": "type",
        },
    )
    class UserAndGroupQuotasProperty:
        def __init__(
            self,
            *,
            id: typing.Optional[jsii.Number] = None,
            storage_capacity_quota_gib: typing.Optional[jsii.Number] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration for how much storage a user or group can use on the volume.

            :param id: The ID of the user or group.
            :param storage_capacity_quota_gib: The amount of storage that the user or group can use in gibibytes (GiB).
            :param type: A value that specifies whether the quota applies to a user or group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-userandgroupquotas.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                user_and_group_quotas_property = fsx.CfnFileSystem.UserAndGroupQuotasProperty(
                    id=123,
                    storage_capacity_quota_gi_b=123,
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if id is not None:
                self._values["id"] = id
            if storage_capacity_quota_gib is not None:
                self._values["storage_capacity_quota_gib"] = storage_capacity_quota_gib
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def id(self) -> typing.Optional[jsii.Number]:
            '''The ID of the user or group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-userandgroupquotas.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-userandgroupquotas-id
            '''
            result = self._values.get("id")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def storage_capacity_quota_gib(self) -> typing.Optional[jsii.Number]:
            '''The amount of storage that the user or group can use in gibibytes (GiB).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-userandgroupquotas.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-userandgroupquotas-storagecapacityquotagib
            '''
            result = self._values.get("storage_capacity_quota_gib")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''A value that specifies whether the quota applies to a user or group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-userandgroupquotas.html#cfn-fsx-filesystem-openzfsconfiguration-rootvolumeconfiguration-userandgroupquotas-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UserAndGroupQuotasProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystem.WindowsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "throughput_capacity": "throughputCapacity",
            "active_directory_id": "activeDirectoryId",
            "aliases": "aliases",
            "audit_log_configuration": "auditLogConfiguration",
            "automatic_backup_retention_days": "automaticBackupRetentionDays",
            "copy_tags_to_backups": "copyTagsToBackups",
            "daily_automatic_backup_start_time": "dailyAutomaticBackupStartTime",
            "deployment_type": "deploymentType",
            "preferred_subnet_id": "preferredSubnetId",
            "self_managed_active_directory_configuration": "selfManagedActiveDirectoryConfiguration",
            "weekly_maintenance_start_time": "weeklyMaintenanceStartTime",
        },
    )
    class WindowsConfigurationProperty:
        def __init__(
            self,
            *,
            throughput_capacity: jsii.Number,
            active_directory_id: typing.Optional[builtins.str] = None,
            aliases: typing.Optional[typing.Sequence[builtins.str]] = None,
            audit_log_configuration: typing.Optional[typing.Union["CfnFileSystem.AuditLogConfigurationProperty", _IResolvable_da3f097b]] = None,
            automatic_backup_retention_days: typing.Optional[jsii.Number] = None,
            copy_tags_to_backups: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            daily_automatic_backup_start_time: typing.Optional[builtins.str] = None,
            deployment_type: typing.Optional[builtins.str] = None,
            preferred_subnet_id: typing.Optional[builtins.str] = None,
            self_managed_active_directory_configuration: typing.Optional[typing.Union["CfnFileSystem.SelfManagedActiveDirectoryConfigurationProperty", _IResolvable_da3f097b]] = None,
            weekly_maintenance_start_time: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The Microsoft Windows configuration for the file system that's being created.

            :param throughput_capacity: Sets the throughput capacity of an Amazon FSx file system, measured in megabytes per second (MB/s), in 2 to the *n* th increments, between 2^3 (8) and 2^11 (2048).
            :param active_directory_id: The ID for an existing AWS Managed Microsoft Active Directory (AD) instance that the file system should join when it's created.
            :param aliases: An array of one or more DNS alias names that you want to associate with the Amazon FSx file system. Aliases allow you to use existing DNS names to access the data in your Amazon FSx file system. You can associate up to 50 aliases with a file system at any time. For more information, see `Working with DNS Aliases <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/managing-dns-aliases.html>`_ and `Walkthrough 5: Using DNS aliases to access your file system <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/walkthrough05-file-system-custom-CNAME.html>`_ , including additional steps you must take to be able to access your file system using a DNS alias. An alias name has to meet the following requirements: - Formatted as a fully-qualified domain name (FQDN), ``hostname.domain`` , for example, ``accounting.example.com`` . - Can contain alphanumeric characters, the underscore (_), and the hyphen (-). - Cannot start or end with a hyphen. - Can start with a numeric. For DNS alias names, Amazon FSx stores alphabetical characters as lowercase letters (a-z), regardless of how you specify them: as uppercase letters, lowercase letters, or the corresponding letters in escape codes.
            :param audit_log_configuration: The configuration that Amazon FSx for Windows File Server uses to audit and log user accesses of files, folders, and file shares on the Amazon FSx for Windows File Server file system.
            :param automatic_backup_retention_days: The number of days to retain automatic backups. The default is to retain backups for 7 days. Setting this value to 0 disables the creation of automatic backups. The maximum retention period for backups is 90 days.
            :param copy_tags_to_backups: A Boolean flag indicating whether tags for the file system should be copied to backups. This value defaults to false. If it's set to true, all tags for the file system are copied to all automatic and user-initiated backups where the user doesn't specify tags. If this value is true, and you specify one or more tags, only the specified tags are copied to backups. If you specify one or more tags when creating a user-initiated backup, no tags are copied from the file system, regardless of this value.
            :param daily_automatic_backup_start_time: The preferred time to take daily automatic backups, formatted HH:MM in the UTC time zone.
            :param deployment_type: Specifies the file system deployment type, valid values are the following:. - ``MULTI_AZ_1`` - Deploys a high availability file system that is configured for Multi-AZ redundancy to tolerate temporary Availability Zone (AZ) unavailability. You can only deploy a Multi-AZ file system in AWS Regions that have a minimum of three Availability Zones. Also supports HDD storage type - ``SINGLE_AZ_1`` - (Default) Choose to deploy a file system that is configured for single AZ redundancy. - ``SINGLE_AZ_2`` - The latest generation Single AZ file system. Specifies a file system that is configured for single AZ redundancy and supports HDD storage type. For more information, see `Availability and Durability: Single-AZ and Multi-AZ File Systems <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/high-availability-multiAZ.html>`_ .
            :param preferred_subnet_id: Required when ``DeploymentType`` is set to ``MULTI_AZ_1`` . This specifies the subnet in which you want the preferred file server to be located. For in- AWS applications, we recommend that you launch your clients in the same Availability Zone (AZ) as your preferred file server to reduce cross-AZ data transfer costs and minimize latency.
            :param self_managed_active_directory_configuration: The configuration that Amazon FSx uses to join a FSx for Windows File Server file system or an ONTAP storage virtual machine (SVM) to a self-managed (including on-premises) Microsoft Active Directory (AD) directory. For more information, see `Using Amazon FSx with your self-managed Microsoft Active Directory <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/self-managed-AD.html>`_ or `Managing SVMs <https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/managing-svms.html>`_ .
            :param weekly_maintenance_start_time: The preferred start time to perform weekly maintenance, formatted d:HH:MM in the UTC time zone, where d is the weekday number, from 1 through 7, beginning with Monday and ending with Sunday.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_fsx as fsx
                
                windows_configuration_property = fsx.CfnFileSystem.WindowsConfigurationProperty(
                    throughput_capacity=123,
                
                    # the properties below are optional
                    active_directory_id="activeDirectoryId",
                    aliases=["aliases"],
                    audit_log_configuration=fsx.CfnFileSystem.AuditLogConfigurationProperty(
                        file_access_audit_log_level="fileAccessAuditLogLevel",
                        file_share_access_audit_log_level="fileShareAccessAuditLogLevel",
                
                        # the properties below are optional
                        audit_log_destination="auditLogDestination"
                    ),
                    automatic_backup_retention_days=123,
                    copy_tags_to_backups=False,
                    daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                    deployment_type="deploymentType",
                    preferred_subnet_id="preferredSubnetId",
                    self_managed_active_directory_configuration=fsx.CfnFileSystem.SelfManagedActiveDirectoryConfigurationProperty(
                        dns_ips=["dnsIps"],
                        domain_name="domainName",
                        file_system_administrators_group="fileSystemAdministratorsGroup",
                        organizational_unit_distinguished_name="organizationalUnitDistinguishedName",
                        password="password",
                        user_name="userName"
                    ),
                    weekly_maintenance_start_time="weeklyMaintenanceStartTime"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "throughput_capacity": throughput_capacity,
            }
            if active_directory_id is not None:
                self._values["active_directory_id"] = active_directory_id
            if aliases is not None:
                self._values["aliases"] = aliases
            if audit_log_configuration is not None:
                self._values["audit_log_configuration"] = audit_log_configuration
            if automatic_backup_retention_days is not None:
                self._values["automatic_backup_retention_days"] = automatic_backup_retention_days
            if copy_tags_to_backups is not None:
                self._values["copy_tags_to_backups"] = copy_tags_to_backups
            if daily_automatic_backup_start_time is not None:
                self._values["daily_automatic_backup_start_time"] = daily_automatic_backup_start_time
            if deployment_type is not None:
                self._values["deployment_type"] = deployment_type
            if preferred_subnet_id is not None:
                self._values["preferred_subnet_id"] = preferred_subnet_id
            if self_managed_active_directory_configuration is not None:
                self._values["self_managed_active_directory_configuration"] = self_managed_active_directory_configuration
            if weekly_maintenance_start_time is not None:
                self._values["weekly_maintenance_start_time"] = weekly_maintenance_start_time

        @builtins.property
        def throughput_capacity(self) -> jsii.Number:
            '''Sets the throughput capacity of an Amazon FSx file system, measured in megabytes per second (MB/s), in 2 to the *n* th increments, between 2^3 (8) and 2^11 (2048).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-throughputcapacity
            '''
            result = self._values.get("throughput_capacity")
            assert result is not None, "Required property 'throughput_capacity' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def active_directory_id(self) -> typing.Optional[builtins.str]:
            '''The ID for an existing AWS Managed Microsoft Active Directory (AD) instance that the file system should join when it's created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-activedirectoryid
            '''
            result = self._values.get("active_directory_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def aliases(self) -> typing.Optional[typing.List[builtins.str]]:
            '''An array of one or more DNS alias names that you want to associate with the Amazon FSx file system.

            Aliases allow you to use existing DNS names to access the data in your Amazon FSx file system. You can associate up to 50 aliases with a file system at any time.

            For more information, see `Working with DNS Aliases <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/managing-dns-aliases.html>`_ and `Walkthrough 5: Using DNS aliases to access your file system <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/walkthrough05-file-system-custom-CNAME.html>`_ , including additional steps you must take to be able to access your file system using a DNS alias.

            An alias name has to meet the following requirements:

            - Formatted as a fully-qualified domain name (FQDN), ``hostname.domain`` , for example, ``accounting.example.com`` .
            - Can contain alphanumeric characters, the underscore (_), and the hyphen (-).
            - Cannot start or end with a hyphen.
            - Can start with a numeric.

            For DNS alias names, Amazon FSx stores alphabetical characters as lowercase letters (a-z), regardless of how you specify them: as uppercase letters, lowercase letters, or the corresponding letters in escape codes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-aliases
            '''
            result = self._values.get("aliases")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def audit_log_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnFileSystem.AuditLogConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration that Amazon FSx for Windows File Server uses to audit and log user accesses of files, folders, and file shares on the Amazon FSx for Windows File Server file system.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-auditlogconfiguration
            '''
            result = self._values.get("audit_log_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnFileSystem.AuditLogConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def automatic_backup_retention_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days to retain automatic backups.

            The default is to retain backups for 7 days. Setting this value to 0 disables the creation of automatic backups. The maximum retention period for backups is 90 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-automaticbackupretentiondays
            '''
            result = self._values.get("automatic_backup_retention_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def copy_tags_to_backups(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A Boolean flag indicating whether tags for the file system should be copied to backups.

            This value defaults to false. If it's set to true, all tags for the file system are copied to all automatic and user-initiated backups where the user doesn't specify tags. If this value is true, and you specify one or more tags, only the specified tags are copied to backups. If you specify one or more tags when creating a user-initiated backup, no tags are copied from the file system, regardless of this value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-copytagstobackups
            '''
            result = self._values.get("copy_tags_to_backups")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def daily_automatic_backup_start_time(self) -> typing.Optional[builtins.str]:
            '''The preferred time to take daily automatic backups, formatted HH:MM in the UTC time zone.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-dailyautomaticbackupstarttime
            '''
            result = self._values.get("daily_automatic_backup_start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def deployment_type(self) -> typing.Optional[builtins.str]:
            '''Specifies the file system deployment type, valid values are the following:.

            - ``MULTI_AZ_1`` - Deploys a high availability file system that is configured for Multi-AZ redundancy to tolerate temporary Availability Zone (AZ) unavailability. You can only deploy a Multi-AZ file system in AWS Regions that have a minimum of three Availability Zones. Also supports HDD storage type
            - ``SINGLE_AZ_1`` - (Default) Choose to deploy a file system that is configured for single AZ redundancy.
            - ``SINGLE_AZ_2`` - The latest generation Single AZ file system. Specifies a file system that is configured for single AZ redundancy and supports HDD storage type.

            For more information, see `Availability and Durability: Single-AZ and Multi-AZ File Systems <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/high-availability-multiAZ.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-deploymenttype
            '''
            result = self._values.get("deployment_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def preferred_subnet_id(self) -> typing.Optional[builtins.str]:
            '''Required when ``DeploymentType`` is set to ``MULTI_AZ_1`` .

            This specifies the subnet in which you want the preferred file server to be located. For in- AWS applications, we recommend that you launch your clients in the same Availability Zone (AZ) as your preferred file server to reduce cross-AZ data transfer costs and minimize latency.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-preferredsubnetid
            '''
            result = self._values.get("preferred_subnet_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def self_managed_active_directory_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnFileSystem.SelfManagedActiveDirectoryConfigurationProperty", _IResolvable_da3f097b]]:
            '''The configuration that Amazon FSx uses to join a FSx for Windows File Server file system or an ONTAP storage virtual machine (SVM) to a self-managed (including on-premises) Microsoft Active Directory (AD) directory.

            For more information, see `Using Amazon FSx with your self-managed Microsoft Active Directory <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/self-managed-AD.html>`_ or `Managing SVMs <https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/managing-svms.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-selfmanagedactivedirectoryconfiguration
            '''
            result = self._values.get("self_managed_active_directory_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnFileSystem.SelfManagedActiveDirectoryConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def weekly_maintenance_start_time(self) -> typing.Optional[builtins.str]:
            '''The preferred start time to perform weekly maintenance, formatted d:HH:MM in the UTC time zone, where d is the weekday number, from 1 through 7, beginning with Monday and ending with Sunday.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-windowsconfiguration.html#cfn-fsx-filesystem-windowsconfiguration-weeklymaintenancestarttime
            '''
            result = self._values.get("weekly_maintenance_start_time")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "WindowsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_fsx.CfnFileSystemProps",
    jsii_struct_bases=[],
    name_mapping={
        "file_system_type": "fileSystemType",
        "subnet_ids": "subnetIds",
        "backup_id": "backupId",
        "file_system_type_version": "fileSystemTypeVersion",
        "kms_key_id": "kmsKeyId",
        "lustre_configuration": "lustreConfiguration",
        "ontap_configuration": "ontapConfiguration",
        "open_zfs_configuration": "openZfsConfiguration",
        "security_group_ids": "securityGroupIds",
        "storage_capacity": "storageCapacity",
        "storage_type": "storageType",
        "tags": "tags",
        "windows_configuration": "windowsConfiguration",
    },
)
class CfnFileSystemProps:
    def __init__(
        self,
        *,
        file_system_type: builtins.str,
        subnet_ids: typing.Sequence[builtins.str],
        backup_id: typing.Optional[builtins.str] = None,
        file_system_type_version: typing.Optional[builtins.str] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        lustre_configuration: typing.Optional[typing.Union[CfnFileSystem.LustreConfigurationProperty, _IResolvable_da3f097b]] = None,
        ontap_configuration: typing.Optional[typing.Union[CfnFileSystem.OntapConfigurationProperty, _IResolvable_da3f097b]] = None,
        open_zfs_configuration: typing.Optional[typing.Union[CfnFileSystem.OpenZFSConfigurationProperty, _IResolvable_da3f097b]] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        storage_capacity: typing.Optional[jsii.Number] = None,
        storage_type: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        windows_configuration: typing.Optional[typing.Union[CfnFileSystem.WindowsConfigurationProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnFileSystem``.

        :param file_system_type: The type of Amazon FSx file system, which can be ``LUSTRE`` , ``WINDOWS`` , ``ONTAP`` , or ``OPENZFS`` .
        :param subnet_ids: Specifies the IDs of the subnets that the file system will be accessible from. For Windows and ONTAP ``MULTI_AZ_1`` deployment types,provide exactly two subnet IDs, one for the preferred file server and one for the standby file server. You specify one of these subnets as the preferred subnet using the ``WindowsConfiguration > PreferredSubnetID`` or ``OntapConfiguration > PreferredSubnetID`` properties. For more information about Multi-AZ file system configuration, see `Availability and durability: Single-AZ and Multi-AZ file systems <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/high-availability-multiAZ.html>`_ in the *Amazon FSx for Windows User Guide* and `Availability and durability <https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/high-availability-multiAZ.html>`_ in the *Amazon FSx for ONTAP User Guide* . For Windows ``SINGLE_AZ_1`` and ``SINGLE_AZ_2`` and all Lustre deployment types, provide exactly one subnet ID. The file server is launched in that subnet's Availability Zone.
        :param backup_id: The ID of the source backup. Specifies the backup that you are copying.
        :param file_system_type_version: (Optional) For FSx for Lustre file systems, sets the Lustre version for the file system that you're creating. Valid values are ``2.10`` and ``2.12`` : - 2.10 is supported by the Scratch and Persistent_1 Lustre deployment types. - 2.12 is supported by all Lustre deployment types. ``2.12`` is required when setting FSx for Lustre ``DeploymentType`` to ``PERSISTENT_2`` . Default value = ``2.10`` , except when ``DeploymentType`` is set to ``PERSISTENT_2`` , then the default is ``2.12`` . .. epigraph:: If you set ``FileSystemTypeVersion`` to ``2.10`` for a ``PERSISTENT_2`` Lustre deployment type, the ``CreateFileSystem`` operation fails.
        :param kms_key_id: The ID of the AWS Key Management Service ( AWS KMS ) key used to encrypt the file system's data for Amazon FSx for Windows File Server file systems, Amazon FSx for NetApp ONTAP file systems, and ``PERSISTENT`` Amazon FSx for Lustre file systems at rest. If this ID isn't specified, the Amazon FSx-managed key for your account is used. The scratch Amazon FSx for Lustre file systems are always encrypted at rest using the Amazon FSx-managed key for your account. For more information, see `Encrypt <https://docs.aws.amazon.com//kms/latest/APIReference/API_Encrypt.html>`_ in the *AWS Key Management Service API Reference* .
        :param lustre_configuration: The Lustre configuration for the file system being created. .. epigraph:: The following parameters are not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository. - ``AutoImportPolicy`` - ``ExportPath`` - ``ImportedChunkSize`` - ``ImportPath``
        :param ontap_configuration: The ONTAP configuration properties of the FSx for ONTAP file system that you are creating.
        :param open_zfs_configuration: The OpenZFS configuration properties for the file system that you are creating.
        :param security_group_ids: A list of IDs specifying the security groups to apply to all network interfaces created for file system access. This list isn't returned in later requests to describe the file system.
        :param storage_capacity: Sets the storage capacity of the file system that you're creating. ``StorageCapacity`` is required if you are creating a new file system. Do not include ``StorageCapacity`` if you are creating a file system from a backup. For Lustre file systems:
        :param storage_type: Sets the storage type for the file system that you're creating. Valid values are ``SSD`` and ``HDD`` . - Set to ``SSD`` to use solid state drive storage. SSD is supported on all Windows, Lustre, ONTAP, and OpenZFS deployment types. - Set to ``HDD`` to use hard disk drive storage. HDD is supported on ``SINGLE_AZ_2`` and ``MULTI_AZ_1`` Windows file system deployment types, and on ``PERSISTENT`` Lustre file system deployment types. Default value is ``SSD`` . For more information, see `Storage type options <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/optimize-fsx-costs.html#storage-type-options>`_ in the *FSx for Windows File Server User Guide* and `Multiple storage options <https://docs.aws.amazon.com/fsx/latest/LustreGuide/what-is.html#storage-options>`_ in the *FSx for Lustre User Guide* .
        :param tags: The tags to associate with the file system. For more information, see `Tagging your Amazon EC2 resources <https://docs.aws.amazon.com//AWSEC2/latest/UserGuide/Using_Tags.html>`_ in the *Amazon EC2 User Guide* .
        :param windows_configuration: The configuration object for the Microsoft Windows file system you are creating. This value is required if ``FileSystemType`` is set to ``WINDOWS`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_fsx as fsx
            
            cfn_file_system_props = fsx.CfnFileSystemProps(
                file_system_type="fileSystemType",
                subnet_ids=["subnetIds"],
            
                # the properties below are optional
                backup_id="backupId",
                file_system_type_version="fileSystemTypeVersion",
                kms_key_id="kmsKeyId",
                lustre_configuration=fsx.CfnFileSystem.LustreConfigurationProperty(
                    auto_import_policy="autoImportPolicy",
                    automatic_backup_retention_days=123,
                    copy_tags_to_backups=False,
                    daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                    data_compression_type="dataCompressionType",
                    deployment_type="deploymentType",
                    drive_cache_type="driveCacheType",
                    export_path="exportPath",
                    imported_file_chunk_size=123,
                    import_path="importPath",
                    per_unit_storage_throughput=123,
                    weekly_maintenance_start_time="weeklyMaintenanceStartTime"
                ),
                ontap_configuration=fsx.CfnFileSystem.OntapConfigurationProperty(
                    deployment_type="deploymentType",
            
                    # the properties below are optional
                    automatic_backup_retention_days=123,
                    daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                    disk_iops_configuration=fsx.CfnFileSystem.DiskIopsConfigurationProperty(
                        iops=123,
                        mode="mode"
                    ),
                    endpoint_ip_address_range="endpointIpAddressRange",
                    fsx_admin_password="fsxAdminPassword",
                    preferred_subnet_id="preferredSubnetId",
                    route_table_ids=["routeTableIds"],
                    throughput_capacity=123,
                    weekly_maintenance_start_time="weeklyMaintenanceStartTime"
                ),
                open_zfs_configuration=fsx.CfnFileSystem.OpenZFSConfigurationProperty(
                    deployment_type="deploymentType",
            
                    # the properties below are optional
                    automatic_backup_retention_days=123,
                    copy_tags_to_backups=False,
                    copy_tags_to_volumes=False,
                    daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                    disk_iops_configuration=fsx.CfnFileSystem.DiskIopsConfigurationProperty(
                        iops=123,
                        mode="mode"
                    ),
                    root_volume_configuration=fsx.CfnFileSystem.RootVolumeConfigurationProperty(
                        copy_tags_to_snapshots=False,
                        data_compression_type="dataCompressionType",
                        nfs_exports=[fsx.CfnFileSystem.NfsExportsProperty(
                            client_configurations=[fsx.CfnFileSystem.ClientConfigurationsProperty(
                                clients="clients",
                                options=["options"]
                            )]
                        )],
                        read_only=False,
                        user_and_group_quotas=[fsx.CfnFileSystem.UserAndGroupQuotasProperty(
                            id=123,
                            storage_capacity_quota_gi_b=123,
                            type="type"
                        )]
                    ),
                    throughput_capacity=123,
                    weekly_maintenance_start_time="weeklyMaintenanceStartTime"
                ),
                security_group_ids=["securityGroupIds"],
                storage_capacity=123,
                storage_type="storageType",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                windows_configuration=fsx.CfnFileSystem.WindowsConfigurationProperty(
                    throughput_capacity=123,
            
                    # the properties below are optional
                    active_directory_id="activeDirectoryId",
                    aliases=["aliases"],
                    audit_log_configuration=fsx.CfnFileSystem.AuditLogConfigurationProperty(
                        file_access_audit_log_level="fileAccessAuditLogLevel",
                        file_share_access_audit_log_level="fileShareAccessAuditLogLevel",
            
                        # the properties below are optional
                        audit_log_destination="auditLogDestination"
                    ),
                    automatic_backup_retention_days=123,
                    copy_tags_to_backups=False,
                    daily_automatic_backup_start_time="dailyAutomaticBackupStartTime",
                    deployment_type="deploymentType",
                    preferred_subnet_id="preferredSubnetId",
                    self_managed_active_directory_configuration=fsx.CfnFileSystem.SelfManagedActiveDirectoryConfigurationProperty(
                        dns_ips=["dnsIps"],
                        domain_name="domainName",
                        file_system_administrators_group="fileSystemAdministratorsGroup",
                        organizational_unit_distinguished_name="organizationalUnitDistinguishedName",
                        password="password",
                        user_name="userName"
                    ),
                    weekly_maintenance_start_time="weeklyMaintenanceStartTime"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "file_system_type": file_system_type,
            "subnet_ids": subnet_ids,
        }
        if backup_id is not None:
            self._values["backup_id"] = backup_id
        if file_system_type_version is not None:
            self._values["file_system_type_version"] = file_system_type_version
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if lustre_configuration is not None:
            self._values["lustre_configuration"] = lustre_configuration
        if ontap_configuration is not None:
            self._values["ontap_configuration"] = ontap_configuration
        if open_zfs_configuration is not None:
            self._values["open_zfs_configuration"] = open_zfs_configuration
        if security_group_ids is not None:
            self._values["security_group_ids"] = security_group_ids
        if storage_capacity is not None:
            self._values["storage_capacity"] = storage_capacity
        if storage_type is not None:
            self._values["storage_type"] = storage_type
        if tags is not None:
            self._values["tags"] = tags
        if windows_configuration is not None:
            self._values["windows_configuration"] = windows_configuration

    @builtins.property
    def file_system_type(self) -> builtins.str:
        '''The type of Amazon FSx file system, which can be ``LUSTRE`` , ``WINDOWS`` , ``ONTAP`` , or ``OPENZFS`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-filesystemtype
        '''
        result = self._values.get("file_system_type")
        assert result is not None, "Required property 'file_system_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subnet_ids(self) -> typing.List[builtins.str]:
        '''Specifies the IDs of the subnets that the file system will be accessible from.

        For Windows and ONTAP ``MULTI_AZ_1`` deployment types,provide exactly two subnet IDs, one for the preferred file server and one for the standby file server. You specify one of these subnets as the preferred subnet using the ``WindowsConfiguration > PreferredSubnetID`` or ``OntapConfiguration > PreferredSubnetID`` properties. For more information about Multi-AZ file system configuration, see `Availability and durability: Single-AZ and Multi-AZ file systems <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/high-availability-multiAZ.html>`_ in the *Amazon FSx for Windows User Guide* and `Availability and durability <https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/high-availability-multiAZ.html>`_ in the *Amazon FSx for ONTAP User Guide* .

        For Windows ``SINGLE_AZ_1`` and ``SINGLE_AZ_2`` and all Lustre deployment types, provide exactly one subnet ID. The file server is launched in that subnet's Availability Zone.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-subnetids
        '''
        result = self._values.get("subnet_ids")
        assert result is not None, "Required property 'subnet_ids' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def backup_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the source backup.

        Specifies the backup that you are copying.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-backupid
        '''
        result = self._values.get("backup_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def file_system_type_version(self) -> typing.Optional[builtins.str]:
        '''(Optional) For FSx for Lustre file systems, sets the Lustre version for the file system that you're creating.

        Valid values are ``2.10`` and ``2.12`` :

        - 2.10 is supported by the Scratch and Persistent_1 Lustre deployment types.
        - 2.12 is supported by all Lustre deployment types. ``2.12`` is required when setting FSx for Lustre ``DeploymentType`` to ``PERSISTENT_2`` .

        Default value = ``2.10`` , except when ``DeploymentType`` is set to ``PERSISTENT_2`` , then the default is ``2.12`` .
        .. epigraph::

           If you set ``FileSystemTypeVersion`` to ``2.10`` for a ``PERSISTENT_2`` Lustre deployment type, the ``CreateFileSystem`` operation fails.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-filesystemtypeversion
        '''
        result = self._values.get("file_system_type_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the AWS Key Management Service ( AWS KMS ) key used to encrypt the file system's data for Amazon FSx for Windows File Server file systems, Amazon FSx for NetApp ONTAP file systems, and ``PERSISTENT`` Amazon FSx for Lustre file systems at rest.

        If this ID isn't specified, the Amazon FSx-managed key for your account is used. The scratch Amazon FSx for Lustre file systems are always encrypted at rest using the Amazon FSx-managed key for your account. For more information, see `Encrypt <https://docs.aws.amazon.com//kms/latest/APIReference/API_Encrypt.html>`_ in the *AWS Key Management Service API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def lustre_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnFileSystem.LustreConfigurationProperty, _IResolvable_da3f097b]]:
        '''The Lustre configuration for the file system being created.

        .. epigraph::

           The following parameters are not supported for file systems with the ``Persistent_2`` deployment type. Instead, use ``CreateDataRepositoryAssociation`` to create a data repository association to link your Lustre file system to a data repository.

           - ``AutoImportPolicy``
           - ``ExportPath``
           - ``ImportedChunkSize``
           - ``ImportPath``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-lustreconfiguration
        '''
        result = self._values.get("lustre_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnFileSystem.LustreConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def ontap_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnFileSystem.OntapConfigurationProperty, _IResolvable_da3f097b]]:
        '''The ONTAP configuration properties of the FSx for ONTAP file system that you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-ontapconfiguration
        '''
        result = self._values.get("ontap_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnFileSystem.OntapConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def open_zfs_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnFileSystem.OpenZFSConfigurationProperty, _IResolvable_da3f097b]]:
        '''The OpenZFS configuration properties for the file system that you are creating.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-openzfsconfiguration
        '''
        result = self._values.get("open_zfs_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnFileSystem.OpenZFSConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of IDs specifying the security groups to apply to all network interfaces created for file system access.

        This list isn't returned in later requests to describe the file system.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-securitygroupids
        '''
        result = self._values.get("security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def storage_capacity(self) -> typing.Optional[jsii.Number]:
        '''Sets the storage capacity of the file system that you're creating.

        ``StorageCapacity`` is required if you are creating a new file system. Do not include ``StorageCapacity`` if you are creating a file system from a backup.

        For Lustre file systems:

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-storagecapacity
        '''
        result = self._values.get("storage_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def storage_type(self) -> typing.Optional[builtins.str]:
        '''Sets the storage type for the file system that you're creating. Valid values are ``SSD`` and ``HDD`` .

        - Set to ``SSD`` to use solid state drive storage. SSD is supported on all Windows, Lustre, ONTAP, and OpenZFS deployment types.
        - Set to ``HDD`` to use hard disk drive storage. HDD is supported on ``SINGLE_AZ_2`` and ``MULTI_AZ_1`` Windows file system deployment types, and on ``PERSISTENT`` Lustre file system deployment types.

        Default value is ``SSD`` . For more information, see `Storage type options <https://docs.aws.amazon.com/fsx/latest/WindowsGuide/optimize-fsx-costs.html#storage-type-options>`_ in the *FSx for Windows File Server User Guide* and `Multiple storage options <https://docs.aws.amazon.com/fsx/latest/LustreGuide/what-is.html#storage-options>`_ in the *FSx for Lustre User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-storagetype
        '''
        result = self._values.get("storage_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to associate with the file system.

        For more information, see `Tagging your Amazon EC2 resources <https://docs.aws.amazon.com//AWSEC2/latest/UserGuide/Using_Tags.html>`_ in the *Amazon EC2 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def windows_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnFileSystem.WindowsConfigurationProperty, _IResolvable_da3f097b]]:
        '''The configuration object for the Microsoft Windows file system you are creating.

        This value is required if ``FileSystemType`` is set to ``WINDOWS`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html#cfn-fsx-filesystem-windowsconfiguration
        '''
        result = self._values.get("windows_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnFileSystem.WindowsConfigurationProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFileSystemProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_fsx.FileSystemAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "dns_name": "dnsName",
        "file_system_id": "fileSystemId",
        "security_group": "securityGroup",
    },
)
class FileSystemAttributes:
    def __init__(
        self,
        *,
        dns_name: builtins.str,
        file_system_id: builtins.str,
        security_group: _ISecurityGroup_acf8a799,
    ) -> None:
        '''Properties that describe an existing FSx file system.

        :param dns_name: The DNS name assigned to this file system.
        :param file_system_id: The ID of the file system, assigned by Amazon FSx.
        :param security_group: The security group of the file system.

        :exampleMetadata: infused

        Example::

            sg = ec2.SecurityGroup.from_security_group_id(self, "FsxSecurityGroup", "{SECURITY-GROUP-ID}")
            fs = fsx.LustreFileSystem.from_lustre_file_system_attributes(self, "FsxLustreFileSystem",
                dns_name="{FILE-SYSTEM-DNS-NAME}",
                file_system_id="{FILE-SYSTEM-ID}",
                security_group=sg
            )
            
            vpc = ec2.Vpc.from_vpc_attributes(self, "Vpc",
                availability_zones=["us-west-2a", "us-west-2b"],
                public_subnet_ids=["{US-WEST-2A-SUBNET-ID}", "{US-WEST-2B-SUBNET-ID}"],
                vpc_id="{VPC-ID}"
            )
            
            inst = ec2.Instance(self, "inst",
                instance_type=ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.LARGE),
                machine_image=ec2.AmazonLinuxImage(
                    generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
                ),
                vpc=vpc,
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PUBLIC
                )
            )
            
            fs.connections.allow_default_port_from(inst)
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "dns_name": dns_name,
            "file_system_id": file_system_id,
            "security_group": security_group,
        }

    @builtins.property
    def dns_name(self) -> builtins.str:
        '''The DNS name assigned to this file system.'''
        result = self._values.get("dns_name")
        assert result is not None, "Required property 'dns_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def file_system_id(self) -> builtins.str:
        '''The ID of the file system, assigned by Amazon FSx.'''
        result = self._values.get("file_system_id")
        assert result is not None, "Required property 'file_system_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def security_group(self) -> _ISecurityGroup_acf8a799:
        '''The security group of the file system.'''
        result = self._values.get("security_group")
        assert result is not None, "Required property 'security_group' is missing"
        return typing.cast(_ISecurityGroup_acf8a799, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FileSystemAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_fsx.FileSystemProps",
    jsii_struct_bases=[],
    name_mapping={
        "storage_capacity_gib": "storageCapacityGiB",
        "vpc": "vpc",
        "backup_id": "backupId",
        "kms_key": "kmsKey",
        "removal_policy": "removalPolicy",
        "security_group": "securityGroup",
    },
)
class FileSystemProps:
    def __init__(
        self,
        *,
        storage_capacity_gib: jsii.Number,
        vpc: _IVpc_f30d5663,
        backup_id: typing.Optional[builtins.str] = None,
        kms_key: typing.Optional[_IKey_5f11635f] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
    ) -> None:
        '''Properties for the FSx file system.

        :param storage_capacity_gib: The storage capacity of the file system being created. For Windows file systems, valid values are 32 GiB to 65,536 GiB. For SCRATCH_1 deployment types, valid values are 1,200, 2,400, 3,600, then continuing in increments of 3,600 GiB. For SCRATCH_2 and PERSISTENT_1 types, valid values are 1,200, 2,400, then continuing in increments of 2,400 GiB.
        :param vpc: The VPC to launch the file system in.
        :param backup_id: The ID of the backup. Specifies the backup to use if you're creating a file system from an existing backup. Default: - no backup will be used.
        :param kms_key: The KMS key used for encryption to protect your data at rest. Default: - the aws/fsx default KMS key for the AWS account being deployed into.
        :param removal_policy: Policy to apply when the file system is removed from the stack. Default: RemovalPolicy.RETAIN
        :param security_group: Security Group to assign to this file system. Default: - creates new security group which allows all outbound traffic.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_fsx as fsx
            from aws_cdk import aws_kms as kms
            
            # key: kms.Key
            # security_group: ec2.SecurityGroup
            # vpc: ec2.Vpc
            
            file_system_props = fsx.FileSystemProps(
                storage_capacity_gi_b=123,
                vpc=vpc,
            
                # the properties below are optional
                backup_id="backupId",
                kms_key=key,
                removal_policy=cdk.RemovalPolicy.DESTROY,
                security_group=security_group
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "storage_capacity_gib": storage_capacity_gib,
            "vpc": vpc,
        }
        if backup_id is not None:
            self._values["backup_id"] = backup_id
        if kms_key is not None:
            self._values["kms_key"] = kms_key
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if security_group is not None:
            self._values["security_group"] = security_group

    @builtins.property
    def storage_capacity_gib(self) -> jsii.Number:
        '''The storage capacity of the file system being created.

        For Windows file systems, valid values are 32 GiB to 65,536 GiB.
        For SCRATCH_1 deployment types, valid values are 1,200, 2,400, 3,600, then continuing in increments of 3,600 GiB.
        For SCRATCH_2 and PERSISTENT_1 types, valid values are 1,200, 2,400, then continuing in increments of 2,400 GiB.
        '''
        result = self._values.get("storage_capacity_gib")
        assert result is not None, "Required property 'storage_capacity_gib' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC to launch the file system in.'''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    @builtins.property
    def backup_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the backup.

        Specifies the backup to use if you're creating a file system from an existing backup.

        :default: - no backup will be used.
        '''
        result = self._values.get("backup_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The KMS key used for encryption to protect your data at rest.

        :default: - the aws/fsx default KMS key for the AWS account being deployed into.
        '''
        result = self._values.get("kms_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Policy to apply when the file system is removed from the stack.

        :default: RemovalPolicy.RETAIN
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security Group to assign to this file system.

        :default: - creates new security group which allows all outbound traffic.
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FileSystemProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_fsx.IFileSystem")
class IFileSystem(_IConnectable_10015a05, typing_extensions.Protocol):
    '''Interface to implement FSx File Systems.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fileSystemId")
    def file_system_id(self) -> builtins.str:
        '''The ID of the file system, assigned by Amazon FSx.

        :attribute: true
        '''
        ...


class _IFileSystemProxy(
    jsii.proxy_for(_IConnectable_10015a05) # type: ignore[misc]
):
    '''Interface to implement FSx File Systems.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_fsx.IFileSystem"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fileSystemId")
    def file_system_id(self) -> builtins.str:
        '''The ID of the file system, assigned by Amazon FSx.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "fileSystemId"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IFileSystem).__jsii_proxy_class__ = lambda : _IFileSystemProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_fsx.LustreConfiguration",
    jsii_struct_bases=[],
    name_mapping={
        "deployment_type": "deploymentType",
        "export_path": "exportPath",
        "imported_file_chunk_size_mib": "importedFileChunkSizeMiB",
        "import_path": "importPath",
        "per_unit_storage_throughput": "perUnitStorageThroughput",
        "weekly_maintenance_start_time": "weeklyMaintenanceStartTime",
    },
)
class LustreConfiguration:
    def __init__(
        self,
        *,
        deployment_type: "LustreDeploymentType",
        export_path: typing.Optional[builtins.str] = None,
        imported_file_chunk_size_mib: typing.Optional[jsii.Number] = None,
        import_path: typing.Optional[builtins.str] = None,
        per_unit_storage_throughput: typing.Optional[jsii.Number] = None,
        weekly_maintenance_start_time: typing.Optional["LustreMaintenanceTime"] = None,
    ) -> None:
        '''The configuration for the Amazon FSx for Lustre file system.

        :param deployment_type: The type of backing file system deployment used by FSx.
        :param export_path: The path in Amazon S3 where the root of your Amazon FSx file system is exported. The path must use the same Amazon S3 bucket as specified in ImportPath. If you only specify a bucket name, such as s3://import-bucket, you get a 1:1 mapping of file system objects to S3 bucket objects. This mapping means that the input data in S3 is overwritten on export. If you provide a custom prefix in the export path, such as s3://import-bucket/[custom-optional-prefix], Amazon FSx exports the contents of your file system to that export prefix in the Amazon S3 bucket. Default: s3://import-bucket/FSxLustre[creation-timestamp]
        :param imported_file_chunk_size_mib: For files imported from a data repository, this value determines the stripe count and maximum amount of data per file (in MiB) stored on a single physical disk. Allowed values are between 1 and 512,000. Default: 1024
        :param import_path: The path to the Amazon S3 bucket (including the optional prefix) that you're using as the data repository for your Amazon FSx for Lustre file system. Must be of the format "s3://{bucketName}/optional-prefix" and cannot exceed 900 characters. Default: - no bucket is imported
        :param per_unit_storage_throughput: Required for the PERSISTENT_1 deployment type, describes the amount of read and write throughput for each 1 tebibyte of storage, in MB/s/TiB. Valid values are 50, 100, 200. Default: - no default, conditionally required for PERSISTENT_1 deployment type
        :param weekly_maintenance_start_time: The preferred day and time to perform weekly maintenance. The first digit is the day of the week, starting at 1 for Monday, then the following are hours and minutes in the UTC time zone, 24 hour clock. For example: '2:20:30' is Tuesdays at 20:30. Default: - no preference

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fsx-filesystem-lustreconfiguration.html
        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            
            
            file_system = fsx.LustreFileSystem(self, "FsxLustreFileSystem",
                lustre_configuration=fsx.LustreConfiguration(deployment_type=fsx.LustreDeploymentType.SCRATCH_2),
                storage_capacity_gi_b=1200,
                vpc=vpc,
                vpc_subnet=vpc.private_subnets[0]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "deployment_type": deployment_type,
        }
        if export_path is not None:
            self._values["export_path"] = export_path
        if imported_file_chunk_size_mib is not None:
            self._values["imported_file_chunk_size_mib"] = imported_file_chunk_size_mib
        if import_path is not None:
            self._values["import_path"] = import_path
        if per_unit_storage_throughput is not None:
            self._values["per_unit_storage_throughput"] = per_unit_storage_throughput
        if weekly_maintenance_start_time is not None:
            self._values["weekly_maintenance_start_time"] = weekly_maintenance_start_time

    @builtins.property
    def deployment_type(self) -> "LustreDeploymentType":
        '''The type of backing file system deployment used by FSx.'''
        result = self._values.get("deployment_type")
        assert result is not None, "Required property 'deployment_type' is missing"
        return typing.cast("LustreDeploymentType", result)

    @builtins.property
    def export_path(self) -> typing.Optional[builtins.str]:
        '''The path in Amazon S3 where the root of your Amazon FSx file system is exported.

        The path must use the same
        Amazon S3 bucket as specified in ImportPath. If you only specify a bucket name, such as s3://import-bucket, you
        get a 1:1 mapping of file system objects to S3 bucket objects. This mapping means that the input data in S3 is
        overwritten on export. If you provide a custom prefix in the export path, such as
        s3://import-bucket/[custom-optional-prefix], Amazon FSx exports the contents of your file system to that export
        prefix in the Amazon S3 bucket.

        :default: s3://import-bucket/FSxLustre[creation-timestamp]
        '''
        result = self._values.get("export_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def imported_file_chunk_size_mib(self) -> typing.Optional[jsii.Number]:
        '''For files imported from a data repository, this value determines the stripe count and maximum amount of data per file (in MiB) stored on a single physical disk.

        Allowed values are between 1 and 512,000.

        :default: 1024
        '''
        result = self._values.get("imported_file_chunk_size_mib")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def import_path(self) -> typing.Optional[builtins.str]:
        '''The path to the Amazon S3 bucket (including the optional prefix) that you're using as the data repository for your Amazon FSx for Lustre file system.

        Must be of the format "s3://{bucketName}/optional-prefix" and cannot
        exceed 900 characters.

        :default: - no bucket is imported
        '''
        result = self._values.get("import_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def per_unit_storage_throughput(self) -> typing.Optional[jsii.Number]:
        '''Required for the PERSISTENT_1 deployment type, describes the amount of read and write throughput for each 1 tebibyte of storage, in MB/s/TiB.

        Valid values are 50, 100, 200.

        :default: - no default, conditionally required for PERSISTENT_1 deployment type
        '''
        result = self._values.get("per_unit_storage_throughput")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def weekly_maintenance_start_time(self) -> typing.Optional["LustreMaintenanceTime"]:
        '''The preferred day and time to perform weekly maintenance.

        The first digit is the day of the week, starting at 1
        for Monday, then the following are hours and minutes in the UTC time zone, 24 hour clock. For example: '2:20:30'
        is Tuesdays at 20:30.

        :default: - no preference
        '''
        result = self._values.get("weekly_maintenance_start_time")
        return typing.cast(typing.Optional["LustreMaintenanceTime"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LustreConfiguration(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_fsx.LustreDeploymentType")
class LustreDeploymentType(enum.Enum):
    '''The different kinds of file system deployments used by Lustre.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        
        
        file_system = fsx.LustreFileSystem(self, "FsxLustreFileSystem",
            lustre_configuration=fsx.LustreConfiguration(deployment_type=fsx.LustreDeploymentType.SCRATCH_2),
            storage_capacity_gi_b=1200,
            vpc=vpc,
            vpc_subnet=vpc.private_subnets[0]
        )
    '''

    SCRATCH_1 = "SCRATCH_1"
    '''Original type for shorter term data processing.

    Data is not replicated and does not persist on server fail.
    '''
    SCRATCH_2 = "SCRATCH_2"
    '''Newer type for shorter term data processing.

    Data is not replicated and does not persist on server fail.
    Provides better support for spiky workloads.
    '''
    PERSISTENT_1 = "PERSISTENT_1"
    '''Long term storage.

    Data is replicated and file servers are replaced if they fail.
    '''
    PERSISTENT_2 = "PERSISTENT_2"
    '''Newer type of long term storage with higher throughput tiers.

    Data is replicated and file servers are replaced if they fail.
    '''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_fsx.LustreFileSystemProps",
    jsii_struct_bases=[FileSystemProps],
    name_mapping={
        "storage_capacity_gib": "storageCapacityGiB",
        "vpc": "vpc",
        "backup_id": "backupId",
        "kms_key": "kmsKey",
        "removal_policy": "removalPolicy",
        "security_group": "securityGroup",
        "lustre_configuration": "lustreConfiguration",
        "vpc_subnet": "vpcSubnet",
    },
)
class LustreFileSystemProps(FileSystemProps):
    def __init__(
        self,
        *,
        storage_capacity_gib: jsii.Number,
        vpc: _IVpc_f30d5663,
        backup_id: typing.Optional[builtins.str] = None,
        kms_key: typing.Optional[_IKey_5f11635f] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        lustre_configuration: LustreConfiguration,
        vpc_subnet: _ISubnet_d57d1229,
    ) -> None:
        '''Properties specific to the Lustre version of the FSx file system.

        :param storage_capacity_gib: The storage capacity of the file system being created. For Windows file systems, valid values are 32 GiB to 65,536 GiB. For SCRATCH_1 deployment types, valid values are 1,200, 2,400, 3,600, then continuing in increments of 3,600 GiB. For SCRATCH_2 and PERSISTENT_1 types, valid values are 1,200, 2,400, then continuing in increments of 2,400 GiB.
        :param vpc: The VPC to launch the file system in.
        :param backup_id: The ID of the backup. Specifies the backup to use if you're creating a file system from an existing backup. Default: - no backup will be used.
        :param kms_key: The KMS key used for encryption to protect your data at rest. Default: - the aws/fsx default KMS key for the AWS account being deployed into.
        :param removal_policy: Policy to apply when the file system is removed from the stack. Default: RemovalPolicy.RETAIN
        :param security_group: Security Group to assign to this file system. Default: - creates new security group which allows all outbound traffic.
        :param lustre_configuration: Additional configuration for FSx specific to Lustre.
        :param vpc_subnet: The subnet that the file system will be accessible from.

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            
            
            file_system = fsx.LustreFileSystem(self, "FsxLustreFileSystem",
                lustre_configuration=fsx.LustreConfiguration(deployment_type=fsx.LustreDeploymentType.SCRATCH_2),
                storage_capacity_gi_b=1200,
                vpc=vpc,
                vpc_subnet=vpc.private_subnets[0]
            )
        '''
        if isinstance(lustre_configuration, dict):
            lustre_configuration = LustreConfiguration(**lustre_configuration)
        self._values: typing.Dict[str, typing.Any] = {
            "storage_capacity_gib": storage_capacity_gib,
            "vpc": vpc,
            "lustre_configuration": lustre_configuration,
            "vpc_subnet": vpc_subnet,
        }
        if backup_id is not None:
            self._values["backup_id"] = backup_id
        if kms_key is not None:
            self._values["kms_key"] = kms_key
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if security_group is not None:
            self._values["security_group"] = security_group

    @builtins.property
    def storage_capacity_gib(self) -> jsii.Number:
        '''The storage capacity of the file system being created.

        For Windows file systems, valid values are 32 GiB to 65,536 GiB.
        For SCRATCH_1 deployment types, valid values are 1,200, 2,400, 3,600, then continuing in increments of 3,600 GiB.
        For SCRATCH_2 and PERSISTENT_1 types, valid values are 1,200, 2,400, then continuing in increments of 2,400 GiB.
        '''
        result = self._values.get("storage_capacity_gib")
        assert result is not None, "Required property 'storage_capacity_gib' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC to launch the file system in.'''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    @builtins.property
    def backup_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the backup.

        Specifies the backup to use if you're creating a file system from an existing backup.

        :default: - no backup will be used.
        '''
        result = self._values.get("backup_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kms_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The KMS key used for encryption to protect your data at rest.

        :default: - the aws/fsx default KMS key for the AWS account being deployed into.
        '''
        result = self._values.get("kms_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Policy to apply when the file system is removed from the stack.

        :default: RemovalPolicy.RETAIN
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security Group to assign to this file system.

        :default: - creates new security group which allows all outbound traffic.
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def lustre_configuration(self) -> LustreConfiguration:
        '''Additional configuration for FSx specific to Lustre.'''
        result = self._values.get("lustre_configuration")
        assert result is not None, "Required property 'lustre_configuration' is missing"
        return typing.cast(LustreConfiguration, result)

    @builtins.property
    def vpc_subnet(self) -> _ISubnet_d57d1229:
        '''The subnet that the file system will be accessible from.'''
        result = self._values.get("vpc_subnet")
        assert result is not None, "Required property 'vpc_subnet' is missing"
        return typing.cast(_ISubnet_d57d1229, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LustreFileSystemProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class LustreMaintenanceTime(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_fsx.LustreMaintenanceTime",
):
    '''Class for scheduling a weekly manitenance time.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_fsx as fsx
        
        lustre_maintenance_time = fsx.LustreMaintenanceTime(
            day=fsx.Weekday.MONDAY,
            hour=123,
            minute=123
        )
    '''

    def __init__(
        self,
        *,
        day: "Weekday",
        hour: jsii.Number,
        minute: jsii.Number,
    ) -> None:
        '''
        :param day: The day of the week for maintenance to be performed.
        :param hour: The hour of the day (from 0-24) for maintenance to be performed.
        :param minute: The minute of the hour (from 0-59) for maintenance to be performed.
        '''
        props = LustreMaintenanceTimeProps(day=day, hour=hour, minute=minute)

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="toTimestamp")
    def to_timestamp(self) -> builtins.str:
        '''Converts a day, hour, and minute into a timestamp as used by FSx for Lustre's weeklyMaintenanceStartTime field.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toTimestamp", []))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_fsx.LustreMaintenanceTimeProps",
    jsii_struct_bases=[],
    name_mapping={"day": "day", "hour": "hour", "minute": "minute"},
)
class LustreMaintenanceTimeProps:
    def __init__(
        self,
        *,
        day: "Weekday",
        hour: jsii.Number,
        minute: jsii.Number,
    ) -> None:
        '''Properties required for setting up a weekly maintenance time.

        :param day: The day of the week for maintenance to be performed.
        :param hour: The hour of the day (from 0-24) for maintenance to be performed.
        :param minute: The minute of the hour (from 0-59) for maintenance to be performed.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_fsx as fsx
            
            lustre_maintenance_time_props = fsx.LustreMaintenanceTimeProps(
                day=fsx.Weekday.MONDAY,
                hour=123,
                minute=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "day": day,
            "hour": hour,
            "minute": minute,
        }

    @builtins.property
    def day(self) -> "Weekday":
        '''The day of the week for maintenance to be performed.'''
        result = self._values.get("day")
        assert result is not None, "Required property 'day' is missing"
        return typing.cast("Weekday", result)

    @builtins.property
    def hour(self) -> jsii.Number:
        '''The hour of the day (from 0-24) for maintenance to be performed.'''
        result = self._values.get("hour")
        assert result is not None, "Required property 'hour' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def minute(self) -> jsii.Number:
        '''The minute of the hour (from 0-59) for maintenance to be performed.'''
        result = self._values.get("minute")
        assert result is not None, "Required property 'minute' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LustreMaintenanceTimeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_fsx.Weekday")
class Weekday(enum.Enum):
    '''Enum for representing all the days of the week.'''

    MONDAY = "MONDAY"
    '''Monday.'''
    TUESDAY = "TUESDAY"
    '''Tuesday.'''
    WEDNESDAY = "WEDNESDAY"
    '''Wednesday.'''
    THURSDAY = "THURSDAY"
    '''Thursday.'''
    FRIDAY = "FRIDAY"
    '''Friday.'''
    SATURDAY = "SATURDAY"
    '''Saturday.'''
    SUNDAY = "SUNDAY"
    '''Sunday.'''


@jsii.implements(IFileSystem)
class FileSystemBase(
    _Resource_45bc6135,
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_fsx.FileSystemBase",
):
    '''A new or imported FSx file system.'''

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

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    @abc.abstractmethod
    def connections(self) -> _Connections_0f31fce8:
        '''The security groups/rules used to allow network connections to the file system.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dnsName")
    @abc.abstractmethod
    def dns_name(self) -> builtins.str:
        '''The DNS name assigned to this file system.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fileSystemId")
    @abc.abstractmethod
    def file_system_id(self) -> builtins.str:
        '''The ID of the file system, assigned by Amazon FSx.

        :attribute: true
        '''
        ...


class _FileSystemBaseProxy(
    FileSystemBase, jsii.proxy_for(_Resource_45bc6135) # type: ignore[misc]
):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''The security groups/rules used to allow network connections to the file system.

        :attribute: true
        '''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dnsName")
    def dns_name(self) -> builtins.str:
        '''The DNS name assigned to this file system.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "dnsName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fileSystemId")
    def file_system_id(self) -> builtins.str:
        '''The ID of the file system, assigned by Amazon FSx.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "fileSystemId"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, FileSystemBase).__jsii_proxy_class__ = lambda : _FileSystemBaseProxy


class LustreFileSystem(
    FileSystemBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_fsx.LustreFileSystem",
):
    '''The FSx for Lustre File System implementation of IFileSystem.

    :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fsx-filesystem.html
    :exampleMetadata: infused
    :resource: AWS::FSx::FileSystem

    Example::

        sg = ec2.SecurityGroup.from_security_group_id(self, "FsxSecurityGroup", "{SECURITY-GROUP-ID}")
        fs = fsx.LustreFileSystem.from_lustre_file_system_attributes(self, "FsxLustreFileSystem",
            dns_name="{FILE-SYSTEM-DNS-NAME}",
            file_system_id="{FILE-SYSTEM-ID}",
            security_group=sg
        )
        
        vpc = ec2.Vpc.from_vpc_attributes(self, "Vpc",
            availability_zones=["us-west-2a", "us-west-2b"],
            public_subnet_ids=["{US-WEST-2A-SUBNET-ID}", "{US-WEST-2B-SUBNET-ID}"],
            vpc_id="{VPC-ID}"
        )
        
        inst = ec2.Instance(self, "inst",
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.LARGE),
            machine_image=ec2.AmazonLinuxImage(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC
            )
        )
        
        fs.connections.allow_default_port_from(inst)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        lustre_configuration: LustreConfiguration,
        vpc_subnet: _ISubnet_d57d1229,
        storage_capacity_gib: jsii.Number,
        vpc: _IVpc_f30d5663,
        backup_id: typing.Optional[builtins.str] = None,
        kms_key: typing.Optional[_IKey_5f11635f] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param lustre_configuration: Additional configuration for FSx specific to Lustre.
        :param vpc_subnet: The subnet that the file system will be accessible from.
        :param storage_capacity_gib: The storage capacity of the file system being created. For Windows file systems, valid values are 32 GiB to 65,536 GiB. For SCRATCH_1 deployment types, valid values are 1,200, 2,400, 3,600, then continuing in increments of 3,600 GiB. For SCRATCH_2 and PERSISTENT_1 types, valid values are 1,200, 2,400, then continuing in increments of 2,400 GiB.
        :param vpc: The VPC to launch the file system in.
        :param backup_id: The ID of the backup. Specifies the backup to use if you're creating a file system from an existing backup. Default: - no backup will be used.
        :param kms_key: The KMS key used for encryption to protect your data at rest. Default: - the aws/fsx default KMS key for the AWS account being deployed into.
        :param removal_policy: Policy to apply when the file system is removed from the stack. Default: RemovalPolicy.RETAIN
        :param security_group: Security Group to assign to this file system. Default: - creates new security group which allows all outbound traffic.
        '''
        props = LustreFileSystemProps(
            lustre_configuration=lustre_configuration,
            vpc_subnet=vpc_subnet,
            storage_capacity_gib=storage_capacity_gib,
            vpc=vpc,
            backup_id=backup_id,
            kms_key=kms_key,
            removal_policy=removal_policy,
            security_group=security_group,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromLustreFileSystemAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_lustre_file_system_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        dns_name: builtins.str,
        file_system_id: builtins.str,
        security_group: _ISecurityGroup_acf8a799,
    ) -> IFileSystem:
        '''Import an existing FSx for Lustre file system from the given properties.

        :param scope: -
        :param id: -
        :param dns_name: The DNS name assigned to this file system.
        :param file_system_id: The ID of the file system, assigned by Amazon FSx.
        :param security_group: The security group of the file system.
        '''
        attrs = FileSystemAttributes(
            dns_name=dns_name,
            file_system_id=file_system_id,
            security_group=security_group,
        )

        return typing.cast(IFileSystem, jsii.sinvoke(cls, "fromLustreFileSystemAttributes", [scope, id, attrs]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''The security groups/rules used to allow network connections to the file system.'''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dnsName")
    def dns_name(self) -> builtins.str:
        '''The DNS name assigned to this file system.'''
        return typing.cast(builtins.str, jsii.get(self, "dnsName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fileSystemId")
    def file_system_id(self) -> builtins.str:
        '''The ID that AWS assigns to the file system.'''
        return typing.cast(builtins.str, jsii.get(self, "fileSystemId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="mountName")
    def mount_name(self) -> builtins.str:
        '''The mount name of the file system, generated by FSx.

        :attribute: LustreMountName
        '''
        return typing.cast(builtins.str, jsii.get(self, "mountName"))


__all__ = [
    "CfnFileSystem",
    "CfnFileSystemProps",
    "FileSystemAttributes",
    "FileSystemBase",
    "FileSystemProps",
    "IFileSystem",
    "LustreConfiguration",
    "LustreDeploymentType",
    "LustreFileSystem",
    "LustreFileSystemProps",
    "LustreMaintenanceTime",
    "LustreMaintenanceTimeProps",
    "Weekday",
]

publication.publish()
