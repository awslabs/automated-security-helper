'''
# AWS Backup Construct Library

AWS Backup is a fully managed backup service that makes it easy to centralize and automate the
backup of data across AWS services in the cloud and on premises. Using AWS Backup, you can
configure backup policies and monitor backup activity for your AWS resources in one place.

## Backup plan and selection

In AWS Backup, a *backup plan* is a policy expression that defines when and how you want to back up
your AWS resources, such as Amazon DynamoDB tables or Amazon Elastic File System (Amazon EFS) file
systems. You can assign resources to backup plans, and AWS Backup automatically backs up and retains
backups for those resources according to the backup plan. You can create multiple backup plans if you
have workloads with different backup requirements.

This module provides ready-made backup plans (similar to the console experience):

```python
# Daily, weekly and monthly with 5 year retention
plan = backup.BackupPlan.daily_weekly_monthly5_year_retention(self, "Plan")
```

Assigning resources to a plan can be done with `addSelection()`:

```python
# plan: backup.BackupPlan

my_table = dynamodb.Table.from_table_name(self, "Table", "myTableName")
my_cool_construct = Construct(self, "MyCoolConstruct")

plan.add_selection("Selection",
    resources=[
        backup.BackupResource.from_dynamo_db_table(my_table),  # A DynamoDB table
        backup.BackupResource.from_tag("stage", "prod"),  # All resources that are tagged stage=prod in the region/account
        backup.BackupResource.from_construct(my_cool_construct)
    ]
)
```

If not specified, a new IAM role with a managed policy for backup will be
created for the selection. The `BackupSelection` implements `IGrantable`.

To add rules to a plan, use `addRule()`:

```python
# plan: backup.BackupPlan

plan.add_rule(backup.BackupPlanRule(
    completion_window=Duration.hours(2),
    start_window=Duration.hours(1),
    schedule_expression=events.Schedule.cron( # Only cron expressions are supported
        day="15",
        hour="3",
        minute="30"),
    move_to_cold_storage_after=Duration.days(30)
))
```

Continuous backup and point-in-time restores (PITR) can be configured.
Property `deleteAfter` defines the retention period for the backup. It is mandatory if PITR is enabled.
If no value is specified, the retention period is set to 35 days which is the maximum retention period supported by PITR.
Property `moveToColdStorageAfter` must not be specified because PITR does not support this option.
This example defines an AWS Backup rule with PITR and a retention period set to 14 days:

```python
# plan: backup.BackupPlan

plan.add_rule(backup.BackupPlanRule(
    enable_continuous_backup=True,
    delete_after=Duration.days(14)
))
```

Ready-made rules are also available:

```python
# plan: backup.BackupPlan

plan.add_rule(backup.BackupPlanRule.daily())
plan.add_rule(backup.BackupPlanRule.weekly())
```

By default a new [vault](#Backup-vault) is created when creating a plan.
It is also possible to specify a vault either at the plan level or at the
rule level.

```python
my_vault = backup.BackupVault.from_backup_vault_name(self, "Vault1", "myVault")
other_vault = backup.BackupVault.from_backup_vault_name(self, "Vault2", "otherVault")

plan = backup.BackupPlan.daily35_day_retention(self, "Plan", my_vault) # Use `myVault` for all plan rules
plan.add_rule(backup.BackupPlanRule.monthly1_year(other_vault))
```

You can [backup](https://docs.aws.amazon.com/aws-backup/latest/devguide/windows-backups.html)
VSS-enabled Windows applications running on Amazon EC2 instances by setting the `windowsVss`
parameter to `true`. If the application has VSS writer registered with Windows VSS,
then AWS Backup creates a snapshot that will be consistent for that application.

```python
plan = backup.BackupPlan(self, "Plan",
    windows_vss=True
)
```

## Backup vault

In AWS Backup, a *backup vault* is a container that you organize your backups in. You can use backup
vaults to set the AWS Key Management Service (AWS KMS) encryption key that is used to encrypt backups
in the backup vault and to control access to the backups in the backup vault. If you require different
encryption keys or access policies for different groups of backups, you can optionally create multiple
backup vaults.

```python
my_key = kms.Key.from_key_arn(self, "MyKey", "aaa")
my_topic = sns.Topic.from_topic_arn(self, "MyTopic", "bbb")

vault = backup.BackupVault(self, "Vault",
    encryption_key=my_key,  # Custom encryption key
    notification_topic=my_topic
)
```

A vault has a default `RemovalPolicy` set to `RETAIN`. Note that removing a vault
that contains recovery points will fail.

You can assign policies to backup vaults and the resources they contain. Assigning policies allows
you to do things like grant access to users to create backup plans and on-demand backups, but limit
their ability to delete recovery points after they're created.

Use the `accessPolicy` property to create a backup vault policy:

```python
vault = backup.BackupVault(self, "Vault",
    access_policy=iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["backup:DeleteRecoveryPoint"],
                resources=["*"],
                conditions={
                    "StringNotLike": {
                        "aws:user_id": ["user1", "user2"
                        ]
                    }
                }
            )
        ]
    )
)
```

Alternativately statements can be added to the vault policy using `addToAccessPolicy()`.

Use the `blockRecoveryPointDeletion` property or the `blockRecoveryPointDeletion()` method to add
a statement to the vault access policy that prevents recovery point deletions in your vault:

```python
# backup_vault: backup.BackupVault
backup.BackupVault(self, "Vault",
    block_recovery_point_deletion=True
)
backup_vault.block_recovery_point_deletion()
```

By default access is not restricted.

## Importing existing backup vault

To import an existing backup vault into your CDK application, use the `BackupVault.fromBackupVaultArn` or `BackupVault.fromBackupVaultName`
static method. Here is an example of giving an IAM Role permission to start a backup job:

```python
imported_vault = backup.BackupVault.from_backup_vault_name(self, "Vault", "myVaultName")

role = iam.Role(self, "Access Role", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))

imported_vault.grant(role, "backup:StartBackupJob")
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
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_dynamodb import ITable as _ITable_504fd401
from ..aws_ec2 import IInstance as _IInstance_ab239e7c
from ..aws_efs import IFileSystem as _IFileSystem_b2d3a7cb
from ..aws_events import Schedule as _Schedule_c151d01f
from ..aws_iam import (
    Grant as _Grant_a7ae64f8,
    IGrantable as _IGrantable_71c4f5de,
    IPrincipal as _IPrincipal_539bb2fd,
    IRole as _IRole_235f5d8e,
    PolicyDocument as _PolicyDocument_3ac34393,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_kms import IKey as _IKey_5f11635f
from ..aws_rds import IDatabaseInstance as _IDatabaseInstance_e4cb03a8
from ..aws_sns import ITopic as _ITopic_9eca4852


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.BackupPlanProps",
    jsii_struct_bases=[],
    name_mapping={
        "backup_plan_name": "backupPlanName",
        "backup_plan_rules": "backupPlanRules",
        "backup_vault": "backupVault",
        "windows_vss": "windowsVss",
    },
)
class BackupPlanProps:
    def __init__(
        self,
        *,
        backup_plan_name: typing.Optional[builtins.str] = None,
        backup_plan_rules: typing.Optional[typing.Sequence["BackupPlanRule"]] = None,
        backup_vault: typing.Optional["IBackupVault"] = None,
        windows_vss: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Properties for a BackupPlan.

        :param backup_plan_name: The display name of the backup plan. Default: - A CDK generated name
        :param backup_plan_rules: Rules for the backup plan. Use ``addRule()`` to add rules after instantiation. Default: - use ``addRule()`` to add rules
        :param backup_vault: The backup vault where backups are stored. Default: - use the vault defined at the rule level. If not defined a new common vault for the plan will be created
        :param windows_vss: Enable Windows VSS backup. Default: false

        :exampleMetadata: infused

        Example::

            plan = backup.BackupPlan(self, "Plan",
                windows_vss=True
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if backup_plan_name is not None:
            self._values["backup_plan_name"] = backup_plan_name
        if backup_plan_rules is not None:
            self._values["backup_plan_rules"] = backup_plan_rules
        if backup_vault is not None:
            self._values["backup_vault"] = backup_vault
        if windows_vss is not None:
            self._values["windows_vss"] = windows_vss

    @builtins.property
    def backup_plan_name(self) -> typing.Optional[builtins.str]:
        '''The display name of the backup plan.

        :default: - A CDK generated name
        '''
        result = self._values.get("backup_plan_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def backup_plan_rules(self) -> typing.Optional[typing.List["BackupPlanRule"]]:
        '''Rules for the backup plan.

        Use ``addRule()`` to add rules after
        instantiation.

        :default: - use ``addRule()`` to add rules
        '''
        result = self._values.get("backup_plan_rules")
        return typing.cast(typing.Optional[typing.List["BackupPlanRule"]], result)

    @builtins.property
    def backup_vault(self) -> typing.Optional["IBackupVault"]:
        '''The backup vault where backups are stored.

        :default:

        - use the vault defined at the rule level. If not defined a new
        common vault for the plan will be created
        '''
        result = self._values.get("backup_vault")
        return typing.cast(typing.Optional["IBackupVault"], result)

    @builtins.property
    def windows_vss(self) -> typing.Optional[builtins.bool]:
        '''Enable Windows VSS backup.

        :default: false

        :see: https://docs.aws.amazon.com/aws-backup/latest/devguide/windows-backups.html
        '''
        result = self._values.get("windows_vss")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BackupPlanProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class BackupPlanRule(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.BackupPlanRule",
):
    '''A backup plan rule.

    :exampleMetadata: infused

    Example::

        # plan: backup.BackupPlan
        
        plan.add_rule(backup.BackupPlanRule.daily())
        plan.add_rule(backup.BackupPlanRule.weekly())
    '''

    def __init__(
        self,
        *,
        backup_vault: typing.Optional["IBackupVault"] = None,
        completion_window: typing.Optional[_Duration_4839e8c3] = None,
        delete_after: typing.Optional[_Duration_4839e8c3] = None,
        enable_continuous_backup: typing.Optional[builtins.bool] = None,
        move_to_cold_storage_after: typing.Optional[_Duration_4839e8c3] = None,
        rule_name: typing.Optional[builtins.str] = None,
        schedule_expression: typing.Optional[_Schedule_c151d01f] = None,
        start_window: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param backup_vault: The backup vault where backups are. Default: - use the vault defined at the plan level. If not defined a new common vault for the plan will be created
        :param completion_window: The duration after a backup job is successfully started before it must be completed or it is canceled by AWS Backup. Default: - 8 hours
        :param delete_after: Specifies the duration after creation that a recovery point is deleted. Must be greater than ``moveToColdStorageAfter``. Default: - recovery point is never deleted
        :param enable_continuous_backup: Enables continuous backup and point-in-time restores (PITR). Property ``deleteAfter`` defines the retention period for the backup. It is mandatory if PITR is enabled. If no value is specified, the retention period is set to 35 days which is the maximum retention period supported by PITR. Property ``moveToColdStorageAfter`` must not be specified because PITR does not support this option. Default: false
        :param move_to_cold_storage_after: Specifies the duration after creation that a recovery point is moved to cold storage. Default: - recovery point is never moved to cold storage
        :param rule_name: A display name for the backup rule. Default: - a CDK generated name
        :param schedule_expression: A CRON expression specifying when AWS Backup initiates a backup job. Default: - no schedule
        :param start_window: The duration after a backup is scheduled before a job is canceled if it doesn't start successfully. Default: - 8 hours
        '''
        props = BackupPlanRuleProps(
            backup_vault=backup_vault,
            completion_window=completion_window,
            delete_after=delete_after,
            enable_continuous_backup=enable_continuous_backup,
            move_to_cold_storage_after=move_to_cold_storage_after,
            rule_name=rule_name,
            schedule_expression=schedule_expression,
            start_window=start_window,
        )

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="daily") # type: ignore[misc]
    @builtins.classmethod
    def daily(
        cls,
        backup_vault: typing.Optional["IBackupVault"] = None,
    ) -> "BackupPlanRule":
        '''Daily with 35 days retention.

        :param backup_vault: -
        '''
        return typing.cast("BackupPlanRule", jsii.sinvoke(cls, "daily", [backup_vault]))

    @jsii.member(jsii_name="monthly1Year") # type: ignore[misc]
    @builtins.classmethod
    def monthly1_year(
        cls,
        backup_vault: typing.Optional["IBackupVault"] = None,
    ) -> "BackupPlanRule":
        '''Monthly 1 year retention, move to cold storage after 1 month.

        :param backup_vault: -
        '''
        return typing.cast("BackupPlanRule", jsii.sinvoke(cls, "monthly1Year", [backup_vault]))

    @jsii.member(jsii_name="monthly5Year") # type: ignore[misc]
    @builtins.classmethod
    def monthly5_year(
        cls,
        backup_vault: typing.Optional["IBackupVault"] = None,
    ) -> "BackupPlanRule":
        '''Monthly 5 year retention, move to cold storage after 3 months.

        :param backup_vault: -
        '''
        return typing.cast("BackupPlanRule", jsii.sinvoke(cls, "monthly5Year", [backup_vault]))

    @jsii.member(jsii_name="monthly7Year") # type: ignore[misc]
    @builtins.classmethod
    def monthly7_year(
        cls,
        backup_vault: typing.Optional["IBackupVault"] = None,
    ) -> "BackupPlanRule":
        '''Monthly 7 year retention, move to cold storage after 3 months.

        :param backup_vault: -
        '''
        return typing.cast("BackupPlanRule", jsii.sinvoke(cls, "monthly7Year", [backup_vault]))

    @jsii.member(jsii_name="weekly") # type: ignore[misc]
    @builtins.classmethod
    def weekly(
        cls,
        backup_vault: typing.Optional["IBackupVault"] = None,
    ) -> "BackupPlanRule":
        '''Weekly with 3 months retention.

        :param backup_vault: -
        '''
        return typing.cast("BackupPlanRule", jsii.sinvoke(cls, "weekly", [backup_vault]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="props")
    def props(self) -> "BackupPlanRuleProps":
        '''Properties of BackupPlanRule.'''
        return typing.cast("BackupPlanRuleProps", jsii.get(self, "props"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.BackupPlanRuleProps",
    jsii_struct_bases=[],
    name_mapping={
        "backup_vault": "backupVault",
        "completion_window": "completionWindow",
        "delete_after": "deleteAfter",
        "enable_continuous_backup": "enableContinuousBackup",
        "move_to_cold_storage_after": "moveToColdStorageAfter",
        "rule_name": "ruleName",
        "schedule_expression": "scheduleExpression",
        "start_window": "startWindow",
    },
)
class BackupPlanRuleProps:
    def __init__(
        self,
        *,
        backup_vault: typing.Optional["IBackupVault"] = None,
        completion_window: typing.Optional[_Duration_4839e8c3] = None,
        delete_after: typing.Optional[_Duration_4839e8c3] = None,
        enable_continuous_backup: typing.Optional[builtins.bool] = None,
        move_to_cold_storage_after: typing.Optional[_Duration_4839e8c3] = None,
        rule_name: typing.Optional[builtins.str] = None,
        schedule_expression: typing.Optional[_Schedule_c151d01f] = None,
        start_window: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Properties for a BackupPlanRule.

        :param backup_vault: The backup vault where backups are. Default: - use the vault defined at the plan level. If not defined a new common vault for the plan will be created
        :param completion_window: The duration after a backup job is successfully started before it must be completed or it is canceled by AWS Backup. Default: - 8 hours
        :param delete_after: Specifies the duration after creation that a recovery point is deleted. Must be greater than ``moveToColdStorageAfter``. Default: - recovery point is never deleted
        :param enable_continuous_backup: Enables continuous backup and point-in-time restores (PITR). Property ``deleteAfter`` defines the retention period for the backup. It is mandatory if PITR is enabled. If no value is specified, the retention period is set to 35 days which is the maximum retention period supported by PITR. Property ``moveToColdStorageAfter`` must not be specified because PITR does not support this option. Default: false
        :param move_to_cold_storage_after: Specifies the duration after creation that a recovery point is moved to cold storage. Default: - recovery point is never moved to cold storage
        :param rule_name: A display name for the backup rule. Default: - a CDK generated name
        :param schedule_expression: A CRON expression specifying when AWS Backup initiates a backup job. Default: - no schedule
        :param start_window: The duration after a backup is scheduled before a job is canceled if it doesn't start successfully. Default: - 8 hours

        :exampleMetadata: infused

        Example::

            # plan: backup.BackupPlan
            
            plan.add_rule(backup.BackupPlanRule(
                completion_window=Duration.hours(2),
                start_window=Duration.hours(1),
                schedule_expression=events.Schedule.cron( # Only cron expressions are supported
                    day="15",
                    hour="3",
                    minute="30"),
                move_to_cold_storage_after=Duration.days(30)
            ))
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if backup_vault is not None:
            self._values["backup_vault"] = backup_vault
        if completion_window is not None:
            self._values["completion_window"] = completion_window
        if delete_after is not None:
            self._values["delete_after"] = delete_after
        if enable_continuous_backup is not None:
            self._values["enable_continuous_backup"] = enable_continuous_backup
        if move_to_cold_storage_after is not None:
            self._values["move_to_cold_storage_after"] = move_to_cold_storage_after
        if rule_name is not None:
            self._values["rule_name"] = rule_name
        if schedule_expression is not None:
            self._values["schedule_expression"] = schedule_expression
        if start_window is not None:
            self._values["start_window"] = start_window

    @builtins.property
    def backup_vault(self) -> typing.Optional["IBackupVault"]:
        '''The backup vault where backups are.

        :default:

        - use the vault defined at the plan level. If not defined a new
        common vault for the plan will be created
        '''
        result = self._values.get("backup_vault")
        return typing.cast(typing.Optional["IBackupVault"], result)

    @builtins.property
    def completion_window(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The duration after a backup job is successfully started before it must be completed or it is canceled by AWS Backup.

        :default: - 8 hours
        '''
        result = self._values.get("completion_window")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def delete_after(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Specifies the duration after creation that a recovery point is deleted.

        Must be greater than ``moveToColdStorageAfter``.

        :default: - recovery point is never deleted
        '''
        result = self._values.get("delete_after")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def enable_continuous_backup(self) -> typing.Optional[builtins.bool]:
        '''Enables continuous backup and point-in-time restores (PITR).

        Property ``deleteAfter`` defines the retention period for the backup. It is mandatory if PITR is enabled.
        If no value is specified, the retention period is set to 35 days which is the maximum retention period supported by PITR.

        Property ``moveToColdStorageAfter`` must not be specified because PITR does not support this option.

        :default: false
        '''
        result = self._values.get("enable_continuous_backup")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def move_to_cold_storage_after(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Specifies the duration after creation that a recovery point is moved to cold storage.

        :default: - recovery point is never moved to cold storage
        '''
        result = self._values.get("move_to_cold_storage_after")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def rule_name(self) -> typing.Optional[builtins.str]:
        '''A display name for the backup rule.

        :default: - a CDK generated name
        '''
        result = self._values.get("rule_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def schedule_expression(self) -> typing.Optional[_Schedule_c151d01f]:
        '''A CRON expression specifying when AWS Backup initiates a backup job.

        :default: - no schedule
        '''
        result = self._values.get("schedule_expression")
        return typing.cast(typing.Optional[_Schedule_c151d01f], result)

    @builtins.property
    def start_window(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The duration after a backup is scheduled before a job is canceled if it doesn't start successfully.

        :default: - 8 hours
        '''
        result = self._values.get("start_window")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BackupPlanRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class BackupResource(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.BackupResource",
):
    '''A resource to backup.

    :exampleMetadata: infused

    Example::

        # plan: backup.BackupPlan
        
        my_table = dynamodb.Table.from_table_name(self, "Table", "myTableName")
        my_cool_construct = Construct(self, "MyCoolConstruct")
        
        plan.add_selection("Selection",
            resources=[
                backup.BackupResource.from_dynamo_db_table(my_table),  # A DynamoDB table
                backup.BackupResource.from_tag("stage", "prod"),  # All resources that are tagged stage=prod in the region/account
                backup.BackupResource.from_construct(my_cool_construct)
            ]
        )
    '''

    def __init__(
        self,
        resource: typing.Optional[builtins.str] = None,
        tag_condition: typing.Optional["TagCondition"] = None,
        construct: typing.Optional[constructs.Construct] = None,
    ) -> None:
        '''
        :param resource: -
        :param tag_condition: -
        :param construct: -
        '''
        jsii.create(self.__class__, self, [resource, tag_condition, construct])

    @jsii.member(jsii_name="fromArn") # type: ignore[misc]
    @builtins.classmethod
    def from_arn(cls, arn: builtins.str) -> "BackupResource":
        '''A list of ARNs or match patterns such as ``arn:aws:ec2:us-east-1:123456789012:volume/*``.

        :param arn: -
        '''
        return typing.cast("BackupResource", jsii.sinvoke(cls, "fromArn", [arn]))

    @jsii.member(jsii_name="fromConstruct") # type: ignore[misc]
    @builtins.classmethod
    def from_construct(cls, construct: constructs.Construct) -> "BackupResource":
        '''Adds all supported resources in a construct.

        :param construct: The construct containing resources to backup.
        '''
        return typing.cast("BackupResource", jsii.sinvoke(cls, "fromConstruct", [construct]))

    @jsii.member(jsii_name="fromDynamoDbTable") # type: ignore[misc]
    @builtins.classmethod
    def from_dynamo_db_table(cls, table: _ITable_504fd401) -> "BackupResource":
        '''A DynamoDB table.

        :param table: -
        '''
        return typing.cast("BackupResource", jsii.sinvoke(cls, "fromDynamoDbTable", [table]))

    @jsii.member(jsii_name="fromEc2Instance") # type: ignore[misc]
    @builtins.classmethod
    def from_ec2_instance(cls, instance: _IInstance_ab239e7c) -> "BackupResource":
        '''An EC2 instance.

        :param instance: -
        '''
        return typing.cast("BackupResource", jsii.sinvoke(cls, "fromEc2Instance", [instance]))

    @jsii.member(jsii_name="fromEfsFileSystem") # type: ignore[misc]
    @builtins.classmethod
    def from_efs_file_system(
        cls,
        file_system: _IFileSystem_b2d3a7cb,
    ) -> "BackupResource":
        '''An EFS file system.

        :param file_system: -
        '''
        return typing.cast("BackupResource", jsii.sinvoke(cls, "fromEfsFileSystem", [file_system]))

    @jsii.member(jsii_name="fromRdsDatabaseInstance") # type: ignore[misc]
    @builtins.classmethod
    def from_rds_database_instance(
        cls,
        instance: _IDatabaseInstance_e4cb03a8,
    ) -> "BackupResource":
        '''A RDS database instance.

        :param instance: -
        '''
        return typing.cast("BackupResource", jsii.sinvoke(cls, "fromRdsDatabaseInstance", [instance]))

    @jsii.member(jsii_name="fromTag") # type: ignore[misc]
    @builtins.classmethod
    def from_tag(
        cls,
        key: builtins.str,
        value: builtins.str,
        operation: typing.Optional["TagOperation"] = None,
    ) -> "BackupResource":
        '''A tag condition.

        :param key: -
        :param value: -
        :param operation: -
        '''
        return typing.cast("BackupResource", jsii.sinvoke(cls, "fromTag", [key, value, operation]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="construct")
    def construct(self) -> typing.Optional[constructs.Construct]:
        '''A construct.'''
        return typing.cast(typing.Optional[constructs.Construct], jsii.get(self, "construct"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resource")
    def resource(self) -> typing.Optional[builtins.str]:
        '''A resource.'''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "resource"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tagCondition")
    def tag_condition(self) -> typing.Optional["TagCondition"]:
        '''A condition on a tag.'''
        return typing.cast(typing.Optional["TagCondition"], jsii.get(self, "tagCondition"))


@jsii.implements(_IGrantable_71c4f5de)
class BackupSelection(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.BackupSelection",
):
    '''A backup selection.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_backup as backup
        from aws_cdk import aws_iam as iam
        
        # backup_plan: backup.BackupPlan
        # backup_resource: backup.BackupResource
        # role: iam.Role
        
        backup_selection = backup.BackupSelection(self, "MyBackupSelection",
            backup_plan=backup_plan,
            resources=[backup_resource],
        
            # the properties below are optional
            allow_restores=False,
            backup_selection_name="backupSelectionName",
            role=role
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        backup_plan: "IBackupPlan",
        resources: typing.Sequence[BackupResource],
        allow_restores: typing.Optional[builtins.bool] = None,
        backup_selection_name: typing.Optional[builtins.str] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param backup_plan: The backup plan for this selection.
        :param resources: The resources to backup. Use the helper static methods defined on ``BackupResource``.
        :param allow_restores: Whether to automatically give restores permissions to the role that AWS Backup uses. If ``true``, the ``AWSBackupServiceRolePolicyForRestores`` managed policy will be attached to the role. Default: false
        :param backup_selection_name: The name for this selection. Default: - a CDK generated name
        :param role: The role that AWS Backup uses to authenticate when backuping or restoring the resources. The ``AWSBackupServiceRolePolicyForBackup`` managed policy will be attached to this role. Default: - a new role will be created
        '''
        props = BackupSelectionProps(
            backup_plan=backup_plan,
            resources=resources,
            allow_restores=allow_restores,
            backup_selection_name=backup_selection_name,
            role=role,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupPlanId")
    def backup_plan_id(self) -> builtins.str:
        '''The identifier of the backup plan.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "backupPlanId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> _IPrincipal_539bb2fd:
        '''The principal to grant permissions to.'''
        return typing.cast(_IPrincipal_539bb2fd, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="selectionId")
    def selection_id(self) -> builtins.str:
        '''The identifier of the backup selection.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "selectionId"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.BackupSelectionOptions",
    jsii_struct_bases=[],
    name_mapping={
        "resources": "resources",
        "allow_restores": "allowRestores",
        "backup_selection_name": "backupSelectionName",
        "role": "role",
    },
)
class BackupSelectionOptions:
    def __init__(
        self,
        *,
        resources: typing.Sequence[BackupResource],
        allow_restores: typing.Optional[builtins.bool] = None,
        backup_selection_name: typing.Optional[builtins.str] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''Options for a BackupSelection.

        :param resources: The resources to backup. Use the helper static methods defined on ``BackupResource``.
        :param allow_restores: Whether to automatically give restores permissions to the role that AWS Backup uses. If ``true``, the ``AWSBackupServiceRolePolicyForRestores`` managed policy will be attached to the role. Default: false
        :param backup_selection_name: The name for this selection. Default: - a CDK generated name
        :param role: The role that AWS Backup uses to authenticate when backuping or restoring the resources. The ``AWSBackupServiceRolePolicyForBackup`` managed policy will be attached to this role. Default: - a new role will be created

        :exampleMetadata: infused

        Example::

            # plan: backup.BackupPlan
            
            my_table = dynamodb.Table.from_table_name(self, "Table", "myTableName")
            my_cool_construct = Construct(self, "MyCoolConstruct")
            
            plan.add_selection("Selection",
                resources=[
                    backup.BackupResource.from_dynamo_db_table(my_table),  # A DynamoDB table
                    backup.BackupResource.from_tag("stage", "prod"),  # All resources that are tagged stage=prod in the region/account
                    backup.BackupResource.from_construct(my_cool_construct)
                ]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resources": resources,
        }
        if allow_restores is not None:
            self._values["allow_restores"] = allow_restores
        if backup_selection_name is not None:
            self._values["backup_selection_name"] = backup_selection_name
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def resources(self) -> typing.List[BackupResource]:
        '''The resources to backup.

        Use the helper static methods defined on ``BackupResource``.
        '''
        result = self._values.get("resources")
        assert result is not None, "Required property 'resources' is missing"
        return typing.cast(typing.List[BackupResource], result)

    @builtins.property
    def allow_restores(self) -> typing.Optional[builtins.bool]:
        '''Whether to automatically give restores permissions to the role that AWS Backup uses.

        If ``true``, the ``AWSBackupServiceRolePolicyForRestores`` managed
        policy will be attached to the role.

        :default: false
        '''
        result = self._values.get("allow_restores")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def backup_selection_name(self) -> typing.Optional[builtins.str]:
        '''The name for this selection.

        :default: - a CDK generated name
        '''
        result = self._values.get("backup_selection_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The role that AWS Backup uses to authenticate when backuping or restoring the resources.

        The ``AWSBackupServiceRolePolicyForBackup`` managed policy
        will be attached to this role.

        :default: - a new role will be created
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BackupSelectionOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.BackupSelectionProps",
    jsii_struct_bases=[BackupSelectionOptions],
    name_mapping={
        "resources": "resources",
        "allow_restores": "allowRestores",
        "backup_selection_name": "backupSelectionName",
        "role": "role",
        "backup_plan": "backupPlan",
    },
)
class BackupSelectionProps(BackupSelectionOptions):
    def __init__(
        self,
        *,
        resources: typing.Sequence[BackupResource],
        allow_restores: typing.Optional[builtins.bool] = None,
        backup_selection_name: typing.Optional[builtins.str] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        backup_plan: "IBackupPlan",
    ) -> None:
        '''Properties for a BackupSelection.

        :param resources: The resources to backup. Use the helper static methods defined on ``BackupResource``.
        :param allow_restores: Whether to automatically give restores permissions to the role that AWS Backup uses. If ``true``, the ``AWSBackupServiceRolePolicyForRestores`` managed policy will be attached to the role. Default: false
        :param backup_selection_name: The name for this selection. Default: - a CDK generated name
        :param role: The role that AWS Backup uses to authenticate when backuping or restoring the resources. The ``AWSBackupServiceRolePolicyForBackup`` managed policy will be attached to this role. Default: - a new role will be created
        :param backup_plan: The backup plan for this selection.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_backup as backup
            from aws_cdk import aws_iam as iam
            
            # backup_plan: backup.BackupPlan
            # backup_resource: backup.BackupResource
            # role: iam.Role
            
            backup_selection_props = backup.BackupSelectionProps(
                backup_plan=backup_plan,
                resources=[backup_resource],
            
                # the properties below are optional
                allow_restores=False,
                backup_selection_name="backupSelectionName",
                role=role
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resources": resources,
            "backup_plan": backup_plan,
        }
        if allow_restores is not None:
            self._values["allow_restores"] = allow_restores
        if backup_selection_name is not None:
            self._values["backup_selection_name"] = backup_selection_name
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def resources(self) -> typing.List[BackupResource]:
        '''The resources to backup.

        Use the helper static methods defined on ``BackupResource``.
        '''
        result = self._values.get("resources")
        assert result is not None, "Required property 'resources' is missing"
        return typing.cast(typing.List[BackupResource], result)

    @builtins.property
    def allow_restores(self) -> typing.Optional[builtins.bool]:
        '''Whether to automatically give restores permissions to the role that AWS Backup uses.

        If ``true``, the ``AWSBackupServiceRolePolicyForRestores`` managed
        policy will be attached to the role.

        :default: false
        '''
        result = self._values.get("allow_restores")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def backup_selection_name(self) -> typing.Optional[builtins.str]:
        '''The name for this selection.

        :default: - a CDK generated name
        '''
        result = self._values.get("backup_selection_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The role that AWS Backup uses to authenticate when backuping or restoring the resources.

        The ``AWSBackupServiceRolePolicyForBackup`` managed policy
        will be attached to this role.

        :default: - a new role will be created
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def backup_plan(self) -> "IBackupPlan":
        '''The backup plan for this selection.'''
        result = self._values.get("backup_plan")
        assert result is not None, "Required property 'backup_plan' is missing"
        return typing.cast("IBackupPlan", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BackupSelectionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_backup.BackupVaultEvents")
class BackupVaultEvents(enum.Enum):
    '''Backup vault events.'''

    BACKUP_JOB_STARTED = "BACKUP_JOB_STARTED"
    '''BACKUP_JOB_STARTED.'''
    BACKUP_JOB_COMPLETED = "BACKUP_JOB_COMPLETED"
    '''BACKUP_JOB_COMPLETED.'''
    BACKUP_JOB_SUCCESSFUL = "BACKUP_JOB_SUCCESSFUL"
    '''BACKUP_JOB_SUCCESSFUL.'''
    BACKUP_JOB_FAILED = "BACKUP_JOB_FAILED"
    '''BACKUP_JOB_FAILED.'''
    BACKUP_JOB_EXPIRED = "BACKUP_JOB_EXPIRED"
    '''BACKUP_JOB_EXPIRED.'''
    RESTORE_JOB_STARTED = "RESTORE_JOB_STARTED"
    '''RESTORE_JOB_STARTED.'''
    RESTORE_JOB_COMPLETED = "RESTORE_JOB_COMPLETED"
    '''RESTORE_JOB_COMPLETED.'''
    RESTORE_JOB_SUCCESSFUL = "RESTORE_JOB_SUCCESSFUL"
    '''RESTORE_JOB_SUCCESSFUL.'''
    RESTORE_JOB_FAILED = "RESTORE_JOB_FAILED"
    '''RESTORE_JOB_FAILED.'''
    COPY_JOB_STARTED = "COPY_JOB_STARTED"
    '''COPY_JOB_STARTED.'''
    COPY_JOB_SUCCESSFUL = "COPY_JOB_SUCCESSFUL"
    '''COPY_JOB_SUCCESSFUL.'''
    COPY_JOB_FAILED = "COPY_JOB_FAILED"
    '''COPY_JOB_FAILED.'''
    RECOVERY_POINT_MODIFIED = "RECOVERY_POINT_MODIFIED"
    '''RECOVERY_POINT_MODIFIED.'''
    BACKUP_PLAN_CREATED = "BACKUP_PLAN_CREATED"
    '''BACKUP_PLAN_CREATED.'''
    BACKUP_PLAN_MODIFIED = "BACKUP_PLAN_MODIFIED"
    '''BACKUP_PLAN_MODIFIED.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.BackupVaultProps",
    jsii_struct_bases=[],
    name_mapping={
        "access_policy": "accessPolicy",
        "backup_vault_name": "backupVaultName",
        "block_recovery_point_deletion": "blockRecoveryPointDeletion",
        "encryption_key": "encryptionKey",
        "notification_events": "notificationEvents",
        "notification_topic": "notificationTopic",
        "removal_policy": "removalPolicy",
    },
)
class BackupVaultProps:
    def __init__(
        self,
        *,
        access_policy: typing.Optional[_PolicyDocument_3ac34393] = None,
        backup_vault_name: typing.Optional[builtins.str] = None,
        block_recovery_point_deletion: typing.Optional[builtins.bool] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        notification_events: typing.Optional[typing.Sequence[BackupVaultEvents]] = None,
        notification_topic: typing.Optional[_ITopic_9eca4852] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
    ) -> None:
        '''Properties for a BackupVault.

        :param access_policy: A resource-based policy that is used to manage access permissions on the backup vault. Default: - access is not restricted
        :param backup_vault_name: The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the AWS Region where they are created. Default: - A CDK generated name
        :param block_recovery_point_deletion: Whether to add statements to the vault access policy that prevents anyone from deleting a recovery point. Default: false
        :param encryption_key: The server-side encryption key to use to protect your backups. Default: - an Amazon managed KMS key
        :param notification_events: The vault events to send. Default: - all vault events if ``notificationTopic`` is defined
        :param notification_topic: A SNS topic to send vault events to. Default: - no notifications
        :param removal_policy: The removal policy to apply to the vault. Note that removing a vault that contains recovery points will fail. Default: RemovalPolicy.RETAIN

        :exampleMetadata: infused

        Example::

            my_key = kms.Key.from_key_arn(self, "MyKey", "aaa")
            my_topic = sns.Topic.from_topic_arn(self, "MyTopic", "bbb")
            
            vault = backup.BackupVault(self, "Vault",
                encryption_key=my_key,  # Custom encryption key
                notification_topic=my_topic
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if access_policy is not None:
            self._values["access_policy"] = access_policy
        if backup_vault_name is not None:
            self._values["backup_vault_name"] = backup_vault_name
        if block_recovery_point_deletion is not None:
            self._values["block_recovery_point_deletion"] = block_recovery_point_deletion
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if notification_events is not None:
            self._values["notification_events"] = notification_events
        if notification_topic is not None:
            self._values["notification_topic"] = notification_topic
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy

    @builtins.property
    def access_policy(self) -> typing.Optional[_PolicyDocument_3ac34393]:
        '''A resource-based policy that is used to manage access permissions on the backup vault.

        :default: - access is not restricted
        '''
        result = self._values.get("access_policy")
        return typing.cast(typing.Optional[_PolicyDocument_3ac34393], result)

    @builtins.property
    def backup_vault_name(self) -> typing.Optional[builtins.str]:
        '''The name of a logical container where backups are stored.

        Backup vaults
        are identified by names that are unique to the account used to create
        them and the AWS Region where they are created.

        :default: - A CDK generated name
        '''
        result = self._values.get("backup_vault_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def block_recovery_point_deletion(self) -> typing.Optional[builtins.bool]:
        '''Whether to add statements to the vault access policy that prevents anyone from deleting a recovery point.

        :default: false
        '''
        result = self._values.get("block_recovery_point_deletion")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The server-side encryption key to use to protect your backups.

        :default: - an Amazon managed KMS key
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def notification_events(self) -> typing.Optional[typing.List[BackupVaultEvents]]:
        '''The vault events to send.

        :default: - all vault events if ``notificationTopic`` is defined

        :see: https://docs.aws.amazon.com/aws-backup/latest/devguide/sns-notifications.html
        '''
        result = self._values.get("notification_events")
        return typing.cast(typing.Optional[typing.List[BackupVaultEvents]], result)

    @builtins.property
    def notification_topic(self) -> typing.Optional[_ITopic_9eca4852]:
        '''A SNS topic to send vault events to.

        :default: - no notifications

        :see: https://docs.aws.amazon.com/aws-backup/latest/devguide/sns-notifications.html
        '''
        result = self._values.get("notification_topic")
        return typing.cast(typing.Optional[_ITopic_9eca4852], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''The removal policy to apply to the vault.

        Note that removing a vault
        that contains recovery points will fail.

        :default: RemovalPolicy.RETAIN
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BackupVaultProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnBackupPlan(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.CfnBackupPlan",
):
    '''A CloudFormation ``AWS::Backup::BackupPlan``.

    Contains an optional backup plan display name and an array of ``BackupRule`` objects, each of which specifies a backup rule. Each rule in a backup plan is a separate scheduled task and can back up a different selection of AWS resources.

    For a sample AWS CloudFormation template, see the `AWS Backup Developer Guide <https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources.html#assigning-resources-cfn>`_ .

    :cloudformationResource: AWS::Backup::BackupPlan
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupplan.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_backup as backup
        
        # backup_options: Any
        
        cfn_backup_plan = backup.CfnBackupPlan(self, "MyCfnBackupPlan",
            backup_plan=backup.CfnBackupPlan.BackupPlanResourceTypeProperty(
                backup_plan_name="backupPlanName",
                backup_plan_rule=[backup.CfnBackupPlan.BackupRuleResourceTypeProperty(
                    rule_name="ruleName",
                    target_backup_vault="targetBackupVault",
        
                    # the properties below are optional
                    completion_window_minutes=123,
                    copy_actions=[backup.CfnBackupPlan.CopyActionResourceTypeProperty(
                        destination_backup_vault_arn="destinationBackupVaultArn",
        
                        # the properties below are optional
                        lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                            delete_after_days=123,
                            move_to_cold_storage_after_days=123
                        )
                    )],
                    enable_continuous_backup=False,
                    lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                        delete_after_days=123,
                        move_to_cold_storage_after_days=123
                    ),
                    recovery_point_tags={
                        "recovery_point_tags_key": "recoveryPointTags"
                    },
                    schedule_expression="scheduleExpression",
                    start_window_minutes=123
                )],
        
                # the properties below are optional
                advanced_backup_settings=[backup.CfnBackupPlan.AdvancedBackupSettingResourceTypeProperty(
                    backup_options=backup_options,
                    resource_type="resourceType"
                )]
            ),
        
            # the properties below are optional
            backup_plan_tags={
                "backup_plan_tags_key": "backupPlanTags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        backup_plan: typing.Union["CfnBackupPlan.BackupPlanResourceTypeProperty", _IResolvable_da3f097b],
        backup_plan_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
    ) -> None:
        '''Create a new ``AWS::Backup::BackupPlan``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param backup_plan: Uniquely identifies the backup plan to be associated with the selection of resources.
        :param backup_plan_tags: To help organize your resources, you can assign your own metadata to the resources that you create. Each tag is a key-value pair. The specified tags are assigned to all backups created with this plan.
        '''
        props = CfnBackupPlanProps(
            backup_plan=backup_plan, backup_plan_tags=backup_plan_tags
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
    @jsii.member(jsii_name="attrBackupPlanArn")
    def attr_backup_plan_arn(self) -> builtins.str:
        '''An Amazon Resource Name (ARN) that uniquely identifies a backup plan;

        for example, ``arn:aws:backup:us-east-1:123456789012:plan:8F81F553-3A74-4A3F-B93D-B3360DC80C50`` .

        :cloudformationAttribute: BackupPlanArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBackupPlanArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrBackupPlanId")
    def attr_backup_plan_id(self) -> builtins.str:
        '''Uniquely identifies a backup plan.

        :cloudformationAttribute: BackupPlanId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBackupPlanId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrVersionId")
    def attr_version_id(self) -> builtins.str:
        '''Unique, randomly generated, Unicode, UTF-8 encoded strings that are at most 1,024 bytes long.

        Version Ids cannot be edited.

        :cloudformationAttribute: VersionId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrVersionId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupPlan")
    def backup_plan(
        self,
    ) -> typing.Union["CfnBackupPlan.BackupPlanResourceTypeProperty", _IResolvable_da3f097b]:
        '''Uniquely identifies the backup plan to be associated with the selection of resources.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupplan.html#cfn-backup-backupplan-backupplan
        '''
        return typing.cast(typing.Union["CfnBackupPlan.BackupPlanResourceTypeProperty", _IResolvable_da3f097b], jsii.get(self, "backupPlan"))

    @backup_plan.setter
    def backup_plan(
        self,
        value: typing.Union["CfnBackupPlan.BackupPlanResourceTypeProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "backupPlan", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupPlanTags")
    def backup_plan_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''To help organize your resources, you can assign your own metadata to the resources that you create.

        Each tag is a key-value pair. The specified tags are assigned to all backups created with this plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupplan.html#cfn-backup-backupplan-backupplantags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], jsii.get(self, "backupPlanTags"))

    @backup_plan_tags.setter
    def backup_plan_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]],
    ) -> None:
        jsii.set(self, "backupPlanTags", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupPlan.AdvancedBackupSettingResourceTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "backup_options": "backupOptions",
            "resource_type": "resourceType",
        },
    )
    class AdvancedBackupSettingResourceTypeProperty:
        def __init__(
            self,
            *,
            backup_options: typing.Any,
            resource_type: builtins.str,
        ) -> None:
            '''Specifies an object containing resource type and backup options.

            This is only supported for Windows VSS backups.

            :param backup_options: The backup option for the resource. Each option is a key-value pair.
            :param resource_type: The name of a resource type. The only supported resource type is EC2.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-advancedbackupsettingresourcetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                # backup_options: Any
                
                advanced_backup_setting_resource_type_property = backup.CfnBackupPlan.AdvancedBackupSettingResourceTypeProperty(
                    backup_options=backup_options,
                    resource_type="resourceType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "backup_options": backup_options,
                "resource_type": resource_type,
            }

        @builtins.property
        def backup_options(self) -> typing.Any:
            '''The backup option for the resource.

            Each option is a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-advancedbackupsettingresourcetype.html#cfn-backup-backupplan-advancedbackupsettingresourcetype-backupoptions
            '''
            result = self._values.get("backup_options")
            assert result is not None, "Required property 'backup_options' is missing"
            return typing.cast(typing.Any, result)

        @builtins.property
        def resource_type(self) -> builtins.str:
            '''The name of a resource type.

            The only supported resource type is EC2.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-advancedbackupsettingresourcetype.html#cfn-backup-backupplan-advancedbackupsettingresourcetype-resourcetype
            '''
            result = self._values.get("resource_type")
            assert result is not None, "Required property 'resource_type' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AdvancedBackupSettingResourceTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupPlan.BackupPlanResourceTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "backup_plan_name": "backupPlanName",
            "backup_plan_rule": "backupPlanRule",
            "advanced_backup_settings": "advancedBackupSettings",
        },
    )
    class BackupPlanResourceTypeProperty:
        def __init__(
            self,
            *,
            backup_plan_name: builtins.str,
            backup_plan_rule: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBackupPlan.BackupRuleResourceTypeProperty", _IResolvable_da3f097b]]],
            advanced_backup_settings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBackupPlan.AdvancedBackupSettingResourceTypeProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies an object containing properties used to create a backup plan.

            :param backup_plan_name: The display name of a backup plan.
            :param backup_plan_rule: An array of ``BackupRule`` objects, each of which specifies a scheduled task that is used to back up a selection of resources.
            :param advanced_backup_settings: A list of backup options for each resource type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupplanresourcetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                # backup_options: Any
                
                backup_plan_resource_type_property = backup.CfnBackupPlan.BackupPlanResourceTypeProperty(
                    backup_plan_name="backupPlanName",
                    backup_plan_rule=[backup.CfnBackupPlan.BackupRuleResourceTypeProperty(
                        rule_name="ruleName",
                        target_backup_vault="targetBackupVault",
                
                        # the properties below are optional
                        completion_window_minutes=123,
                        copy_actions=[backup.CfnBackupPlan.CopyActionResourceTypeProperty(
                            destination_backup_vault_arn="destinationBackupVaultArn",
                
                            # the properties below are optional
                            lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                                delete_after_days=123,
                                move_to_cold_storage_after_days=123
                            )
                        )],
                        enable_continuous_backup=False,
                        lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                            delete_after_days=123,
                            move_to_cold_storage_after_days=123
                        ),
                        recovery_point_tags={
                            "recovery_point_tags_key": "recoveryPointTags"
                        },
                        schedule_expression="scheduleExpression",
                        start_window_minutes=123
                    )],
                
                    # the properties below are optional
                    advanced_backup_settings=[backup.CfnBackupPlan.AdvancedBackupSettingResourceTypeProperty(
                        backup_options=backup_options,
                        resource_type="resourceType"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "backup_plan_name": backup_plan_name,
                "backup_plan_rule": backup_plan_rule,
            }
            if advanced_backup_settings is not None:
                self._values["advanced_backup_settings"] = advanced_backup_settings

        @builtins.property
        def backup_plan_name(self) -> builtins.str:
            '''The display name of a backup plan.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupplanresourcetype.html#cfn-backup-backupplan-backupplanresourcetype-backupplanname
            '''
            result = self._values.get("backup_plan_name")
            assert result is not None, "Required property 'backup_plan_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def backup_plan_rule(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBackupPlan.BackupRuleResourceTypeProperty", _IResolvable_da3f097b]]]:
            '''An array of ``BackupRule`` objects, each of which specifies a scheduled task that is used to back up a selection of resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupplanresourcetype.html#cfn-backup-backupplan-backupplanresourcetype-backupplanrule
            '''
            result = self._values.get("backup_plan_rule")
            assert result is not None, "Required property 'backup_plan_rule' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBackupPlan.BackupRuleResourceTypeProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def advanced_backup_settings(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBackupPlan.AdvancedBackupSettingResourceTypeProperty", _IResolvable_da3f097b]]]]:
            '''A list of backup options for each resource type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupplanresourcetype.html#cfn-backup-backupplan-backupplanresourcetype-advancedbackupsettings
            '''
            result = self._values.get("advanced_backup_settings")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBackupPlan.AdvancedBackupSettingResourceTypeProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BackupPlanResourceTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupPlan.BackupRuleResourceTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "rule_name": "ruleName",
            "target_backup_vault": "targetBackupVault",
            "completion_window_minutes": "completionWindowMinutes",
            "copy_actions": "copyActions",
            "enable_continuous_backup": "enableContinuousBackup",
            "lifecycle": "lifecycle",
            "recovery_point_tags": "recoveryPointTags",
            "schedule_expression": "scheduleExpression",
            "start_window_minutes": "startWindowMinutes",
        },
    )
    class BackupRuleResourceTypeProperty:
        def __init__(
            self,
            *,
            rule_name: builtins.str,
            target_backup_vault: builtins.str,
            completion_window_minutes: typing.Optional[jsii.Number] = None,
            copy_actions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBackupPlan.CopyActionResourceTypeProperty", _IResolvable_da3f097b]]]] = None,
            enable_continuous_backup: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            lifecycle: typing.Optional[typing.Union["CfnBackupPlan.LifecycleResourceTypeProperty", _IResolvable_da3f097b]] = None,
            recovery_point_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            schedule_expression: typing.Optional[builtins.str] = None,
            start_window_minutes: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies an object containing properties used to schedule a task to back up a selection of resources.

            :param rule_name: A display name for a backup rule.
            :param target_backup_vault: The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the AWS Region where they are created. They consist of letters, numbers, and hyphens.
            :param completion_window_minutes: A value in minutes after a backup job is successfully started before it must be completed or it is canceled by AWS Backup .
            :param copy_actions: An array of CopyAction objects, which contains the details of the copy operation.
            :param enable_continuous_backup: Enables continuous backup and point-in-time restores (PITR).
            :param lifecycle: The lifecycle defines when a protected resource is transitioned to cold storage and when it expires. AWS Backup transitions and expires backups automatically according to the lifecycle that you define.
            :param recovery_point_tags: To help organize your resources, you can assign your own metadata to the resources that you create. Each tag is a key-value pair.
            :param schedule_expression: A CRON expression specifying when AWS Backup initiates a backup job.
            :param start_window_minutes: An optional value that specifies a period of time in minutes after a backup is scheduled before a job is canceled if it doesn't start successfully.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                backup_rule_resource_type_property = backup.CfnBackupPlan.BackupRuleResourceTypeProperty(
                    rule_name="ruleName",
                    target_backup_vault="targetBackupVault",
                
                    # the properties below are optional
                    completion_window_minutes=123,
                    copy_actions=[backup.CfnBackupPlan.CopyActionResourceTypeProperty(
                        destination_backup_vault_arn="destinationBackupVaultArn",
                
                        # the properties below are optional
                        lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                            delete_after_days=123,
                            move_to_cold_storage_after_days=123
                        )
                    )],
                    enable_continuous_backup=False,
                    lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                        delete_after_days=123,
                        move_to_cold_storage_after_days=123
                    ),
                    recovery_point_tags={
                        "recovery_point_tags_key": "recoveryPointTags"
                    },
                    schedule_expression="scheduleExpression",
                    start_window_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "rule_name": rule_name,
                "target_backup_vault": target_backup_vault,
            }
            if completion_window_minutes is not None:
                self._values["completion_window_minutes"] = completion_window_minutes
            if copy_actions is not None:
                self._values["copy_actions"] = copy_actions
            if enable_continuous_backup is not None:
                self._values["enable_continuous_backup"] = enable_continuous_backup
            if lifecycle is not None:
                self._values["lifecycle"] = lifecycle
            if recovery_point_tags is not None:
                self._values["recovery_point_tags"] = recovery_point_tags
            if schedule_expression is not None:
                self._values["schedule_expression"] = schedule_expression
            if start_window_minutes is not None:
                self._values["start_window_minutes"] = start_window_minutes

        @builtins.property
        def rule_name(self) -> builtins.str:
            '''A display name for a backup rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-rulename
            '''
            result = self._values.get("rule_name")
            assert result is not None, "Required property 'rule_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def target_backup_vault(self) -> builtins.str:
            '''The name of a logical container where backups are stored.

            Backup vaults are identified by names that are unique to the account used to create them and the AWS Region where they are created. They consist of letters, numbers, and hyphens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-targetbackupvault
            '''
            result = self._values.get("target_backup_vault")
            assert result is not None, "Required property 'target_backup_vault' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def completion_window_minutes(self) -> typing.Optional[jsii.Number]:
            '''A value in minutes after a backup job is successfully started before it must be completed or it is canceled by AWS Backup .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-completionwindowminutes
            '''
            result = self._values.get("completion_window_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def copy_actions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBackupPlan.CopyActionResourceTypeProperty", _IResolvable_da3f097b]]]]:
            '''An array of CopyAction objects, which contains the details of the copy operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-copyactions
            '''
            result = self._values.get("copy_actions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBackupPlan.CopyActionResourceTypeProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def enable_continuous_backup(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables continuous backup and point-in-time restores (PITR).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-enablecontinuousbackup
            '''
            result = self._values.get("enable_continuous_backup")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def lifecycle(
            self,
        ) -> typing.Optional[typing.Union["CfnBackupPlan.LifecycleResourceTypeProperty", _IResolvable_da3f097b]]:
            '''The lifecycle defines when a protected resource is transitioned to cold storage and when it expires.

            AWS Backup transitions and expires backups automatically according to the lifecycle that you define.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-lifecycle
            '''
            result = self._values.get("lifecycle")
            return typing.cast(typing.Optional[typing.Union["CfnBackupPlan.LifecycleResourceTypeProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def recovery_point_tags(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''To help organize your resources, you can assign your own metadata to the resources that you create.

            Each tag is a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-recoverypointtags
            '''
            result = self._values.get("recovery_point_tags")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def schedule_expression(self) -> typing.Optional[builtins.str]:
            '''A CRON expression specifying when AWS Backup initiates a backup job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-scheduleexpression
            '''
            result = self._values.get("schedule_expression")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def start_window_minutes(self) -> typing.Optional[jsii.Number]:
            '''An optional value that specifies a period of time in minutes after a backup is scheduled before a job is canceled if it doesn't start successfully.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-backupruleresourcetype.html#cfn-backup-backupplan-backupruleresourcetype-startwindowminutes
            '''
            result = self._values.get("start_window_minutes")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BackupRuleResourceTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupPlan.CopyActionResourceTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_backup_vault_arn": "destinationBackupVaultArn",
            "lifecycle": "lifecycle",
        },
    )
    class CopyActionResourceTypeProperty:
        def __init__(
            self,
            *,
            destination_backup_vault_arn: builtins.str,
            lifecycle: typing.Optional[typing.Union["CfnBackupPlan.LifecycleResourceTypeProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Copies backups created by a backup rule to another vault.

            :param destination_backup_vault_arn: An Amazon Resource Name (ARN) that uniquely identifies the destination backup vault for the copied backup. For example, ``arn:aws:backup:us-east-1:123456789012:vault:aBackupVault.``
            :param lifecycle: Defines when a protected resource is transitioned to cold storage and when it expires. AWS Backup transitions and expires backups automatically according to the lifecycle that you define. If you do not specify a lifecycle, AWS Backup applies the lifecycle policy of the source backup to the destination backup. Backups transitioned to cold storage must be stored in cold storage for a minimum of 90 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-copyactionresourcetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                copy_action_resource_type_property = backup.CfnBackupPlan.CopyActionResourceTypeProperty(
                    destination_backup_vault_arn="destinationBackupVaultArn",
                
                    # the properties below are optional
                    lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                        delete_after_days=123,
                        move_to_cold_storage_after_days=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination_backup_vault_arn": destination_backup_vault_arn,
            }
            if lifecycle is not None:
                self._values["lifecycle"] = lifecycle

        @builtins.property
        def destination_backup_vault_arn(self) -> builtins.str:
            '''An Amazon Resource Name (ARN) that uniquely identifies the destination backup vault for the copied backup.

            For example, ``arn:aws:backup:us-east-1:123456789012:vault:aBackupVault.``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-copyactionresourcetype.html#cfn-backup-backupplan-copyactionresourcetype-destinationbackupvaultarn
            '''
            result = self._values.get("destination_backup_vault_arn")
            assert result is not None, "Required property 'destination_backup_vault_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def lifecycle(
            self,
        ) -> typing.Optional[typing.Union["CfnBackupPlan.LifecycleResourceTypeProperty", _IResolvable_da3f097b]]:
            '''Defines when a protected resource is transitioned to cold storage and when it expires.

            AWS Backup transitions and expires backups automatically according to the lifecycle that you define. If you do not specify a lifecycle, AWS Backup applies the lifecycle policy of the source backup to the destination backup.

            Backups transitioned to cold storage must be stored in cold storage for a minimum of 90 days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-copyactionresourcetype.html#cfn-backup-backupplan-copyactionresourcetype-lifecycle
            '''
            result = self._values.get("lifecycle")
            return typing.cast(typing.Optional[typing.Union["CfnBackupPlan.LifecycleResourceTypeProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CopyActionResourceTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupPlan.LifecycleResourceTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delete_after_days": "deleteAfterDays",
            "move_to_cold_storage_after_days": "moveToColdStorageAfterDays",
        },
    )
    class LifecycleResourceTypeProperty:
        def __init__(
            self,
            *,
            delete_after_days: typing.Optional[jsii.Number] = None,
            move_to_cold_storage_after_days: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies an object containing an array of ``Transition`` objects that determine how long in days before a recovery point transitions to cold storage or is deleted.

            :param delete_after_days: Specifies the number of days after creation that a recovery point is deleted. Must be greater than ``MoveToColdStorageAfterDays`` .
            :param move_to_cold_storage_after_days: Specifies the number of days after creation that a recovery point is moved to cold storage.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-lifecycleresourcetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                lifecycle_resource_type_property = backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                    delete_after_days=123,
                    move_to_cold_storage_after_days=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if delete_after_days is not None:
                self._values["delete_after_days"] = delete_after_days
            if move_to_cold_storage_after_days is not None:
                self._values["move_to_cold_storage_after_days"] = move_to_cold_storage_after_days

        @builtins.property
        def delete_after_days(self) -> typing.Optional[jsii.Number]:
            '''Specifies the number of days after creation that a recovery point is deleted.

            Must be greater than ``MoveToColdStorageAfterDays`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-lifecycleresourcetype.html#cfn-backup-backupplan-lifecycleresourcetype-deleteafterdays
            '''
            result = self._values.get("delete_after_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def move_to_cold_storage_after_days(self) -> typing.Optional[jsii.Number]:
            '''Specifies the number of days after creation that a recovery point is moved to cold storage.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupplan-lifecycleresourcetype.html#cfn-backup-backupplan-lifecycleresourcetype-movetocoldstorageafterdays
            '''
            result = self._values.get("move_to_cold_storage_after_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LifecycleResourceTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.CfnBackupPlanProps",
    jsii_struct_bases=[],
    name_mapping={"backup_plan": "backupPlan", "backup_plan_tags": "backupPlanTags"},
)
class CfnBackupPlanProps:
    def __init__(
        self,
        *,
        backup_plan: typing.Union[CfnBackupPlan.BackupPlanResourceTypeProperty, _IResolvable_da3f097b],
        backup_plan_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnBackupPlan``.

        :param backup_plan: Uniquely identifies the backup plan to be associated with the selection of resources.
        :param backup_plan_tags: To help organize your resources, you can assign your own metadata to the resources that you create. Each tag is a key-value pair. The specified tags are assigned to all backups created with this plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupplan.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_backup as backup
            
            # backup_options: Any
            
            cfn_backup_plan_props = backup.CfnBackupPlanProps(
                backup_plan=backup.CfnBackupPlan.BackupPlanResourceTypeProperty(
                    backup_plan_name="backupPlanName",
                    backup_plan_rule=[backup.CfnBackupPlan.BackupRuleResourceTypeProperty(
                        rule_name="ruleName",
                        target_backup_vault="targetBackupVault",
            
                        # the properties below are optional
                        completion_window_minutes=123,
                        copy_actions=[backup.CfnBackupPlan.CopyActionResourceTypeProperty(
                            destination_backup_vault_arn="destinationBackupVaultArn",
            
                            # the properties below are optional
                            lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                                delete_after_days=123,
                                move_to_cold_storage_after_days=123
                            )
                        )],
                        enable_continuous_backup=False,
                        lifecycle=backup.CfnBackupPlan.LifecycleResourceTypeProperty(
                            delete_after_days=123,
                            move_to_cold_storage_after_days=123
                        ),
                        recovery_point_tags={
                            "recovery_point_tags_key": "recoveryPointTags"
                        },
                        schedule_expression="scheduleExpression",
                        start_window_minutes=123
                    )],
            
                    # the properties below are optional
                    advanced_backup_settings=[backup.CfnBackupPlan.AdvancedBackupSettingResourceTypeProperty(
                        backup_options=backup_options,
                        resource_type="resourceType"
                    )]
                ),
            
                # the properties below are optional
                backup_plan_tags={
                    "backup_plan_tags_key": "backupPlanTags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "backup_plan": backup_plan,
        }
        if backup_plan_tags is not None:
            self._values["backup_plan_tags"] = backup_plan_tags

    @builtins.property
    def backup_plan(
        self,
    ) -> typing.Union[CfnBackupPlan.BackupPlanResourceTypeProperty, _IResolvable_da3f097b]:
        '''Uniquely identifies the backup plan to be associated with the selection of resources.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupplan.html#cfn-backup-backupplan-backupplan
        '''
        result = self._values.get("backup_plan")
        assert result is not None, "Required property 'backup_plan' is missing"
        return typing.cast(typing.Union[CfnBackupPlan.BackupPlanResourceTypeProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def backup_plan_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''To help organize your resources, you can assign your own metadata to the resources that you create.

        Each tag is a key-value pair. The specified tags are assigned to all backups created with this plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupplan.html#cfn-backup-backupplan-backupplantags
        '''
        result = self._values.get("backup_plan_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBackupPlanProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnBackupSelection(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.CfnBackupSelection",
):
    '''A CloudFormation ``AWS::Backup::BackupSelection``.

    Specifies a set of resources to assign to a backup plan.

    For a sample AWS CloudFormation template, see the `AWS Backup Developer Guide <https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources.html#assigning-resources-cfn>`_ .

    :cloudformationResource: AWS::Backup::BackupSelection
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupselection.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_backup as backup
        
        # conditions: Any
        
        cfn_backup_selection = backup.CfnBackupSelection(self, "MyCfnBackupSelection",
            backup_plan_id="backupPlanId",
            backup_selection=backup.CfnBackupSelection.BackupSelectionResourceTypeProperty(
                iam_role_arn="iamRoleArn",
                selection_name="selectionName",
        
                # the properties below are optional
                conditions=conditions,
                list_of_tags=[backup.CfnBackupSelection.ConditionResourceTypeProperty(
                    condition_key="conditionKey",
                    condition_type="conditionType",
                    condition_value="conditionValue"
                )],
                not_resources=["notResources"],
                resources=["resources"]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        backup_plan_id: builtins.str,
        backup_selection: typing.Union["CfnBackupSelection.BackupSelectionResourceTypeProperty", _IResolvable_da3f097b],
    ) -> None:
        '''Create a new ``AWS::Backup::BackupSelection``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param backup_plan_id: Uniquely identifies a backup plan.
        :param backup_selection: Specifies the body of a request to assign a set of resources to a backup plan. It includes an array of resources, an optional array of patterns to exclude resources, an optional role to provide access to the AWS service the resource belongs to, and an optional array of tags used to identify a set of resources.
        '''
        props = CfnBackupSelectionProps(
            backup_plan_id=backup_plan_id, backup_selection=backup_selection
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
    @jsii.member(jsii_name="attrBackupPlanId")
    def attr_backup_plan_id(self) -> builtins.str:
        '''Uniquely identifies a backup plan.

        :cloudformationAttribute: BackupPlanId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBackupPlanId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''Uniquely identifies the backup selection.

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSelectionId")
    def attr_selection_id(self) -> builtins.str:
        '''Uniquely identifies a request to assign a set of resources to a backup plan.

        :cloudformationAttribute: SelectionId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSelectionId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupPlanId")
    def backup_plan_id(self) -> builtins.str:
        '''Uniquely identifies a backup plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupselection.html#cfn-backup-backupselection-backupplanid
        '''
        return typing.cast(builtins.str, jsii.get(self, "backupPlanId"))

    @backup_plan_id.setter
    def backup_plan_id(self, value: builtins.str) -> None:
        jsii.set(self, "backupPlanId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupSelection")
    def backup_selection(
        self,
    ) -> typing.Union["CfnBackupSelection.BackupSelectionResourceTypeProperty", _IResolvable_da3f097b]:
        '''Specifies the body of a request to assign a set of resources to a backup plan.

        It includes an array of resources, an optional array of patterns to exclude resources, an optional role to provide access to the AWS service the resource belongs to, and an optional array of tags used to identify a set of resources.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupselection.html#cfn-backup-backupselection-backupselection
        '''
        return typing.cast(typing.Union["CfnBackupSelection.BackupSelectionResourceTypeProperty", _IResolvable_da3f097b], jsii.get(self, "backupSelection"))

    @backup_selection.setter
    def backup_selection(
        self,
        value: typing.Union["CfnBackupSelection.BackupSelectionResourceTypeProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "backupSelection", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupSelection.BackupSelectionResourceTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "iam_role_arn": "iamRoleArn",
            "selection_name": "selectionName",
            "conditions": "conditions",
            "list_of_tags": "listOfTags",
            "not_resources": "notResources",
            "resources": "resources",
        },
    )
    class BackupSelectionResourceTypeProperty:
        def __init__(
            self,
            *,
            iam_role_arn: builtins.str,
            selection_name: builtins.str,
            conditions: typing.Any = None,
            list_of_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBackupSelection.ConditionResourceTypeProperty", _IResolvable_da3f097b]]]] = None,
            not_resources: typing.Optional[typing.Sequence[builtins.str]] = None,
            resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Specifies an object containing properties used to assign a set of resources to a backup plan.

            :param iam_role_arn: The ARN of the IAM role that AWS Backup uses to authenticate when backing up the target resource; for example, ``arn:aws:iam::123456789012:role/S3Access`` .
            :param selection_name: The display name of a resource selection document.
            :param conditions: A list of conditions that you define to assign resources to your backup plans using tags. For example, ``"StringEquals": {"Department": "accounting"`` . Condition operators are case sensitive. ``Conditions`` differs from ``ListOfTags`` as follows: - When you specify more than one condition, you only assign the resources that match ALL conditions (using AND logic). - ``Conditions`` supports ``StringEquals`` , ``StringLike`` , ``StringNotEquals`` , and ``StringNotLike`` . ``ListOfTags`` only supports ``StringEquals`` .
            :param list_of_tags: An array of conditions used to specify a set of resources to assign to a backup plan; for example, ``"STRINGEQUALS": {"Department":"accounting"`` .
            :param not_resources: A list of Amazon Resource Names (ARNs) to exclude from a backup plan. The maximum number of ARNs is 500 without wildcards, or 30 ARNs with wildcards. If you need to exclude many resources from a backup plan, consider a different resource selection strategy, such as assigning only one or a few resource types or refining your resource selection using tags.
            :param resources: An array of strings that contain Amazon Resource Names (ARNs) of resources to assign to a backup plan.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-backupselectionresourcetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                # conditions: Any
                
                backup_selection_resource_type_property = backup.CfnBackupSelection.BackupSelectionResourceTypeProperty(
                    iam_role_arn="iamRoleArn",
                    selection_name="selectionName",
                
                    # the properties below are optional
                    conditions=conditions,
                    list_of_tags=[backup.CfnBackupSelection.ConditionResourceTypeProperty(
                        condition_key="conditionKey",
                        condition_type="conditionType",
                        condition_value="conditionValue"
                    )],
                    not_resources=["notResources"],
                    resources=["resources"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "iam_role_arn": iam_role_arn,
                "selection_name": selection_name,
            }
            if conditions is not None:
                self._values["conditions"] = conditions
            if list_of_tags is not None:
                self._values["list_of_tags"] = list_of_tags
            if not_resources is not None:
                self._values["not_resources"] = not_resources
            if resources is not None:
                self._values["resources"] = resources

        @builtins.property
        def iam_role_arn(self) -> builtins.str:
            '''The ARN of the IAM role that AWS Backup uses to authenticate when backing up the target resource;

            for example, ``arn:aws:iam::123456789012:role/S3Access`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-backupselectionresourcetype.html#cfn-backup-backupselection-backupselectionresourcetype-iamrolearn
            '''
            result = self._values.get("iam_role_arn")
            assert result is not None, "Required property 'iam_role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def selection_name(self) -> builtins.str:
            '''The display name of a resource selection document.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-backupselectionresourcetype.html#cfn-backup-backupselection-backupselectionresourcetype-selectionname
            '''
            result = self._values.get("selection_name")
            assert result is not None, "Required property 'selection_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def conditions(self) -> typing.Any:
            '''A list of conditions that you define to assign resources to your backup plans using tags.

            For example, ``"StringEquals": {"Department": "accounting"`` . Condition operators are case sensitive.

            ``Conditions`` differs from ``ListOfTags`` as follows:

            - When you specify more than one condition, you only assign the resources that match ALL conditions (using AND logic).
            - ``Conditions`` supports ``StringEquals`` , ``StringLike`` , ``StringNotEquals`` , and ``StringNotLike`` . ``ListOfTags`` only supports ``StringEquals`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-backupselectionresourcetype.html#cfn-backup-backupselection-backupselectionresourcetype-conditions
            '''
            result = self._values.get("conditions")
            return typing.cast(typing.Any, result)

        @builtins.property
        def list_of_tags(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBackupSelection.ConditionResourceTypeProperty", _IResolvable_da3f097b]]]]:
            '''An array of conditions used to specify a set of resources to assign to a backup plan;

            for example, ``"STRINGEQUALS": {"Department":"accounting"`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-backupselectionresourcetype.html#cfn-backup-backupselection-backupselectionresourcetype-listoftags
            '''
            result = self._values.get("list_of_tags")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBackupSelection.ConditionResourceTypeProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def not_resources(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of Amazon Resource Names (ARNs) to exclude from a backup plan.

            The maximum number of ARNs is 500 without wildcards, or 30 ARNs with wildcards.

            If you need to exclude many resources from a backup plan, consider a different resource selection strategy, such as assigning only one or a few resource types or refining your resource selection using tags.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-backupselectionresourcetype.html#cfn-backup-backupselection-backupselectionresourcetype-notresources
            '''
            result = self._values.get("not_resources")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def resources(self) -> typing.Optional[typing.List[builtins.str]]:
            '''An array of strings that contain Amazon Resource Names (ARNs) of resources to assign to a backup plan.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-backupselectionresourcetype.html#cfn-backup-backupselection-backupselectionresourcetype-resources
            '''
            result = self._values.get("resources")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BackupSelectionResourceTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupSelection.ConditionResourceTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "condition_key": "conditionKey",
            "condition_type": "conditionType",
            "condition_value": "conditionValue",
        },
    )
    class ConditionResourceTypeProperty:
        def __init__(
            self,
            *,
            condition_key: builtins.str,
            condition_type: builtins.str,
            condition_value: builtins.str,
        ) -> None:
            '''Specifies an object that contains an array of triplets made up of a condition type (such as ``STRINGEQUALS`` ), a key, and a value.

            Conditions are used to filter resources in a selection that is assigned to a backup plan.

            :param condition_key: The key in a key-value pair. For example, in ``"Department": "accounting"`` , ``"Department"`` is the key.
            :param condition_type: An operation, such as ``STRINGEQUALS`` , that is applied to a key-value pair used to filter resources in a selection.
            :param condition_value: The value in a key-value pair. For example, in ``"Department": "accounting"`` , ``"accounting"`` is the value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-conditionresourcetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                condition_resource_type_property = backup.CfnBackupSelection.ConditionResourceTypeProperty(
                    condition_key="conditionKey",
                    condition_type="conditionType",
                    condition_value="conditionValue"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "condition_key": condition_key,
                "condition_type": condition_type,
                "condition_value": condition_value,
            }

        @builtins.property
        def condition_key(self) -> builtins.str:
            '''The key in a key-value pair.

            For example, in ``"Department": "accounting"`` , ``"Department"`` is the key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-conditionresourcetype.html#cfn-backup-backupselection-conditionresourcetype-conditionkey
            '''
            result = self._values.get("condition_key")
            assert result is not None, "Required property 'condition_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def condition_type(self) -> builtins.str:
            '''An operation, such as ``STRINGEQUALS`` , that is applied to a key-value pair used to filter resources in a selection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-conditionresourcetype.html#cfn-backup-backupselection-conditionresourcetype-conditiontype
            '''
            result = self._values.get("condition_type")
            assert result is not None, "Required property 'condition_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def condition_value(self) -> builtins.str:
            '''The value in a key-value pair.

            For example, in ``"Department": "accounting"`` , ``"accounting"`` is the value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupselection-conditionresourcetype.html#cfn-backup-backupselection-conditionresourcetype-conditionvalue
            '''
            result = self._values.get("condition_value")
            assert result is not None, "Required property 'condition_value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConditionResourceTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.CfnBackupSelectionProps",
    jsii_struct_bases=[],
    name_mapping={
        "backup_plan_id": "backupPlanId",
        "backup_selection": "backupSelection",
    },
)
class CfnBackupSelectionProps:
    def __init__(
        self,
        *,
        backup_plan_id: builtins.str,
        backup_selection: typing.Union[CfnBackupSelection.BackupSelectionResourceTypeProperty, _IResolvable_da3f097b],
    ) -> None:
        '''Properties for defining a ``CfnBackupSelection``.

        :param backup_plan_id: Uniquely identifies a backup plan.
        :param backup_selection: Specifies the body of a request to assign a set of resources to a backup plan. It includes an array of resources, an optional array of patterns to exclude resources, an optional role to provide access to the AWS service the resource belongs to, and an optional array of tags used to identify a set of resources.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupselection.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_backup as backup
            
            # conditions: Any
            
            cfn_backup_selection_props = backup.CfnBackupSelectionProps(
                backup_plan_id="backupPlanId",
                backup_selection=backup.CfnBackupSelection.BackupSelectionResourceTypeProperty(
                    iam_role_arn="iamRoleArn",
                    selection_name="selectionName",
            
                    # the properties below are optional
                    conditions=conditions,
                    list_of_tags=[backup.CfnBackupSelection.ConditionResourceTypeProperty(
                        condition_key="conditionKey",
                        condition_type="conditionType",
                        condition_value="conditionValue"
                    )],
                    not_resources=["notResources"],
                    resources=["resources"]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "backup_plan_id": backup_plan_id,
            "backup_selection": backup_selection,
        }

    @builtins.property
    def backup_plan_id(self) -> builtins.str:
        '''Uniquely identifies a backup plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupselection.html#cfn-backup-backupselection-backupplanid
        '''
        result = self._values.get("backup_plan_id")
        assert result is not None, "Required property 'backup_plan_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def backup_selection(
        self,
    ) -> typing.Union[CfnBackupSelection.BackupSelectionResourceTypeProperty, _IResolvable_da3f097b]:
        '''Specifies the body of a request to assign a set of resources to a backup plan.

        It includes an array of resources, an optional array of patterns to exclude resources, an optional role to provide access to the AWS service the resource belongs to, and an optional array of tags used to identify a set of resources.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupselection.html#cfn-backup-backupselection-backupselection
        '''
        result = self._values.get("backup_selection")
        assert result is not None, "Required property 'backup_selection' is missing"
        return typing.cast(typing.Union[CfnBackupSelection.BackupSelectionResourceTypeProperty, _IResolvable_da3f097b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBackupSelectionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnBackupVault(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.CfnBackupVault",
):
    '''A CloudFormation ``AWS::Backup::BackupVault``.

    Creates a logical container where backups are stored. A ``CreateBackupVault`` request includes a name, optionally one or more resource tags, an encryption key, and a request ID.

    Do not include sensitive data, such as passport numbers, in the name of a backup vault.

    For a sample AWS CloudFormation template, see the `AWS Backup Developer Guide <https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources.html#assigning-resources-cfn>`_ .

    :cloudformationResource: AWS::Backup::BackupVault
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_backup as backup
        
        # access_policy: Any
        
        cfn_backup_vault = backup.CfnBackupVault(self, "MyCfnBackupVault",
            backup_vault_name="backupVaultName",
        
            # the properties below are optional
            access_policy=access_policy,
            backup_vault_tags={
                "backup_vault_tags_key": "backupVaultTags"
            },
            encryption_key_arn="encryptionKeyArn",
            lock_configuration=backup.CfnBackupVault.LockConfigurationTypeProperty(
                min_retention_days=123,
        
                # the properties below are optional
                changeable_for_days=123,
                max_retention_days=123
            ),
            notifications=backup.CfnBackupVault.NotificationObjectTypeProperty(
                backup_vault_events=["backupVaultEvents"],
                sns_topic_arn="snsTopicArn"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        backup_vault_name: builtins.str,
        access_policy: typing.Any = None,
        backup_vault_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        encryption_key_arn: typing.Optional[builtins.str] = None,
        lock_configuration: typing.Optional[typing.Union["CfnBackupVault.LockConfigurationTypeProperty", _IResolvable_da3f097b]] = None,
        notifications: typing.Optional[typing.Union["CfnBackupVault.NotificationObjectTypeProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Backup::BackupVault``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param backup_vault_name: The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the AWS Region where they are created. They consist of lowercase letters, numbers, and hyphens.
        :param access_policy: A resource-based policy that is used to manage access permissions on the target backup vault.
        :param backup_vault_tags: Metadata that you can assign to help organize the resources that you create. Each tag is a key-value pair.
        :param encryption_key_arn: A server-side encryption key you can specify to encrypt your backups from services that support full AWS Backup management; for example, ``arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`` . If you specify a key, you must specify its ARN, not its alias. If you do not specify a key, AWS Backup creates a KMS key for you by default. To learn which AWS Backup services support full AWS Backup management and how AWS Backup handles encryption for backups from services that do not yet support full AWS Backup , see `Encryption for backups in AWS Backup <https://docs.aws.amazon.com/aws-backup/latest/devguide/encryption.html>`_
        :param lock_configuration: Configuration for `AWS Backup Vault Lock <https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html>`_ .
        :param notifications: The SNS event notifications for the specified backup vault.
        '''
        props = CfnBackupVaultProps(
            backup_vault_name=backup_vault_name,
            access_policy=access_policy,
            backup_vault_tags=backup_vault_tags,
            encryption_key_arn=encryption_key_arn,
            lock_configuration=lock_configuration,
            notifications=notifications,
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
    @jsii.member(jsii_name="attrBackupVaultArn")
    def attr_backup_vault_arn(self) -> builtins.str:
        '''An Amazon Resource Name (ARN) that uniquely identifies a backup vault;

        for example, ``arn:aws:backup:us-east-1:123456789012:backup-vault:aBackupVault`` .

        :cloudformationAttribute: BackupVaultArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBackupVaultArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrBackupVaultName")
    def attr_backup_vault_name(self) -> builtins.str:
        '''The name of a logical container where backups are stored.

        Backup vaults are identified by names that are unique to the account used to create them and the Region where they are created. They consist of lowercase and uppercase letters, numbers, and hyphens.

        :cloudformationAttribute: BackupVaultName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrBackupVaultName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessPolicy")
    def access_policy(self) -> typing.Any:
        '''A resource-based policy that is used to manage access permissions on the target backup vault.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-accesspolicy
        '''
        return typing.cast(typing.Any, jsii.get(self, "accessPolicy"))

    @access_policy.setter
    def access_policy(self, value: typing.Any) -> None:
        jsii.set(self, "accessPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVaultName")
    def backup_vault_name(self) -> builtins.str:
        '''The name of a logical container where backups are stored.

        Backup vaults are identified by names that are unique to the account used to create them and the AWS Region where they are created. They consist of lowercase letters, numbers, and hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-backupvaultname
        '''
        return typing.cast(builtins.str, jsii.get(self, "backupVaultName"))

    @backup_vault_name.setter
    def backup_vault_name(self, value: builtins.str) -> None:
        jsii.set(self, "backupVaultName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVaultTags")
    def backup_vault_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''Metadata that you can assign to help organize the resources that you create.

        Each tag is a key-value pair.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-backupvaulttags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], jsii.get(self, "backupVaultTags"))

    @backup_vault_tags.setter
    def backup_vault_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]],
    ) -> None:
        jsii.set(self, "backupVaultTags", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKeyArn")
    def encryption_key_arn(self) -> typing.Optional[builtins.str]:
        '''A server-side encryption key you can specify to encrypt your backups from services that support full AWS Backup management;

        for example, ``arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`` . If you specify a key, you must specify its ARN, not its alias. If you do not specify a key, AWS Backup creates a KMS key for you by default.

        To learn which AWS Backup services support full AWS Backup management and how AWS Backup handles encryption for backups from services that do not yet support full AWS Backup , see `Encryption for backups in AWS Backup <https://docs.aws.amazon.com/aws-backup/latest/devguide/encryption.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-encryptionkeyarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "encryptionKeyArn"))

    @encryption_key_arn.setter
    def encryption_key_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "encryptionKeyArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lockConfiguration")
    def lock_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBackupVault.LockConfigurationTypeProperty", _IResolvable_da3f097b]]:
        '''Configuration for `AWS Backup Vault Lock <https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-lockconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBackupVault.LockConfigurationTypeProperty", _IResolvable_da3f097b]], jsii.get(self, "lockConfiguration"))

    @lock_configuration.setter
    def lock_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBackupVault.LockConfigurationTypeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "lockConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notifications")
    def notifications(
        self,
    ) -> typing.Optional[typing.Union["CfnBackupVault.NotificationObjectTypeProperty", _IResolvable_da3f097b]]:
        '''The SNS event notifications for the specified backup vault.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-notifications
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBackupVault.NotificationObjectTypeProperty", _IResolvable_da3f097b]], jsii.get(self, "notifications"))

    @notifications.setter
    def notifications(
        self,
        value: typing.Optional[typing.Union["CfnBackupVault.NotificationObjectTypeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "notifications", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupVault.LockConfigurationTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "min_retention_days": "minRetentionDays",
            "changeable_for_days": "changeableForDays",
            "max_retention_days": "maxRetentionDays",
        },
    )
    class LockConfigurationTypeProperty:
        def __init__(
            self,
            *,
            min_retention_days: jsii.Number,
            changeable_for_days: typing.Optional[jsii.Number] = None,
            max_retention_days: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The ``LockConfigurationType`` property type specifies configuration for `AWS Backup Vault Lock <https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html>`_ .

            :param min_retention_days: The AWS Backup Vault Lock configuration that specifies the minimum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to retain certain data for at least seven years (2555 days). If this parameter is not specified, Vault Lock will not enforce a minimum retention period. If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or longer than the minimum retention period. If the job's retention period is shorter than that minimum retention period, then the vault fails that backup or copy job, and you should either modify your lifecycle settings or use a different vault. Recovery points already saved in the vault prior to Vault Lock are not affected.
            :param changeable_for_days: The AWS Backup Vault Lock configuration that specifies the number of days before the lock date. For example, setting ``ChangeableForDays`` to 30 on Jan. 1, 2022 at 8pm UTC will set the lock date to Jan. 31, 2022 at 8pm UTC. AWS Backup enforces a 72-hour cooling-off period before Vault Lock takes effect and becomes immutable. Therefore, you must set ``ChangeableForDays`` to 3 or greater. Before the lock date, you can delete Vault Lock from the vault using ``DeleteBackupVaultLockConfiguration`` or change the Vault Lock configuration using ``PutBackupVaultLockConfiguration`` . On and after the lock date, the Vault Lock becomes immutable and cannot be changed or deleted. If this parameter is not specified, you can delete Vault Lock from the vault using ``DeleteBackupVaultLockConfiguration`` or change the Vault Lock configuration using ``PutBackupVaultLockConfiguration`` at any time.
            :param max_retention_days: The AWS Backup Vault Lock configuration that specifies the maximum retention period that the vault retains its recovery points. This setting can be useful if, for example, your organization's policies require you to destroy certain data after retaining it for four years (1460 days). If this parameter is not included, Vault Lock does not enforce a maximum retention period on the recovery points in the vault. If this parameter is included without a value, Vault Lock will not enforce a maximum retention period. If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or shorter than the maximum retention period. If the job's retention period is longer than that maximum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. Recovery points already saved in the vault prior to Vault Lock are not affected.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupvault-lockconfigurationtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                lock_configuration_type_property = backup.CfnBackupVault.LockConfigurationTypeProperty(
                    min_retention_days=123,
                
                    # the properties below are optional
                    changeable_for_days=123,
                    max_retention_days=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "min_retention_days": min_retention_days,
            }
            if changeable_for_days is not None:
                self._values["changeable_for_days"] = changeable_for_days
            if max_retention_days is not None:
                self._values["max_retention_days"] = max_retention_days

        @builtins.property
        def min_retention_days(self) -> jsii.Number:
            '''The AWS Backup Vault Lock configuration that specifies the minimum retention period that the vault retains its recovery points.

            This setting can be useful if, for example, your organization's policies require you to retain certain data for at least seven years (2555 days).

            If this parameter is not specified, Vault Lock will not enforce a minimum retention period.

            If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or longer than the minimum retention period. If the job's retention period is shorter than that minimum retention period, then the vault fails that backup or copy job, and you should either modify your lifecycle settings or use a different vault. Recovery points already saved in the vault prior to Vault Lock are not affected.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupvault-lockconfigurationtype.html#cfn-backup-backupvault-lockconfigurationtype-minretentiondays
            '''
            result = self._values.get("min_retention_days")
            assert result is not None, "Required property 'min_retention_days' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def changeable_for_days(self) -> typing.Optional[jsii.Number]:
            '''The AWS Backup Vault Lock configuration that specifies the number of days before the lock date.

            For example, setting ``ChangeableForDays`` to 30 on Jan. 1, 2022 at 8pm UTC will set the lock date to Jan. 31, 2022 at 8pm UTC.

            AWS Backup enforces a 72-hour cooling-off period before Vault Lock takes effect and becomes immutable. Therefore, you must set ``ChangeableForDays`` to 3 or greater.

            Before the lock date, you can delete Vault Lock from the vault using ``DeleteBackupVaultLockConfiguration`` or change the Vault Lock configuration using ``PutBackupVaultLockConfiguration`` . On and after the lock date, the Vault Lock becomes immutable and cannot be changed or deleted.

            If this parameter is not specified, you can delete Vault Lock from the vault using ``DeleteBackupVaultLockConfiguration`` or change the Vault Lock configuration using ``PutBackupVaultLockConfiguration`` at any time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupvault-lockconfigurationtype.html#cfn-backup-backupvault-lockconfigurationtype-changeablefordays
            '''
            result = self._values.get("changeable_for_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_retention_days(self) -> typing.Optional[jsii.Number]:
            '''The AWS Backup Vault Lock configuration that specifies the maximum retention period that the vault retains its recovery points.

            This setting can be useful if, for example, your organization's policies require you to destroy certain data after retaining it for four years (1460 days).

            If this parameter is not included, Vault Lock does not enforce a maximum retention period on the recovery points in the vault. If this parameter is included without a value, Vault Lock will not enforce a maximum retention period.

            If this parameter is specified, any backup or copy job to the vault must have a lifecycle policy with a retention period equal to or shorter than the maximum retention period. If the job's retention period is longer than that maximum retention period, then the vault fails the backup or copy job, and you should either modify your lifecycle settings or use a different vault. Recovery points already saved in the vault prior to Vault Lock are not affected.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupvault-lockconfigurationtype.html#cfn-backup-backupvault-lockconfigurationtype-maxretentiondays
            '''
            result = self._values.get("max_retention_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LockConfigurationTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnBackupVault.NotificationObjectTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "backup_vault_events": "backupVaultEvents",
            "sns_topic_arn": "snsTopicArn",
        },
    )
    class NotificationObjectTypeProperty:
        def __init__(
            self,
            *,
            backup_vault_events: typing.Sequence[builtins.str],
            sns_topic_arn: builtins.str,
        ) -> None:
            '''Specifies an object containing SNS event notification properties for the target backup vault.

            :param backup_vault_events: An array of events that indicate the status of jobs to back up resources to the backup vault. For valid events, see `BackupVaultEvents <https://docs.aws.amazon.com/aws-backup/latest/devguide/API_PutBackupVaultNotifications.html#API_PutBackupVaultNotifications_RequestSyntax>`_ in the *AWS Backup API Guide* .
            :param sns_topic_arn: An ARN that uniquely identifies an Amazon Simple Notification Service (Amazon SNS) topic; for example, ``arn:aws:sns:us-west-2:111122223333:MyTopic`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupvault-notificationobjecttype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                notification_object_type_property = backup.CfnBackupVault.NotificationObjectTypeProperty(
                    backup_vault_events=["backupVaultEvents"],
                    sns_topic_arn="snsTopicArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "backup_vault_events": backup_vault_events,
                "sns_topic_arn": sns_topic_arn,
            }

        @builtins.property
        def backup_vault_events(self) -> typing.List[builtins.str]:
            '''An array of events that indicate the status of jobs to back up resources to the backup vault.

            For valid events, see `BackupVaultEvents <https://docs.aws.amazon.com/aws-backup/latest/devguide/API_PutBackupVaultNotifications.html#API_PutBackupVaultNotifications_RequestSyntax>`_ in the *AWS Backup API Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupvault-notificationobjecttype.html#cfn-backup-backupvault-notificationobjecttype-backupvaultevents
            '''
            result = self._values.get("backup_vault_events")
            assert result is not None, "Required property 'backup_vault_events' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def sns_topic_arn(self) -> builtins.str:
            '''An ARN that uniquely identifies an Amazon Simple Notification Service (Amazon SNS) topic;

            for example, ``arn:aws:sns:us-west-2:111122223333:MyTopic`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-backupvault-notificationobjecttype.html#cfn-backup-backupvault-notificationobjecttype-snstopicarn
            '''
            result = self._values.get("sns_topic_arn")
            assert result is not None, "Required property 'sns_topic_arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotificationObjectTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.CfnBackupVaultProps",
    jsii_struct_bases=[],
    name_mapping={
        "backup_vault_name": "backupVaultName",
        "access_policy": "accessPolicy",
        "backup_vault_tags": "backupVaultTags",
        "encryption_key_arn": "encryptionKeyArn",
        "lock_configuration": "lockConfiguration",
        "notifications": "notifications",
    },
)
class CfnBackupVaultProps:
    def __init__(
        self,
        *,
        backup_vault_name: builtins.str,
        access_policy: typing.Any = None,
        backup_vault_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        encryption_key_arn: typing.Optional[builtins.str] = None,
        lock_configuration: typing.Optional[typing.Union[CfnBackupVault.LockConfigurationTypeProperty, _IResolvable_da3f097b]] = None,
        notifications: typing.Optional[typing.Union[CfnBackupVault.NotificationObjectTypeProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnBackupVault``.

        :param backup_vault_name: The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the AWS Region where they are created. They consist of lowercase letters, numbers, and hyphens.
        :param access_policy: A resource-based policy that is used to manage access permissions on the target backup vault.
        :param backup_vault_tags: Metadata that you can assign to help organize the resources that you create. Each tag is a key-value pair.
        :param encryption_key_arn: A server-side encryption key you can specify to encrypt your backups from services that support full AWS Backup management; for example, ``arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`` . If you specify a key, you must specify its ARN, not its alias. If you do not specify a key, AWS Backup creates a KMS key for you by default. To learn which AWS Backup services support full AWS Backup management and how AWS Backup handles encryption for backups from services that do not yet support full AWS Backup , see `Encryption for backups in AWS Backup <https://docs.aws.amazon.com/aws-backup/latest/devguide/encryption.html>`_
        :param lock_configuration: Configuration for `AWS Backup Vault Lock <https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html>`_ .
        :param notifications: The SNS event notifications for the specified backup vault.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_backup as backup
            
            # access_policy: Any
            
            cfn_backup_vault_props = backup.CfnBackupVaultProps(
                backup_vault_name="backupVaultName",
            
                # the properties below are optional
                access_policy=access_policy,
                backup_vault_tags={
                    "backup_vault_tags_key": "backupVaultTags"
                },
                encryption_key_arn="encryptionKeyArn",
                lock_configuration=backup.CfnBackupVault.LockConfigurationTypeProperty(
                    min_retention_days=123,
            
                    # the properties below are optional
                    changeable_for_days=123,
                    max_retention_days=123
                ),
                notifications=backup.CfnBackupVault.NotificationObjectTypeProperty(
                    backup_vault_events=["backupVaultEvents"],
                    sns_topic_arn="snsTopicArn"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "backup_vault_name": backup_vault_name,
        }
        if access_policy is not None:
            self._values["access_policy"] = access_policy
        if backup_vault_tags is not None:
            self._values["backup_vault_tags"] = backup_vault_tags
        if encryption_key_arn is not None:
            self._values["encryption_key_arn"] = encryption_key_arn
        if lock_configuration is not None:
            self._values["lock_configuration"] = lock_configuration
        if notifications is not None:
            self._values["notifications"] = notifications

    @builtins.property
    def backup_vault_name(self) -> builtins.str:
        '''The name of a logical container where backups are stored.

        Backup vaults are identified by names that are unique to the account used to create them and the AWS Region where they are created. They consist of lowercase letters, numbers, and hyphens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-backupvaultname
        '''
        result = self._values.get("backup_vault_name")
        assert result is not None, "Required property 'backup_vault_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def access_policy(self) -> typing.Any:
        '''A resource-based policy that is used to manage access permissions on the target backup vault.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-accesspolicy
        '''
        result = self._values.get("access_policy")
        return typing.cast(typing.Any, result)

    @builtins.property
    def backup_vault_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''Metadata that you can assign to help organize the resources that you create.

        Each tag is a key-value pair.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-backupvaulttags
        '''
        result = self._values.get("backup_vault_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

    @builtins.property
    def encryption_key_arn(self) -> typing.Optional[builtins.str]:
        '''A server-side encryption key you can specify to encrypt your backups from services that support full AWS Backup management;

        for example, ``arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`` . If you specify a key, you must specify its ARN, not its alias. If you do not specify a key, AWS Backup creates a KMS key for you by default.

        To learn which AWS Backup services support full AWS Backup management and how AWS Backup handles encryption for backups from services that do not yet support full AWS Backup , see `Encryption for backups in AWS Backup <https://docs.aws.amazon.com/aws-backup/latest/devguide/encryption.html>`_

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-encryptionkeyarn
        '''
        result = self._values.get("encryption_key_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def lock_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBackupVault.LockConfigurationTypeProperty, _IResolvable_da3f097b]]:
        '''Configuration for `AWS Backup Vault Lock <https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-lockconfiguration
        '''
        result = self._values.get("lock_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBackupVault.LockConfigurationTypeProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def notifications(
        self,
    ) -> typing.Optional[typing.Union[CfnBackupVault.NotificationObjectTypeProperty, _IResolvable_da3f097b]]:
        '''The SNS event notifications for the specified backup vault.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-notifications
        '''
        result = self._values.get("notifications")
        return typing.cast(typing.Optional[typing.Union[CfnBackupVault.NotificationObjectTypeProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBackupVaultProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnFramework(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.CfnFramework",
):
    '''A CloudFormation ``AWS::Backup::Framework``.

    Creates a framework with one or more controls. A framework is a collection of controls that you can use to evaluate your backup practices. By using pre-built customizable controls to define your policies, you can evaluate whether your backup practices comply with your policies and which resources are not yet in compliance.

    For a sample AWS CloudFormation template, see the `AWS Backup Developer Guide <https://docs.aws.amazon.com/aws-backup/latest/devguide/bam-cfn-integration.html#bam-cfn-frameworks-template>`_ .

    :cloudformationResource: AWS::Backup::Framework
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_backup as backup
        
        # control_scope: Any
        
        cfn_framework = backup.CfnFramework(self, "MyCfnFramework",
            framework_controls=[backup.CfnFramework.FrameworkControlProperty(
                control_name="controlName",
        
                # the properties below are optional
                control_input_parameters=[backup.CfnFramework.ControlInputParameterProperty(
                    parameter_name="parameterName",
                    parameter_value="parameterValue"
                )],
                control_scope=control_scope
            )],
        
            # the properties below are optional
            framework_description="frameworkDescription",
            framework_name="frameworkName",
            framework_tags=[CfnTag(
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
        framework_controls: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFramework.FrameworkControlProperty", _IResolvable_da3f097b]]],
        framework_description: typing.Optional[builtins.str] = None,
        framework_name: typing.Optional[builtins.str] = None,
        framework_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Backup::Framework``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param framework_controls: Contains detailed information about all of the controls of a framework. Each framework must contain at least one control.
        :param framework_description: An optional description of the framework with a maximum 1,024 characters.
        :param framework_name: The unique name of a framework. This name is between 1 and 256 characters, starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_).
        :param framework_tags: A list of tags with which to tag your framework.
        '''
        props = CfnFrameworkProps(
            framework_controls=framework_controls,
            framework_description=framework_description,
            framework_name=framework_name,
            framework_tags=framework_tags,
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
    @jsii.member(jsii_name="attrCreationTime")
    def attr_creation_time(self) -> _IResolvable_da3f097b:
        '''The UTC time when you created your framework.

        :cloudformationAttribute: CreationTime
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrCreationTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDeploymentStatus")
    def attr_deployment_status(self) -> builtins.str:
        '''Depolyment status refers to whether your framework has completed deployment.

        This status is usually ``Completed`` , but might also be ``Create in progress`` or another status. For a list of statuses, see `Framework compliance status <https://docs.aws.amazon.com/aws-backup/latest/devguide/viewing-frameworks.html>`_ in the *Developer Guide* .

        :cloudformationAttribute: DeploymentStatus
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDeploymentStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrFrameworkArn")
    def attr_framework_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of your framework.

        :cloudformationAttribute: FrameworkArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrFrameworkArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrFrameworkStatus")
    def attr_framework_status(self) -> builtins.str:
        '''Framework status refers to whether you have turned on resource tracking for all of your resources.

        This status is ``Active`` when you turn on all resources the framework evaluates. For other statuses and steps to correct them, see `Framework compliance status <https://docs.aws.amazon.com/aws-backup/latest/devguide/viewing-frameworks.html>`_ in the *Developer Guide* .

        :cloudformationAttribute: FrameworkStatus
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrFrameworkStatus"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="frameworkControls")
    def framework_controls(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFramework.FrameworkControlProperty", _IResolvable_da3f097b]]]:
        '''Contains detailed information about all of the controls of a framework.

        Each framework must contain at least one control.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html#cfn-backup-framework-frameworkcontrols
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFramework.FrameworkControlProperty", _IResolvable_da3f097b]]], jsii.get(self, "frameworkControls"))

    @framework_controls.setter
    def framework_controls(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFramework.FrameworkControlProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "frameworkControls", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="frameworkDescription")
    def framework_description(self) -> typing.Optional[builtins.str]:
        '''An optional description of the framework with a maximum 1,024 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html#cfn-backup-framework-frameworkdescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "frameworkDescription"))

    @framework_description.setter
    def framework_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "frameworkDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="frameworkName")
    def framework_name(self) -> typing.Optional[builtins.str]:
        '''The unique name of a framework.

        This name is between 1 and 256 characters, starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html#cfn-backup-framework-frameworkname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "frameworkName"))

    @framework_name.setter
    def framework_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "frameworkName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="frameworkTags")
    def framework_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''A list of tags with which to tag your framework.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html#cfn-backup-framework-frameworktags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], jsii.get(self, "frameworkTags"))

    @framework_tags.setter
    def framework_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]],
    ) -> None:
        jsii.set(self, "frameworkTags", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnFramework.ControlInputParameterProperty",
        jsii_struct_bases=[],
        name_mapping={
            "parameter_name": "parameterName",
            "parameter_value": "parameterValue",
        },
    )
    class ControlInputParameterProperty:
        def __init__(
            self,
            *,
            parameter_name: builtins.str,
            parameter_value: builtins.str,
        ) -> None:
            '''A list of parameters for a control.

            A control can have zero, one, or more than one parameter. An example of a control with two parameters is: "backup plan frequency is at least ``daily`` and the retention period is at least ``1 year`` ". The first parameter is ``daily`` . The second parameter is ``1 year`` .

            :param parameter_name: The name of a parameter, for example, ``BackupPlanFrequency`` .
            :param parameter_value: The value of parameter, for example, ``hourly`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-framework-controlinputparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                control_input_parameter_property = backup.CfnFramework.ControlInputParameterProperty(
                    parameter_name="parameterName",
                    parameter_value="parameterValue"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "parameter_name": parameter_name,
                "parameter_value": parameter_value,
            }

        @builtins.property
        def parameter_name(self) -> builtins.str:
            '''The name of a parameter, for example, ``BackupPlanFrequency`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-framework-controlinputparameter.html#cfn-backup-framework-controlinputparameter-parametername
            '''
            result = self._values.get("parameter_name")
            assert result is not None, "Required property 'parameter_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def parameter_value(self) -> builtins.str:
            '''The value of parameter, for example, ``hourly`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-framework-controlinputparameter.html#cfn-backup-framework-controlinputparameter-parametervalue
            '''
            result = self._values.get("parameter_value")
            assert result is not None, "Required property 'parameter_value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ControlInputParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_backup.CfnFramework.FrameworkControlProperty",
        jsii_struct_bases=[],
        name_mapping={
            "control_name": "controlName",
            "control_input_parameters": "controlInputParameters",
            "control_scope": "controlScope",
        },
    )
    class FrameworkControlProperty:
        def __init__(
            self,
            *,
            control_name: builtins.str,
            control_input_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFramework.ControlInputParameterProperty", _IResolvable_da3f097b]]]] = None,
            control_scope: typing.Any = None,
        ) -> None:
            '''Contains detailed information about all of the controls of a framework.

            Each framework must contain at least one control.

            :param control_name: The name of a control. This name is between 1 and 256 characters.
            :param control_input_parameters: A list of ``ParameterName`` and ``ParameterValue`` pairs.
            :param control_scope: The scope of a control. The control scope defines what the control will evaluate. Three examples of control scopes are: a specific backup plan, all backup plans with a specific tag, or all backup plans. For more information, see ``ControlScope`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-framework-frameworkcontrol.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_backup as backup
                
                # control_scope: Any
                
                framework_control_property = backup.CfnFramework.FrameworkControlProperty(
                    control_name="controlName",
                
                    # the properties below are optional
                    control_input_parameters=[backup.CfnFramework.ControlInputParameterProperty(
                        parameter_name="parameterName",
                        parameter_value="parameterValue"
                    )],
                    control_scope=control_scope
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "control_name": control_name,
            }
            if control_input_parameters is not None:
                self._values["control_input_parameters"] = control_input_parameters
            if control_scope is not None:
                self._values["control_scope"] = control_scope

        @builtins.property
        def control_name(self) -> builtins.str:
            '''The name of a control.

            This name is between 1 and 256 characters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-framework-frameworkcontrol.html#cfn-backup-framework-frameworkcontrol-controlname
            '''
            result = self._values.get("control_name")
            assert result is not None, "Required property 'control_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def control_input_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFramework.ControlInputParameterProperty", _IResolvable_da3f097b]]]]:
            '''A list of ``ParameterName`` and ``ParameterValue`` pairs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-framework-frameworkcontrol.html#cfn-backup-framework-frameworkcontrol-controlinputparameters
            '''
            result = self._values.get("control_input_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFramework.ControlInputParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def control_scope(self) -> typing.Any:
            '''The scope of a control.

            The control scope defines what the control will evaluate. Three examples of control scopes are: a specific backup plan, all backup plans with a specific tag, or all backup plans. For more information, see ``ControlScope`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-backup-framework-frameworkcontrol.html#cfn-backup-framework-frameworkcontrol-controlscope
            '''
            result = self._values.get("control_scope")
            return typing.cast(typing.Any, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FrameworkControlProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.CfnFrameworkProps",
    jsii_struct_bases=[],
    name_mapping={
        "framework_controls": "frameworkControls",
        "framework_description": "frameworkDescription",
        "framework_name": "frameworkName",
        "framework_tags": "frameworkTags",
    },
)
class CfnFrameworkProps:
    def __init__(
        self,
        *,
        framework_controls: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnFramework.FrameworkControlProperty, _IResolvable_da3f097b]]],
        framework_description: typing.Optional[builtins.str] = None,
        framework_name: typing.Optional[builtins.str] = None,
        framework_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnFramework``.

        :param framework_controls: Contains detailed information about all of the controls of a framework. Each framework must contain at least one control.
        :param framework_description: An optional description of the framework with a maximum 1,024 characters.
        :param framework_name: The unique name of a framework. This name is between 1 and 256 characters, starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_).
        :param framework_tags: A list of tags with which to tag your framework.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_backup as backup
            
            # control_scope: Any
            
            cfn_framework_props = backup.CfnFrameworkProps(
                framework_controls=[backup.CfnFramework.FrameworkControlProperty(
                    control_name="controlName",
            
                    # the properties below are optional
                    control_input_parameters=[backup.CfnFramework.ControlInputParameterProperty(
                        parameter_name="parameterName",
                        parameter_value="parameterValue"
                    )],
                    control_scope=control_scope
                )],
            
                # the properties below are optional
                framework_description="frameworkDescription",
                framework_name="frameworkName",
                framework_tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "framework_controls": framework_controls,
        }
        if framework_description is not None:
            self._values["framework_description"] = framework_description
        if framework_name is not None:
            self._values["framework_name"] = framework_name
        if framework_tags is not None:
            self._values["framework_tags"] = framework_tags

    @builtins.property
    def framework_controls(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFramework.FrameworkControlProperty, _IResolvable_da3f097b]]]:
        '''Contains detailed information about all of the controls of a framework.

        Each framework must contain at least one control.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html#cfn-backup-framework-frameworkcontrols
        '''
        result = self._values.get("framework_controls")
        assert result is not None, "Required property 'framework_controls' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFramework.FrameworkControlProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def framework_description(self) -> typing.Optional[builtins.str]:
        '''An optional description of the framework with a maximum 1,024 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html#cfn-backup-framework-frameworkdescription
        '''
        result = self._values.get("framework_description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def framework_name(self) -> typing.Optional[builtins.str]:
        '''The unique name of a framework.

        This name is between 1 and 256 characters, starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html#cfn-backup-framework-frameworkname
        '''
        result = self._values.get("framework_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def framework_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''A list of tags with which to tag your framework.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-framework.html#cfn-backup-framework-frameworktags
        '''
        result = self._values.get("framework_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFrameworkProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnReportPlan(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.CfnReportPlan",
):
    '''A CloudFormation ``AWS::Backup::ReportPlan``.

    Creates a report plan. A report plan is a document that contains information about the contents of the report and where AWS Backup will deliver it.

    If you call ``CreateReportPlan`` with a plan that already exists, you receive an ``AlreadyExistsException`` exception.

    For a sample AWS CloudFormation template, see the `AWS Backup Developer Guide <https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources.html#assigning-resources-cfn>`_ .

    :cloudformationResource: AWS::Backup::ReportPlan
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_backup as backup
        
        # report_delivery_channel: Any
        # report_setting: Any
        
        cfn_report_plan = backup.CfnReportPlan(self, "MyCfnReportPlan",
            report_delivery_channel=report_delivery_channel,
            report_setting=report_setting,
        
            # the properties below are optional
            report_plan_description="reportPlanDescription",
            report_plan_name="reportPlanName",
            report_plan_tags=[CfnTag(
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
        report_delivery_channel: typing.Any,
        report_setting: typing.Any,
        report_plan_description: typing.Optional[builtins.str] = None,
        report_plan_name: typing.Optional[builtins.str] = None,
        report_plan_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Backup::ReportPlan``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param report_delivery_channel: Contains information about where and how to deliver your reports, specifically your Amazon S3 bucket name, S3 key prefix, and the formats of your reports.
        :param report_setting: Identifies the report template for the report. Reports are built using a report template. The report templates are:. ``RESOURCE_COMPLIANCE_REPORT | CONTROL_COMPLIANCE_REPORT | BACKUP_JOB_REPORT | COPY_JOB_REPORT | RESTORE_JOB_REPORT`` If the report template is ``RESOURCE_COMPLIANCE_REPORT`` or ``CONTROL_COMPLIANCE_REPORT`` , this API resource also describes the report coverage by AWS Regions and frameworks.
        :param report_plan_description: An optional description of the report plan with a maximum 1,024 characters.
        :param report_plan_name: The unique name of the report plan. This name is between 1 and 256 characters starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_).
        :param report_plan_tags: A list of tags to tag your report plan.
        '''
        props = CfnReportPlanProps(
            report_delivery_channel=report_delivery_channel,
            report_setting=report_setting,
            report_plan_description=report_plan_description,
            report_plan_name=report_plan_name,
            report_plan_tags=report_plan_tags,
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
    @jsii.member(jsii_name="attrReportPlanArn")
    def attr_report_plan_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of your report plan.

        :cloudformationAttribute: ReportPlanArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrReportPlanArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="reportDeliveryChannel")
    def report_delivery_channel(self) -> typing.Any:
        '''Contains information about where and how to deliver your reports, specifically your Amazon S3 bucket name, S3 key prefix, and the formats of your reports.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportdeliverychannel
        '''
        return typing.cast(typing.Any, jsii.get(self, "reportDeliveryChannel"))

    @report_delivery_channel.setter
    def report_delivery_channel(self, value: typing.Any) -> None:
        jsii.set(self, "reportDeliveryChannel", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="reportSetting")
    def report_setting(self) -> typing.Any:
        '''Identifies the report template for the report. Reports are built using a report template. The report templates are:.

        ``RESOURCE_COMPLIANCE_REPORT | CONTROL_COMPLIANCE_REPORT | BACKUP_JOB_REPORT | COPY_JOB_REPORT | RESTORE_JOB_REPORT``

        If the report template is ``RESOURCE_COMPLIANCE_REPORT`` or ``CONTROL_COMPLIANCE_REPORT`` , this API resource also describes the report coverage by AWS Regions and frameworks.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportsetting
        '''
        return typing.cast(typing.Any, jsii.get(self, "reportSetting"))

    @report_setting.setter
    def report_setting(self, value: typing.Any) -> None:
        jsii.set(self, "reportSetting", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="reportPlanDescription")
    def report_plan_description(self) -> typing.Optional[builtins.str]:
        '''An optional description of the report plan with a maximum 1,024 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportplandescription
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "reportPlanDescription"))

    @report_plan_description.setter
    def report_plan_description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "reportPlanDescription", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="reportPlanName")
    def report_plan_name(self) -> typing.Optional[builtins.str]:
        '''The unique name of the report plan.

        This name is between 1 and 256 characters starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportplanname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "reportPlanName"))

    @report_plan_name.setter
    def report_plan_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "reportPlanName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="reportPlanTags")
    def report_plan_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''A list of tags to tag your report plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportplantags
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], jsii.get(self, "reportPlanTags"))

    @report_plan_tags.setter
    def report_plan_tags(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]],
    ) -> None:
        jsii.set(self, "reportPlanTags", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.CfnReportPlanProps",
    jsii_struct_bases=[],
    name_mapping={
        "report_delivery_channel": "reportDeliveryChannel",
        "report_setting": "reportSetting",
        "report_plan_description": "reportPlanDescription",
        "report_plan_name": "reportPlanName",
        "report_plan_tags": "reportPlanTags",
    },
)
class CfnReportPlanProps:
    def __init__(
        self,
        *,
        report_delivery_channel: typing.Any,
        report_setting: typing.Any,
        report_plan_description: typing.Optional[builtins.str] = None,
        report_plan_name: typing.Optional[builtins.str] = None,
        report_plan_tags: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnReportPlan``.

        :param report_delivery_channel: Contains information about where and how to deliver your reports, specifically your Amazon S3 bucket name, S3 key prefix, and the formats of your reports.
        :param report_setting: Identifies the report template for the report. Reports are built using a report template. The report templates are:. ``RESOURCE_COMPLIANCE_REPORT | CONTROL_COMPLIANCE_REPORT | BACKUP_JOB_REPORT | COPY_JOB_REPORT | RESTORE_JOB_REPORT`` If the report template is ``RESOURCE_COMPLIANCE_REPORT`` or ``CONTROL_COMPLIANCE_REPORT`` , this API resource also describes the report coverage by AWS Regions and frameworks.
        :param report_plan_description: An optional description of the report plan with a maximum 1,024 characters.
        :param report_plan_name: The unique name of the report plan. This name is between 1 and 256 characters starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_).
        :param report_plan_tags: A list of tags to tag your report plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_backup as backup
            
            # report_delivery_channel: Any
            # report_setting: Any
            
            cfn_report_plan_props = backup.CfnReportPlanProps(
                report_delivery_channel=report_delivery_channel,
                report_setting=report_setting,
            
                # the properties below are optional
                report_plan_description="reportPlanDescription",
                report_plan_name="reportPlanName",
                report_plan_tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "report_delivery_channel": report_delivery_channel,
            "report_setting": report_setting,
        }
        if report_plan_description is not None:
            self._values["report_plan_description"] = report_plan_description
        if report_plan_name is not None:
            self._values["report_plan_name"] = report_plan_name
        if report_plan_tags is not None:
            self._values["report_plan_tags"] = report_plan_tags

    @builtins.property
    def report_delivery_channel(self) -> typing.Any:
        '''Contains information about where and how to deliver your reports, specifically your Amazon S3 bucket name, S3 key prefix, and the formats of your reports.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportdeliverychannel
        '''
        result = self._values.get("report_delivery_channel")
        assert result is not None, "Required property 'report_delivery_channel' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def report_setting(self) -> typing.Any:
        '''Identifies the report template for the report. Reports are built using a report template. The report templates are:.

        ``RESOURCE_COMPLIANCE_REPORT | CONTROL_COMPLIANCE_REPORT | BACKUP_JOB_REPORT | COPY_JOB_REPORT | RESTORE_JOB_REPORT``

        If the report template is ``RESOURCE_COMPLIANCE_REPORT`` or ``CONTROL_COMPLIANCE_REPORT`` , this API resource also describes the report coverage by AWS Regions and frameworks.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportsetting
        '''
        result = self._values.get("report_setting")
        assert result is not None, "Required property 'report_setting' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def report_plan_description(self) -> typing.Optional[builtins.str]:
        '''An optional description of the report plan with a maximum 1,024 characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportplandescription
        '''
        result = self._values.get("report_plan_description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def report_plan_name(self) -> typing.Optional[builtins.str]:
        '''The unique name of the report plan.

        This name is between 1 and 256 characters starting with a letter, and consisting of letters (a-z, A-Z), numbers (0-9), and underscores (_).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportplanname
        '''
        result = self._values.get("report_plan_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def report_plan_tags(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
        '''A list of tags to tag your report plan.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-reportplan.html#cfn-backup-reportplan-reportplantags
        '''
        result = self._values.get("report_plan_tags")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnReportPlanProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_backup.IBackupPlan")
class IBackupPlan(_IResource_c80c4260, typing_extensions.Protocol):
    '''A backup plan.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupPlanId")
    def backup_plan_id(self) -> builtins.str:
        '''The identifier of the backup plan.

        :attribute: true
        '''
        ...


class _IBackupPlanProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A backup plan.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_backup.IBackupPlan"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupPlanId")
    def backup_plan_id(self) -> builtins.str:
        '''The identifier of the backup plan.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "backupPlanId"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IBackupPlan).__jsii_proxy_class__ = lambda : _IBackupPlanProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_backup.IBackupVault")
class IBackupVault(_IResource_c80c4260, typing_extensions.Protocol):
    '''A backup vault.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVaultArn")
    def backup_vault_arn(self) -> builtins.str:
        '''The ARN of the backup vault.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVaultName")
    def backup_vault_name(self) -> builtins.str:
        '''The name of a logical container where backups are stored.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the actions defined in actions to the given grantee on this backup vault.

        :param grantee: -
        :param actions: -
        '''
        ...


class _IBackupVaultProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A backup vault.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_backup.IBackupVault"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVaultArn")
    def backup_vault_arn(self) -> builtins.str:
        '''The ARN of the backup vault.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "backupVaultArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVaultName")
    def backup_vault_name(self) -> builtins.str:
        '''The name of a logical container where backups are stored.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "backupVaultName"))

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the actions defined in actions to the given grantee on this backup vault.

        :param grantee: -
        :param actions: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *actions]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IBackupVault).__jsii_proxy_class__ = lambda : _IBackupVaultProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_backup.TagCondition",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "value": "value", "operation": "operation"},
)
class TagCondition:
    def __init__(
        self,
        *,
        key: builtins.str,
        value: builtins.str,
        operation: typing.Optional["TagOperation"] = None,
    ) -> None:
        '''A tag condition.

        :param key: The key in a key-value pair. For example, in ``"ec2:ResourceTag/Department": "accounting"``, ``ec2:ResourceTag/Department`` is the key.
        :param value: The value in a key-value pair. For example, in ``"ec2:ResourceTag/Department": "accounting"``, ``accounting`` is the value.
        :param operation: An operation that is applied to a key-value pair used to filter resources in a selection. Default: STRING_EQUALS

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_backup as backup
            
            tag_condition = backup.TagCondition(
                key="key",
                value="value",
            
                # the properties below are optional
                operation=backup.TagOperation.STRING_EQUALS
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "key": key,
            "value": value,
        }
        if operation is not None:
            self._values["operation"] = operation

    @builtins.property
    def key(self) -> builtins.str:
        '''The key in a key-value pair.

        For example, in ``"ec2:ResourceTag/Department": "accounting"``,
        ``ec2:ResourceTag/Department`` is the key.
        '''
        result = self._values.get("key")
        assert result is not None, "Required property 'key' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def value(self) -> builtins.str:
        '''The value in a key-value pair.

        For example, in ``"ec2:ResourceTag/Department": "accounting"``,
        ``accounting`` is the value.
        '''
        result = self._values.get("value")
        assert result is not None, "Required property 'value' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def operation(self) -> typing.Optional["TagOperation"]:
        '''An operation that is applied to a key-value pair used to filter resources in a selection.

        :default: STRING_EQUALS
        '''
        result = self._values.get("operation")
        return typing.cast(typing.Optional["TagOperation"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TagCondition(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_backup.TagOperation")
class TagOperation(enum.Enum):
    '''An operation that is applied to a key-value pair.'''

    STRING_EQUALS = "STRING_EQUALS"
    '''StringEquals.'''
    DUMMY = "DUMMY"
    '''Dummy member.'''


@jsii.implements(IBackupPlan)
class BackupPlan(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.BackupPlan",
):
    '''A backup plan.

    :exampleMetadata: infused

    Example::

        # Daily, weekly and monthly with 5 year retention
        plan = backup.BackupPlan.daily_weekly_monthly5_year_retention(self, "Plan")
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        backup_plan_name: typing.Optional[builtins.str] = None,
        backup_plan_rules: typing.Optional[typing.Sequence[BackupPlanRule]] = None,
        backup_vault: typing.Optional[IBackupVault] = None,
        windows_vss: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param backup_plan_name: The display name of the backup plan. Default: - A CDK generated name
        :param backup_plan_rules: Rules for the backup plan. Use ``addRule()`` to add rules after instantiation. Default: - use ``addRule()`` to add rules
        :param backup_vault: The backup vault where backups are stored. Default: - use the vault defined at the rule level. If not defined a new common vault for the plan will be created
        :param windows_vss: Enable Windows VSS backup. Default: false
        '''
        props = BackupPlanProps(
            backup_plan_name=backup_plan_name,
            backup_plan_rules=backup_plan_rules,
            backup_vault=backup_vault,
            windows_vss=windows_vss,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="daily35DayRetention") # type: ignore[misc]
    @builtins.classmethod
    def daily35_day_retention(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        backup_vault: typing.Optional[IBackupVault] = None,
    ) -> "BackupPlan":
        '''Daily with 35 day retention.

        :param scope: -
        :param id: -
        :param backup_vault: -
        '''
        return typing.cast("BackupPlan", jsii.sinvoke(cls, "daily35DayRetention", [scope, id, backup_vault]))

    @jsii.member(jsii_name="dailyMonthly1YearRetention") # type: ignore[misc]
    @builtins.classmethod
    def daily_monthly1_year_retention(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        backup_vault: typing.Optional[IBackupVault] = None,
    ) -> "BackupPlan":
        '''Daily and monthly with 1 year retention.

        :param scope: -
        :param id: -
        :param backup_vault: -
        '''
        return typing.cast("BackupPlan", jsii.sinvoke(cls, "dailyMonthly1YearRetention", [scope, id, backup_vault]))

    @jsii.member(jsii_name="dailyWeeklyMonthly5YearRetention") # type: ignore[misc]
    @builtins.classmethod
    def daily_weekly_monthly5_year_retention(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        backup_vault: typing.Optional[IBackupVault] = None,
    ) -> "BackupPlan":
        '''Daily, weekly and monthly with 5 year retention.

        :param scope: -
        :param id: -
        :param backup_vault: -
        '''
        return typing.cast("BackupPlan", jsii.sinvoke(cls, "dailyWeeklyMonthly5YearRetention", [scope, id, backup_vault]))

    @jsii.member(jsii_name="dailyWeeklyMonthly7YearRetention") # type: ignore[misc]
    @builtins.classmethod
    def daily_weekly_monthly7_year_retention(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        backup_vault: typing.Optional[IBackupVault] = None,
    ) -> "BackupPlan":
        '''Daily, weekly and monthly with 7 year retention.

        :param scope: -
        :param id: -
        :param backup_vault: -
        '''
        return typing.cast("BackupPlan", jsii.sinvoke(cls, "dailyWeeklyMonthly7YearRetention", [scope, id, backup_vault]))

    @jsii.member(jsii_name="fromBackupPlanId") # type: ignore[misc]
    @builtins.classmethod
    def from_backup_plan_id(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        backup_plan_id: builtins.str,
    ) -> IBackupPlan:
        '''Import an existing backup plan.

        :param scope: -
        :param id: -
        :param backup_plan_id: -
        '''
        return typing.cast(IBackupPlan, jsii.sinvoke(cls, "fromBackupPlanId", [scope, id, backup_plan_id]))

    @jsii.member(jsii_name="addRule")
    def add_rule(self, rule: BackupPlanRule) -> None:
        '''Adds a rule to a plan.

        :param rule: the rule to add.
        '''
        return typing.cast(None, jsii.invoke(self, "addRule", [rule]))

    @jsii.member(jsii_name="addSelection")
    def add_selection(
        self,
        id: builtins.str,
        *,
        resources: typing.Sequence[BackupResource],
        allow_restores: typing.Optional[builtins.bool] = None,
        backup_selection_name: typing.Optional[builtins.str] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> BackupSelection:
        '''Adds a selection to this plan.

        :param id: -
        :param resources: The resources to backup. Use the helper static methods defined on ``BackupResource``.
        :param allow_restores: Whether to automatically give restores permissions to the role that AWS Backup uses. If ``true``, the ``AWSBackupServiceRolePolicyForRestores`` managed policy will be attached to the role. Default: false
        :param backup_selection_name: The name for this selection. Default: - a CDK generated name
        :param role: The role that AWS Backup uses to authenticate when backuping or restoring the resources. The ``AWSBackupServiceRolePolicyForBackup`` managed policy will be attached to this role. Default: - a new role will be created
        '''
        options = BackupSelectionOptions(
            resources=resources,
            allow_restores=allow_restores,
            backup_selection_name=backup_selection_name,
            role=role,
        )

        return typing.cast(BackupSelection, jsii.invoke(self, "addSelection", [id, options]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupPlanArn")
    def backup_plan_arn(self) -> builtins.str:
        '''The ARN of the backup plan.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "backupPlanArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupPlanId")
    def backup_plan_id(self) -> builtins.str:
        '''The identifier of the backup plan.'''
        return typing.cast(builtins.str, jsii.get(self, "backupPlanId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVault")
    def backup_vault(self) -> IBackupVault:
        '''The backup vault where backups are stored if not defined at the rule level.'''
        return typing.cast(IBackupVault, jsii.get(self, "backupVault"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="versionId")
    def version_id(self) -> builtins.str:
        '''Version Id.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "versionId"))


@jsii.implements(IBackupVault)
class BackupVault(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_backup.BackupVault",
):
    '''A backup vault.

    :exampleMetadata: infused

    Example::

        imported_vault = backup.BackupVault.from_backup_vault_name(self, "Vault", "myVaultName")
        
        role = iam.Role(self, "Access Role", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        
        imported_vault.grant(role, "backup:StartBackupJob")
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        access_policy: typing.Optional[_PolicyDocument_3ac34393] = None,
        backup_vault_name: typing.Optional[builtins.str] = None,
        block_recovery_point_deletion: typing.Optional[builtins.bool] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        notification_events: typing.Optional[typing.Sequence[BackupVaultEvents]] = None,
        notification_topic: typing.Optional[_ITopic_9eca4852] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param access_policy: A resource-based policy that is used to manage access permissions on the backup vault. Default: - access is not restricted
        :param backup_vault_name: The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the AWS Region where they are created. Default: - A CDK generated name
        :param block_recovery_point_deletion: Whether to add statements to the vault access policy that prevents anyone from deleting a recovery point. Default: false
        :param encryption_key: The server-side encryption key to use to protect your backups. Default: - an Amazon managed KMS key
        :param notification_events: The vault events to send. Default: - all vault events if ``notificationTopic`` is defined
        :param notification_topic: A SNS topic to send vault events to. Default: - no notifications
        :param removal_policy: The removal policy to apply to the vault. Note that removing a vault that contains recovery points will fail. Default: RemovalPolicy.RETAIN
        '''
        props = BackupVaultProps(
            access_policy=access_policy,
            backup_vault_name=backup_vault_name,
            block_recovery_point_deletion=block_recovery_point_deletion,
            encryption_key=encryption_key,
            notification_events=notification_events,
            notification_topic=notification_topic,
            removal_policy=removal_policy,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromBackupVaultArn") # type: ignore[misc]
    @builtins.classmethod
    def from_backup_vault_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        backup_vault_arn: builtins.str,
    ) -> IBackupVault:
        '''Import an existing backup vault by arn.

        :param scope: -
        :param id: -
        :param backup_vault_arn: -
        '''
        return typing.cast(IBackupVault, jsii.sinvoke(cls, "fromBackupVaultArn", [scope, id, backup_vault_arn]))

    @jsii.member(jsii_name="fromBackupVaultName") # type: ignore[misc]
    @builtins.classmethod
    def from_backup_vault_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        backup_vault_name: builtins.str,
    ) -> IBackupVault:
        '''Import an existing backup vault by name.

        :param scope: -
        :param id: -
        :param backup_vault_name: -
        '''
        return typing.cast(IBackupVault, jsii.sinvoke(cls, "fromBackupVaultName", [scope, id, backup_vault_name]))

    @jsii.member(jsii_name="addToAccessPolicy")
    def add_to_access_policy(self, statement: _PolicyStatement_0fe33853) -> None:
        '''Adds a statement to the vault access policy.

        :param statement: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToAccessPolicy", [statement]))

    @jsii.member(jsii_name="blockRecoveryPointDeletion")
    def block_recovery_point_deletion(self) -> None:
        '''Adds a statement to the vault access policy that prevents anyone from deleting a recovery point.'''
        return typing.cast(None, jsii.invoke(self, "blockRecoveryPointDeletion", []))

    @jsii.member(jsii_name="grant")
    def grant(
        self,
        grantee: _IGrantable_71c4f5de,
        *actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Grant the actions defined in actions to the given grantee on this Backup Vault resource.

        :param grantee: Principal to grant right to.
        :param actions: The actions to grant.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grant", [grantee, *actions]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVaultArn")
    def backup_vault_arn(self) -> builtins.str:
        '''The ARN of the backup vault.'''
        return typing.cast(builtins.str, jsii.get(self, "backupVaultArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="backupVaultName")
    def backup_vault_name(self) -> builtins.str:
        '''The name of a logical container where backups are stored.'''
        return typing.cast(builtins.str, jsii.get(self, "backupVaultName"))


__all__ = [
    "BackupPlan",
    "BackupPlanProps",
    "BackupPlanRule",
    "BackupPlanRuleProps",
    "BackupResource",
    "BackupSelection",
    "BackupSelectionOptions",
    "BackupSelectionProps",
    "BackupVault",
    "BackupVaultEvents",
    "BackupVaultProps",
    "CfnBackupPlan",
    "CfnBackupPlanProps",
    "CfnBackupSelection",
    "CfnBackupSelectionProps",
    "CfnBackupVault",
    "CfnBackupVaultProps",
    "CfnFramework",
    "CfnFrameworkProps",
    "CfnReportPlan",
    "CfnReportPlanProps",
    "IBackupPlan",
    "IBackupVault",
    "TagCondition",
    "TagOperation",
]

publication.publish()
