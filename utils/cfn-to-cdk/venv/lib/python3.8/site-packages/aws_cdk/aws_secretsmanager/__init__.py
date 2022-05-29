'''
# AWS Secrets Manager Construct Library

```python
import aws_cdk.aws_secretsmanager as secretsmanager
```

## Create a new Secret in a Stack

In order to have SecretsManager generate a new secret value automatically,
you can get started with the following:

```python
# Default secret
secret = secretsmanager.Secret(self, "Secret")
# Using the default secret
iam.User(self, "User",
    password=secret.secret_value
)
# Templated secret
templated_secret = secretsmanager.Secret(self, "TemplatedSecret",
    generate_secret_string=secretsmanager.SecretStringGenerator(
        secret_string_template=JSON.stringify({"username": "user"}),
        generate_string_key="password"
    )
)
# Using the templated secret
iam.User(self, "OtherUser",
    user_name=templated_secret.secret_value_from_json("username").to_string(),
    password=templated_secret.secret_value_from_json("password")
)
```

If you need to use a pre-existing secret, the recommended way is to manually
provision the secret in *AWS SecretsManager* and use the `Secret.fromSecretArn`
or `Secret.fromSecretAttributes` method to make it available in your CDK Application:

```python
# encryption_key: kms.Key

secret = secretsmanager.Secret.from_secret_attributes(self, "ImportedSecret",
    secret_arn="arn:aws:secretsmanager:<region>:<account-id-number>:secret:<secret-name>-<random-6-characters>",
    # If the secret is encrypted using a KMS-hosted CMK, either import or reference that key:
    encryption_key=encryption_key
)
```

SecretsManager secret values can only be used in select set of properties. For the
list of properties, see [the CloudFormation Dynamic References documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html).

A secret can set `RemovalPolicy`. If it set to `RETAIN`, that removing a secret will fail.

## Grant permission to use the secret to a role

You must grant permission to a resource for that resource to be allowed to
use a secret. This can be achieved with the `Secret.grantRead` and/or `Secret.grantUpdate`
method, depending on your need:

```python
role = iam.Role(self, "SomeRole", assumed_by=iam.AccountRootPrincipal())
secret = secretsmanager.Secret(self, "Secret")
secret.grant_read(role)
secret.grant_write(role)
```

If, as in the following example, your secret was created with a KMS key:

```python
# role: iam.Role

key = kms.Key(self, "KMS")
secret = secretsmanager.Secret(self, "Secret", encryption_key=key)
secret.grant_read(role)
secret.grant_write(role)
```

then `Secret.grantRead` and `Secret.grantWrite` will also grant the role the
relevant encrypt and decrypt permissions to the KMS key through the
SecretsManager service principal.

The principal is automatically added to Secret resource policy and KMS Key policy for cross account access:

```python
other_account = iam.AccountPrincipal("1234")
key = kms.Key(self, "KMS")
secret = secretsmanager.Secret(self, "Secret", encryption_key=key)
secret.grant_read(other_account)
```

## Rotating a Secret

### Using a Custom Lambda Function

A rotation schedule can be added to a Secret using a custom Lambda function:

```python
import aws_cdk.aws_lambda as lambda_

# fn: lambda.Function

secret = secretsmanager.Secret(self, "Secret")

secret.add_rotation_schedule("RotationSchedule",
    rotation_lambda=fn,
    automatically_after=Duration.days(15)
)
```

Note: The required permissions for Lambda to call SecretsManager and the other way round are automatically granted based on [AWS Documentation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-required-permissions.html) as long as the Lambda is not imported.

See [Overview of the Lambda Rotation Function](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-lambda-function-overview.html) on how to implement a Lambda Rotation Function.

### Using a Hosted Lambda Function

Use the `hostedRotation` prop to rotate a secret with a hosted Lambda function:

```python
secret = secretsmanager.Secret(self, "Secret")

secret.add_rotation_schedule("RotationSchedule",
    hosted_rotation=secretsmanager.HostedRotation.mysql_single_user()
)
```

Hosted rotation is available for secrets representing credentials for MySQL, PostgreSQL, Oracle,
MariaDB, SQLServer, Redshift and MongoDB (both for the single and multi user schemes).

When deployed in a VPC, the hosted rotation implements `ec2.IConnectable`:

```python
# my_vpc: ec2.Vpc
# db_connections: ec2.Connections
# secret: secretsmanager.Secret


my_hosted_rotation = secretsmanager.HostedRotation.mysql_single_user(vpc=my_vpc)
secret.add_rotation_schedule("RotationSchedule", hosted_rotation=my_hosted_rotation)
db_connections.allow_default_port_from(my_hosted_rotation)
```

See also [Automating secret creation in AWS CloudFormation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_cloudformation.html).

## Rotating database credentials

Define a `SecretRotation` to rotate database credentials:

```python
# my_secret: secretsmanager.Secret
# my_database: ec2.IConnectable
# my_vpc: ec2.Vpc


secretsmanager.SecretRotation(self, "SecretRotation",
    application=secretsmanager.SecretRotationApplication.MYSQL_ROTATION_SINGLE_USER,  # MySQL single user scheme
    secret=my_secret,
    target=my_database,  # a Connectable
    vpc=my_vpc,  # The VPC where the secret rotation application will be deployed
    exclude_characters=" %+:;{}"
)
```

The secret must be a JSON string with the following format:

```json
{
  "engine": "<required: database engine>",
  "host": "<required: instance host name>",
  "username": "<required: username>",
  "password": "<required: password>",
  "dbname": "<optional: database name>",
  "port": "<optional: if not specified, default port will be used>",
  "masterarn": "<required for multi user rotation: the arn of the master secret which will be used to create users/change passwords>"
}
```

For the multi user scheme, a `masterSecret` must be specified:

```python
# my_user_secret: secretsmanager.Secret
# my_master_secret: secretsmanager.Secret
# my_database: ec2.IConnectable
# my_vpc: ec2.Vpc


secretsmanager.SecretRotation(self, "SecretRotation",
    application=secretsmanager.SecretRotationApplication.MYSQL_ROTATION_MULTI_USER,
    secret=my_user_secret,  # The secret that will be rotated
    master_secret=my_master_secret,  # The secret used for the rotation
    target=my_database,
    vpc=my_vpc
)
```

See also [aws-rds](https://github.com/aws/aws-cdk/blob/master/packages/%40aws-cdk/aws-rds/README.md) where
credentials generation and rotation is integrated.

## Importing Secrets

Existing secrets can be imported by ARN, name, and other attributes (including the KMS key used to encrypt the secret).
Secrets imported by name should use the short-form of the name (without the SecretsManager-provided suffx);
the secret name must exist in the same account and region as the stack.
Importing by name makes it easier to reference secrets created in different regions, each with their own suffix and ARN.

```python
secret_complete_arn = "arn:aws:secretsmanager:eu-west-1:111111111111:secret:MySecret-f3gDy9"
secret_partial_arn = "arn:aws:secretsmanager:eu-west-1:111111111111:secret:MySecret" # No Secrets Manager suffix
encryption_key = kms.Key.from_key_arn(self, "MyEncKey", "arn:aws:kms:eu-west-1:111111111111:key/21c4b39b-fde2-4273-9ac0-d9bb5c0d0030")
my_secret_from_complete_arn = secretsmanager.Secret.from_secret_complete_arn(self, "SecretFromCompleteArn", secret_complete_arn)
my_secret_from_partial_arn = secretsmanager.Secret.from_secret_partial_arn(self, "SecretFromPartialArn", secret_partial_arn)
my_secret_from_name = secretsmanager.Secret.from_secret_name_v2(self, "SecretFromName", "MySecret")
my_secret_from_attrs = secretsmanager.Secret.from_secret_attributes(self, "SecretFromAttributes",
    secret_complete_arn=secret_complete_arn,
    encryption_key=encryption_key
)
```

## Replicating secrets

Secrets can be replicated to multiple regions by specifying `replicaRegions`:

```python
# my_key: kms.Key

secretsmanager.Secret(self, "Secret",
    replica_regions=[secretsmanager.ReplicaRegion(
        region="eu-west-1"
    ), secretsmanager.ReplicaRegion(
        region="eu-central-1",
        encryption_key=my_key
    )
    ]
)
```

Alternatively, use `addReplicaRegion()`:

```python
secret = secretsmanager.Secret(self, "Secret")
secret.add_replica_region("eu-west-1")
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
    IInterfaceVpcEndpoint as _IInterfaceVpcEndpoint_7481aea1,
    ISecurityGroup as _ISecurityGroup_acf8a799,
    IVpc as _IVpc_f30d5663,
    SubnetSelection as _SubnetSelection_e57d76df,
)
from ..aws_iam import (
    AddToResourcePolicyResult as _AddToResourcePolicyResult_1d0a53ad,
    Grant as _Grant_a7ae64f8,
    IGrantable as _IGrantable_71c4f5de,
    PolicyDocument as _PolicyDocument_3ac34393,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_kms import IKey as _IKey_5f11635f
from ..aws_lambda import IFunction as _IFunction_6adb0ab8


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.AttachedSecretOptions",
    jsii_struct_bases=[],
    name_mapping={"target": "target"},
)
class AttachedSecretOptions:
    def __init__(self, *, target: "ISecretAttachmentTarget") -> None:
        '''Options to add a secret attachment to a secret.

        :param target: The target to attach the secret to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            # secret_attachment_target: secretsmanager.ISecretAttachmentTarget
            
            attached_secret_options = secretsmanager.AttachedSecretOptions(
                target=secret_attachment_target
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target": target,
        }

    @builtins.property
    def target(self) -> "ISecretAttachmentTarget":
        '''The target to attach the secret to.'''
        result = self._values.get("target")
        assert result is not None, "Required property 'target' is missing"
        return typing.cast("ISecretAttachmentTarget", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AttachedSecretOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_secretsmanager.AttachmentTargetType")
class AttachmentTargetType(enum.Enum):
    '''The type of service or database that's being associated with the secret.'''

    RDS_DB_INSTANCE = "RDS_DB_INSTANCE"
    '''AWS::RDS::DBInstance.'''
    RDS_DB_CLUSTER = "RDS_DB_CLUSTER"
    '''AWS::RDS::DBCluster.'''
    RDS_DB_PROXY = "RDS_DB_PROXY"
    '''AWS::RDS::DBProxy.'''
    REDSHIFT_CLUSTER = "REDSHIFT_CLUSTER"
    '''AWS::Redshift::Cluster.'''
    DOCDB_DB_INSTANCE = "DOCDB_DB_INSTANCE"
    '''AWS::DocDB::DBInstance.'''
    DOCDB_DB_CLUSTER = "DOCDB_DB_CLUSTER"
    '''AWS::DocDB::DBCluster.'''


@jsii.implements(_IInspectable_c2943556)
class CfnResourcePolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.CfnResourcePolicy",
):
    '''A CloudFormation ``AWS::SecretsManager::ResourcePolicy``.

    Attaches a resource-based permission policy to a secret. A resource-based policy is optional. For more information, see `Authentication and access control for Secrets Manager <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html>`_

    For information about attaching a policy in the console, see `Attach a permissions policy to a secret <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-based-policies.html>`_ .

    *Required permissions:* ``secretsmanager:PutResourcePolicy`` . For more information, see `IAM policy actions for Secrets Manager <https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecretsmanager.html#awssecretsmanager-actions-as-permissions>`_ and `Authentication and access control in Secrets Manager <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html>`_ .

    :cloudformationResource: AWS::SecretsManager::ResourcePolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_secretsmanager as secretsmanager
        
        # resource_policy: Any
        
        cfn_resource_policy = secretsmanager.CfnResourcePolicy(self, "MyCfnResourcePolicy",
            resource_policy=resource_policy,
            secret_id="secretId",
        
            # the properties below are optional
            block_public_policy=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        resource_policy: typing.Any,
        secret_id: builtins.str,
        block_public_policy: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::SecretsManager::ResourcePolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param resource_policy: A JSON-formatted string for an AWS resource-based policy. For example policies, see `Permissions policy examples <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html>`_ .
        :param secret_id: The ARN or name of the secret to attach the resource-based policy. For an ARN, we recommend that you specify a complete ARN rather than a partial ARN.
        :param block_public_policy: Specifies whether to block resource-based policies that allow broad access to the secret. By default, Secrets Manager blocks policies that allow broad access, for example those that use a wildcard for the principal.
        '''
        props = CfnResourcePolicyProps(
            resource_policy=resource_policy,
            secret_id=secret_id,
            block_public_policy=block_public_policy,
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
    @jsii.member(jsii_name="resourcePolicy")
    def resource_policy(self) -> typing.Any:
        '''A JSON-formatted string for an AWS resource-based policy.

        For example policies, see `Permissions policy examples <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html#cfn-secretsmanager-resourcepolicy-resourcepolicy
        '''
        return typing.cast(typing.Any, jsii.get(self, "resourcePolicy"))

    @resource_policy.setter
    def resource_policy(self, value: typing.Any) -> None:
        jsii.set(self, "resourcePolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretId")
    def secret_id(self) -> builtins.str:
        '''The ARN or name of the secret to attach the resource-based policy.

        For an ARN, we recommend that you specify a complete ARN rather than a partial ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html#cfn-secretsmanager-resourcepolicy-secretid
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretId"))

    @secret_id.setter
    def secret_id(self, value: builtins.str) -> None:
        jsii.set(self, "secretId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="blockPublicPolicy")
    def block_public_policy(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether to block resource-based policies that allow broad access to the secret.

        By default, Secrets Manager blocks policies that allow broad access, for example those that use a wildcard for the principal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html#cfn-secretsmanager-resourcepolicy-blockpublicpolicy
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "blockPublicPolicy"))

    @block_public_policy.setter
    def block_public_policy(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "blockPublicPolicy", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.CfnResourcePolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "resource_policy": "resourcePolicy",
        "secret_id": "secretId",
        "block_public_policy": "blockPublicPolicy",
    },
)
class CfnResourcePolicyProps:
    def __init__(
        self,
        *,
        resource_policy: typing.Any,
        secret_id: builtins.str,
        block_public_policy: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnResourcePolicy``.

        :param resource_policy: A JSON-formatted string for an AWS resource-based policy. For example policies, see `Permissions policy examples <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html>`_ .
        :param secret_id: The ARN or name of the secret to attach the resource-based policy. For an ARN, we recommend that you specify a complete ARN rather than a partial ARN.
        :param block_public_policy: Specifies whether to block resource-based policies that allow broad access to the secret. By default, Secrets Manager blocks policies that allow broad access, for example those that use a wildcard for the principal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            # resource_policy: Any
            
            cfn_resource_policy_props = secretsmanager.CfnResourcePolicyProps(
                resource_policy=resource_policy,
                secret_id="secretId",
            
                # the properties below are optional
                block_public_policy=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resource_policy": resource_policy,
            "secret_id": secret_id,
        }
        if block_public_policy is not None:
            self._values["block_public_policy"] = block_public_policy

    @builtins.property
    def resource_policy(self) -> typing.Any:
        '''A JSON-formatted string for an AWS resource-based policy.

        For example policies, see `Permissions policy examples <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html#cfn-secretsmanager-resourcepolicy-resourcepolicy
        '''
        result = self._values.get("resource_policy")
        assert result is not None, "Required property 'resource_policy' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def secret_id(self) -> builtins.str:
        '''The ARN or name of the secret to attach the resource-based policy.

        For an ARN, we recommend that you specify a complete ARN rather than a partial ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html#cfn-secretsmanager-resourcepolicy-secretid
        '''
        result = self._values.get("secret_id")
        assert result is not None, "Required property 'secret_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def block_public_policy(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether to block resource-based policies that allow broad access to the secret.

        By default, Secrets Manager blocks policies that allow broad access, for example those that use a wildcard for the principal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html#cfn-secretsmanager-resourcepolicy-blockpublicpolicy
        '''
        result = self._values.get("block_public_policy")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnResourcePolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRotationSchedule(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.CfnRotationSchedule",
):
    '''A CloudFormation ``AWS::SecretsManager::RotationSchedule``.

    Configures rotation for a secret. You must already configure the secret with the details of the database or service. If you define both the secret and the database or service in an AWS CloudFormation template, then define the `AWS::SecretsManager::SecretTargetAttachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html>`_ resource to populate the secret with the connection details of the database or service before you attempt to configure rotation.

    :cloudformationResource: AWS::SecretsManager::RotationSchedule
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_secretsmanager as secretsmanager
        
        cfn_rotation_schedule = secretsmanager.CfnRotationSchedule(self, "MyCfnRotationSchedule",
            secret_id="secretId",
        
            # the properties below are optional
            hosted_rotation_lambda=secretsmanager.CfnRotationSchedule.HostedRotationLambdaProperty(
                rotation_type="rotationType",
        
                # the properties below are optional
                kms_key_arn="kmsKeyArn",
                master_secret_arn="masterSecretArn",
                master_secret_kms_key_arn="masterSecretKmsKeyArn",
                rotation_lambda_name="rotationLambdaName",
                superuser_secret_arn="superuserSecretArn",
                superuser_secret_kms_key_arn="superuserSecretKmsKeyArn",
                vpc_security_group_ids="vpcSecurityGroupIds",
                vpc_subnet_ids="vpcSubnetIds"
            ),
            rotate_immediately_on_update=False,
            rotation_lambda_arn="rotationLambdaArn",
            rotation_rules=secretsmanager.CfnRotationSchedule.RotationRulesProperty(
                automatically_after_days=123,
                duration="duration",
                schedule_expression="scheduleExpression"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        secret_id: builtins.str,
        hosted_rotation_lambda: typing.Optional[typing.Union["CfnRotationSchedule.HostedRotationLambdaProperty", _IResolvable_da3f097b]] = None,
        rotate_immediately_on_update: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        rotation_lambda_arn: typing.Optional[builtins.str] = None,
        rotation_rules: typing.Optional[typing.Union["CfnRotationSchedule.RotationRulesProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::SecretsManager::RotationSchedule``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param secret_id: The ARN or name of the secret to rotate. To reference a secret also created in this template, use the `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the secret's logical ID.
        :param hosted_rotation_lambda: To use these values, you must specify ``Transform: AWS::SecretsManager-2020-07-23`` at the beginning of the CloudFormation template. When you enter valid values for ``RotationSchedule.HostedRotationLambda`` , Secrets Manager launches a Lambda that performs rotation on the secret specified in the ``secret-id`` property. The template creates a Lambda as part of a nested stack within the current stack.
        :param rotate_immediately_on_update: Specifies whether to rotate the secret immediately or wait until the next scheduled rotation window. The rotation schedule is defined in ``RotationRules`` . If you don't immediately rotate the secret, Secrets Manager tests the rotation configuration by running the ```testSecret`` step <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_how.html>`_ of the Lambda rotation function. The test creates an ``AWSPENDING`` version of the secret and then removes it. If you don't specify this value, then by default, Secrets Manager rotates the secret immediately.
        :param rotation_lambda_arn: The ARN of the Lambda function that can rotate the secret. If you don't specify this parameter, then the secret must already have the ARN of a Lambda function configured. To reference a Lambda function also created in this template, use the `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the function's logical ID.
        :param rotation_rules: A structure that defines the rotation configuration for this secret.
        '''
        props = CfnRotationScheduleProps(
            secret_id=secret_id,
            hosted_rotation_lambda=hosted_rotation_lambda,
            rotate_immediately_on_update=rotate_immediately_on_update,
            rotation_lambda_arn=rotation_lambda_arn,
            rotation_rules=rotation_rules,
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
    @jsii.member(jsii_name="secretId")
    def secret_id(self) -> builtins.str:
        '''The ARN or name of the secret to rotate.

        To reference a secret also created in this template, use the `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the secret's logical ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-secretid
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretId"))

    @secret_id.setter
    def secret_id(self, value: builtins.str) -> None:
        jsii.set(self, "secretId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hostedRotationLambda")
    def hosted_rotation_lambda(
        self,
    ) -> typing.Optional[typing.Union["CfnRotationSchedule.HostedRotationLambdaProperty", _IResolvable_da3f097b]]:
        '''To use these values, you must specify ``Transform: AWS::SecretsManager-2020-07-23`` at the beginning of the CloudFormation template.

        When you enter valid values for ``RotationSchedule.HostedRotationLambda`` , Secrets Manager launches a Lambda that performs rotation on the secret specified in the ``secret-id`` property. The template creates a Lambda as part of a nested stack within the current stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda
        '''
        return typing.cast(typing.Optional[typing.Union["CfnRotationSchedule.HostedRotationLambdaProperty", _IResolvable_da3f097b]], jsii.get(self, "hostedRotationLambda"))

    @hosted_rotation_lambda.setter
    def hosted_rotation_lambda(
        self,
        value: typing.Optional[typing.Union["CfnRotationSchedule.HostedRotationLambdaProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "hostedRotationLambda", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="rotateImmediatelyOnUpdate")
    def rotate_immediately_on_update(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether to rotate the secret immediately or wait until the next scheduled rotation window.

        The rotation schedule is defined in ``RotationRules`` .

        If you don't immediately rotate the secret, Secrets Manager tests the rotation configuration by running the ```testSecret`` step <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_how.html>`_ of the Lambda rotation function. The test creates an ``AWSPENDING`` version of the secret and then removes it.

        If you don't specify this value, then by default, Secrets Manager rotates the secret immediately.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-rotateimmediatelyonupdate
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "rotateImmediatelyOnUpdate"))

    @rotate_immediately_on_update.setter
    def rotate_immediately_on_update(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "rotateImmediatelyOnUpdate", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="rotationLambdaArn")
    def rotation_lambda_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the Lambda function that can rotate the secret.

        If you don't specify this parameter, then the secret must already have the ARN of a Lambda function configured.

        To reference a Lambda function also created in this template, use the `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the function's logical ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-rotationlambdaarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "rotationLambdaArn"))

    @rotation_lambda_arn.setter
    def rotation_lambda_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "rotationLambdaArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="rotationRules")
    def rotation_rules(
        self,
    ) -> typing.Optional[typing.Union["CfnRotationSchedule.RotationRulesProperty", _IResolvable_da3f097b]]:
        '''A structure that defines the rotation configuration for this secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-rotationrules
        '''
        return typing.cast(typing.Optional[typing.Union["CfnRotationSchedule.RotationRulesProperty", _IResolvable_da3f097b]], jsii.get(self, "rotationRules"))

    @rotation_rules.setter
    def rotation_rules(
        self,
        value: typing.Optional[typing.Union["CfnRotationSchedule.RotationRulesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "rotationRules", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_secretsmanager.CfnRotationSchedule.HostedRotationLambdaProperty",
        jsii_struct_bases=[],
        name_mapping={
            "rotation_type": "rotationType",
            "kms_key_arn": "kmsKeyArn",
            "master_secret_arn": "masterSecretArn",
            "master_secret_kms_key_arn": "masterSecretKmsKeyArn",
            "rotation_lambda_name": "rotationLambdaName",
            "superuser_secret_arn": "superuserSecretArn",
            "superuser_secret_kms_key_arn": "superuserSecretKmsKeyArn",
            "vpc_security_group_ids": "vpcSecurityGroupIds",
            "vpc_subnet_ids": "vpcSubnetIds",
        },
    )
    class HostedRotationLambdaProperty:
        def __init__(
            self,
            *,
            rotation_type: builtins.str,
            kms_key_arn: typing.Optional[builtins.str] = None,
            master_secret_arn: typing.Optional[builtins.str] = None,
            master_secret_kms_key_arn: typing.Optional[builtins.str] = None,
            rotation_lambda_name: typing.Optional[builtins.str] = None,
            superuser_secret_arn: typing.Optional[builtins.str] = None,
            superuser_secret_kms_key_arn: typing.Optional[builtins.str] = None,
            vpc_security_group_ids: typing.Optional[builtins.str] = None,
            vpc_subnet_ids: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies that you want to create a hosted Lambda rotation function.

            To use these values, you must specify ``Transform: AWS::SecretsManager-2020-07-23`` at the beginning of the CloudFormation template.

            :param rotation_type: The type of rotation template to use. For more information, see `Secrets Manager rotation function templates <https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_available-rotation-templates.html>`_ . You can specify one of the following ``RotationTypes`` : - MySQLSingleUser - MySQLMultiUser - PostgreSQLSingleUser - PostgreSQLMultiUser - OracleSingleUser - OracleMultiUser - MariaDBSingleUser - MariaDBMultiUser - SQLServerSingleUser - SQLServerMultiUser - RedshiftSingleUser - RedshiftMultiUser - MongoDBSingleUser - MongoDBMultiUser
            :param kms_key_arn: The ARN of the KMS key that Secrets Manager uses to encrypt the secret. If you don't specify this value, then Secrets Manager uses the key ``aws/secretsmanager`` . If ``aws/secretsmanager`` doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value.
            :param master_secret_arn: The ARN of the secret that contains elevated credentials. The Lambda rotation function uses this secret for the `Alternating users rotation strategy <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets_strategies.html#rotating-secrets-two-users>`_ .
            :param master_secret_kms_key_arn: The ARN of the KMS key that Secrets Manager uses to encrypt the elevated secret if you use the `alternating users strategy <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets_strategies.html#rotating-secrets-two-users>`_ . If you don't specify this value and you use the alternating users strategy, then Secrets Manager uses the key ``aws/secretsmanager`` . If ``aws/secretsmanager`` doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value.
            :param rotation_lambda_name: The name of the Lambda rotation function.
            :param superuser_secret_arn: The ARN of the secret that contains elevated credentials. The Lambda rotation function uses this secret for the `Alternating users rotation strategy <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets_strategies.html#rotating-secrets-two-users>`_ .
            :param superuser_secret_kms_key_arn: The ARN of the KMS key that Secrets Manager uses to encrypt the elevated secret if you use the `alternating users strategy <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets_strategies.html#rotating-secrets-two-users>`_ . If you don't specify this value and you use the alternating users strategy, then Secrets Manager uses the key ``aws/secretsmanager`` . If ``aws/secretsmanager`` doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value.
            :param vpc_security_group_ids: A comma-separated list of security group IDs applied to the target database. The templates applies the same security groups as on the Lambda rotation function that is created as part of this stack.
            :param vpc_subnet_ids: A comma separated list of VPC subnet IDs of the target database network. The Lambda rotation function is in the same subnet group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_secretsmanager as secretsmanager
                
                hosted_rotation_lambda_property = secretsmanager.CfnRotationSchedule.HostedRotationLambdaProperty(
                    rotation_type="rotationType",
                
                    # the properties below are optional
                    kms_key_arn="kmsKeyArn",
                    master_secret_arn="masterSecretArn",
                    master_secret_kms_key_arn="masterSecretKmsKeyArn",
                    rotation_lambda_name="rotationLambdaName",
                    superuser_secret_arn="superuserSecretArn",
                    superuser_secret_kms_key_arn="superuserSecretKmsKeyArn",
                    vpc_security_group_ids="vpcSecurityGroupIds",
                    vpc_subnet_ids="vpcSubnetIds"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "rotation_type": rotation_type,
            }
            if kms_key_arn is not None:
                self._values["kms_key_arn"] = kms_key_arn
            if master_secret_arn is not None:
                self._values["master_secret_arn"] = master_secret_arn
            if master_secret_kms_key_arn is not None:
                self._values["master_secret_kms_key_arn"] = master_secret_kms_key_arn
            if rotation_lambda_name is not None:
                self._values["rotation_lambda_name"] = rotation_lambda_name
            if superuser_secret_arn is not None:
                self._values["superuser_secret_arn"] = superuser_secret_arn
            if superuser_secret_kms_key_arn is not None:
                self._values["superuser_secret_kms_key_arn"] = superuser_secret_kms_key_arn
            if vpc_security_group_ids is not None:
                self._values["vpc_security_group_ids"] = vpc_security_group_ids
            if vpc_subnet_ids is not None:
                self._values["vpc_subnet_ids"] = vpc_subnet_ids

        @builtins.property
        def rotation_type(self) -> builtins.str:
            '''The type of rotation template to use. For more information, see `Secrets Manager rotation function templates <https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_available-rotation-templates.html>`_ .

            You can specify one of the following ``RotationTypes`` :

            - MySQLSingleUser
            - MySQLMultiUser
            - PostgreSQLSingleUser
            - PostgreSQLMultiUser
            - OracleSingleUser
            - OracleMultiUser
            - MariaDBSingleUser
            - MariaDBMultiUser
            - SQLServerSingleUser
            - SQLServerMultiUser
            - RedshiftSingleUser
            - RedshiftMultiUser
            - MongoDBSingleUser
            - MongoDBMultiUser

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-rotationtype
            '''
            result = self._values.get("rotation_type")
            assert result is not None, "Required property 'rotation_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the KMS key that Secrets Manager uses to encrypt the secret.

            If you don't specify this value, then Secrets Manager uses the key ``aws/secretsmanager`` . If ``aws/secretsmanager`` doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-kmskeyarn
            '''
            result = self._values.get("kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def master_secret_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the secret that contains elevated credentials.

            The Lambda rotation function uses this secret for the `Alternating users rotation strategy <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets_strategies.html#rotating-secrets-two-users>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-mastersecretarn
            '''
            result = self._values.get("master_secret_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def master_secret_kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the KMS key that Secrets Manager uses to encrypt the elevated secret if you use the `alternating users strategy <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets_strategies.html#rotating-secrets-two-users>`_ . If you don't specify this value and you use the alternating users strategy, then Secrets Manager uses the key ``aws/secretsmanager`` . If ``aws/secretsmanager`` doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-mastersecretkmskeyarn
            '''
            result = self._values.get("master_secret_kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def rotation_lambda_name(self) -> typing.Optional[builtins.str]:
            '''The name of the Lambda rotation function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-rotationlambdaname
            '''
            result = self._values.get("rotation_lambda_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def superuser_secret_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the secret that contains elevated credentials.

            The Lambda rotation function uses this secret for the `Alternating users rotation strategy <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets_strategies.html#rotating-secrets-two-users>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-superusersecretarn
            '''
            result = self._values.get("superuser_secret_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def superuser_secret_kms_key_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the KMS key that Secrets Manager uses to encrypt the elevated secret if you use the `alternating users strategy <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets_strategies.html#rotating-secrets-two-users>`_ . If you don't specify this value and you use the alternating users strategy, then Secrets Manager uses the key ``aws/secretsmanager`` . If ``aws/secretsmanager`` doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-superusersecretkmskeyarn
            '''
            result = self._values.get("superuser_secret_kms_key_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def vpc_security_group_ids(self) -> typing.Optional[builtins.str]:
            '''A comma-separated list of security group IDs applied to the target database.

            The templates applies the same security groups as on the Lambda rotation function that is created as part of this stack.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-vpcsecuritygroupids
            '''
            result = self._values.get("vpc_security_group_ids")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def vpc_subnet_ids(self) -> typing.Optional[builtins.str]:
            '''A comma separated list of VPC subnet IDs of the target database network.

            The Lambda rotation function is in the same subnet group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda-vpcsubnetids
            '''
            result = self._values.get("vpc_subnet_ids")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HostedRotationLambdaProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_secretsmanager.CfnRotationSchedule.RotationRulesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "automatically_after_days": "automaticallyAfterDays",
            "duration": "duration",
            "schedule_expression": "scheduleExpression",
        },
    )
    class RotationRulesProperty:
        def __init__(
            self,
            *,
            automatically_after_days: typing.Optional[jsii.Number] = None,
            duration: typing.Optional[builtins.str] = None,
            schedule_expression: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure that defines the rotation configuration for the secret.

            :param automatically_after_days: The number of days between automatic scheduled rotations of the secret. You can use this value to check that your secret meets your compliance guidelines for how often secrets must be rotated. In ``DescribeSecret`` and ``ListSecrets`` , this value is calculated from the rotation schedule after every successful rotation. In ``RotateSecret`` , you can set the rotation schedule in ``RotationRules`` with ``AutomaticallyAfterDays`` or ``ScheduleExpression`` , but not both.
            :param duration: The length of the rotation window in hours, for example ``3h`` for a three hour window. Secrets Manager rotates your secret at any time during this window. The window must not go into the next UTC day. If you don't specify this value, the window automatically ends at the end of the UTC day. The window begins according to the ``ScheduleExpression`` . For more information, including examples, see `Schedule expressions in Secrets Manager rotation <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html>`_ .
            :param schedule_expression: A ``cron()`` or ``rate()`` expression that defines the schedule for rotating your secret. Secrets Manager rotation schedules use UTC time zone. Secrets Manager ``rate()`` expressions represent the interval in days that you want to rotate your secret, for example ``rate(10 days)`` . If you use a ``rate()`` expression, the rotation window opens at midnight, and Secrets Manager rotates your secret any time that day after midnight. You can set a ``Duration`` to shorten the rotation window. You can use a ``cron()`` expression to create rotation schedules that are more detailed than a rotation interval. For more information, including examples, see `Schedule expressions in Secrets Manager rotation <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html>`_ . If you use a ``cron()`` expression, Secrets Manager rotates your secret any time during that day after the window opens. For example, ``cron(0 8 1 * ? *)`` represents a rotation window that occurs on the first day of every month beginning at 8:00 AM UTC. Secrets Manager rotates the secret any time that day after 8:00 AM. You can set a ``Duration`` to shorten the rotation window.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-rotationrules.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_secretsmanager as secretsmanager
                
                rotation_rules_property = secretsmanager.CfnRotationSchedule.RotationRulesProperty(
                    automatically_after_days=123,
                    duration="duration",
                    schedule_expression="scheduleExpression"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if automatically_after_days is not None:
                self._values["automatically_after_days"] = automatically_after_days
            if duration is not None:
                self._values["duration"] = duration
            if schedule_expression is not None:
                self._values["schedule_expression"] = schedule_expression

        @builtins.property
        def automatically_after_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days between automatic scheduled rotations of the secret.

            You can use this value to check that your secret meets your compliance guidelines for how often secrets must be rotated.

            In ``DescribeSecret`` and ``ListSecrets`` , this value is calculated from the rotation schedule after every successful rotation. In ``RotateSecret`` , you can set the rotation schedule in ``RotationRules`` with ``AutomaticallyAfterDays`` or ``ScheduleExpression`` , but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-rotationrules.html#cfn-secretsmanager-rotationschedule-rotationrules-automaticallyafterdays
            '''
            result = self._values.get("automatically_after_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def duration(self) -> typing.Optional[builtins.str]:
            '''The length of the rotation window in hours, for example ``3h`` for a three hour window.

            Secrets Manager rotates your secret at any time during this window. The window must not go into the next UTC day. If you don't specify this value, the window automatically ends at the end of the UTC day. The window begins according to the ``ScheduleExpression`` . For more information, including examples, see `Schedule expressions in Secrets Manager rotation <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-rotationrules.html#cfn-secretsmanager-rotationschedule-rotationrules-duration
            '''
            result = self._values.get("duration")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def schedule_expression(self) -> typing.Optional[builtins.str]:
            '''A ``cron()`` or ``rate()`` expression that defines the schedule for rotating your secret.

            Secrets Manager rotation schedules use UTC time zone.

            Secrets Manager ``rate()`` expressions represent the interval in days that you want to rotate your secret, for example ``rate(10 days)`` . If you use a ``rate()`` expression, the rotation window opens at midnight, and Secrets Manager rotates your secret any time that day after midnight. You can set a ``Duration`` to shorten the rotation window.

            You can use a ``cron()`` expression to create rotation schedules that are more detailed than a rotation interval. For more information, including examples, see `Schedule expressions in Secrets Manager rotation <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_schedule.html>`_ . If you use a ``cron()`` expression, Secrets Manager rotates your secret any time during that day after the window opens. For example, ``cron(0 8 1 * ? *)`` represents a rotation window that occurs on the first day of every month beginning at 8:00 AM UTC. Secrets Manager rotates the secret any time that day after 8:00 AM. You can set a ``Duration`` to shorten the rotation window.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-rotationrules.html#cfn-secretsmanager-rotationschedule-rotationrules-scheduleexpression
            '''
            result = self._values.get("schedule_expression")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RotationRulesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.CfnRotationScheduleProps",
    jsii_struct_bases=[],
    name_mapping={
        "secret_id": "secretId",
        "hosted_rotation_lambda": "hostedRotationLambda",
        "rotate_immediately_on_update": "rotateImmediatelyOnUpdate",
        "rotation_lambda_arn": "rotationLambdaArn",
        "rotation_rules": "rotationRules",
    },
)
class CfnRotationScheduleProps:
    def __init__(
        self,
        *,
        secret_id: builtins.str,
        hosted_rotation_lambda: typing.Optional[typing.Union[CfnRotationSchedule.HostedRotationLambdaProperty, _IResolvable_da3f097b]] = None,
        rotate_immediately_on_update: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        rotation_lambda_arn: typing.Optional[builtins.str] = None,
        rotation_rules: typing.Optional[typing.Union[CfnRotationSchedule.RotationRulesProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRotationSchedule``.

        :param secret_id: The ARN or name of the secret to rotate. To reference a secret also created in this template, use the `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the secret's logical ID.
        :param hosted_rotation_lambda: To use these values, you must specify ``Transform: AWS::SecretsManager-2020-07-23`` at the beginning of the CloudFormation template. When you enter valid values for ``RotationSchedule.HostedRotationLambda`` , Secrets Manager launches a Lambda that performs rotation on the secret specified in the ``secret-id`` property. The template creates a Lambda as part of a nested stack within the current stack.
        :param rotate_immediately_on_update: Specifies whether to rotate the secret immediately or wait until the next scheduled rotation window. The rotation schedule is defined in ``RotationRules`` . If you don't immediately rotate the secret, Secrets Manager tests the rotation configuration by running the ```testSecret`` step <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_how.html>`_ of the Lambda rotation function. The test creates an ``AWSPENDING`` version of the secret and then removes it. If you don't specify this value, then by default, Secrets Manager rotates the secret immediately.
        :param rotation_lambda_arn: The ARN of the Lambda function that can rotate the secret. If you don't specify this parameter, then the secret must already have the ARN of a Lambda function configured. To reference a Lambda function also created in this template, use the `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the function's logical ID.
        :param rotation_rules: A structure that defines the rotation configuration for this secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            cfn_rotation_schedule_props = secretsmanager.CfnRotationScheduleProps(
                secret_id="secretId",
            
                # the properties below are optional
                hosted_rotation_lambda=secretsmanager.CfnRotationSchedule.HostedRotationLambdaProperty(
                    rotation_type="rotationType",
            
                    # the properties below are optional
                    kms_key_arn="kmsKeyArn",
                    master_secret_arn="masterSecretArn",
                    master_secret_kms_key_arn="masterSecretKmsKeyArn",
                    rotation_lambda_name="rotationLambdaName",
                    superuser_secret_arn="superuserSecretArn",
                    superuser_secret_kms_key_arn="superuserSecretKmsKeyArn",
                    vpc_security_group_ids="vpcSecurityGroupIds",
                    vpc_subnet_ids="vpcSubnetIds"
                ),
                rotate_immediately_on_update=False,
                rotation_lambda_arn="rotationLambdaArn",
                rotation_rules=secretsmanager.CfnRotationSchedule.RotationRulesProperty(
                    automatically_after_days=123,
                    duration="duration",
                    schedule_expression="scheduleExpression"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "secret_id": secret_id,
        }
        if hosted_rotation_lambda is not None:
            self._values["hosted_rotation_lambda"] = hosted_rotation_lambda
        if rotate_immediately_on_update is not None:
            self._values["rotate_immediately_on_update"] = rotate_immediately_on_update
        if rotation_lambda_arn is not None:
            self._values["rotation_lambda_arn"] = rotation_lambda_arn
        if rotation_rules is not None:
            self._values["rotation_rules"] = rotation_rules

    @builtins.property
    def secret_id(self) -> builtins.str:
        '''The ARN or name of the secret to rotate.

        To reference a secret also created in this template, use the `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the secret's logical ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-secretid
        '''
        result = self._values.get("secret_id")
        assert result is not None, "Required property 'secret_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def hosted_rotation_lambda(
        self,
    ) -> typing.Optional[typing.Union[CfnRotationSchedule.HostedRotationLambdaProperty, _IResolvable_da3f097b]]:
        '''To use these values, you must specify ``Transform: AWS::SecretsManager-2020-07-23`` at the beginning of the CloudFormation template.

        When you enter valid values for ``RotationSchedule.HostedRotationLambda`` , Secrets Manager launches a Lambda that performs rotation on the secret specified in the ``secret-id`` property. The template creates a Lambda as part of a nested stack within the current stack.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-hostedrotationlambda
        '''
        result = self._values.get("hosted_rotation_lambda")
        return typing.cast(typing.Optional[typing.Union[CfnRotationSchedule.HostedRotationLambdaProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def rotate_immediately_on_update(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether to rotate the secret immediately or wait until the next scheduled rotation window.

        The rotation schedule is defined in ``RotationRules`` .

        If you don't immediately rotate the secret, Secrets Manager tests the rotation configuration by running the ```testSecret`` step <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_how.html>`_ of the Lambda rotation function. The test creates an ``AWSPENDING`` version of the secret and then removes it.

        If you don't specify this value, then by default, Secrets Manager rotates the secret immediately.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-rotateimmediatelyonupdate
        '''
        result = self._values.get("rotate_immediately_on_update")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def rotation_lambda_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the Lambda function that can rotate the secret.

        If you don't specify this parameter, then the secret must already have the ARN of a Lambda function configured.

        To reference a Lambda function also created in this template, use the `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the function's logical ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-rotationlambdaarn
        '''
        result = self._values.get("rotation_lambda_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def rotation_rules(
        self,
    ) -> typing.Optional[typing.Union[CfnRotationSchedule.RotationRulesProperty, _IResolvable_da3f097b]]:
        '''A structure that defines the rotation configuration for this secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html#cfn-secretsmanager-rotationschedule-rotationrules
        '''
        result = self._values.get("rotation_rules")
        return typing.cast(typing.Optional[typing.Union[CfnRotationSchedule.RotationRulesProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRotationScheduleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSecret(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.CfnSecret",
):
    '''A CloudFormation ``AWS::SecretsManager::Secret``.

    Creates a new secret. A *secret* is a set of credentials, such as a user name and password, that you store in an encrypted form in Secrets Manager. The secret also includes the connection information to access a database or other service, which Secrets Manager doesn't encrypt. A secret in Secrets Manager consists of both the protected secret data and the important information needed to manage the secret.

    For information about creating a secret in the console, see `Create a secret <https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_create-basic-secret.html>`_ .

    For information about creating a secret using the CLI or SDK, see `CreateSecret <https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html>`_ .

    To specify the encrypted value for the secret, you must include either the ``GenerateSecretString`` or the ``SecretString`` property, but not both. We recommend that you use the ``GenerateSecretString`` property to generate a random password as shown in the examples. You can't generate a secret with a ``SecretBinary`` secret value using AWS CloudFormation .
    .. epigraph::

       Do not create a dynamic reference using a backslash ``(\\)`` as the final value. AWS CloudFormation cannot resolve those references, which causes a resource failure.

    :cloudformationResource: AWS::SecretsManager::Secret
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_secretsmanager as secretsmanager
        
        cfn_secret = secretsmanager.CfnSecret(self, "MyCfnSecret",
            description="description",
            generate_secret_string=secretsmanager.CfnSecret.GenerateSecretStringProperty(
                exclude_characters="excludeCharacters",
                exclude_lowercase=False,
                exclude_numbers=False,
                exclude_punctuation=False,
                exclude_uppercase=False,
                generate_string_key="generateStringKey",
                include_space=False,
                password_length=123,
                require_each_included_type=False,
                secret_string_template="secretStringTemplate"
            ),
            kms_key_id="kmsKeyId",
            name="name",
            replica_regions=[secretsmanager.CfnSecret.ReplicaRegionProperty(
                region="region",
        
                # the properties below are optional
                kms_key_id="kmsKeyId"
            )],
            secret_string="secretString",
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
        description: typing.Optional[builtins.str] = None,
        generate_secret_string: typing.Optional[typing.Union["CfnSecret.GenerateSecretStringProperty", _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        replica_regions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnSecret.ReplicaRegionProperty", _IResolvable_da3f097b]]]] = None,
        secret_string: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::SecretsManager::Secret``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: The description of the secret.
        :param generate_secret_string: A structure that specifies how to generate a password to encrypt and store in the secret. Either ``GenerateSecretString`` or ``SecretString`` must have a value, but not both. They cannot both be empty. We recommend that you specify the maximum length and include every character type that the system you are generating a password for can support.
        :param kms_key_id: The ARN, key ID, or alias of the AWS KMS key that Secrets Manager uses to encrypt the secret value in the secret. To use a AWS KMS key in a different account, use the key ARN or the alias ARN. If you don't specify this value, then Secrets Manager uses the key ``aws/secretsmanager`` . If that key doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value. If the secret is in a different AWS account from the credentials calling the API, then you can't use ``aws/secretsmanager`` to encrypt the secret, and you must create and use a customer managed AWS KMS key.
        :param name: The name of the new secret. The secret name can contain ASCII letters, numbers, and the following characters: /_+=.@- Do not end your secret name with a hyphen followed by six characters. If you do so, you risk confusion and unexpected results when searching for a secret by partial ARN. Secrets Manager automatically adds a hyphen and six random characters after the secret name at the end of the ARN.
        :param replica_regions: A custom type that specifies a ``Region`` and the ``KmsKeyId`` for a replica secret.
        :param secret_string: The text to encrypt and store in the secret. We recommend you use a JSON structure of key/value pairs for your secret value. Either ``GenerateSecretString`` or ``SecretString`` must have a value, but not both. They cannot both be empty. We recommend that you use the ``GenerateSecretString`` property to generate a random password.
        :param tags: A list of tags to attach to the secret. Each tag is a key and value pair of strings in a JSON text string, for example: ``[{"Key":"CostCenter","Value":"12345"},{"Key":"environment","Value":"production"}]`` Secrets Manager tag key names are case sensitive. A tag with the key "ABC" is a different tag from one with key "abc". If you check tags in permissions policies as part of your security strategy, then adding or removing a tag can change permissions. If the completion of this operation would result in you losing your permissions for this secret, then Secrets Manager blocks the operation and returns an ``Access Denied`` error. For more information, see `Control access to secrets using tags <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html#tag-secrets-abac>`_ and `Limit access to identities with tags that match secrets' tags <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html#auth-and-access_tags2>`_ . For information about how to format a JSON parameter for the various command line tool environments, see `Using JSON for Parameters <https://docs.aws.amazon.com/cli/latest/userguide/cli-using-param.html#cli-using-param-json>`_ . If your command-line tool or SDK requires quotation marks around the parameter, you should use single quotes to avoid confusion with the double quotes required in the JSON text. The following restrictions apply to tags: - Maximum number of tags per secret: 50 - Maximum key length: 127 Unicode characters in UTF-8 - Maximum value length: 255 Unicode characters in UTF-8 - Tag keys and values are case sensitive. - Do not use the ``aws:`` prefix in your tag names or values because AWS reserves it for AWS use. You can't edit or delete tag names or values with this prefix. Tags with this prefix do not count against your tags per secret limit. - If you use your tagging schema across multiple services and resources, other services might have restrictions on allowed characters. Generally allowed characters: letters, spaces, and numbers representable in UTF-8, plus the following special characters: + - = . _ : / @.
        '''
        props = CfnSecretProps(
            description=description,
            generate_secret_string=generate_secret_string,
            kms_key_id=kms_key_id,
            name=name,
            replica_regions=replica_regions,
            secret_string=secret_string,
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
        '''A list of tags to attach to the secret.

        Each tag is a key and value pair of strings in a JSON text string, for example:

        ``[{"Key":"CostCenter","Value":"12345"},{"Key":"environment","Value":"production"}]``

        Secrets Manager tag key names are case sensitive. A tag with the key "ABC" is a different tag from one with key "abc".

        If you check tags in permissions policies as part of your security strategy, then adding or removing a tag can change permissions. If the completion of this operation would result in you losing your permissions for this secret, then Secrets Manager blocks the operation and returns an ``Access Denied`` error. For more information, see `Control access to secrets using tags <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html#tag-secrets-abac>`_ and `Limit access to identities with tags that match secrets' tags <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html#auth-and-access_tags2>`_ .

        For information about how to format a JSON parameter for the various command line tool environments, see `Using JSON for Parameters <https://docs.aws.amazon.com/cli/latest/userguide/cli-using-param.html#cli-using-param-json>`_ . If your command-line tool or SDK requires quotation marks around the parameter, you should use single quotes to avoid confusion with the double quotes required in the JSON text.

        The following restrictions apply to tags:

        - Maximum number of tags per secret: 50
        - Maximum key length: 127 Unicode characters in UTF-8
        - Maximum value length: 255 Unicode characters in UTF-8
        - Tag keys and values are case sensitive.
        - Do not use the ``aws:`` prefix in your tag names or values because AWS reserves it for AWS use. You can't edit or delete tag names or values with this prefix. Tags with this prefix do not count against your tags per secret limit.
        - If you use your tagging schema across multiple services and resources, other services might have restrictions on allowed characters. Generally allowed characters: letters, spaces, and numbers representable in UTF-8, plus the following special characters: + - = . _ : / @.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="generateSecretString")
    def generate_secret_string(
        self,
    ) -> typing.Optional[typing.Union["CfnSecret.GenerateSecretStringProperty", _IResolvable_da3f097b]]:
        '''A structure that specifies how to generate a password to encrypt and store in the secret.

        Either ``GenerateSecretString`` or ``SecretString`` must have a value, but not both. They cannot both be empty.

        We recommend that you specify the maximum length and include every character type that the system you are generating a password for can support.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-generatesecretstring
        '''
        return typing.cast(typing.Optional[typing.Union["CfnSecret.GenerateSecretStringProperty", _IResolvable_da3f097b]], jsii.get(self, "generateSecretString"))

    @generate_secret_string.setter
    def generate_secret_string(
        self,
        value: typing.Optional[typing.Union["CfnSecret.GenerateSecretStringProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "generateSecretString", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKeyId")
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The ARN, key ID, or alias of the AWS KMS key that Secrets Manager uses to encrypt the secret value in the secret.

        To use a AWS KMS key in a different account, use the key ARN or the alias ARN.

        If you don't specify this value, then Secrets Manager uses the key ``aws/secretsmanager`` . If that key doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value.

        If the secret is in a different AWS account from the credentials calling the API, then you can't use ``aws/secretsmanager`` to encrypt the secret, and you must create and use a customer managed AWS KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-kmskeyid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKeyId"))

    @kms_key_id.setter
    def kms_key_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKeyId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new secret.

        The secret name can contain ASCII letters, numbers, and the following characters: /_+=.@-

        Do not end your secret name with a hyphen followed by six characters. If you do so, you risk confusion and unexpected results when searching for a secret by partial ARN. Secrets Manager automatically adds a hyphen and six random characters after the secret name at the end of the ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicaRegions")
    def replica_regions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSecret.ReplicaRegionProperty", _IResolvable_da3f097b]]]]:
        '''A custom type that specifies a ``Region`` and the ``KmsKeyId`` for a replica secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-replicaregions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSecret.ReplicaRegionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "replicaRegions"))

    @replica_regions.setter
    def replica_regions(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSecret.ReplicaRegionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "replicaRegions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretString")
    def secret_string(self) -> typing.Optional[builtins.str]:
        '''The text to encrypt and store in the secret.

        We recommend you use a JSON structure of key/value pairs for your secret value.

        Either ``GenerateSecretString`` or ``SecretString`` must have a value, but not both. They cannot both be empty. We recommend that you use the ``GenerateSecretString`` property to generate a random password.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-secretstring
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "secretString"))

    @secret_string.setter
    def secret_string(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "secretString", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_secretsmanager.CfnSecret.GenerateSecretStringProperty",
        jsii_struct_bases=[],
        name_mapping={
            "exclude_characters": "excludeCharacters",
            "exclude_lowercase": "excludeLowercase",
            "exclude_numbers": "excludeNumbers",
            "exclude_punctuation": "excludePunctuation",
            "exclude_uppercase": "excludeUppercase",
            "generate_string_key": "generateStringKey",
            "include_space": "includeSpace",
            "password_length": "passwordLength",
            "require_each_included_type": "requireEachIncludedType",
            "secret_string_template": "secretStringTemplate",
        },
    )
    class GenerateSecretStringProperty:
        def __init__(
            self,
            *,
            exclude_characters: typing.Optional[builtins.str] = None,
            exclude_lowercase: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            exclude_numbers: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            exclude_punctuation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            exclude_uppercase: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            generate_string_key: typing.Optional[builtins.str] = None,
            include_space: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            password_length: typing.Optional[jsii.Number] = None,
            require_each_included_type: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            secret_string_template: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Generates a random password.

            We recommend that you specify the maximum length and include every character type that the system you are generating a password for can support.

            *Required permissions:* ``secretsmanager:GetRandomPassword`` . For more information, see `IAM policy actions for Secrets Manager <https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecretsmanager.html#awssecretsmanager-actions-as-permissions>`_ and `Authentication and access control in Secrets Manager <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html>`_ .

            :param exclude_characters: A string of the characters that you don't want in the password.
            :param exclude_lowercase: Specifies whether to exclude lowercase letters from the password. If you don't include this switch, the password can contain lowercase letters.
            :param exclude_numbers: Specifies whether to exclude numbers from the password. If you don't include this switch, the password can contain numbers.
            :param exclude_punctuation: Specifies whether to exclude the following punctuation characters from the password: `! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \\ ] ^ _ `` { | } ~`` . If you don't include this switch, the password can contain punctuation.
            :param exclude_uppercase: Specifies whether to exclude uppercase letters from the password. If you don't include this switch, the password can contain uppercase letters.
            :param generate_string_key: The JSON key name for the key/value pair, where the value is the generated password. This pair is added to the JSON structure specified by the ``SecretStringTemplate`` parameter. If you specify this parameter, then you must also specify ``SecretStringTemplate`` .
            :param include_space: Specifies whether to include the space character. If you include this switch, the password can contain space characters.
            :param password_length: The length of the password. If you don't include this parameter, the default length is 32 characters.
            :param require_each_included_type: Specifies whether to include at least one upper and lowercase letter, one number, and one punctuation. If you don't include this switch, the password contains at least one of every character type.
            :param secret_string_template: A template that the generated string must match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_secretsmanager as secretsmanager
                
                generate_secret_string_property = secretsmanager.CfnSecret.GenerateSecretStringProperty(
                    exclude_characters="excludeCharacters",
                    exclude_lowercase=False,
                    exclude_numbers=False,
                    exclude_punctuation=False,
                    exclude_uppercase=False,
                    generate_string_key="generateStringKey",
                    include_space=False,
                    password_length=123,
                    require_each_included_type=False,
                    secret_string_template="secretStringTemplate"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if exclude_characters is not None:
                self._values["exclude_characters"] = exclude_characters
            if exclude_lowercase is not None:
                self._values["exclude_lowercase"] = exclude_lowercase
            if exclude_numbers is not None:
                self._values["exclude_numbers"] = exclude_numbers
            if exclude_punctuation is not None:
                self._values["exclude_punctuation"] = exclude_punctuation
            if exclude_uppercase is not None:
                self._values["exclude_uppercase"] = exclude_uppercase
            if generate_string_key is not None:
                self._values["generate_string_key"] = generate_string_key
            if include_space is not None:
                self._values["include_space"] = include_space
            if password_length is not None:
                self._values["password_length"] = password_length
            if require_each_included_type is not None:
                self._values["require_each_included_type"] = require_each_included_type
            if secret_string_template is not None:
                self._values["secret_string_template"] = secret_string_template

        @builtins.property
        def exclude_characters(self) -> typing.Optional[builtins.str]:
            '''A string of the characters that you don't want in the password.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-excludecharacters
            '''
            result = self._values.get("exclude_characters")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def exclude_lowercase(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether to exclude lowercase letters from the password.

            If you don't include this switch, the password can contain lowercase letters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-excludelowercase
            '''
            result = self._values.get("exclude_lowercase")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def exclude_numbers(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether to exclude numbers from the password.

            If you don't include this switch, the password can contain numbers.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-excludenumbers
            '''
            result = self._values.get("exclude_numbers")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def exclude_punctuation(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether to exclude the following punctuation characters from the password: `!

            " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \\ ] ^ _ `` { | } ~`` . If you don't include this switch, the password can contain punctuation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-excludepunctuation
            '''
            result = self._values.get("exclude_punctuation")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def exclude_uppercase(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether to exclude uppercase letters from the password.

            If you don't include this switch, the password can contain uppercase letters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-excludeuppercase
            '''
            result = self._values.get("exclude_uppercase")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def generate_string_key(self) -> typing.Optional[builtins.str]:
            '''The JSON key name for the key/value pair, where the value is the generated password.

            This pair is added to the JSON structure specified by the ``SecretStringTemplate`` parameter. If you specify this parameter, then you must also specify ``SecretStringTemplate`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-generatestringkey
            '''
            result = self._values.get("generate_string_key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def include_space(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether to include the space character.

            If you include this switch, the password can contain space characters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-includespace
            '''
            result = self._values.get("include_space")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def password_length(self) -> typing.Optional[jsii.Number]:
            '''The length of the password.

            If you don't include this parameter, the default length is 32 characters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-passwordlength
            '''
            result = self._values.get("password_length")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def require_each_included_type(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether to include at least one upper and lowercase letter, one number, and one punctuation.

            If you don't include this switch, the password contains at least one of every character type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-requireeachincludedtype
            '''
            result = self._values.get("require_each_included_type")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def secret_string_template(self) -> typing.Optional[builtins.str]:
            '''A template that the generated string must match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-generatesecretstring.html#cfn-secretsmanager-secret-generatesecretstring-secretstringtemplate
            '''
            result = self._values.get("secret_string_template")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "GenerateSecretStringProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_secretsmanager.CfnSecret.ReplicaRegionProperty",
        jsii_struct_bases=[],
        name_mapping={"region": "region", "kms_key_id": "kmsKeyId"},
    )
    class ReplicaRegionProperty:
        def __init__(
            self,
            *,
            region: builtins.str,
            kms_key_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A custom type that specifies a ``Region`` and the ``KmsKeyId`` for a replica secret.

            :param region: ``CfnSecret.ReplicaRegionProperty.Region``.
            :param kms_key_id: The ARN, key ID, or alias of the KMS key to encrypt the secret. If you don't include this field, Secrets Manager uses ``aws/secretsmanager`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-replicaregion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_secretsmanager as secretsmanager
                
                replica_region_property = secretsmanager.CfnSecret.ReplicaRegionProperty(
                    region="region",
                
                    # the properties below are optional
                    kms_key_id="kmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "region": region,
            }
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id

        @builtins.property
        def region(self) -> builtins.str:
            '''``CfnSecret.ReplicaRegionProperty.Region``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-replicaregion.html#cfn-secretsmanager-secret-replicaregion-region
            '''
            result = self._values.get("region")
            assert result is not None, "Required property 'region' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''The ARN, key ID, or alias of the KMS key to encrypt the secret.

            If you don't include this field, Secrets Manager uses ``aws/secretsmanager`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-secret-replicaregion.html#cfn-secretsmanager-secret-replicaregion-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicaRegionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.CfnSecretProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "generate_secret_string": "generateSecretString",
        "kms_key_id": "kmsKeyId",
        "name": "name",
        "replica_regions": "replicaRegions",
        "secret_string": "secretString",
        "tags": "tags",
    },
)
class CfnSecretProps:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        generate_secret_string: typing.Optional[typing.Union[CfnSecret.GenerateSecretStringProperty, _IResolvable_da3f097b]] = None,
        kms_key_id: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        replica_regions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnSecret.ReplicaRegionProperty, _IResolvable_da3f097b]]]] = None,
        secret_string: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSecret``.

        :param description: The description of the secret.
        :param generate_secret_string: A structure that specifies how to generate a password to encrypt and store in the secret. Either ``GenerateSecretString`` or ``SecretString`` must have a value, but not both. They cannot both be empty. We recommend that you specify the maximum length and include every character type that the system you are generating a password for can support.
        :param kms_key_id: The ARN, key ID, or alias of the AWS KMS key that Secrets Manager uses to encrypt the secret value in the secret. To use a AWS KMS key in a different account, use the key ARN or the alias ARN. If you don't specify this value, then Secrets Manager uses the key ``aws/secretsmanager`` . If that key doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value. If the secret is in a different AWS account from the credentials calling the API, then you can't use ``aws/secretsmanager`` to encrypt the secret, and you must create and use a customer managed AWS KMS key.
        :param name: The name of the new secret. The secret name can contain ASCII letters, numbers, and the following characters: /_+=.@- Do not end your secret name with a hyphen followed by six characters. If you do so, you risk confusion and unexpected results when searching for a secret by partial ARN. Secrets Manager automatically adds a hyphen and six random characters after the secret name at the end of the ARN.
        :param replica_regions: A custom type that specifies a ``Region`` and the ``KmsKeyId`` for a replica secret.
        :param secret_string: The text to encrypt and store in the secret. We recommend you use a JSON structure of key/value pairs for your secret value. Either ``GenerateSecretString`` or ``SecretString`` must have a value, but not both. They cannot both be empty. We recommend that you use the ``GenerateSecretString`` property to generate a random password.
        :param tags: A list of tags to attach to the secret. Each tag is a key and value pair of strings in a JSON text string, for example: ``[{"Key":"CostCenter","Value":"12345"},{"Key":"environment","Value":"production"}]`` Secrets Manager tag key names are case sensitive. A tag with the key "ABC" is a different tag from one with key "abc". If you check tags in permissions policies as part of your security strategy, then adding or removing a tag can change permissions. If the completion of this operation would result in you losing your permissions for this secret, then Secrets Manager blocks the operation and returns an ``Access Denied`` error. For more information, see `Control access to secrets using tags <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html#tag-secrets-abac>`_ and `Limit access to identities with tags that match secrets' tags <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html#auth-and-access_tags2>`_ . For information about how to format a JSON parameter for the various command line tool environments, see `Using JSON for Parameters <https://docs.aws.amazon.com/cli/latest/userguide/cli-using-param.html#cli-using-param-json>`_ . If your command-line tool or SDK requires quotation marks around the parameter, you should use single quotes to avoid confusion with the double quotes required in the JSON text. The following restrictions apply to tags: - Maximum number of tags per secret: 50 - Maximum key length: 127 Unicode characters in UTF-8 - Maximum value length: 255 Unicode characters in UTF-8 - Tag keys and values are case sensitive. - Do not use the ``aws:`` prefix in your tag names or values because AWS reserves it for AWS use. You can't edit or delete tag names or values with this prefix. Tags with this prefix do not count against your tags per secret limit. - If you use your tagging schema across multiple services and resources, other services might have restrictions on allowed characters. Generally allowed characters: letters, spaces, and numbers representable in UTF-8, plus the following special characters: + - = . _ : / @.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            cfn_secret_props = secretsmanager.CfnSecretProps(
                description="description",
                generate_secret_string=secretsmanager.CfnSecret.GenerateSecretStringProperty(
                    exclude_characters="excludeCharacters",
                    exclude_lowercase=False,
                    exclude_numbers=False,
                    exclude_punctuation=False,
                    exclude_uppercase=False,
                    generate_string_key="generateStringKey",
                    include_space=False,
                    password_length=123,
                    require_each_included_type=False,
                    secret_string_template="secretStringTemplate"
                ),
                kms_key_id="kmsKeyId",
                name="name",
                replica_regions=[secretsmanager.CfnSecret.ReplicaRegionProperty(
                    region="region",
            
                    # the properties below are optional
                    kms_key_id="kmsKeyId"
                )],
                secret_string="secretString",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if generate_secret_string is not None:
            self._values["generate_secret_string"] = generate_secret_string
        if kms_key_id is not None:
            self._values["kms_key_id"] = kms_key_id
        if name is not None:
            self._values["name"] = name
        if replica_regions is not None:
            self._values["replica_regions"] = replica_regions
        if secret_string is not None:
            self._values["secret_string"] = secret_string
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def generate_secret_string(
        self,
    ) -> typing.Optional[typing.Union[CfnSecret.GenerateSecretStringProperty, _IResolvable_da3f097b]]:
        '''A structure that specifies how to generate a password to encrypt and store in the secret.

        Either ``GenerateSecretString`` or ``SecretString`` must have a value, but not both. They cannot both be empty.

        We recommend that you specify the maximum length and include every character type that the system you are generating a password for can support.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-generatesecretstring
        '''
        result = self._values.get("generate_secret_string")
        return typing.cast(typing.Optional[typing.Union[CfnSecret.GenerateSecretStringProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def kms_key_id(self) -> typing.Optional[builtins.str]:
        '''The ARN, key ID, or alias of the AWS KMS key that Secrets Manager uses to encrypt the secret value in the secret.

        To use a AWS KMS key in a different account, use the key ARN or the alias ARN.

        If you don't specify this value, then Secrets Manager uses the key ``aws/secretsmanager`` . If that key doesn't yet exist, then Secrets Manager creates it for you automatically the first time it encrypts the secret value.

        If the secret is in a different AWS account from the credentials calling the API, then you can't use ``aws/secretsmanager`` to encrypt the secret, and you must create and use a customer managed AWS KMS key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-kmskeyid
        '''
        result = self._values.get("kms_key_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the new secret.

        The secret name can contain ASCII letters, numbers, and the following characters: /_+=.@-

        Do not end your secret name with a hyphen followed by six characters. If you do so, you risk confusion and unexpected results when searching for a secret by partial ARN. Secrets Manager automatically adds a hyphen and six random characters after the secret name at the end of the ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def replica_regions(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnSecret.ReplicaRegionProperty, _IResolvable_da3f097b]]]]:
        '''A custom type that specifies a ``Region`` and the ``KmsKeyId`` for a replica secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-replicaregions
        '''
        result = self._values.get("replica_regions")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnSecret.ReplicaRegionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def secret_string(self) -> typing.Optional[builtins.str]:
        '''The text to encrypt and store in the secret.

        We recommend you use a JSON structure of key/value pairs for your secret value.

        Either ``GenerateSecretString`` or ``SecretString`` must have a value, but not both. They cannot both be empty. We recommend that you use the ``GenerateSecretString`` property to generate a random password.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-secretstring
        '''
        result = self._values.get("secret_string")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags to attach to the secret.

        Each tag is a key and value pair of strings in a JSON text string, for example:

        ``[{"Key":"CostCenter","Value":"12345"},{"Key":"environment","Value":"production"}]``

        Secrets Manager tag key names are case sensitive. A tag with the key "ABC" is a different tag from one with key "abc".

        If you check tags in permissions policies as part of your security strategy, then adding or removing a tag can change permissions. If the completion of this operation would result in you losing your permissions for this secret, then Secrets Manager blocks the operation and returns an ``Access Denied`` error. For more information, see `Control access to secrets using tags <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html#tag-secrets-abac>`_ and `Limit access to identities with tags that match secrets' tags <https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html#auth-and-access_tags2>`_ .

        For information about how to format a JSON parameter for the various command line tool environments, see `Using JSON for Parameters <https://docs.aws.amazon.com/cli/latest/userguide/cli-using-param.html#cli-using-param-json>`_ . If your command-line tool or SDK requires quotation marks around the parameter, you should use single quotes to avoid confusion with the double quotes required in the JSON text.

        The following restrictions apply to tags:

        - Maximum number of tags per secret: 50
        - Maximum key length: 127 Unicode characters in UTF-8
        - Maximum value length: 255 Unicode characters in UTF-8
        - Tag keys and values are case sensitive.
        - Do not use the ``aws:`` prefix in your tag names or values because AWS reserves it for AWS use. You can't edit or delete tag names or values with this prefix. Tags with this prefix do not count against your tags per secret limit.
        - If you use your tagging schema across multiple services and resources, other services might have restrictions on allowed characters. Generally allowed characters: letters, spaces, and numbers representable in UTF-8, plus the following special characters: + - = . _ : / @.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html#cfn-secretsmanager-secret-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSecretProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSecretTargetAttachment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.CfnSecretTargetAttachment",
):
    '''A CloudFormation ``AWS::SecretsManager::SecretTargetAttachment``.

    The ``AWS::SecretsManager::SecretTargetAttachment`` resource completes the final link between a Secrets Manager secret and the associated database. This is required because each has a dependency on the other. No matter which one you create first, the other doesn't exist yet. To resolve this, you must create the resources in the following order:

    - Define the secret without referencing the service or database. You can't reference the service or database because it doesn't exist yet. The secret must contain a user name and password.
    - Next, define the service or database. Include the reference to the secret to use stored credentials to define the database admin user and password.
    - Finally, define a ``SecretTargetAttachment`` resource type to finish configuring the secret with the required database engine type and the connection details of the service or database. The rotation function requires the details, if you attach one later by defining a `AWS::SecretsManager::RotationSchedule <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html>`_ resource type.

    :cloudformationResource: AWS::SecretsManager::SecretTargetAttachment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_secretsmanager as secretsmanager
        
        cfn_secret_target_attachment = secretsmanager.CfnSecretTargetAttachment(self, "MyCfnSecretTargetAttachment",
            secret_id="secretId",
            target_id="targetId",
            target_type="targetType"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        secret_id: builtins.str,
        target_id: builtins.str,
        target_type: builtins.str,
    ) -> None:
        '''Create a new ``AWS::SecretsManager::SecretTargetAttachment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param secret_id: The ARN or name of the secret. To reference a secret also created in this template, use the see `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the secret's logical ID.
        :param target_id: The ID of the database or cluster.
        :param target_type: A string that defines the type of service or database associated with the secret. This value instructs Secrets Manager how to update the secret with the details of the service or database. This value must be one of the following: - AWS::RDS::DBInstance - AWS::RDS::DBCluster - AWS::Redshift::Cluster - AWS::DocDB::DBInstance - AWS::DocDB::DBCluster
        '''
        props = CfnSecretTargetAttachmentProps(
            secret_id=secret_id, target_id=target_id, target_type=target_type
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
    @jsii.member(jsii_name="secretId")
    def secret_id(self) -> builtins.str:
        '''The ARN or name of the secret.

        To reference a secret also created in this template, use the see `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the secret's logical ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html#cfn-secretsmanager-secrettargetattachment-secretid
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretId"))

    @secret_id.setter
    def secret_id(self, value: builtins.str) -> None:
        jsii.set(self, "secretId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetId")
    def target_id(self) -> builtins.str:
        '''The ID of the database or cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html#cfn-secretsmanager-secrettargetattachment-targetid
        '''
        return typing.cast(builtins.str, jsii.get(self, "targetId"))

    @target_id.setter
    def target_id(self, value: builtins.str) -> None:
        jsii.set(self, "targetId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetType")
    def target_type(self) -> builtins.str:
        '''A string that defines the type of service or database associated with the secret.

        This value instructs Secrets Manager how to update the secret with the details of the service or database. This value must be one of the following:

        - AWS::RDS::DBInstance
        - AWS::RDS::DBCluster
        - AWS::Redshift::Cluster
        - AWS::DocDB::DBInstance
        - AWS::DocDB::DBCluster

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html#cfn-secretsmanager-secrettargetattachment-targettype
        '''
        return typing.cast(builtins.str, jsii.get(self, "targetType"))

    @target_type.setter
    def target_type(self, value: builtins.str) -> None:
        jsii.set(self, "targetType", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.CfnSecretTargetAttachmentProps",
    jsii_struct_bases=[],
    name_mapping={
        "secret_id": "secretId",
        "target_id": "targetId",
        "target_type": "targetType",
    },
)
class CfnSecretTargetAttachmentProps:
    def __init__(
        self,
        *,
        secret_id: builtins.str,
        target_id: builtins.str,
        target_type: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnSecretTargetAttachment``.

        :param secret_id: The ARN or name of the secret. To reference a secret also created in this template, use the see `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the secret's logical ID.
        :param target_id: The ID of the database or cluster.
        :param target_type: A string that defines the type of service or database associated with the secret. This value instructs Secrets Manager how to update the secret with the details of the service or database. This value must be one of the following: - AWS::RDS::DBInstance - AWS::RDS::DBCluster - AWS::Redshift::Cluster - AWS::DocDB::DBInstance - AWS::DocDB::DBCluster

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            cfn_secret_target_attachment_props = secretsmanager.CfnSecretTargetAttachmentProps(
                secret_id="secretId",
                target_id="targetId",
                target_type="targetType"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "secret_id": secret_id,
            "target_id": target_id,
            "target_type": target_type,
        }

    @builtins.property
    def secret_id(self) -> builtins.str:
        '''The ARN or name of the secret.

        To reference a secret also created in this template, use the see `Ref <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-ref.html>`_ function with the secret's logical ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html#cfn-secretsmanager-secrettargetattachment-secretid
        '''
        result = self._values.get("secret_id")
        assert result is not None, "Required property 'secret_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def target_id(self) -> builtins.str:
        '''The ID of the database or cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html#cfn-secretsmanager-secrettargetattachment-targetid
        '''
        result = self._values.get("target_id")
        assert result is not None, "Required property 'target_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def target_type(self) -> builtins.str:
        '''A string that defines the type of service or database associated with the secret.

        This value instructs Secrets Manager how to update the secret with the details of the service or database. This value must be one of the following:

        - AWS::RDS::DBInstance
        - AWS::RDS::DBCluster
        - AWS::Redshift::Cluster
        - AWS::DocDB::DBInstance
        - AWS::DocDB::DBCluster

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html#cfn-secretsmanager-secrettargetattachment-targettype
        '''
        result = self._values.get("target_type")
        assert result is not None, "Required property 'target_type' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSecretTargetAttachmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IConnectable_10015a05)
class HostedRotation(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.HostedRotation",
):
    '''A hosted rotation.

    :exampleMetadata: infused

    Example::

        secret = secretsmanager.Secret(self, "Secret")
        
        secret.add_rotation_schedule("RotationSchedule",
            hosted_rotation=secretsmanager.HostedRotation.mysql_single_user()
        )
    '''

    @jsii.member(jsii_name="mariaDbMultiUser") # type: ignore[misc]
    @builtins.classmethod
    def maria_db_multi_user(
        cls,
        *,
        master_secret: "ISecret",
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''MariaDB Multi User.

        :param master_secret: The master secret for a multi user rotation scheme.
        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = MultiUserHostedRotationOptions(
            master_secret=master_secret,
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "mariaDbMultiUser", [options]))

    @jsii.member(jsii_name="mariaDbSingleUser") # type: ignore[misc]
    @builtins.classmethod
    def maria_db_single_user(
        cls,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''MariaDB Single User.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = SingleUserHostedRotationOptions(
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "mariaDbSingleUser", [options]))

    @jsii.member(jsii_name="mongoDbMultiUser") # type: ignore[misc]
    @builtins.classmethod
    def mongo_db_multi_user(
        cls,
        *,
        master_secret: "ISecret",
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''MongoDB Multi User.

        :param master_secret: The master secret for a multi user rotation scheme.
        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = MultiUserHostedRotationOptions(
            master_secret=master_secret,
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "mongoDbMultiUser", [options]))

    @jsii.member(jsii_name="mongoDbSingleUser") # type: ignore[misc]
    @builtins.classmethod
    def mongo_db_single_user(
        cls,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''MongoDB Single User.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = SingleUserHostedRotationOptions(
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "mongoDbSingleUser", [options]))

    @jsii.member(jsii_name="mysqlMultiUser") # type: ignore[misc]
    @builtins.classmethod
    def mysql_multi_user(
        cls,
        *,
        master_secret: "ISecret",
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''MySQL Multi User.

        :param master_secret: The master secret for a multi user rotation scheme.
        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = MultiUserHostedRotationOptions(
            master_secret=master_secret,
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "mysqlMultiUser", [options]))

    @jsii.member(jsii_name="mysqlSingleUser") # type: ignore[misc]
    @builtins.classmethod
    def mysql_single_user(
        cls,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''MySQL Single User.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = SingleUserHostedRotationOptions(
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "mysqlSingleUser", [options]))

    @jsii.member(jsii_name="oracleMultiUser") # type: ignore[misc]
    @builtins.classmethod
    def oracle_multi_user(
        cls,
        *,
        master_secret: "ISecret",
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''Oracle Multi User.

        :param master_secret: The master secret for a multi user rotation scheme.
        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = MultiUserHostedRotationOptions(
            master_secret=master_secret,
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "oracleMultiUser", [options]))

    @jsii.member(jsii_name="oracleSingleUser") # type: ignore[misc]
    @builtins.classmethod
    def oracle_single_user(
        cls,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''Oracle Single User.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = SingleUserHostedRotationOptions(
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "oracleSingleUser", [options]))

    @jsii.member(jsii_name="postgreSqlMultiUser") # type: ignore[misc]
    @builtins.classmethod
    def postgre_sql_multi_user(
        cls,
        *,
        master_secret: "ISecret",
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''PostgreSQL Multi User.

        :param master_secret: The master secret for a multi user rotation scheme.
        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = MultiUserHostedRotationOptions(
            master_secret=master_secret,
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "postgreSqlMultiUser", [options]))

    @jsii.member(jsii_name="postgreSqlSingleUser") # type: ignore[misc]
    @builtins.classmethod
    def postgre_sql_single_user(
        cls,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''PostgreSQL Single User.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = SingleUserHostedRotationOptions(
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "postgreSqlSingleUser", [options]))

    @jsii.member(jsii_name="redshiftMultiUser") # type: ignore[misc]
    @builtins.classmethod
    def redshift_multi_user(
        cls,
        *,
        master_secret: "ISecret",
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''Redshift Multi User.

        :param master_secret: The master secret for a multi user rotation scheme.
        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = MultiUserHostedRotationOptions(
            master_secret=master_secret,
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "redshiftMultiUser", [options]))

    @jsii.member(jsii_name="redshiftSingleUser") # type: ignore[misc]
    @builtins.classmethod
    def redshift_single_user(
        cls,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''Redshift Single User.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = SingleUserHostedRotationOptions(
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "redshiftSingleUser", [options]))

    @jsii.member(jsii_name="sqlServerMultiUser") # type: ignore[misc]
    @builtins.classmethod
    def sql_server_multi_user(
        cls,
        *,
        master_secret: "ISecret",
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''SQL Server Multi User.

        :param master_secret: The master secret for a multi user rotation scheme.
        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = MultiUserHostedRotationOptions(
            master_secret=master_secret,
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "sqlServerMultiUser", [options]))

    @jsii.member(jsii_name="sqlServerSingleUser") # type: ignore[misc]
    @builtins.classmethod
    def sql_server_single_user(
        cls,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> "HostedRotation":
        '''SQL Server Single User.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        options = SingleUserHostedRotationOptions(
            function_name=function_name,
            security_groups=security_groups,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        return typing.cast("HostedRotation", jsii.sinvoke(cls, "sqlServerSingleUser", [options]))

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        secret: "ISecret",
        scope: constructs.Construct,
    ) -> CfnRotationSchedule.HostedRotationLambdaProperty:
        '''Binds this hosted rotation to a secret.

        :param secret: -
        :param scope: -
        '''
        return typing.cast(CfnRotationSchedule.HostedRotationLambdaProperty, jsii.invoke(self, "bind", [secret, scope]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''Security group connections for this hosted rotation.'''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))


class HostedRotationType(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.HostedRotationType",
):
    '''Hosted rotation type.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_secretsmanager as secretsmanager
        
        hosted_rotation_type = secretsmanager.HostedRotationType.MARIADB_MULTI_USER
    '''

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MARIADB_MULTI_USER")
    def MARIADB_MULTI_USER(cls) -> "HostedRotationType":
        '''MariaDB Multi User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "MARIADB_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MARIADB_SINGLE_USER")
    def MARIADB_SINGLE_USER(cls) -> "HostedRotationType":
        '''MariaDB Single User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "MARIADB_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MONGODB_MULTI_USER")
    def MONGODB_MULTI_USER(cls) -> "HostedRotationType":
        '''MongoDB Multi User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "MONGODB_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MONGODB_SINGLE_USER")
    def MONGODB_SINGLE_USER(cls) -> "HostedRotationType":
        '''MongoDB Single User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "MONGODB_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MYSQL_MULTI_USER")
    def MYSQL_MULTI_USER(cls) -> "HostedRotationType":
        '''MySQL Multi User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "MYSQL_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MYSQL_SINGLE_USER")
    def MYSQL_SINGLE_USER(cls) -> "HostedRotationType":
        '''MySQL Single User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "MYSQL_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="ORACLE_MULTI_USER")
    def ORACLE_MULTI_USER(cls) -> "HostedRotationType":
        '''Oracle Multi User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "ORACLE_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="ORACLE_SINGLE_USER")
    def ORACLE_SINGLE_USER(cls) -> "HostedRotationType":
        '''Oracle Single User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "ORACLE_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="POSTGRESQL_MULTI_USER")
    def POSTGRESQL_MULTI_USER(cls) -> "HostedRotationType":
        '''PostgreSQL Multi User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "POSTGRESQL_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="POSTGRESQL_SINGLE_USER")
    def POSTGRESQL_SINGLE_USER(cls) -> "HostedRotationType":
        '''PostgreSQL Single User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "POSTGRESQL_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="REDSHIFT_MULTI_USER")
    def REDSHIFT_MULTI_USER(cls) -> "HostedRotationType":
        '''Redshift Multi User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "REDSHIFT_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="REDSHIFT_SINGLE_USER")
    def REDSHIFT_SINGLE_USER(cls) -> "HostedRotationType":
        '''Redshift Single User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "REDSHIFT_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="SQLSERVER_MULTI_USER")
    def SQLSERVER_MULTI_USER(cls) -> "HostedRotationType":
        '''SQL Server Multi User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "SQLSERVER_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="SQLSERVER_SINGLE_USER")
    def SQLSERVER_SINGLE_USER(cls) -> "HostedRotationType":
        '''SQL Server Single User.'''
        return typing.cast("HostedRotationType", jsii.sget(cls, "SQLSERVER_SINGLE_USER"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The type of rotation.'''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isMultiUser")
    def is_multi_user(self) -> typing.Optional[builtins.bool]:
        '''Whether the rotation uses the mutli user scheme.'''
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "isMultiUser"))


@jsii.interface(jsii_type="aws-cdk-lib.aws_secretsmanager.ISecret")
class ISecret(_IResource_c80c4260, typing_extensions.Protocol):
    '''A secret in AWS Secrets Manager.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretArn")
    def secret_arn(self) -> builtins.str:
        '''The ARN of the secret in AWS Secrets Manager.

        Will return the full ARN if available, otherwise a partial arn.
        For secrets imported by the deprecated ``fromSecretName``, it will return the ``secretName``.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretName")
    def secret_name(self) -> builtins.str:
        '''The name of the secret.

        For "owned" secrets, this will be the full resource name (secret name + suffix), unless the
        '@aws-cdk/aws-secretsmanager:parseOwnedSecretName' feature flag is set.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretValue")
    def secret_value(self) -> _SecretValue_3dd0ddae:
        '''Retrieve the value of the stored secret as a ``SecretValue``.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The customer-managed encryption key that is used to encrypt this secret, if any.

        When not specified, the default
        KMS key for the account and region is being used.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretFullArn")
    def secret_full_arn(self) -> typing.Optional[builtins.str]:
        '''The full ARN of the secret in AWS Secrets Manager, which is the ARN including the Secrets Manager-supplied 6-character suffix.

        This is equal to ``secretArn`` in most cases, but is undefined when a full ARN is not available (e.g., secrets imported by name).
        '''
        ...

    @jsii.member(jsii_name="addRotationSchedule")
    def add_rotation_schedule(
        self,
        id: builtins.str,
        *,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        hosted_rotation: typing.Optional[HostedRotation] = None,
        rotation_lambda: typing.Optional[_IFunction_6adb0ab8] = None,
    ) -> "RotationSchedule":
        '''Adds a rotation schedule to the secret.

        :param id: -
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param hosted_rotation: Hosted rotation. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        :param rotation_lambda: A Lambda function that can rotate the secret. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        ...

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the IAM resource policy associated with this secret.

        If this secret was created in this stack, a resource policy will be
        automatically created upon the first call to ``addToResourcePolicy``. If
        the secret is imported, then this is a no-op.

        :param statement: -
        '''
        ...

    @jsii.member(jsii_name="attach")
    def attach(self, target: "ISecretAttachmentTarget") -> "ISecret":
        '''Attach a target to this secret.

        :param target: The target to attach.

        :return: An attached secret
        '''
        ...

    @jsii.member(jsii_name="denyAccountRootDelete")
    def deny_account_root_delete(self) -> None:
        '''Denies the ``DeleteSecret`` action to all principals within the current account.'''
        ...

    @jsii.member(jsii_name="grantRead")
    def grant_read(
        self,
        grantee: _IGrantable_71c4f5de,
        version_stages: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> _Grant_a7ae64f8:
        '''Grants reading the secret value to some role.

        :param grantee: the principal being granted permission.
        :param version_stages: the version stages the grant is limited to. If not specified, no restriction on the version stages is applied.
        '''
        ...

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grants writing and updating the secret value to some role.

        :param grantee: the principal being granted permission.
        '''
        ...

    @jsii.member(jsii_name="secretValueFromJson")
    def secret_value_from_json(self, key: builtins.str) -> _SecretValue_3dd0ddae:
        '''Interpret the secret as a JSON object and return a field's value from it as a ``SecretValue``.

        :param key: -
        '''
        ...


class _ISecretProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A secret in AWS Secrets Manager.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_secretsmanager.ISecret"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretArn")
    def secret_arn(self) -> builtins.str:
        '''The ARN of the secret in AWS Secrets Manager.

        Will return the full ARN if available, otherwise a partial arn.
        For secrets imported by the deprecated ``fromSecretName``, it will return the ``secretName``.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretName")
    def secret_name(self) -> builtins.str:
        '''The name of the secret.

        For "owned" secrets, this will be the full resource name (secret name + suffix), unless the
        '@aws-cdk/aws-secretsmanager:parseOwnedSecretName' feature flag is set.
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretValue")
    def secret_value(self) -> _SecretValue_3dd0ddae:
        '''Retrieve the value of the stored secret as a ``SecretValue``.

        :attribute: true
        '''
        return typing.cast(_SecretValue_3dd0ddae, jsii.get(self, "secretValue"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The customer-managed encryption key that is used to encrypt this secret, if any.

        When not specified, the default
        KMS key for the account and region is being used.
        '''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionKey"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretFullArn")
    def secret_full_arn(self) -> typing.Optional[builtins.str]:
        '''The full ARN of the secret in AWS Secrets Manager, which is the ARN including the Secrets Manager-supplied 6-character suffix.

        This is equal to ``secretArn`` in most cases, but is undefined when a full ARN is not available (e.g., secrets imported by name).
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "secretFullArn"))

    @jsii.member(jsii_name="addRotationSchedule")
    def add_rotation_schedule(
        self,
        id: builtins.str,
        *,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        hosted_rotation: typing.Optional[HostedRotation] = None,
        rotation_lambda: typing.Optional[_IFunction_6adb0ab8] = None,
    ) -> "RotationSchedule":
        '''Adds a rotation schedule to the secret.

        :param id: -
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param hosted_rotation: Hosted rotation. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        :param rotation_lambda: A Lambda function that can rotate the secret. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        options = RotationScheduleOptions(
            automatically_after=automatically_after,
            hosted_rotation=hosted_rotation,
            rotation_lambda=rotation_lambda,
        )

        return typing.cast("RotationSchedule", jsii.invoke(self, "addRotationSchedule", [id, options]))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the IAM resource policy associated with this secret.

        If this secret was created in this stack, a resource policy will be
        automatically created upon the first call to ``addToResourcePolicy``. If
        the secret is imported, then this is a no-op.

        :param statement: -
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

    @jsii.member(jsii_name="attach")
    def attach(self, target: "ISecretAttachmentTarget") -> ISecret:
        '''Attach a target to this secret.

        :param target: The target to attach.

        :return: An attached secret
        '''
        return typing.cast(ISecret, jsii.invoke(self, "attach", [target]))

    @jsii.member(jsii_name="denyAccountRootDelete")
    def deny_account_root_delete(self) -> None:
        '''Denies the ``DeleteSecret`` action to all principals within the current account.'''
        return typing.cast(None, jsii.invoke(self, "denyAccountRootDelete", []))

    @jsii.member(jsii_name="grantRead")
    def grant_read(
        self,
        grantee: _IGrantable_71c4f5de,
        version_stages: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> _Grant_a7ae64f8:
        '''Grants reading the secret value to some role.

        :param grantee: the principal being granted permission.
        :param version_stages: the version stages the grant is limited to. If not specified, no restriction on the version stages is applied.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [grantee, version_stages]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grants writing and updating the secret value to some role.

        :param grantee: the principal being granted permission.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [grantee]))

    @jsii.member(jsii_name="secretValueFromJson")
    def secret_value_from_json(self, key: builtins.str) -> _SecretValue_3dd0ddae:
        '''Interpret the secret as a JSON object and return a field's value from it as a ``SecretValue``.

        :param key: -
        '''
        return typing.cast(_SecretValue_3dd0ddae, jsii.invoke(self, "secretValueFromJson", [key]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ISecret).__jsii_proxy_class__ = lambda : _ISecretProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_secretsmanager.ISecretAttachmentTarget")
class ISecretAttachmentTarget(typing_extensions.Protocol):
    '''A secret attachment target.'''

    @jsii.member(jsii_name="asSecretAttachmentTarget")
    def as_secret_attachment_target(self) -> "SecretAttachmentTargetProps":
        '''Renders the target specifications.'''
        ...


class _ISecretAttachmentTargetProxy:
    '''A secret attachment target.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_secretsmanager.ISecretAttachmentTarget"

    @jsii.member(jsii_name="asSecretAttachmentTarget")
    def as_secret_attachment_target(self) -> "SecretAttachmentTargetProps":
        '''Renders the target specifications.'''
        return typing.cast("SecretAttachmentTargetProps", jsii.invoke(self, "asSecretAttachmentTarget", []))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ISecretAttachmentTarget).__jsii_proxy_class__ = lambda : _ISecretAttachmentTargetProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_secretsmanager.ISecretTargetAttachment")
class ISecretTargetAttachment(ISecret, typing_extensions.Protocol):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretTargetAttachmentSecretArn")
    def secret_target_attachment_secret_arn(self) -> builtins.str:
        '''Same as ``secretArn``.

        :attribute: true
        '''
        ...


class _ISecretTargetAttachmentProxy(
    jsii.proxy_for(ISecret) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_secretsmanager.ISecretTargetAttachment"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretTargetAttachmentSecretArn")
    def secret_target_attachment_secret_arn(self) -> builtins.str:
        '''Same as ``secretArn``.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretTargetAttachmentSecretArn"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ISecretTargetAttachment).__jsii_proxy_class__ = lambda : _ISecretTargetAttachmentProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.ReplicaRegion",
    jsii_struct_bases=[],
    name_mapping={"region": "region", "encryption_key": "encryptionKey"},
)
class ReplicaRegion:
    def __init__(
        self,
        *,
        region: builtins.str,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
    ) -> None:
        '''Secret replica region.

        :param region: The name of the region.
        :param encryption_key: The customer-managed encryption key to use for encrypting the secret value. Default: - A default KMS key for the account and region is used.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_kms as kms
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            # key: kms.Key
            
            replica_region = secretsmanager.ReplicaRegion(
                region="region",
            
                # the properties below are optional
                encryption_key=key
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "region": region,
        }
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key

    @builtins.property
    def region(self) -> builtins.str:
        '''The name of the region.'''
        result = self._values.get("region")
        assert result is not None, "Required property 'region' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The customer-managed encryption key to use for encrypting the secret value.

        :default: - A default KMS key for the account and region is used.
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ReplicaRegion(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ResourcePolicy(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.ResourcePolicy",
):
    '''Resource Policy for SecretsManager Secrets.

    Policies define the operations that are allowed on this resource.

    You almost never need to define this construct directly.

    All AWS resources that support resource policies have a method called
    ``addToResourcePolicy()``, which will automatically create a new resource
    policy if one doesn't exist yet, otherwise it will add to the existing
    policy.

    Prefer to use ``addToResourcePolicy()`` instead.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_secretsmanager as secretsmanager
        
        # secret: secretsmanager.Secret
        
        resource_policy = secretsmanager.ResourcePolicy(self, "MyResourcePolicy",
            secret=secret
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        secret: ISecret,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param secret: The secret to attach a resource-based permissions policy.
        '''
        props = ResourcePolicyProps(secret=secret)

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="document")
    def document(self) -> _PolicyDocument_3ac34393:
        '''The IAM policy document for this policy.'''
        return typing.cast(_PolicyDocument_3ac34393, jsii.get(self, "document"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.ResourcePolicyProps",
    jsii_struct_bases=[],
    name_mapping={"secret": "secret"},
)
class ResourcePolicyProps:
    def __init__(self, *, secret: ISecret) -> None:
        '''Construction properties for a ResourcePolicy.

        :param secret: The secret to attach a resource-based permissions policy.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            # secret: secretsmanager.Secret
            
            resource_policy_props = secretsmanager.ResourcePolicyProps(
                secret=secret
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "secret": secret,
        }

    @builtins.property
    def secret(self) -> ISecret:
        '''The secret to attach a resource-based permissions policy.'''
        result = self._values.get("secret")
        assert result is not None, "Required property 'secret' is missing"
        return typing.cast(ISecret, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ResourcePolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class RotationSchedule(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.RotationSchedule",
):
    '''A rotation schedule.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_lambda as lambda_
        from aws_cdk import aws_secretsmanager as secretsmanager
        
        # function_: lambda.Function
        # hosted_rotation: secretsmanager.HostedRotation
        # secret: secretsmanager.Secret
        
        rotation_schedule = secretsmanager.RotationSchedule(self, "MyRotationSchedule",
            secret=secret,
        
            # the properties below are optional
            automatically_after=cdk.Duration.minutes(30),
            hosted_rotation=hosted_rotation,
            rotation_lambda=function_
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        secret: ISecret,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        hosted_rotation: typing.Optional[HostedRotation] = None,
        rotation_lambda: typing.Optional[_IFunction_6adb0ab8] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param secret: The secret to rotate. If hosted rotation is used, this must be a JSON string with the following format:: { "engine": <required: database engine>, "host": <required: instance host name>, "username": <required: username>, "password": <required: password>, "dbname": <optional: database name>, "port": <optional: if not specified, default port will be used>, "masterarn": <required for multi user rotation: the arn of the master secret which will be used to create users/change passwords> } This is typically the case for a secret referenced from an ``AWS::SecretsManager::SecretTargetAttachment`` or an ``ISecret`` returned by the ``attach()`` method of ``Secret``.
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param hosted_rotation: Hosted rotation. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        :param rotation_lambda: A Lambda function that can rotate the secret. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        props = RotationScheduleProps(
            secret=secret,
            automatically_after=automatically_after,
            hosted_rotation=hosted_rotation,
            rotation_lambda=rotation_lambda,
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.RotationScheduleOptions",
    jsii_struct_bases=[],
    name_mapping={
        "automatically_after": "automaticallyAfter",
        "hosted_rotation": "hostedRotation",
        "rotation_lambda": "rotationLambda",
    },
)
class RotationScheduleOptions:
    def __init__(
        self,
        *,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        hosted_rotation: typing.Optional[HostedRotation] = None,
        rotation_lambda: typing.Optional[_IFunction_6adb0ab8] = None,
    ) -> None:
        '''Options to add a rotation schedule to a secret.

        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param hosted_rotation: Hosted rotation. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        :param rotation_lambda: A Lambda function that can rotate the secret. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_lambda as lambda_
            
            # fn: lambda.Function
            
            secret = secretsmanager.Secret(self, "Secret")
            
            secret.add_rotation_schedule("RotationSchedule",
                rotation_lambda=fn,
                automatically_after=Duration.days(15)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if automatically_after is not None:
            self._values["automatically_after"] = automatically_after
        if hosted_rotation is not None:
            self._values["hosted_rotation"] = hosted_rotation
        if rotation_lambda is not None:
            self._values["rotation_lambda"] = rotation_lambda

    @builtins.property
    def automatically_after(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation.

        :default: Duration.days(30)
        '''
        result = self._values.get("automatically_after")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def hosted_rotation(self) -> typing.Optional[HostedRotation]:
        '''Hosted rotation.

        :default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        result = self._values.get("hosted_rotation")
        return typing.cast(typing.Optional[HostedRotation], result)

    @builtins.property
    def rotation_lambda(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A Lambda function that can rotate the secret.

        :default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        result = self._values.get("rotation_lambda")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RotationScheduleOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.RotationScheduleProps",
    jsii_struct_bases=[RotationScheduleOptions],
    name_mapping={
        "automatically_after": "automaticallyAfter",
        "hosted_rotation": "hostedRotation",
        "rotation_lambda": "rotationLambda",
        "secret": "secret",
    },
)
class RotationScheduleProps(RotationScheduleOptions):
    def __init__(
        self,
        *,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        hosted_rotation: typing.Optional[HostedRotation] = None,
        rotation_lambda: typing.Optional[_IFunction_6adb0ab8] = None,
        secret: ISecret,
    ) -> None:
        '''Construction properties for a RotationSchedule.

        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param hosted_rotation: Hosted rotation. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        :param rotation_lambda: A Lambda function that can rotate the secret. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        :param secret: The secret to rotate. If hosted rotation is used, this must be a JSON string with the following format:: { "engine": <required: database engine>, "host": <required: instance host name>, "username": <required: username>, "password": <required: password>, "dbname": <optional: database name>, "port": <optional: if not specified, default port will be used>, "masterarn": <required for multi user rotation: the arn of the master secret which will be used to create users/change passwords> } This is typically the case for a secret referenced from an ``AWS::SecretsManager::SecretTargetAttachment`` or an ``ISecret`` returned by the ``attach()`` method of ``Secret``.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_lambda as lambda_
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            # function_: lambda.Function
            # hosted_rotation: secretsmanager.HostedRotation
            # secret: secretsmanager.Secret
            
            rotation_schedule_props = secretsmanager.RotationScheduleProps(
                secret=secret,
            
                # the properties below are optional
                automatically_after=cdk.Duration.minutes(30),
                hosted_rotation=hosted_rotation,
                rotation_lambda=function_
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "secret": secret,
        }
        if automatically_after is not None:
            self._values["automatically_after"] = automatically_after
        if hosted_rotation is not None:
            self._values["hosted_rotation"] = hosted_rotation
        if rotation_lambda is not None:
            self._values["rotation_lambda"] = rotation_lambda

    @builtins.property
    def automatically_after(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation.

        :default: Duration.days(30)
        '''
        result = self._values.get("automatically_after")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def hosted_rotation(self) -> typing.Optional[HostedRotation]:
        '''Hosted rotation.

        :default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        result = self._values.get("hosted_rotation")
        return typing.cast(typing.Optional[HostedRotation], result)

    @builtins.property
    def rotation_lambda(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A Lambda function that can rotate the secret.

        :default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        result = self._values.get("rotation_lambda")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def secret(self) -> ISecret:
        '''The secret to rotate.

        If hosted rotation is used, this must be a JSON string with the following format::

           {
              "engine": <required: database engine>,
              "host": <required: instance host name>,
              "username": <required: username>,
              "password": <required: password>,
              "dbname": <optional: database name>,
              "port": <optional: if not specified, default port will be used>,
              "masterarn": <required for multi user rotation: the arn of the master secret which will be used to create users/change passwords>
           }

        This is typically the case for a secret referenced from an ``AWS::SecretsManager::SecretTargetAttachment``
        or an ``ISecret`` returned by the ``attach()`` method of ``Secret``.
        '''
        result = self._values.get("secret")
        assert result is not None, "Required property 'secret' is missing"
        return typing.cast(ISecret, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RotationScheduleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(ISecret)
class Secret(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.Secret",
):
    '''Creates a new secret in AWS SecretsManager.

    :exampleMetadata: infused

    Example::

        # Creates a new IAM user, access and secret keys, and stores the secret access key in a Secret.
        user = iam.User(self, "User")
        access_key = iam.AccessKey(self, "AccessKey", user=user)
        secret_value = secretsmanager.SecretStringValueBeta1.from_token(access_key.secret_access_key.to_string())
        secretsmanager.Secret(self, "Secret",
            secret_string_beta1=secret_value
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        generate_secret_string: typing.Optional["SecretStringGenerator"] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        replica_regions: typing.Optional[typing.Sequence[ReplicaRegion]] = None,
        secret_name: typing.Optional[builtins.str] = None,
        secret_string_beta1: typing.Optional["SecretStringValueBeta1"] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param description: An optional, human-friendly description of the secret. Default: - No description.
        :param encryption_key: The customer-managed encryption key to use for encrypting the secret value. Default: - A default KMS key for the account and region is used.
        :param generate_secret_string: Configuration for how to generate a secret value. Only one of ``secretString`` and ``generateSecretString`` can be provided. Default: - 32 characters with upper-case letters, lower-case letters, punctuation and numbers (at least one from each category), per the default values of ``SecretStringGenerator``.
        :param removal_policy: Policy to apply when the secret is removed from this stack. Default: - Not set.
        :param replica_regions: A list of regions where to replicate this secret. Default: - Secret is not replicated
        :param secret_name: A name for the secret. Note that deleting secrets from SecretsManager does not happen immediately, but after a 7 to 30 days blackout period. During that period, it is not possible to create another secret that shares the same name. Default: - A name is generated by CloudFormation.
        :param secret_string_beta1: Initial value for the secret. **NOTE:** *It is **highly** encouraged to leave this field undefined and allow SecretsManager to create the secret value. The secret string -- if provided -- will be included in the output of the cdk as part of synthesis, and will appear in the CloudFormation template in the console. This can be secure(-ish) if that value is merely reference to another resource (or one of its attributes), but if the value is a plaintext string, it will be visible to anyone with access to the CloudFormation template (via the AWS Console, SDKs, or CLI). Specifies text data that you want to encrypt and store in this new version of the secret. May be a simple string value, or a string representation of a JSON structure. Only one of ``secretString`` and ``generateSecretString`` can be provided. Default: - SecretsManager generates a new secret value.
        '''
        props = SecretProps(
            description=description,
            encryption_key=encryption_key,
            generate_secret_string=generate_secret_string,
            removal_policy=removal_policy,
            replica_regions=replica_regions,
            secret_name=secret_name,
            secret_string_beta1=secret_string_beta1,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromSecretAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_secret_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        secret_complete_arn: typing.Optional[builtins.str] = None,
        secret_partial_arn: typing.Optional[builtins.str] = None,
    ) -> ISecret:
        '''Import an existing secret into the Stack.

        :param scope: the scope of the import.
        :param id: the ID of the imported Secret in the construct tree.
        :param encryption_key: The encryption key that is used to encrypt the secret, unless the default SecretsManager key is used.
        :param secret_complete_arn: The complete ARN of the secret in SecretsManager. This is the ARN including the Secrets Manager 6-character suffix. Cannot be used with ``secretArn`` or ``secretPartialArn``.
        :param secret_partial_arn: The partial ARN of the secret in SecretsManager. This is the ARN without the Secrets Manager 6-character suffix. Cannot be used with ``secretArn`` or ``secretCompleteArn``.
        '''
        attrs = SecretAttributes(
            encryption_key=encryption_key,
            secret_complete_arn=secret_complete_arn,
            secret_partial_arn=secret_partial_arn,
        )

        return typing.cast(ISecret, jsii.sinvoke(cls, "fromSecretAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromSecretCompleteArn") # type: ignore[misc]
    @builtins.classmethod
    def from_secret_complete_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        secret_complete_arn: builtins.str,
    ) -> ISecret:
        '''Imports a secret by complete ARN.

        The complete ARN is the ARN with the Secrets Manager-supplied suffix.

        :param scope: -
        :param id: -
        :param secret_complete_arn: -
        '''
        return typing.cast(ISecret, jsii.sinvoke(cls, "fromSecretCompleteArn", [scope, id, secret_complete_arn]))

    @jsii.member(jsii_name="fromSecretNameV2") # type: ignore[misc]
    @builtins.classmethod
    def from_secret_name_v2(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        secret_name: builtins.str,
    ) -> ISecret:
        '''Imports a secret by secret name.

        A secret with this name must exist in the same account & region.
        Replaces the deprecated ``fromSecretName``.

        :param scope: -
        :param id: -
        :param secret_name: -
        '''
        return typing.cast(ISecret, jsii.sinvoke(cls, "fromSecretNameV2", [scope, id, secret_name]))

    @jsii.member(jsii_name="fromSecretPartialArn") # type: ignore[misc]
    @builtins.classmethod
    def from_secret_partial_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        secret_partial_arn: builtins.str,
    ) -> ISecret:
        '''Imports a secret by partial ARN.

        The partial ARN is the ARN without the Secrets Manager-supplied suffix.

        :param scope: -
        :param id: -
        :param secret_partial_arn: -
        '''
        return typing.cast(ISecret, jsii.sinvoke(cls, "fromSecretPartialArn", [scope, id, secret_partial_arn]))

    @jsii.member(jsii_name="addReplicaRegion")
    def add_replica_region(
        self,
        region: builtins.str,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
    ) -> None:
        '''Adds a replica region for the secret.

        :param region: The name of the region.
        :param encryption_key: The customer-managed encryption key to use for encrypting the secret value.
        '''
        return typing.cast(None, jsii.invoke(self, "addReplicaRegion", [region, encryption_key]))

    @jsii.member(jsii_name="addRotationSchedule")
    def add_rotation_schedule(
        self,
        id: builtins.str,
        *,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        hosted_rotation: typing.Optional[HostedRotation] = None,
        rotation_lambda: typing.Optional[_IFunction_6adb0ab8] = None,
    ) -> RotationSchedule:
        '''Adds a rotation schedule to the secret.

        :param id: -
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param hosted_rotation: Hosted rotation. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        :param rotation_lambda: A Lambda function that can rotate the secret. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        options = RotationScheduleOptions(
            automatically_after=automatically_after,
            hosted_rotation=hosted_rotation,
            rotation_lambda=rotation_lambda,
        )

        return typing.cast(RotationSchedule, jsii.invoke(self, "addRotationSchedule", [id, options]))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the IAM resource policy associated with this secret.

        If this secret was created in this stack, a resource policy will be
        automatically created upon the first call to ``addToResourcePolicy``. If
        the secret is imported, then this is a no-op.

        :param statement: -
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

    @jsii.member(jsii_name="attach")
    def attach(self, target: ISecretAttachmentTarget) -> ISecret:
        '''Attach a target to this secret.

        :param target: The target to attach.

        :return: An attached secret
        '''
        return typing.cast(ISecret, jsii.invoke(self, "attach", [target]))

    @jsii.member(jsii_name="denyAccountRootDelete")
    def deny_account_root_delete(self) -> None:
        '''Denies the ``DeleteSecret`` action to all principals within the current account.'''
        return typing.cast(None, jsii.invoke(self, "denyAccountRootDelete", []))

    @jsii.member(jsii_name="grantRead")
    def grant_read(
        self,
        grantee: _IGrantable_71c4f5de,
        version_stages: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> _Grant_a7ae64f8:
        '''Grants reading the secret value to some role.

        :param grantee: -
        :param version_stages: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [grantee, version_stages]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grants writing and updating the secret value to some role.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [grantee]))

    @jsii.member(jsii_name="secretValueFromJson")
    def secret_value_from_json(self, json_field: builtins.str) -> _SecretValue_3dd0ddae:
        '''Interpret the secret as a JSON object and return a field's value from it as a ``SecretValue``.

        :param json_field: -
        '''
        return typing.cast(_SecretValue_3dd0ddae, jsii.invoke(self, "secretValueFromJson", [json_field]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="arnForPolicies")
    def _arn_for_policies(self) -> builtins.str:
        '''Provides an identifier for this secret for use in IAM policies.

        If there is a full ARN, this is just the ARN;
        if we have a partial ARN -- due to either importing by secret name or partial ARN --
        then we need to add a suffix to capture the full ARN's format.
        '''
        return typing.cast(builtins.str, jsii.get(self, "arnForPolicies"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreatePolicy")
    def _auto_create_policy(self) -> builtins.bool:
        return typing.cast(builtins.bool, jsii.get(self, "autoCreatePolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretArn")
    def secret_arn(self) -> builtins.str:
        '''The ARN of the secret in AWS Secrets Manager.

        Will return the full ARN if available, otherwise a partial arn.
        For secrets imported by the deprecated ``fromSecretName``, it will return the ``secretName``.
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretName")
    def secret_name(self) -> builtins.str:
        '''The name of the secret.

        For "owned" secrets, this will be the full resource name (secret name + suffix), unless the
        '@aws-cdk/aws-secretsmanager:parseOwnedSecretName' feature flag is set.
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretValue")
    def secret_value(self) -> _SecretValue_3dd0ddae:
        '''Retrieve the value of the stored secret as a ``SecretValue``.'''
        return typing.cast(_SecretValue_3dd0ddae, jsii.get(self, "secretValue"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The customer-managed encryption key that is used to encrypt this secret, if any.

        When not specified, the default
        KMS key for the account and region is being used.
        '''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionKey"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretFullArn")
    def secret_full_arn(self) -> typing.Optional[builtins.str]:
        '''The full ARN of the secret in AWS Secrets Manager, which is the ARN including the Secrets Manager-supplied 6-character suffix.

        This is equal to ``secretArn`` in most cases, but is undefined when a full ARN is not available (e.g., secrets imported by name).
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "secretFullArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretAttachmentTargetProps",
    jsii_struct_bases=[],
    name_mapping={"target_id": "targetId", "target_type": "targetType"},
)
class SecretAttachmentTargetProps:
    def __init__(
        self,
        *,
        target_id: builtins.str,
        target_type: AttachmentTargetType,
    ) -> None:
        '''Attachment target specifications.

        :param target_id: The id of the target to attach the secret to.
        :param target_type: The type of the target to attach the secret to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            secret_attachment_target_props = secretsmanager.SecretAttachmentTargetProps(
                target_id="targetId",
                target_type=secretsmanager.AttachmentTargetType.RDS_DB_INSTANCE
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_id": target_id,
            "target_type": target_type,
        }

    @builtins.property
    def target_id(self) -> builtins.str:
        '''The id of the target to attach the secret to.'''
        result = self._values.get("target_id")
        assert result is not None, "Required property 'target_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def target_type(self) -> AttachmentTargetType:
        '''The type of the target to attach the secret to.'''
        result = self._values.get("target_type")
        assert result is not None, "Required property 'target_type' is missing"
        return typing.cast(AttachmentTargetType, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SecretAttachmentTargetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "encryption_key": "encryptionKey",
        "secret_complete_arn": "secretCompleteArn",
        "secret_partial_arn": "secretPartialArn",
    },
)
class SecretAttributes:
    def __init__(
        self,
        *,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        secret_complete_arn: typing.Optional[builtins.str] = None,
        secret_partial_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Attributes required to import an existing secret into the Stack.

        One ARN format (``secretArn``, ``secretCompleteArn``, ``secretPartialArn``) must be provided.

        :param encryption_key: The encryption key that is used to encrypt the secret, unless the default SecretsManager key is used.
        :param secret_complete_arn: The complete ARN of the secret in SecretsManager. This is the ARN including the Secrets Manager 6-character suffix. Cannot be used with ``secretArn`` or ``secretPartialArn``.
        :param secret_partial_arn: The partial ARN of the secret in SecretsManager. This is the ARN without the Secrets Manager 6-character suffix. Cannot be used with ``secretArn`` or ``secretCompleteArn``.

        :exampleMetadata: infused

        Example::

            # encryption_key: kms.Key
            
            secret = secretsmanager.Secret.from_secret_attributes(self, "ImportedSecret",
                secret_arn="arn:aws:secretsmanager:<region>:<account-id-number>:secret:<secret-name>-<random-6-characters>",
                # If the secret is encrypted using a KMS-hosted CMK, either import or reference that key:
                encryption_key=encryption_key
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if secret_complete_arn is not None:
            self._values["secret_complete_arn"] = secret_complete_arn
        if secret_partial_arn is not None:
            self._values["secret_partial_arn"] = secret_partial_arn

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The encryption key that is used to encrypt the secret, unless the default SecretsManager key is used.'''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def secret_complete_arn(self) -> typing.Optional[builtins.str]:
        '''The complete ARN of the secret in SecretsManager.

        This is the ARN including the Secrets Manager 6-character suffix.
        Cannot be used with ``secretArn`` or ``secretPartialArn``.
        '''
        result = self._values.get("secret_complete_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def secret_partial_arn(self) -> typing.Optional[builtins.str]:
        '''The partial ARN of the secret in SecretsManager.

        This is the ARN without the Secrets Manager 6-character suffix.
        Cannot be used with ``secretArn`` or ``secretCompleteArn``.
        '''
        result = self._values.get("secret_partial_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SecretAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "encryption_key": "encryptionKey",
        "generate_secret_string": "generateSecretString",
        "removal_policy": "removalPolicy",
        "replica_regions": "replicaRegions",
        "secret_name": "secretName",
        "secret_string_beta1": "secretStringBeta1",
    },
)
class SecretProps:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        generate_secret_string: typing.Optional["SecretStringGenerator"] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        replica_regions: typing.Optional[typing.Sequence[ReplicaRegion]] = None,
        secret_name: typing.Optional[builtins.str] = None,
        secret_string_beta1: typing.Optional["SecretStringValueBeta1"] = None,
    ) -> None:
        '''The properties required to create a new secret in AWS Secrets Manager.

        :param description: An optional, human-friendly description of the secret. Default: - No description.
        :param encryption_key: The customer-managed encryption key to use for encrypting the secret value. Default: - A default KMS key for the account and region is used.
        :param generate_secret_string: Configuration for how to generate a secret value. Only one of ``secretString`` and ``generateSecretString`` can be provided. Default: - 32 characters with upper-case letters, lower-case letters, punctuation and numbers (at least one from each category), per the default values of ``SecretStringGenerator``.
        :param removal_policy: Policy to apply when the secret is removed from this stack. Default: - Not set.
        :param replica_regions: A list of regions where to replicate this secret. Default: - Secret is not replicated
        :param secret_name: A name for the secret. Note that deleting secrets from SecretsManager does not happen immediately, but after a 7 to 30 days blackout period. During that period, it is not possible to create another secret that shares the same name. Default: - A name is generated by CloudFormation.
        :param secret_string_beta1: Initial value for the secret. **NOTE:** *It is **highly** encouraged to leave this field undefined and allow SecretsManager to create the secret value. The secret string -- if provided -- will be included in the output of the cdk as part of synthesis, and will appear in the CloudFormation template in the console. This can be secure(-ish) if that value is merely reference to another resource (or one of its attributes), but if the value is a plaintext string, it will be visible to anyone with access to the CloudFormation template (via the AWS Console, SDKs, or CLI). Specifies text data that you want to encrypt and store in this new version of the secret. May be a simple string value, or a string representation of a JSON structure. Only one of ``secretString`` and ``generateSecretString`` can be provided. Default: - SecretsManager generates a new secret value.

        :exampleMetadata: infused

        Example::

            # Creates a new IAM user, access and secret keys, and stores the secret access key in a Secret.
            user = iam.User(self, "User")
            access_key = iam.AccessKey(self, "AccessKey", user=user)
            secret_value = secretsmanager.SecretStringValueBeta1.from_token(access_key.secret_access_key.to_string())
            secretsmanager.Secret(self, "Secret",
                secret_string_beta1=secret_value
            )
        '''
        if isinstance(generate_secret_string, dict):
            generate_secret_string = SecretStringGenerator(**generate_secret_string)
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if generate_secret_string is not None:
            self._values["generate_secret_string"] = generate_secret_string
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if replica_regions is not None:
            self._values["replica_regions"] = replica_regions
        if secret_name is not None:
            self._values["secret_name"] = secret_name
        if secret_string_beta1 is not None:
            self._values["secret_string_beta1"] = secret_string_beta1

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''An optional, human-friendly description of the secret.

        :default: - No description.
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The customer-managed encryption key to use for encrypting the secret value.

        :default: - A default KMS key for the account and region is used.
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def generate_secret_string(self) -> typing.Optional["SecretStringGenerator"]:
        '''Configuration for how to generate a secret value.

        Only one of ``secretString`` and ``generateSecretString`` can be provided.

        :default:

        - 32 characters with upper-case letters, lower-case letters, punctuation and numbers (at least one from each
        category), per the default values of ``SecretStringGenerator``.
        '''
        result = self._values.get("generate_secret_string")
        return typing.cast(typing.Optional["SecretStringGenerator"], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Policy to apply when the secret is removed from this stack.

        :default: - Not set.
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def replica_regions(self) -> typing.Optional[typing.List[ReplicaRegion]]:
        '''A list of regions where to replicate this secret.

        :default: - Secret is not replicated
        '''
        result = self._values.get("replica_regions")
        return typing.cast(typing.Optional[typing.List[ReplicaRegion]], result)

    @builtins.property
    def secret_name(self) -> typing.Optional[builtins.str]:
        '''A name for the secret.

        Note that deleting secrets from SecretsManager does not happen immediately, but after a 7 to
        30 days blackout period. During that period, it is not possible to create another secret that shares the same name.

        :default: - A name is generated by CloudFormation.
        '''
        result = self._values.get("secret_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def secret_string_beta1(self) -> typing.Optional["SecretStringValueBeta1"]:
        '''Initial value for the secret.

        **NOTE:** *It is **highly** encouraged to leave this field undefined and allow SecretsManager to create the secret value.
        The secret string -- if provided -- will be included in the output of the cdk as part of synthesis,
        and will appear in the CloudFormation template in the console. This can be secure(-ish) if that value is merely reference to
        another resource (or one of its attributes), but if the value is a plaintext string, it will be visible to anyone with access
        to the CloudFormation template (via the AWS Console, SDKs, or CLI).

        Specifies text data that you want to encrypt and store in this new version of the secret.
        May be a simple string value, or a string representation of a JSON structure.

        Only one of ``secretString`` and ``generateSecretString`` can be provided.

        :default: - SecretsManager generates a new secret value.
        '''
        result = self._values.get("secret_string_beta1")
        return typing.cast(typing.Optional["SecretStringValueBeta1"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SecretProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class SecretRotation(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretRotation",
):
    '''Secret rotation for a service or database.

    :exampleMetadata: infused

    Example::

        # my_secret: secretsmanager.Secret
        # my_database: ec2.IConnectable
        # my_vpc: ec2.Vpc
        
        
        secretsmanager.SecretRotation(self, "SecretRotation",
            application=secretsmanager.SecretRotationApplication.MYSQL_ROTATION_SINGLE_USER,  # MySQL single user scheme
            secret=my_secret,
            target=my_database,  # a Connectable
            vpc=my_vpc,  # The VPC where the secret rotation application will be deployed
            exclude_characters=" %+:;{}"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        application: "SecretRotationApplication",
        secret: ISecret,
        target: _IConnectable_10015a05,
        vpc: _IVpc_f30d5663,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        endpoint: typing.Optional[_IInterfaceVpcEndpoint_7481aea1] = None,
        exclude_characters: typing.Optional[builtins.str] = None,
        master_secret: typing.Optional[ISecret] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param application: The serverless application for the rotation.
        :param secret: The secret to rotate. It must be a JSON string with the following format:. Example:: { "engine": <required: database engine>, "host": <required: instance host name>, "username": <required: username>, "password": <required: password>, "dbname": <optional: database name>, "port": <optional: if not specified, default port will be used>, "masterarn": <required for multi user rotation: the arn of the master secret which will be used to create users/change passwords> } This is typically the case for a secret referenced from an ``AWS::SecretsManager::SecretTargetAttachment`` or an ``ISecret`` returned by the ``attach()`` method of ``Secret``.
        :param target: The target service or database.
        :param vpc: The VPC where the Lambda rotation function will run.
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param endpoint: The VPC interface endpoint to use for the Secrets Manager API. If you enable private DNS hostnames for your VPC private endpoint (the default), you don't need to specify an endpoint. The standard Secrets Manager DNS hostname the Secrets Manager CLI and SDKs use by default (https://secretsmanager..amazonaws.com) automatically resolves to your VPC endpoint. Default: https://secretsmanager..amazonaws.com
        :param exclude_characters: Characters which should not appear in the generated password. Default: - no additional characters are explicitly excluded
        :param master_secret: The master secret for a multi user rotation scheme. Default: - single user rotation scheme
        :param security_group: The security group for the Lambda rotation function. Default: - a new security group is created
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        '''
        props = SecretRotationProps(
            application=application,
            secret=secret,
            target=target,
            vpc=vpc,
            automatically_after=automatically_after,
            endpoint=endpoint,
            exclude_characters=exclude_characters,
            master_secret=master_secret,
            security_group=security_group,
            vpc_subnets=vpc_subnets,
        )

        jsii.create(self.__class__, self, [scope, id, props])


class SecretRotationApplication(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretRotationApplication",
):
    '''A secret rotation serverless application.

    :exampleMetadata: infused

    Example::

        # my_secret: secretsmanager.Secret
        # my_database: ec2.IConnectable
        # my_vpc: ec2.Vpc
        
        
        secretsmanager.SecretRotation(self, "SecretRotation",
            application=secretsmanager.SecretRotationApplication.MYSQL_ROTATION_SINGLE_USER,  # MySQL single user scheme
            secret=my_secret,
            target=my_database,  # a Connectable
            vpc=my_vpc,  # The VPC where the secret rotation application will be deployed
            exclude_characters=" %+:;{}"
        )
    '''

    def __init__(
        self,
        application_id: builtins.str,
        semantic_version: builtins.str,
        *,
        is_multi_user: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''
        :param application_id: -
        :param semantic_version: -
        :param is_multi_user: Whether the rotation application uses the mutli user scheme. Default: false
        '''
        options = SecretRotationApplicationOptions(is_multi_user=is_multi_user)

        jsii.create(self.__class__, self, [application_id, semantic_version, options])

    @jsii.member(jsii_name="applicationArnForPartition")
    def application_arn_for_partition(self, partition: builtins.str) -> builtins.str:
        '''Returns the application ARN for the current partition.

        Can be used in combination with a ``CfnMapping`` to automatically select the correct ARN based on the current partition.

        :param partition: -
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "applicationArnForPartition", [partition]))

    @jsii.member(jsii_name="semanticVersionForPartition")
    def semantic_version_for_partition(self, partition: builtins.str) -> builtins.str:
        '''The semantic version of the app for the current partition.

        Can be used in combination with a ``CfnMapping`` to automatically select the correct version based on the current partition.

        :param partition: -
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "semanticVersionForPartition", [partition]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MARIADB_ROTATION_MULTI_USER")
    def MARIADB_ROTATION_MULTI_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS MariaDB using the multi user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "MARIADB_ROTATION_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MARIADB_ROTATION_SINGLE_USER")
    def MARIADB_ROTATION_SINGLE_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS MariaDB using the single user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "MARIADB_ROTATION_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MONGODB_ROTATION_MULTI_USER")
    def MONGODB_ROTATION_MULTI_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for MongoDB using the multi user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "MONGODB_ROTATION_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MONGODB_ROTATION_SINGLE_USER")
    def MONGODB_ROTATION_SINGLE_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for MongoDB using the single user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "MONGODB_ROTATION_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MYSQL_ROTATION_MULTI_USER")
    def MYSQL_ROTATION_MULTI_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS MySQL using the multi user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "MYSQL_ROTATION_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MYSQL_ROTATION_SINGLE_USER")
    def MYSQL_ROTATION_SINGLE_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS MySQL using the single user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "MYSQL_ROTATION_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="ORACLE_ROTATION_MULTI_USER")
    def ORACLE_ROTATION_MULTI_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS Oracle using the multi user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "ORACLE_ROTATION_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="ORACLE_ROTATION_SINGLE_USER")
    def ORACLE_ROTATION_SINGLE_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS Oracle using the single user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "ORACLE_ROTATION_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="POSTGRES_ROTATION_MULTI_USER")
    def POSTGRES_ROTATION_MULTI_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS PostgreSQL using the multi user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "POSTGRES_ROTATION_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="POSTGRES_ROTATION_SINGLE_USER")
    def POSTGRES_ROTATION_SINGLE_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS PostgreSQL using the single user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "POSTGRES_ROTATION_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="REDSHIFT_ROTATION_MULTI_USER")
    def REDSHIFT_ROTATION_MULTI_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for Amazon Redshift using the multi user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "REDSHIFT_ROTATION_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="REDSHIFT_ROTATION_SINGLE_USER")
    def REDSHIFT_ROTATION_SINGLE_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for Amazon Redshift using the single user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "REDSHIFT_ROTATION_SINGLE_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="SQLSERVER_ROTATION_MULTI_USER")
    def SQLSERVER_ROTATION_MULTI_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS SQL Server using the multi user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "SQLSERVER_ROTATION_MULTI_USER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="SQLSERVER_ROTATION_SINGLE_USER")
    def SQLSERVER_ROTATION_SINGLE_USER(cls) -> "SecretRotationApplication":
        '''Conducts an AWS SecretsManager secret rotation for RDS SQL Server using the single user rotation scheme.'''
        return typing.cast("SecretRotationApplication", jsii.sget(cls, "SQLSERVER_ROTATION_SINGLE_USER"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isMultiUser")
    def is_multi_user(self) -> typing.Optional[builtins.bool]:
        '''Whether the rotation application uses the mutli user scheme.'''
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "isMultiUser"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretRotationApplicationOptions",
    jsii_struct_bases=[],
    name_mapping={"is_multi_user": "isMultiUser"},
)
class SecretRotationApplicationOptions:
    def __init__(self, *, is_multi_user: typing.Optional[builtins.bool] = None) -> None:
        '''Options for a SecretRotationApplication.

        :param is_multi_user: Whether the rotation application uses the mutli user scheme. Default: false

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            secret_rotation_application_options = secretsmanager.SecretRotationApplicationOptions(
                is_multi_user=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if is_multi_user is not None:
            self._values["is_multi_user"] = is_multi_user

    @builtins.property
    def is_multi_user(self) -> typing.Optional[builtins.bool]:
        '''Whether the rotation application uses the mutli user scheme.

        :default: false
        '''
        result = self._values.get("is_multi_user")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SecretRotationApplicationOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretRotationProps",
    jsii_struct_bases=[],
    name_mapping={
        "application": "application",
        "secret": "secret",
        "target": "target",
        "vpc": "vpc",
        "automatically_after": "automaticallyAfter",
        "endpoint": "endpoint",
        "exclude_characters": "excludeCharacters",
        "master_secret": "masterSecret",
        "security_group": "securityGroup",
        "vpc_subnets": "vpcSubnets",
    },
)
class SecretRotationProps:
    def __init__(
        self,
        *,
        application: SecretRotationApplication,
        secret: ISecret,
        target: _IConnectable_10015a05,
        vpc: _IVpc_f30d5663,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        endpoint: typing.Optional[_IInterfaceVpcEndpoint_7481aea1] = None,
        exclude_characters: typing.Optional[builtins.str] = None,
        master_secret: typing.Optional[ISecret] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''Construction properties for a SecretRotation.

        :param application: The serverless application for the rotation.
        :param secret: The secret to rotate. It must be a JSON string with the following format:. Example:: { "engine": <required: database engine>, "host": <required: instance host name>, "username": <required: username>, "password": <required: password>, "dbname": <optional: database name>, "port": <optional: if not specified, default port will be used>, "masterarn": <required for multi user rotation: the arn of the master secret which will be used to create users/change passwords> } This is typically the case for a secret referenced from an ``AWS::SecretsManager::SecretTargetAttachment`` or an ``ISecret`` returned by the ``attach()`` method of ``Secret``.
        :param target: The target service or database.
        :param vpc: The VPC where the Lambda rotation function will run.
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param endpoint: The VPC interface endpoint to use for the Secrets Manager API. If you enable private DNS hostnames for your VPC private endpoint (the default), you don't need to specify an endpoint. The standard Secrets Manager DNS hostname the Secrets Manager CLI and SDKs use by default (https://secretsmanager..amazonaws.com) automatically resolves to your VPC endpoint. Default: https://secretsmanager..amazonaws.com
        :param exclude_characters: Characters which should not appear in the generated password. Default: - no additional characters are explicitly excluded
        :param master_secret: The master secret for a multi user rotation scheme. Default: - single user rotation scheme
        :param security_group: The security group for the Lambda rotation function. Default: - a new security group is created
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.

        :exampleMetadata: infused

        Example::

            # my_secret: secretsmanager.Secret
            # my_database: ec2.IConnectable
            # my_vpc: ec2.Vpc
            
            
            secretsmanager.SecretRotation(self, "SecretRotation",
                application=secretsmanager.SecretRotationApplication.MYSQL_ROTATION_SINGLE_USER,  # MySQL single user scheme
                secret=my_secret,
                target=my_database,  # a Connectable
                vpc=my_vpc,  # The VPC where the secret rotation application will be deployed
                exclude_characters=" %+:;{}"
            )
        '''
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        self._values: typing.Dict[str, typing.Any] = {
            "application": application,
            "secret": secret,
            "target": target,
            "vpc": vpc,
        }
        if automatically_after is not None:
            self._values["automatically_after"] = automatically_after
        if endpoint is not None:
            self._values["endpoint"] = endpoint
        if exclude_characters is not None:
            self._values["exclude_characters"] = exclude_characters
        if master_secret is not None:
            self._values["master_secret"] = master_secret
        if security_group is not None:
            self._values["security_group"] = security_group
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets

    @builtins.property
    def application(self) -> SecretRotationApplication:
        '''The serverless application for the rotation.'''
        result = self._values.get("application")
        assert result is not None, "Required property 'application' is missing"
        return typing.cast(SecretRotationApplication, result)

    @builtins.property
    def secret(self) -> ISecret:
        '''The secret to rotate. It must be a JSON string with the following format:.

        Example::

           {
              "engine": <required: database engine>,
              "host": <required: instance host name>,
              "username": <required: username>,
              "password": <required: password>,
              "dbname": <optional: database name>,
              "port": <optional: if not specified, default port will be used>,
              "masterarn": <required for multi user rotation: the arn of the master secret which will be used to create users/change passwords>
           }

        This is typically the case for a secret referenced from an ``AWS::SecretsManager::SecretTargetAttachment``
        or an ``ISecret`` returned by the ``attach()`` method of ``Secret``.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html
        '''
        result = self._values.get("secret")
        assert result is not None, "Required property 'secret' is missing"
        return typing.cast(ISecret, result)

    @builtins.property
    def target(self) -> _IConnectable_10015a05:
        '''The target service or database.'''
        result = self._values.get("target")
        assert result is not None, "Required property 'target' is missing"
        return typing.cast(_IConnectable_10015a05, result)

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC where the Lambda rotation function will run.'''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    @builtins.property
    def automatically_after(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation.

        :default: Duration.days(30)
        '''
        result = self._values.get("automatically_after")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def endpoint(self) -> typing.Optional[_IInterfaceVpcEndpoint_7481aea1]:
        '''The VPC interface endpoint to use for the Secrets Manager API.

        If you enable private DNS hostnames for your VPC private endpoint (the default), you don't
        need to specify an endpoint. The standard Secrets Manager DNS hostname the Secrets Manager
        CLI and SDKs use by default (https://secretsmanager..amazonaws.com) automatically
        resolves to your VPC endpoint.

        :default: https://secretsmanager..amazonaws.com
        '''
        result = self._values.get("endpoint")
        return typing.cast(typing.Optional[_IInterfaceVpcEndpoint_7481aea1], result)

    @builtins.property
    def exclude_characters(self) -> typing.Optional[builtins.str]:
        '''Characters which should not appear in the generated password.

        :default: - no additional characters are explicitly excluded
        '''
        result = self._values.get("exclude_characters")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def master_secret(self) -> typing.Optional[ISecret]:
        '''The master secret for a multi user rotation scheme.

        :default: - single user rotation scheme
        '''
        result = self._values.get("master_secret")
        return typing.cast(typing.Optional[ISecret], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''The security group for the Lambda rotation function.

        :default: - a new security group is created
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''The type of subnets in the VPC where the Lambda rotation function will run.

        :default: - the Vpc default strategy if not specified.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SecretRotationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretStringGenerator",
    jsii_struct_bases=[],
    name_mapping={
        "exclude_characters": "excludeCharacters",
        "exclude_lowercase": "excludeLowercase",
        "exclude_numbers": "excludeNumbers",
        "exclude_punctuation": "excludePunctuation",
        "exclude_uppercase": "excludeUppercase",
        "generate_string_key": "generateStringKey",
        "include_space": "includeSpace",
        "password_length": "passwordLength",
        "require_each_included_type": "requireEachIncludedType",
        "secret_string_template": "secretStringTemplate",
    },
)
class SecretStringGenerator:
    def __init__(
        self,
        *,
        exclude_characters: typing.Optional[builtins.str] = None,
        exclude_lowercase: typing.Optional[builtins.bool] = None,
        exclude_numbers: typing.Optional[builtins.bool] = None,
        exclude_punctuation: typing.Optional[builtins.bool] = None,
        exclude_uppercase: typing.Optional[builtins.bool] = None,
        generate_string_key: typing.Optional[builtins.str] = None,
        include_space: typing.Optional[builtins.bool] = None,
        password_length: typing.Optional[jsii.Number] = None,
        require_each_included_type: typing.Optional[builtins.bool] = None,
        secret_string_template: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Configuration to generate secrets such as passwords automatically.

        :param exclude_characters: A string that includes characters that shouldn't be included in the generated password. The string can be a minimum of ``0`` and a maximum of ``4096`` characters long. Default: no exclusions
        :param exclude_lowercase: Specifies that the generated password shouldn't include lowercase letters. Default: false
        :param exclude_numbers: Specifies that the generated password shouldn't include digits. Default: false
        :param exclude_punctuation: Specifies that the generated password shouldn't include punctuation characters. Default: false
        :param exclude_uppercase: Specifies that the generated password shouldn't include uppercase letters. Default: false
        :param generate_string_key: The JSON key name that's used to add the generated password to the JSON structure specified by the ``secretStringTemplate`` parameter. If you specify ``generateStringKey`` then ``secretStringTemplate`` must be also be specified.
        :param include_space: Specifies that the generated password can include the space character. Default: false
        :param password_length: The desired length of the generated password. Default: 32
        :param require_each_included_type: Specifies whether the generated password must include at least one of every allowed character type. Default: true
        :param secret_string_template: A properly structured JSON string that the generated password can be added to. The ``generateStringKey`` is combined with the generated random string and inserted into the JSON structure that's specified by this parameter. The merged JSON string is returned as the completed SecretString of the secret. If you specify ``secretStringTemplate`` then ``generateStringKey`` must be also be specified.

        :exampleMetadata: infused

        Example::

            # Default secret
            secret = secretsmanager.Secret(self, "Secret")
            # Using the default secret
            iam.User(self, "User",
                password=secret.secret_value
            )
            # Templated secret
            templated_secret = secretsmanager.Secret(self, "TemplatedSecret",
                generate_secret_string=secretsmanager.SecretStringGenerator(
                    secret_string_template=JSON.stringify({"username": "user"}),
                    generate_string_key="password"
                )
            )
            # Using the templated secret
            iam.User(self, "OtherUser",
                user_name=templated_secret.secret_value_from_json("username").to_string(),
                password=templated_secret.secret_value_from_json("password")
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if exclude_characters is not None:
            self._values["exclude_characters"] = exclude_characters
        if exclude_lowercase is not None:
            self._values["exclude_lowercase"] = exclude_lowercase
        if exclude_numbers is not None:
            self._values["exclude_numbers"] = exclude_numbers
        if exclude_punctuation is not None:
            self._values["exclude_punctuation"] = exclude_punctuation
        if exclude_uppercase is not None:
            self._values["exclude_uppercase"] = exclude_uppercase
        if generate_string_key is not None:
            self._values["generate_string_key"] = generate_string_key
        if include_space is not None:
            self._values["include_space"] = include_space
        if password_length is not None:
            self._values["password_length"] = password_length
        if require_each_included_type is not None:
            self._values["require_each_included_type"] = require_each_included_type
        if secret_string_template is not None:
            self._values["secret_string_template"] = secret_string_template

    @builtins.property
    def exclude_characters(self) -> typing.Optional[builtins.str]:
        '''A string that includes characters that shouldn't be included in the generated password.

        The string can be a minimum
        of ``0`` and a maximum of ``4096`` characters long.

        :default: no exclusions
        '''
        result = self._values.get("exclude_characters")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def exclude_lowercase(self) -> typing.Optional[builtins.bool]:
        '''Specifies that the generated password shouldn't include lowercase letters.

        :default: false
        '''
        result = self._values.get("exclude_lowercase")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def exclude_numbers(self) -> typing.Optional[builtins.bool]:
        '''Specifies that the generated password shouldn't include digits.

        :default: false
        '''
        result = self._values.get("exclude_numbers")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def exclude_punctuation(self) -> typing.Optional[builtins.bool]:
        '''Specifies that the generated password shouldn't include punctuation characters.

        :default: false
        '''
        result = self._values.get("exclude_punctuation")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def exclude_uppercase(self) -> typing.Optional[builtins.bool]:
        '''Specifies that the generated password shouldn't include uppercase letters.

        :default: false
        '''
        result = self._values.get("exclude_uppercase")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def generate_string_key(self) -> typing.Optional[builtins.str]:
        '''The JSON key name that's used to add the generated password to the JSON structure specified by the ``secretStringTemplate`` parameter.

        If you specify ``generateStringKey`` then ``secretStringTemplate``
        must be also be specified.
        '''
        result = self._values.get("generate_string_key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def include_space(self) -> typing.Optional[builtins.bool]:
        '''Specifies that the generated password can include the space character.

        :default: false
        '''
        result = self._values.get("include_space")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def password_length(self) -> typing.Optional[jsii.Number]:
        '''The desired length of the generated password.

        :default: 32
        '''
        result = self._values.get("password_length")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def require_each_included_type(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the generated password must include at least one of every allowed character type.

        :default: true
        '''
        result = self._values.get("require_each_included_type")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def secret_string_template(self) -> typing.Optional[builtins.str]:
        '''A properly structured JSON string that the generated password can be added to.

        The ``generateStringKey`` is
        combined with the generated random string and inserted into the JSON structure that's specified by this parameter.
        The merged JSON string is returned as the completed SecretString of the secret. If you specify ``secretStringTemplate``
        then ``generateStringKey`` must be also be specified.
        '''
        result = self._values.get("secret_string_template")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SecretStringGenerator(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class SecretStringValueBeta1(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretStringValueBeta1",
):
    '''An experimental class used to specify an initial secret value for a Secret.

    The class wraps a simple string (or JSON representation) in order to provide some safety checks and warnings
    about the dangers of using plaintext strings as initial secret seed values via CDK/CloudFormation.

    :exampleMetadata: infused

    Example::

        # Creates a new IAM user, access and secret keys, and stores the secret access key in a Secret.
        user = iam.User(self, "User")
        access_key = iam.AccessKey(self, "AccessKey", user=user)
        secret_value = secretsmanager.SecretStringValueBeta1.from_token(access_key.secret_access_key.to_string())
        secretsmanager.Secret(self, "Secret",
            secret_string_beta1=secret_value
        )
    '''

    @jsii.member(jsii_name="fromToken") # type: ignore[misc]
    @builtins.classmethod
    def from_token(
        cls,
        secret_value_from_token: builtins.str,
    ) -> "SecretStringValueBeta1":
        '''Creates a ``SecretValueValueBeta1`` from a string value coming from a Token.

        The intent is to enable creating secrets from references (e.g., ``Ref``, ``Fn::GetAtt``) from other resources.
        This might be the direct output of another Construct, or the output of a Custom Resource.
        This method throws if it determines the input is an unsafe plaintext string.

        For example::

           # Creates a new IAM user, access and secret keys, and stores the secret access key in a Secret.
           user = iam.User(self, "User")
           access_key = iam.AccessKey(self, "AccessKey", user=user)
           secret_value = secretsmanager.SecretStringValueBeta1.from_token(access_key.secret_access_key.to_string())
           secretsmanager.Secret(self, "Secret",
               secret_string_beta1=secret_value
           )

        The secret may also be embedded in a string representation of a JSON structure:
        const secretValue = secretsmanager.SecretStringValueBeta1.fromToken(JSON.stringify({
        username: user.userName,
        database: 'foo',
        password: accessKey.secretAccessKey.toString(),
        }));

        Note that the value being a Token does *not* guarantee safety. For example, a Lazy-evaluated string
        (e.g., ``Lazy.string({ produce: () => 'myInsecurePassword' }))``) is a Token, but as the output is
        ultimately a plaintext string, and so insecure.

        :param secret_value_from_token: a secret value coming from a Construct attribute or Custom Resource output.
        '''
        return typing.cast("SecretStringValueBeta1", jsii.sinvoke(cls, "fromToken", [secret_value_from_token]))

    @jsii.member(jsii_name="fromUnsafePlaintext") # type: ignore[misc]
    @builtins.classmethod
    def from_unsafe_plaintext(
        cls,
        secret_value: builtins.str,
    ) -> "SecretStringValueBeta1":
        '''Creates a ``SecretStringValueBeta1`` from a plaintext value.

        This approach is inherently unsafe, as the secret value may be visible in your source control repository
        and will also appear in plaintext in the resulting CloudFormation template, including in the AWS Console or APIs.
        Usage of this method is discouraged, especially for production workloads.

        :param secret_value: -
        '''
        return typing.cast("SecretStringValueBeta1", jsii.sinvoke(cls, "fromUnsafePlaintext", [secret_value]))

    @jsii.member(jsii_name="secretValue")
    def secret_value(self) -> builtins.str:
        '''Returns the secret value.'''
        return typing.cast(builtins.str, jsii.invoke(self, "secretValue", []))


@jsii.implements(ISecretTargetAttachment, ISecret)
class SecretTargetAttachment(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretTargetAttachment",
):
    '''An attached secret.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_secretsmanager as secretsmanager
        
        # secret: secretsmanager.Secret
        # secret_attachment_target: secretsmanager.ISecretAttachmentTarget
        
        secret_target_attachment = secretsmanager.SecretTargetAttachment(self, "MySecretTargetAttachment",
            secret=secret,
            target=secret_attachment_target
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        secret: ISecret,
        target: ISecretAttachmentTarget,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param secret: The secret to attach to the target.
        :param target: The target to attach the secret to.
        '''
        props = SecretTargetAttachmentProps(secret=secret, target=target)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromSecretTargetAttachmentSecretArn") # type: ignore[misc]
    @builtins.classmethod
    def from_secret_target_attachment_secret_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        secret_target_attachment_secret_arn: builtins.str,
    ) -> ISecretTargetAttachment:
        '''
        :param scope: -
        :param id: -
        :param secret_target_attachment_secret_arn: -
        '''
        return typing.cast(ISecretTargetAttachment, jsii.sinvoke(cls, "fromSecretTargetAttachmentSecretArn", [scope, id, secret_target_attachment_secret_arn]))

    @jsii.member(jsii_name="addRotationSchedule")
    def add_rotation_schedule(
        self,
        id: builtins.str,
        *,
        automatically_after: typing.Optional[_Duration_4839e8c3] = None,
        hosted_rotation: typing.Optional[HostedRotation] = None,
        rotation_lambda: typing.Optional[_IFunction_6adb0ab8] = None,
    ) -> RotationSchedule:
        '''Adds a rotation schedule to the secret.

        :param id: -
        :param automatically_after: Specifies the number of days after the previous rotation before Secrets Manager triggers the next automatic rotation. Default: Duration.days(30)
        :param hosted_rotation: Hosted rotation. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        :param rotation_lambda: A Lambda function that can rotate the secret. Default: - either ``rotationLambda`` or ``hostedRotation`` must be specified
        '''
        options = RotationScheduleOptions(
            automatically_after=automatically_after,
            hosted_rotation=hosted_rotation,
            rotation_lambda=rotation_lambda,
        )

        return typing.cast(RotationSchedule, jsii.invoke(self, "addRotationSchedule", [id, options]))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the IAM resource policy associated with this secret.

        If this secret was created in this stack, a resource policy will be
        automatically created upon the first call to ``addToResourcePolicy``. If
        the secret is imported, then this is a no-op.

        :param statement: -
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [statement]))

    @jsii.member(jsii_name="attach")
    def attach(self, target: ISecretAttachmentTarget) -> ISecret:
        '''Attach a target to this secret.

        :param target: The target to attach.

        :return: An attached secret
        '''
        return typing.cast(ISecret, jsii.invoke(self, "attach", [target]))

    @jsii.member(jsii_name="denyAccountRootDelete")
    def deny_account_root_delete(self) -> None:
        '''Denies the ``DeleteSecret`` action to all principals within the current account.'''
        return typing.cast(None, jsii.invoke(self, "denyAccountRootDelete", []))

    @jsii.member(jsii_name="grantRead")
    def grant_read(
        self,
        grantee: _IGrantable_71c4f5de,
        version_stages: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> _Grant_a7ae64f8:
        '''Grants reading the secret value to some role.

        :param grantee: -
        :param version_stages: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [grantee, version_stages]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grants writing and updating the secret value to some role.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [grantee]))

    @jsii.member(jsii_name="secretValueFromJson")
    def secret_value_from_json(self, json_field: builtins.str) -> _SecretValue_3dd0ddae:
        '''Interpret the secret as a JSON object and return a field's value from it as a ``SecretValue``.

        :param json_field: -
        '''
        return typing.cast(_SecretValue_3dd0ddae, jsii.invoke(self, "secretValueFromJson", [json_field]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="arnForPolicies")
    def _arn_for_policies(self) -> builtins.str:
        '''Provides an identifier for this secret for use in IAM policies.

        If there is a full ARN, this is just the ARN;
        if we have a partial ARN -- due to either importing by secret name or partial ARN --
        then we need to add a suffix to capture the full ARN's format.
        '''
        return typing.cast(builtins.str, jsii.get(self, "arnForPolicies"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreatePolicy")
    def _auto_create_policy(self) -> builtins.bool:
        return typing.cast(builtins.bool, jsii.get(self, "autoCreatePolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretArn")
    def secret_arn(self) -> builtins.str:
        '''The ARN of the secret in AWS Secrets Manager.

        Will return the full ARN if available, otherwise a partial arn.
        For secrets imported by the deprecated ``fromSecretName``, it will return the ``secretName``.
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretName")
    def secret_name(self) -> builtins.str:
        '''The name of the secret.

        For "owned" secrets, this will be the full resource name (secret name + suffix), unless the
        '@aws-cdk/aws-secretsmanager:parseOwnedSecretName' feature flag is set.
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretTargetAttachmentSecretArn")
    def secret_target_attachment_secret_arn(self) -> builtins.str:
        '''Same as ``secretArn``.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "secretTargetAttachmentSecretArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretValue")
    def secret_value(self) -> _SecretValue_3dd0ddae:
        '''Retrieve the value of the stored secret as a ``SecretValue``.'''
        return typing.cast(_SecretValue_3dd0ddae, jsii.get(self, "secretValue"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''The customer-managed encryption key that is used to encrypt this secret, if any.

        When not specified, the default
        KMS key for the account and region is being used.
        '''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionKey"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretFullArn")
    def secret_full_arn(self) -> typing.Optional[builtins.str]:
        '''The full ARN of the secret in AWS Secrets Manager, which is the ARN including the Secrets Manager-supplied 6-character suffix.

        This is equal to ``secretArn`` in most cases, but is undefined when a full ARN is not available (e.g., secrets imported by name).
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "secretFullArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.SecretTargetAttachmentProps",
    jsii_struct_bases=[AttachedSecretOptions],
    name_mapping={"target": "target", "secret": "secret"},
)
class SecretTargetAttachmentProps(AttachedSecretOptions):
    def __init__(self, *, target: ISecretAttachmentTarget, secret: ISecret) -> None:
        '''Construction properties for an AttachedSecret.

        :param target: The target to attach the secret to.
        :param secret: The secret to attach to the target.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            # secret: secretsmanager.Secret
            # secret_attachment_target: secretsmanager.ISecretAttachmentTarget
            
            secret_target_attachment_props = secretsmanager.SecretTargetAttachmentProps(
                secret=secret,
                target=secret_attachment_target
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target": target,
            "secret": secret,
        }

    @builtins.property
    def target(self) -> ISecretAttachmentTarget:
        '''The target to attach the secret to.'''
        result = self._values.get("target")
        assert result is not None, "Required property 'target' is missing"
        return typing.cast(ISecretAttachmentTarget, result)

    @builtins.property
    def secret(self) -> ISecret:
        '''The secret to attach to the target.'''
        result = self._values.get("secret")
        assert result is not None, "Required property 'secret' is missing"
        return typing.cast(ISecret, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SecretTargetAttachmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.SingleUserHostedRotationOptions",
    jsii_struct_bases=[],
    name_mapping={
        "function_name": "functionName",
        "security_groups": "securityGroups",
        "vpc": "vpc",
        "vpc_subnets": "vpcSubnets",
    },
)
class SingleUserHostedRotationOptions:
    def __init__(
        self,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''Single user hosted rotation options.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.

        :exampleMetadata: infused

        Example::

            # my_vpc: ec2.Vpc
            # db_connections: ec2.Connections
            # secret: secretsmanager.Secret
            
            
            my_hosted_rotation = secretsmanager.HostedRotation.mysql_single_user(vpc=my_vpc)
            secret.add_rotation_schedule("RotationSchedule", hosted_rotation=my_hosted_rotation)
            db_connections.allow_default_port_from(my_hosted_rotation)
        '''
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        self._values: typing.Dict[str, typing.Any] = {}
        if function_name is not None:
            self._values["function_name"] = function_name
        if security_groups is not None:
            self._values["security_groups"] = security_groups
        if vpc is not None:
            self._values["vpc"] = vpc
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets

    @builtins.property
    def function_name(self) -> typing.Optional[builtins.str]:
        '''A name for the Lambda created to rotate the secret.

        :default: - a CloudFormation generated name
        '''
        result = self._values.get("function_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def security_groups(self) -> typing.Optional[typing.List[_ISecurityGroup_acf8a799]]:
        '''A list of security groups for the Lambda created to rotate the secret.

        :default: - a new security group is created
        '''
        result = self._values.get("security_groups")
        return typing.cast(typing.Optional[typing.List[_ISecurityGroup_acf8a799]], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC where the Lambda rotation function will run.

        :default: - the Lambda is not deployed in a VPC
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''The type of subnets in the VPC where the Lambda rotation function will run.

        :default: - the Vpc default strategy if not specified.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SingleUserHostedRotationOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_secretsmanager.MultiUserHostedRotationOptions",
    jsii_struct_bases=[SingleUserHostedRotationOptions],
    name_mapping={
        "function_name": "functionName",
        "security_groups": "securityGroups",
        "vpc": "vpc",
        "vpc_subnets": "vpcSubnets",
        "master_secret": "masterSecret",
    },
)
class MultiUserHostedRotationOptions(SingleUserHostedRotationOptions):
    def __init__(
        self,
        *,
        function_name: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        master_secret: ISecret,
    ) -> None:
        '''Multi user hosted rotation options.

        :param function_name: A name for the Lambda created to rotate the secret. Default: - a CloudFormation generated name
        :param security_groups: A list of security groups for the Lambda created to rotate the secret. Default: - a new security group is created
        :param vpc: The VPC where the Lambda rotation function will run. Default: - the Lambda is not deployed in a VPC
        :param vpc_subnets: The type of subnets in the VPC where the Lambda rotation function will run. Default: - the Vpc default strategy if not specified.
        :param master_secret: The master secret for a multi user rotation scheme.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            # secret: secretsmanager.Secret
            # security_group: ec2.SecurityGroup
            # subnet: ec2.Subnet
            # subnet_filter: ec2.SubnetFilter
            # vpc: ec2.Vpc
            
            multi_user_hosted_rotation_options = secretsmanager.MultiUserHostedRotationOptions(
                master_secret=secret,
            
                # the properties below are optional
                function_name="functionName",
                security_groups=[security_group],
                vpc=vpc,
                vpc_subnets=ec2.SubnetSelection(
                    availability_zones=["availabilityZones"],
                    one_per_az=False,
                    subnet_filters=[subnet_filter],
                    subnet_group_name="subnetGroupName",
                    subnets=[subnet],
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
                )
            )
        '''
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        self._values: typing.Dict[str, typing.Any] = {
            "master_secret": master_secret,
        }
        if function_name is not None:
            self._values["function_name"] = function_name
        if security_groups is not None:
            self._values["security_groups"] = security_groups
        if vpc is not None:
            self._values["vpc"] = vpc
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets

    @builtins.property
    def function_name(self) -> typing.Optional[builtins.str]:
        '''A name for the Lambda created to rotate the secret.

        :default: - a CloudFormation generated name
        '''
        result = self._values.get("function_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def security_groups(self) -> typing.Optional[typing.List[_ISecurityGroup_acf8a799]]:
        '''A list of security groups for the Lambda created to rotate the secret.

        :default: - a new security group is created
        '''
        result = self._values.get("security_groups")
        return typing.cast(typing.Optional[typing.List[_ISecurityGroup_acf8a799]], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC where the Lambda rotation function will run.

        :default: - the Lambda is not deployed in a VPC
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''The type of subnets in the VPC where the Lambda rotation function will run.

        :default: - the Vpc default strategy if not specified.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def master_secret(self) -> ISecret:
        '''The master secret for a multi user rotation scheme.'''
        result = self._values.get("master_secret")
        assert result is not None, "Required property 'master_secret' is missing"
        return typing.cast(ISecret, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MultiUserHostedRotationOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "AttachedSecretOptions",
    "AttachmentTargetType",
    "CfnResourcePolicy",
    "CfnResourcePolicyProps",
    "CfnRotationSchedule",
    "CfnRotationScheduleProps",
    "CfnSecret",
    "CfnSecretProps",
    "CfnSecretTargetAttachment",
    "CfnSecretTargetAttachmentProps",
    "HostedRotation",
    "HostedRotationType",
    "ISecret",
    "ISecretAttachmentTarget",
    "ISecretTargetAttachment",
    "MultiUserHostedRotationOptions",
    "ReplicaRegion",
    "ResourcePolicy",
    "ResourcePolicyProps",
    "RotationSchedule",
    "RotationScheduleOptions",
    "RotationScheduleProps",
    "Secret",
    "SecretAttachmentTargetProps",
    "SecretAttributes",
    "SecretProps",
    "SecretRotation",
    "SecretRotationApplication",
    "SecretRotationApplicationOptions",
    "SecretRotationProps",
    "SecretStringGenerator",
    "SecretStringValueBeta1",
    "SecretTargetAttachment",
    "SecretTargetAttachmentProps",
    "SingleUserHostedRotationOptions",
]

publication.publish()
