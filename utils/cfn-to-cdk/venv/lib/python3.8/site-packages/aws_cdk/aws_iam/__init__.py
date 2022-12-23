'''
# AWS Identity and Access Management Construct Library

Define a role and add permissions to it. This will automatically create and
attach an IAM policy to the role:

```python
role = Role(self, "MyRole",
    assumed_by=ServicePrincipal("sns.amazonaws.com")
)

role.add_to_policy(PolicyStatement(
    resources=["*"],
    actions=["lambda:InvokeFunction"]
))
```

Define a policy and attach it to groups, users and roles. Note that it is possible to attach
the policy either by calling `xxx.attachInlinePolicy(policy)` or `policy.attachToXxx(xxx)`.

```python
user = User(self, "MyUser", password=SecretValue.plain_text("1234"))
group = Group(self, "MyGroup")

policy = Policy(self, "MyPolicy")
policy.attach_to_user(user)
group.attach_inline_policy(policy)
```

Managed policies can be attached using `xxx.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))`:

```python
group = Group(self, "MyGroup")
group.add_managed_policy(ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess"))
```

## Granting permissions to resources

Many of the AWS CDK resources have `grant*` methods that allow you to grant other resources access to that resource. As an example, the following code gives a Lambda function write permissions (Put, Update, Delete) to a DynamoDB table.

```python
# fn: lambda.Function
# table: dynamodb.Table


table.grant_write_data(fn)
```

The more generic `grant` method allows you to give specific permissions to a resource:

```python
# fn: lambda.Function
# table: dynamodb.Table


table.grant(fn, "dynamodb:PutItem")
```

The `grant*` methods accept an `IGrantable` object. This interface is implemented by IAM principlal resources (groups, users and roles) and resources that assume a role such as a Lambda function, EC2 instance or a Codebuild project.

You can find which `grant*` methods exist for a resource in the [AWS CDK API Reference](https://docs.aws.amazon.com/cdk/api/latest/docs/aws-construct-library.html).

## Roles

Many AWS resources require *Roles* to operate. These Roles define the AWS API
calls an instance or other AWS service is allowed to make.

Creating Roles and populating them with the right permissions *Statements* is
a necessary but tedious part of setting up AWS infrastructure. In order to
help you focus on your business logic, CDK will take care of creating
roles and populating them with least-privilege permissions automatically.

All constructs that require Roles will create one for you if don't specify
one at construction time. Permissions will be added to that role
automatically if you associate the construct with other constructs from the
AWS Construct Library (for example, if you tell an *AWS CodePipeline* to trigger
an *AWS Lambda Function*, the Pipeline's Role will automatically get
`lambda:InvokeFunction` permissions on that particular Lambda Function),
or if you explicitly grant permissions using `grant` functions (see the
previous section).

### Opting out of automatic permissions management

You may prefer to manage a Role's permissions yourself instead of having the
CDK automatically manage them for you. This may happen in one of the
following cases:

* You don't like the permissions that CDK automatically generates and
  want to substitute your own set.
* The least-permissions policy that the CDK generates is becoming too
  big for IAM to store, and you need to add some wildcards to keep the
  policy size down.

To prevent constructs from updating your Role's policy, pass the object
returned by `myRole.withoutPolicyUpdates()` instead of `myRole` itself.

For example, to have an AWS CodePipeline *not* automatically add the required
permissions to trigger the expected targets, do the following:

```python
role = iam.Role(self, "Role",
    assumed_by=iam.ServicePrincipal("codepipeline.amazonaws.com"),
    # custom description if desired
    description="This is a custom role..."
)

codepipeline.Pipeline(self, "Pipeline",
    # Give the Pipeline an immutable view of the Role
    role=role.without_policy_updates()
)

# You now have to manage the Role policies yourself
role.add_to_policy(iam.PolicyStatement(
    actions=[],
    resources=[]
))
```

### Using existing roles

If there are Roles in your account that have already been created which you
would like to use in your CDK application, you can use `Role.fromRoleArn` to
import them, as follows:

```python
role = iam.Role.from_role_arn(self, "Role", "arn:aws:iam::123456789012:role/MyExistingRole",
    # Set 'mutable' to 'false' to use the role as-is and prevent adding new
    # policies to it. The default is 'true', which means the role may be
    # modified as part of the deployment.
    mutable=False
)
```

## Configuring an ExternalId

If you need to create Roles that will be assumed by third parties, it is generally a good idea to [require an `ExternalId`
to assume them](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html).  Configuring
an `ExternalId` works like this:

```python
role = iam.Role(self, "MyRole",
    assumed_by=iam.AccountPrincipal("123456789012"),
    external_ids=["SUPPLY-ME"]
)
```

## Principals vs Identities

When we say *Principal*, we mean an entity you grant permissions to. This
entity can be an AWS Service, a Role, or something more abstract such as "all
users in this account" or even "all users in this organization". An
*Identity* is an IAM representing a single IAM entity that can have
a policy attached, one of `Role`, `User`, or `Group`.

## IAM Principals

When defining policy statements as part of an AssumeRole policy or as part of a
resource policy, statements would usually refer to a specific IAM principal
under `Principal`.

IAM principals are modeled as classes that derive from the `iam.PolicyPrincipal`
abstract class. Principal objects include principal type (string) and value
(array of string), optional set of conditions and the action that this principal
requires when it is used in an assume role policy document.

To add a principal to a policy statement you can either use the abstract
`statement.addPrincipal`, one of the concrete `addXxxPrincipal` methods:

* `addAwsPrincipal`, `addArnPrincipal` or `new ArnPrincipal(arn)` for `{ "AWS": arn }`
* `addAwsAccountPrincipal` or `new AccountPrincipal(accountId)` for `{ "AWS": account-arn }`
* `addServicePrincipal` or `new ServicePrincipal(service)` for `{ "Service": service }`
* `addAccountRootPrincipal` or `new AccountRootPrincipal()` for `{ "AWS": { "Ref: "AWS::AccountId" } }`
* `addCanonicalUserPrincipal` or `new CanonicalUserPrincipal(id)` for `{ "CanonicalUser": id }`
* `addFederatedPrincipal` or `new FederatedPrincipal(federated, conditions, assumeAction)` for
  `{ "Federated": arn }` and a set of optional conditions and the assume role action to use.
* `addAnyPrincipal` or `new AnyPrincipal` for `{ "AWS": "*" }`

If multiple principals are added to the policy statement, they will be merged together:

```python
statement = iam.PolicyStatement()
statement.add_service_principal("cloudwatch.amazonaws.com")
statement.add_service_principal("ec2.amazonaws.com")
statement.add_arn_principal("arn:aws:boom:boom")
```

Will result in:

```json
{
  "Principal": {
    "Service": [ "cloudwatch.amazonaws.com", "ec2.amazonaws.com" ],
    "AWS": "arn:aws:boom:boom"
  }
}
```

The `CompositePrincipal` class can also be used to define complex principals, for example:

```python
role = iam.Role(self, "MyRole",
    assumed_by=iam.CompositePrincipal(
        iam.ServicePrincipal("ec2.amazonaws.com"),
        iam.AccountPrincipal("1818188181818187272"))
)
```

The `PrincipalWithConditions` class can be used to add conditions to a
principal, especially those that don't take a `conditions` parameter in their
constructor. The `principal.withConditions()` method can be used to create a
`PrincipalWithConditions` from an existing principal, for example:

```python
principal = iam.AccountPrincipal("123456789000").with_conditions({"StringEquals": {"foo": "baz"}})
```

> NOTE: If you need to define an IAM condition that uses a token (such as a
> deploy-time attribute of another resource) in a JSON map key, use `CfnJson` to
> render this condition. See [this test](./test/integ.condition-with-ref.ts) for
> an example.

The `WebIdentityPrincipal` class can be used as a principal for web identities like
Cognito, Amazon, Google or Facebook, for example:

```python
principal = iam.WebIdentityPrincipal("cognito-identity.amazonaws.com", {
    "StringEquals": {"cognito-identity.amazonaws.com:aud": "us-east-2:12345678-abcd-abcd-abcd-123456"},
    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"}
})
```

If your identity provider is configured to assume a Role with [session
tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html), you
need to call `.withSessionTags()` to add the required permissions to the Role's
policy document:

```python
iam.Role(self, "Role",
    assumed_by=iam.WebIdentityPrincipal("cognito-identity.amazonaws.com", {
        "StringEquals": {
            "cognito-identity.amazonaws.com:aud": "us-east-2:12345678-abcd-abcd-abcd-123456"
        },
        "ForAnyValue:StringLike": {
            "cognito-identity.amazonaws.com:amr": "unauthenticated"
        }
    }).with_session_tags()
)
```

## Parsing JSON Policy Documents

The `PolicyDocument.fromJson` and `PolicyStatement.fromJson` static methods can be used to parse JSON objects. For example:

```python
policy_document = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "FirstStatement",
        "Effect": "Allow",
        "Action": ["iam:ChangePassword"],
        "Resource": "*"
    }, {
        "Sid": "SecondStatement",
        "Effect": "Allow",
        "Action": "s3:ListAllMyBuckets",
        "Resource": "*"
    }, {
        "Sid": "ThirdStatement",
        "Effect": "Allow",
        "Action": ["s3:List*", "s3:Get*"
        ],
        "Resource": ["arn:aws:s3:::confidential-data", "arn:aws:s3:::confidential-data/*"
        ],
        "Condition": {"Bool": {"aws:_multi_factor_auth_present": "true"}}
    }
    ]
}

custom_policy_document = iam.PolicyDocument.from_json(policy_document)

# You can pass this document as an initial document to a ManagedPolicy
# or inline Policy.
new_managed_policy = iam.ManagedPolicy(self, "MyNewManagedPolicy",
    document=custom_policy_document
)
new_policy = iam.Policy(self, "MyNewPolicy",
    document=custom_policy_document
)
```

## Permissions Boundaries

[Permissions
Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
can be used as a mechanism to prevent privilege esclation by creating new
`Role`s. Permissions Boundaries are a Managed Policy, attached to Roles or
Users, that represent the *maximum* set of permissions they can have. The
effective set of permissions of a Role (or User) will be the intersection of
the Identity Policy and the Permissions Boundary attached to the Role (or
User). Permissions Boundaries are typically created by account
Administrators, and their use on newly created `Role`s will be enforced by
IAM policies.

It is possible to attach Permissions Boundaries to all Roles created in a construct
tree all at once:

```python
# Directly apply the boundary to a Role you create
# role: iam.Role

# Apply the boundary to an Role that was implicitly created for you
# fn: lambda.Function

# Remove a Permissions Boundary that is inherited, for example from the Stack level
# custom_resource: CustomResource
# This imports an existing policy.
boundary = iam.ManagedPolicy.from_managed_policy_arn(self, "Boundary", "arn:aws:iam::123456789012:policy/boundary")

# This creates a new boundary
boundary2 = iam.ManagedPolicy(self, "Boundary2",
    statements=[
        iam.PolicyStatement(
            effect=iam.Effect.DENY,
            actions=["iam:*"],
            resources=["*"]
        )
    ]
)
iam.PermissionsBoundary.of(role).apply(boundary)
iam.PermissionsBoundary.of(fn).apply(boundary)

# Apply the boundary to all Roles in a stack
iam.PermissionsBoundary.of(self).apply(boundary)
iam.PermissionsBoundary.of(custom_resource).clear()
```

## OpenID Connect Providers

OIDC identity providers are entities in IAM that describe an external identity
provider (IdP) service that supports the [OpenID Connect](http://openid.net/connect) (OIDC) standard, such
as Google or Salesforce. You use an IAM OIDC identity provider when you want to
establish trust between an OIDC-compatible IdP and your AWS account. This is
useful when creating a mobile app or web application that requires access to AWS
resources, but you don't want to create custom sign-in code or manage your own
user identities. For more information about this scenario, see [About Web
Identity Federation] and the relevant documentation in the [Amazon Cognito
Identity Pools Developer Guide].

The following examples defines an OpenID Connect provider. Two client IDs
(audiences) are will be able to send authentication requests to
[https://openid/connect](https://openid/connect).

```python
provider = iam.OpenIdConnectProvider(self, "MyProvider",
    url="https://openid/connect",
    client_ids=["myclient1", "myclient2"]
)
```

You can specify an optional list of `thumbprints`. If not specified, the
thumbprint of the root certificate authority (CA) will automatically be obtained
from the host as described
[here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html).

Once you define an OpenID connect provider, you can use it with AWS services
that expect an IAM OIDC provider. For example, when you define an [Amazon
Cognito identity
pool](https://docs.aws.amazon.com/cognito/latest/developerguide/open-id.html)
you can reference the provider's ARN as follows:

```python
import aws_cdk.aws_cognito as cognito

# my_provider: iam.OpenIdConnectProvider

cognito.CfnIdentityPool(self, "IdentityPool",
    open_id_connect_provider_arns=[my_provider.open_id_connect_provider_arn],
    # And the other properties for your identity pool
    allow_unauthenticated_identities=False
)
```

The `OpenIdConnectPrincipal` class can be used as a principal used with a `OpenIdConnectProvider`, for example:

```python
provider = iam.OpenIdConnectProvider(self, "MyProvider",
    url="https://openid/connect",
    client_ids=["myclient1", "myclient2"]
)
principal = iam.OpenIdConnectPrincipal(provider)
```

## SAML provider

An IAM SAML 2.0 identity provider is an entity in IAM that describes an external
identity provider (IdP) service that supports the SAML 2.0 (Security Assertion
Markup Language 2.0) standard. You use an IAM identity provider when you want
to establish trust between a SAML-compatible IdP such as Shibboleth or Active
Directory Federation Services and AWS, so that users in your organization can
access AWS resources. IAM SAML identity providers are used as principals in an
IAM trust policy.

```python
iam.SamlProvider(self, "Provider",
    metadata_document=iam.SamlMetadataDocument.from_file("/path/to/saml-metadata-document.xml")
)
```

The `SamlPrincipal` class can be used as a principal with a `SamlProvider`:

```python
provider = iam.SamlProvider(self, "Provider",
    metadata_document=iam.SamlMetadataDocument.from_file("/path/to/saml-metadata-document.xml")
)
principal = iam.SamlPrincipal(provider, {
    "StringEquals": {
        "SAML:iss": "issuer"
    }
})
```

When creating a role for programmatic and AWS Management Console access, use the `SamlConsolePrincipal`
class:

```python
provider = iam.SamlProvider(self, "Provider",
    metadata_document=iam.SamlMetadataDocument.from_file("/path/to/saml-metadata-document.xml")
)
iam.Role(self, "Role",
    assumed_by=iam.SamlConsolePrincipal(provider)
)
```

## Users

IAM manages users for your AWS account. To create a new user:

```python
user = iam.User(self, "MyUser")
```

To import an existing user by name [with path](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-friendly-names):

```python
user = iam.User.from_user_name(self, "MyImportedUserByName", "johnsmith")
```

To import an existing user by ARN:

```python
user = iam.User.from_user_arn(self, "MyImportedUserByArn", "arn:aws:iam::123456789012:user/johnsmith")
```

To import an existing user by attributes:

```python
user = iam.User.from_user_attributes(self, "MyImportedUserByAttributes",
    user_arn="arn:aws:iam::123456789012:user/johnsmith"
)
```

### Access Keys

The ability for a user to make API calls via the CLI or an SDK is enabled by the user having an
access key pair. To create an access key:

```python
user = iam.User(self, "MyUser")
access_key = iam.AccessKey(self, "MyAccessKey", user=user)
```

You can force CloudFormation to rotate the access key by providing a monotonically increasing `serial`
property. Simply provide a higher serial value than any number used previously:

```python
user = iam.User(self, "MyUser")
access_key = iam.AccessKey(self, "MyAccessKey", user=user, serial=1)
```

An access key may only be associated with a single user and cannot be "moved" between users. Changing
the user associated with an access key replaces the access key (and its ID and secret value).

## Groups

An IAM user group is a collection of IAM users. User groups let you specify permissions for multiple users.

```python
group = iam.Group(self, "MyGroup")
```

To import an existing group by ARN:

```python
group = iam.Group.from_group_arn(self, "MyImportedGroupByArn", "arn:aws:iam::account-id:group/group-name")
```

To import an existing group by name [with path](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-friendly-names):

```python
group = iam.Group.from_group_name(self, "MyImportedGroupByName", "group-name")
```

To add a user to a group (both for a new and imported user/group):

```python
user = iam.User(self, "MyUser") # or User.fromUserName(stack, 'User', 'johnsmith');
group = iam.Group(self, "MyGroup") # or Group.fromGroupArn(stack, 'Group', 'arn:aws:iam::account-id:group/group-name');

user.add_to_group(group)
# or
group.add_user(user)
```

## Features

* Policy name uniqueness is enforced. If two policies by the same name are attached to the same
  principal, the attachment will fail.
* Policy names are not required - the CDK logical ID will be used and ensured to be unique.
* Policies are validated during synthesis to ensure that they have actions, and that policies
  attached to IAM principals specify relevant resources, while policies attached to resources
  specify which IAM principals they apply to.
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
    IResolveContext as _IResolveContext_b2df1921,
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    SecretValue as _SecretValue_3dd0ddae,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.AccessKeyProps",
    jsii_struct_bases=[],
    name_mapping={"user": "user", "serial": "serial", "status": "status"},
)
class AccessKeyProps:
    def __init__(
        self,
        *,
        user: "IUser",
        serial: typing.Optional[jsii.Number] = None,
        status: typing.Optional["AccessKeyStatus"] = None,
    ) -> None:
        '''Properties for defining an IAM access key.

        :param user: The IAM user this key will belong to. Changing this value will result in the access key being deleted and a new access key (with a different ID and secret value) being assigned to the new user.
        :param serial: A CloudFormation-specific value that signifies the access key should be replaced/rotated. This value can only be incremented. Incrementing this value will cause CloudFormation to replace the Access Key resource. Default: - No serial value
        :param status: The status of the access key. An Active access key is allowed to be used to make API calls; An Inactive key cannot. Default: - The access key is active

        :exampleMetadata: infused

        Example::

            user = iam.User(self, "MyUser")
            access_key = iam.AccessKey(self, "MyAccessKey", user=user, serial=1)
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "user": user,
        }
        if serial is not None:
            self._values["serial"] = serial
        if status is not None:
            self._values["status"] = status

    @builtins.property
    def user(self) -> "IUser":
        '''The IAM user this key will belong to.

        Changing this value will result in the access key being deleted and a new
        access key (with a different ID and secret value) being assigned to the new
        user.
        '''
        result = self._values.get("user")
        assert result is not None, "Required property 'user' is missing"
        return typing.cast("IUser", result)

    @builtins.property
    def serial(self) -> typing.Optional[jsii.Number]:
        '''A CloudFormation-specific value that signifies the access key should be replaced/rotated.

        This value can only be incremented. Incrementing this
        value will cause CloudFormation to replace the Access Key resource.

        :default: - No serial value
        '''
        result = self._values.get("serial")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def status(self) -> typing.Optional["AccessKeyStatus"]:
        '''The status of the access key.

        An Active access key is allowed to be used
        to make API calls; An Inactive key cannot.

        :default: - The access key is active
        '''
        result = self._values.get("status")
        return typing.cast(typing.Optional["AccessKeyStatus"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AccessKeyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_iam.AccessKeyStatus")
class AccessKeyStatus(enum.Enum):
    '''Valid statuses for an IAM Access Key.'''

    ACTIVE = "ACTIVE"
    '''An active access key.

    An active key can be used to make API calls.
    '''
    INACTIVE = "INACTIVE"
    '''An inactive access key.

    An inactive key cannot be used to make API calls.
    '''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.AddToPrincipalPolicyResult",
    jsii_struct_bases=[],
    name_mapping={
        "statement_added": "statementAdded",
        "policy_dependable": "policyDependable",
    },
)
class AddToPrincipalPolicyResult:
    def __init__(
        self,
        *,
        statement_added: builtins.bool,
        policy_dependable: typing.Optional[constructs.IDependable] = None,
    ) -> None:
        '''Result of calling ``addToPrincipalPolicy``.

        :param statement_added: Whether the statement was added to the identity's policies.
        :param policy_dependable: Dependable which allows depending on the policy change being applied. Default: - Required if ``statementAdded`` is true.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            import constructs as constructs
            
            # dependable: constructs.IDependable
            
            add_to_principal_policy_result = iam.AddToPrincipalPolicyResult(
                statement_added=False,
            
                # the properties below are optional
                policy_dependable=dependable
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "statement_added": statement_added,
        }
        if policy_dependable is not None:
            self._values["policy_dependable"] = policy_dependable

    @builtins.property
    def statement_added(self) -> builtins.bool:
        '''Whether the statement was added to the identity's policies.'''
        result = self._values.get("statement_added")
        assert result is not None, "Required property 'statement_added' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def policy_dependable(self) -> typing.Optional[constructs.IDependable]:
        '''Dependable which allows depending on the policy change being applied.

        :default: - Required if ``statementAdded`` is true.
        '''
        result = self._values.get("policy_dependable")
        return typing.cast(typing.Optional[constructs.IDependable], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddToPrincipalPolicyResult(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.AddToResourcePolicyResult",
    jsii_struct_bases=[],
    name_mapping={
        "statement_added": "statementAdded",
        "policy_dependable": "policyDependable",
    },
)
class AddToResourcePolicyResult:
    def __init__(
        self,
        *,
        statement_added: builtins.bool,
        policy_dependable: typing.Optional[constructs.IDependable] = None,
    ) -> None:
        '''Result of calling addToResourcePolicy.

        :param statement_added: Whether the statement was added.
        :param policy_dependable: Dependable which allows depending on the policy change being applied. Default: - If ``statementAdded`` is true, the resource object itself. Otherwise, no dependable.

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            bucket = s3.Bucket.from_bucket_name(self, "existingBucket", "bucket-name")
            
            # No policy statement will be added to the resource
            result = bucket.add_to_resource_policy(iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[bucket.arn_for_objects("file.txt")],
                principals=[iam.AccountRootPrincipal()]
            ))
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "statement_added": statement_added,
        }
        if policy_dependable is not None:
            self._values["policy_dependable"] = policy_dependable

    @builtins.property
    def statement_added(self) -> builtins.bool:
        '''Whether the statement was added.'''
        result = self._values.get("statement_added")
        assert result is not None, "Required property 'statement_added' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def policy_dependable(self) -> typing.Optional[constructs.IDependable]:
        '''Dependable which allows depending on the policy change being applied.

        :default:

        - If ``statementAdded`` is true, the resource object itself.
        Otherwise, no dependable.
        '''
        result = self._values.get("policy_dependable")
        return typing.cast(typing.Optional[constructs.IDependable], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddToResourcePolicyResult(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnAccessKey(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnAccessKey",
):
    '''A CloudFormation ``AWS::IAM::AccessKey``.

    Creates a new AWS secret access key and corresponding AWS access key ID for the specified user. The default status for new keys is ``Active`` .

    If you do not specify a user name, IAM determines the user name implicitly based on the AWS access key ID signing the request. This operation works for access keys under the AWS account . Consequently, you can use this operation to manage AWS account root user credentials. This is true even if the AWS account has no associated users.

    For information about quotas on the number of keys you can create, see `IAM and AWS STS quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>`_ in the *IAM User Guide* .
    .. epigraph::

       To ensure the security of your AWS account , the secret access key is accessible only during key and user creation. You must save the key (for example, in a text file) if you want to be able to access it again. If a secret key is lost, you can delete the access keys for the associated user and then create new keys.

    :cloudformationResource: AWS::IAM::AccessKey
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        cfn_access_key = iam.CfnAccessKey(self, "MyCfnAccessKey",
            user_name="userName",
        
            # the properties below are optional
            serial=123,
            status="status"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user_name: builtins.str,
        serial: typing.Optional[jsii.Number] = None,
        status: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::AccessKey``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param user_name: The name of the IAM user that the new key will belong to. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param serial: This value is specific to CloudFormation and can only be *incremented* . Incrementing this value notifies CloudFormation that you want to rotate your access key. When you update your stack, CloudFormation will replace the existing access key with a new key.
        :param status: The status of the access key. ``Active`` means that the key is valid for API calls, while ``Inactive`` means it is not.
        '''
        props = CfnAccessKeyProps(user_name=user_name, serial=serial, status=status)

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
    @jsii.member(jsii_name="attrSecretAccessKey")
    def attr_secret_access_key(self) -> builtins.str:
        '''Returns the secret access key for the specified AWS::IAM::AccessKey resource.

        For example: wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY.

        :cloudformationAttribute: SecretAccessKey
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSecretAccessKey"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> builtins.str:
        '''The name of the IAM user that the new key will belong to.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html#cfn-iam-accesskey-username
        '''
        return typing.cast(builtins.str, jsii.get(self, "userName"))

    @user_name.setter
    def user_name(self, value: builtins.str) -> None:
        jsii.set(self, "userName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serial")
    def serial(self) -> typing.Optional[jsii.Number]:
        '''This value is specific to CloudFormation and can only be *incremented* .

        Incrementing this value notifies CloudFormation that you want to rotate your access key. When you update your stack, CloudFormation will replace the existing access key with a new key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html#cfn-iam-accesskey-serial
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "serial"))

    @serial.setter
    def serial(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "serial", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="status")
    def status(self) -> typing.Optional[builtins.str]:
        '''The status of the access key.

        ``Active`` means that the key is valid for API calls, while ``Inactive`` means it is not.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html#cfn-iam-accesskey-status
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "status"))

    @status.setter
    def status(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "status", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnAccessKeyProps",
    jsii_struct_bases=[],
    name_mapping={"user_name": "userName", "serial": "serial", "status": "status"},
)
class CfnAccessKeyProps:
    def __init__(
        self,
        *,
        user_name: builtins.str,
        serial: typing.Optional[jsii.Number] = None,
        status: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnAccessKey``.

        :param user_name: The name of the IAM user that the new key will belong to. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param serial: This value is specific to CloudFormation and can only be *incremented* . Incrementing this value notifies CloudFormation that you want to rotate your access key. When you update your stack, CloudFormation will replace the existing access key with a new key.
        :param status: The status of the access key. ``Active`` means that the key is valid for API calls, while ``Inactive`` means it is not.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            cfn_access_key_props = iam.CfnAccessKeyProps(
                user_name="userName",
            
                # the properties below are optional
                serial=123,
                status="status"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "user_name": user_name,
        }
        if serial is not None:
            self._values["serial"] = serial
        if status is not None:
            self._values["status"] = status

    @builtins.property
    def user_name(self) -> builtins.str:
        '''The name of the IAM user that the new key will belong to.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html#cfn-iam-accesskey-username
        '''
        result = self._values.get("user_name")
        assert result is not None, "Required property 'user_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def serial(self) -> typing.Optional[jsii.Number]:
        '''This value is specific to CloudFormation and can only be *incremented* .

        Incrementing this value notifies CloudFormation that you want to rotate your access key. When you update your stack, CloudFormation will replace the existing access key with a new key.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html#cfn-iam-accesskey-serial
        '''
        result = self._values.get("serial")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def status(self) -> typing.Optional[builtins.str]:
        '''The status of the access key.

        ``Active`` means that the key is valid for API calls, while ``Inactive`` means it is not.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html#cfn-iam-accesskey-status
        '''
        result = self._values.get("status")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAccessKeyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnGroup",
):
    '''A CloudFormation ``AWS::IAM::Group``.

    Creates a new group.

    For information about the number of groups you can create, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .

    :cloudformationResource: AWS::IAM::Group
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # policy_document: Any
        
        cfn_group = iam.CfnGroup(self, "MyCfnGroup",
            group_name="groupName",
            managed_policy_arns=["managedPolicyArns"],
            path="path",
            policies=[iam.CfnGroup.PolicyProperty(
                policy_document=policy_document,
                policy_name="policyName"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        group_name: typing.Optional[builtins.str] = None,
        managed_policy_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        path: typing.Optional[builtins.str] = None,
        policies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnGroup.PolicyProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::Group``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param group_name: The name of the group to create. Do not include the path in this value. The group name must be unique within the account. Group names are not distinguished by case. For example, you cannot create groups named both "ADMINS" and "admins". If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the group name. .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ . .. epigraph:: Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .
        :param managed_policy_arns: The Amazon Resource Name (ARN) of the IAM policy you want to attach. For more information about ARNs, see `Amazon Resource Names (ARNs) <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .
        :param path: The path to the group. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        :param policies: Adds or updates an inline policy document that is embedded in the specified IAM group. To view AWS::IAM::Group snippets, see `Declaring an IAM Group Resource <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-group>`_ . .. epigraph:: The name of each inline policy for a role, user, or group must be unique. If you don't choose unique names, updates to the IAM identity will fail. For information about limits on the number of inline policies that you can embed in a group, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .
        '''
        props = CfnGroupProps(
            group_name=group_name,
            managed_policy_arns=managed_policy_arns,
            path=path,
            policies=policies,
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
        '''Returns the Amazon Resource Name (ARN) for the specified ``AWS::IAM::Group`` resource.

        For example: ``arn:aws:iam::123456789012:group/mystack-mygroup-1DZETITOWEKVO`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groupName")
    def group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the group to create. Do not include the path in this value.

        The group name must be unique within the account. Group names are not distinguished by case. For example, you cannot create groups named both "ADMINS" and "admins". If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the group name.
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ .
        .. epigraph::

           Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html#cfn-iam-group-groupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "groupName"))

    @group_name.setter
    def group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "groupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedPolicyArns")
    def managed_policy_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The Amazon Resource Name (ARN) of the IAM policy you want to attach.

        For more information about ARNs, see `Amazon Resource Names (ARNs) <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html#cfn-iam-group-managepolicyarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "managedPolicyArns"))

    @managed_policy_arns.setter
    def managed_policy_arns(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "managedPolicyArns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> typing.Optional[builtins.str]:
        '''The path to the group. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html#cfn-iam-group-path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "path"))

    @path.setter
    def path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policies")
    def policies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGroup.PolicyProperty", _IResolvable_da3f097b]]]]:
        '''Adds or updates an inline policy document that is embedded in the specified IAM group.

        To view AWS::IAM::Group snippets, see `Declaring an IAM Group Resource <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-group>`_ .
        .. epigraph::

           The name of each inline policy for a role, user, or group must be unique. If you don't choose unique names, updates to the IAM identity will fail.

        For information about limits on the number of inline policies that you can embed in a group, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html#cfn-iam-group-policies
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGroup.PolicyProperty", _IResolvable_da3f097b]]]], jsii.get(self, "policies"))

    @policies.setter
    def policies(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnGroup.PolicyProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "policies", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iam.CfnGroup.PolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "policy_document": "policyDocument",
            "policy_name": "policyName",
        },
    )
    class PolicyProperty:
        def __init__(
            self,
            *,
            policy_document: typing.Any,
            policy_name: builtins.str,
        ) -> None:
            '''Contains information about an attached policy.

            An attached policy is a managed policy that has been attached to a user, group, or role.

            For more information about managed policies, see `Managed Policies and Inline Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* .

            :param policy_document: The policy document.
            :param policy_name: The friendly name (not ARN) identifying the policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iam as iam
                
                # policy_document: Any
                
                policy_property = iam.CfnGroup.PolicyProperty(
                    policy_document=policy_document,
                    policy_name="policyName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "policy_document": policy_document,
                "policy_name": policy_name,
            }

        @builtins.property
        def policy_document(self) -> typing.Any:
            '''The policy document.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html#cfn-iam-policies-policydocument
            '''
            result = self._values.get("policy_document")
            assert result is not None, "Required property 'policy_document' is missing"
            return typing.cast(typing.Any, result)

        @builtins.property
        def policy_name(self) -> builtins.str:
            '''The friendly name (not ARN) identifying the policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html#cfn-iam-policies-policyname
            '''
            result = self._values.get("policy_name")
            assert result is not None, "Required property 'policy_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "group_name": "groupName",
        "managed_policy_arns": "managedPolicyArns",
        "path": "path",
        "policies": "policies",
    },
)
class CfnGroupProps:
    def __init__(
        self,
        *,
        group_name: typing.Optional[builtins.str] = None,
        managed_policy_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        path: typing.Optional[builtins.str] = None,
        policies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnGroup.PolicyProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnGroup``.

        :param group_name: The name of the group to create. Do not include the path in this value. The group name must be unique within the account. Group names are not distinguished by case. For example, you cannot create groups named both "ADMINS" and "admins". If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the group name. .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ . .. epigraph:: Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .
        :param managed_policy_arns: The Amazon Resource Name (ARN) of the IAM policy you want to attach. For more information about ARNs, see `Amazon Resource Names (ARNs) <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .
        :param path: The path to the group. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        :param policies: Adds or updates an inline policy document that is embedded in the specified IAM group. To view AWS::IAM::Group snippets, see `Declaring an IAM Group Resource <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-group>`_ . .. epigraph:: The name of each inline policy for a role, user, or group must be unique. If you don't choose unique names, updates to the IAM identity will fail. For information about limits on the number of inline policies that you can embed in a group, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # policy_document: Any
            
            cfn_group_props = iam.CfnGroupProps(
                group_name="groupName",
                managed_policy_arns=["managedPolicyArns"],
                path="path",
                policies=[iam.CfnGroup.PolicyProperty(
                    policy_document=policy_document,
                    policy_name="policyName"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if group_name is not None:
            self._values["group_name"] = group_name
        if managed_policy_arns is not None:
            self._values["managed_policy_arns"] = managed_policy_arns
        if path is not None:
            self._values["path"] = path
        if policies is not None:
            self._values["policies"] = policies

    @builtins.property
    def group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the group to create. Do not include the path in this value.

        The group name must be unique within the account. Group names are not distinguished by case. For example, you cannot create groups named both "ADMINS" and "admins". If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the group name.
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ .
        .. epigraph::

           Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html#cfn-iam-group-groupname
        '''
        result = self._values.get("group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def managed_policy_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The Amazon Resource Name (ARN) of the IAM policy you want to attach.

        For more information about ARNs, see `Amazon Resource Names (ARNs) <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html#cfn-iam-group-managepolicyarns
        '''
        result = self._values.get("managed_policy_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path to the group. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html#cfn-iam-group-path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def policies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnGroup.PolicyProperty, _IResolvable_da3f097b]]]]:
        '''Adds or updates an inline policy document that is embedded in the specified IAM group.

        To view AWS::IAM::Group snippets, see `Declaring an IAM Group Resource <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-group>`_ .
        .. epigraph::

           The name of each inline policy for a role, user, or group must be unique. If you don't choose unique names, updates to the IAM identity will fail.

        For information about limits on the number of inline policies that you can embed in a group, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html#cfn-iam-group-policies
        '''
        result = self._values.get("policies")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnGroup.PolicyProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnInstanceProfile(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnInstanceProfile",
):
    '''A CloudFormation ``AWS::IAM::InstanceProfile``.

    Creates a new instance profile. For information about instance profiles, see `Using instance profiles <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html>`_ .

    For information about the number of instance profiles you can create, see `IAM object quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>`_ in the *IAM User Guide* .

    :cloudformationResource: AWS::IAM::InstanceProfile
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        cfn_instance_profile = iam.CfnInstanceProfile(self, "MyCfnInstanceProfile",
            roles=["roles"],
        
            # the properties below are optional
            instance_profile_name="instanceProfileName",
            path="path"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        roles: typing.Sequence[builtins.str],
        instance_profile_name: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::InstanceProfile``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param roles: The name of the role to associate with the instance profile. Only one role can be assigned to an EC2 instance at a time, and all applications on the instance share the same role and permissions.
        :param instance_profile_name: The name of the instance profile to create. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param path: The path to the instance profile. For more information about paths, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        '''
        props = CfnInstanceProfileProps(
            roles=roles, instance_profile_name=instance_profile_name, path=path
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
        '''Returns the Amazon Resource Name (ARN) for the instance profile. For example:.

        ``{"Fn::GetAtt" : ["MyProfile", "Arn"] }``

        This returns a value such as ``arn:aws:iam::1234567890:instance-profile/MyProfile-ASDNSDLKJ`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roles")
    def roles(self) -> typing.List[builtins.str]:
        '''The name of the role to associate with the instance profile.

        Only one role can be assigned to an EC2 instance at a time, and all applications on the instance share the same role and permissions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html#cfn-iam-instanceprofile-roles
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "roles"))

    @roles.setter
    def roles(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "roles", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceProfileName")
    def instance_profile_name(self) -> typing.Optional[builtins.str]:
        '''The name of the instance profile to create.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html#cfn-iam-instanceprofile-instanceprofilename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "instanceProfileName"))

    @instance_profile_name.setter
    def instance_profile_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "instanceProfileName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> typing.Optional[builtins.str]:
        '''The path to the instance profile.

        For more information about paths, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html#cfn-iam-instanceprofile-path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "path"))

    @path.setter
    def path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "path", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnInstanceProfileProps",
    jsii_struct_bases=[],
    name_mapping={
        "roles": "roles",
        "instance_profile_name": "instanceProfileName",
        "path": "path",
    },
)
class CfnInstanceProfileProps:
    def __init__(
        self,
        *,
        roles: typing.Sequence[builtins.str],
        instance_profile_name: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnInstanceProfile``.

        :param roles: The name of the role to associate with the instance profile. Only one role can be assigned to an EC2 instance at a time, and all applications on the instance share the same role and permissions.
        :param instance_profile_name: The name of the instance profile to create. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param path: The path to the instance profile. For more information about paths, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            cfn_instance_profile_props = iam.CfnInstanceProfileProps(
                roles=["roles"],
            
                # the properties below are optional
                instance_profile_name="instanceProfileName",
                path="path"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "roles": roles,
        }
        if instance_profile_name is not None:
            self._values["instance_profile_name"] = instance_profile_name
        if path is not None:
            self._values["path"] = path

    @builtins.property
    def roles(self) -> typing.List[builtins.str]:
        '''The name of the role to associate with the instance profile.

        Only one role can be assigned to an EC2 instance at a time, and all applications on the instance share the same role and permissions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html#cfn-iam-instanceprofile-roles
        '''
        result = self._values.get("roles")
        assert result is not None, "Required property 'roles' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def instance_profile_name(self) -> typing.Optional[builtins.str]:
        '''The name of the instance profile to create.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html#cfn-iam-instanceprofile-instanceprofilename
        '''
        result = self._values.get("instance_profile_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path to the instance profile.

        For more information about paths, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html#cfn-iam-instanceprofile-path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnInstanceProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnManagedPolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnManagedPolicy",
):
    '''A CloudFormation ``AWS::IAM::ManagedPolicy``.

    Creates a new managed policy for your AWS account .

    This operation creates a policy version with a version identifier of ``v1`` and sets v1 as the policy's default version. For more information about policy versions, see `Versioning for managed policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-versions.html>`_ in the *IAM User Guide* .

    As a best practice, you can validate your IAM policies. To learn more, see `Validating IAM policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_policy-validator.html>`_ in the *IAM User Guide* .

    For more information about managed policies in general, see `Managed policies and inline policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* .

    :cloudformationResource: AWS::IAM::ManagedPolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # policy_document: Any
        
        cfn_managed_policy = iam.CfnManagedPolicy(self, "MyCfnManagedPolicy",
            policy_document=policy_document,
        
            # the properties below are optional
            description="description",
            groups=["groups"],
            managed_policy_name="managedPolicyName",
            path="path",
            roles=["roles"],
            users=["users"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        policy_document: typing.Any,
        description: typing.Optional[builtins.str] = None,
        groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        managed_policy_name: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        roles: typing.Optional[typing.Sequence[builtins.str]] = None,
        users: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::ManagedPolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param policy_document: The JSON policy document that you want to use as the content for the new policy. You must provide policies in JSON format in IAM. However, for AWS CloudFormation templates formatted in YAML, you can provide the policy in JSON or YAML format. AWS CloudFormation always converts a YAML policy to JSON format before submitting it to IAM. The maximum length of the policy document that you can pass in this operation, including whitespace, is listed below. To view the maximum character counts of a managed policy with no whitespaces, see `IAM and AWS STS character quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-entity-length>`_ . To learn more about JSON policy grammar, see `Grammar of the IAM JSON policy language <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html>`_ in the *IAM User Guide* . The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following: - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` ) - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )
        :param description: A friendly description of the policy. Typically used to store information about the permissions defined in the policy. For example, "Grants access to production DynamoDB tables." The policy description is immutable. After a value is assigned, it cannot be changed.
        :param groups: The name (friendly name, not ARN) of the group to attach the policy to. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param managed_policy_name: The friendly name of the policy. .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ . .. epigraph:: Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .
        :param path: The path for the policy. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters. .. epigraph:: You cannot use an asterisk (*) in the path name.
        :param roles: The name (friendly name, not ARN) of the role to attach the policy to. This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@- .. epigraph:: If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.
        :param users: The name (friendly name, not ARN) of the IAM user to attach the policy to. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        '''
        props = CfnManagedPolicyProps(
            policy_document=policy_document,
            description=description,
            groups=groups,
            managed_policy_name=managed_policy_name,
            path=path,
            roles=roles,
            users=users,
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
    @jsii.member(jsii_name="policyDocument")
    def policy_document(self) -> typing.Any:
        '''The JSON policy document that you want to use as the content for the new policy.

        You must provide policies in JSON format in IAM. However, for AWS CloudFormation templates formatted in YAML, you can provide the policy in JSON or YAML format. AWS CloudFormation always converts a YAML policy to JSON format before submitting it to IAM.

        The maximum length of the policy document that you can pass in this operation, including whitespace, is listed below. To view the maximum character counts of a managed policy with no whitespaces, see `IAM and AWS STS character quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-entity-length>`_ .

        To learn more about JSON policy grammar, see `Grammar of the IAM JSON policy language <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html>`_ in the *IAM User Guide* .

        The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following:

        - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range
        - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` )
        - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-policydocument
        '''
        return typing.cast(typing.Any, jsii.get(self, "policyDocument"))

    @policy_document.setter
    def policy_document(self, value: typing.Any) -> None:
        jsii.set(self, "policyDocument", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A friendly description of the policy.

        Typically used to store information about the permissions defined in the policy. For example, "Grants access to production DynamoDB tables."

        The policy description is immutable. After a value is assigned, it cannot be changed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groups")
    def groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name (friendly name, not ARN) of the group to attach the policy to.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-groups
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "groups"))

    @groups.setter
    def groups(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "groups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedPolicyName")
    def managed_policy_name(self) -> typing.Optional[builtins.str]:
        '''The friendly name of the policy.

        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ .
        .. epigraph::

           Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-managedpolicyname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "managedPolicyName"))

    @managed_policy_name.setter
    def managed_policy_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "managedPolicyName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the policy.

        For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        .. epigraph::

           You cannot use an asterisk (*) in the path name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-ec2-dhcpoptions-path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "path"))

    @path.setter
    def path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roles")
    def roles(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name (friendly name, not ARN) of the role to attach the policy to.

        This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        .. epigraph::

           If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-roles
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "roles"))

    @roles.setter
    def roles(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "roles", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="users")
    def users(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name (friendly name, not ARN) of the IAM user to attach the policy to.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-users
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "users"))

    @users.setter
    def users(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "users", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnManagedPolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "policy_document": "policyDocument",
        "description": "description",
        "groups": "groups",
        "managed_policy_name": "managedPolicyName",
        "path": "path",
        "roles": "roles",
        "users": "users",
    },
)
class CfnManagedPolicyProps:
    def __init__(
        self,
        *,
        policy_document: typing.Any,
        description: typing.Optional[builtins.str] = None,
        groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        managed_policy_name: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        roles: typing.Optional[typing.Sequence[builtins.str]] = None,
        users: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnManagedPolicy``.

        :param policy_document: The JSON policy document that you want to use as the content for the new policy. You must provide policies in JSON format in IAM. However, for AWS CloudFormation templates formatted in YAML, you can provide the policy in JSON or YAML format. AWS CloudFormation always converts a YAML policy to JSON format before submitting it to IAM. The maximum length of the policy document that you can pass in this operation, including whitespace, is listed below. To view the maximum character counts of a managed policy with no whitespaces, see `IAM and AWS STS character quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-entity-length>`_ . To learn more about JSON policy grammar, see `Grammar of the IAM JSON policy language <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html>`_ in the *IAM User Guide* . The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following: - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` ) - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )
        :param description: A friendly description of the policy. Typically used to store information about the permissions defined in the policy. For example, "Grants access to production DynamoDB tables." The policy description is immutable. After a value is assigned, it cannot be changed.
        :param groups: The name (friendly name, not ARN) of the group to attach the policy to. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param managed_policy_name: The friendly name of the policy. .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ . .. epigraph:: Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .
        :param path: The path for the policy. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters. .. epigraph:: You cannot use an asterisk (*) in the path name.
        :param roles: The name (friendly name, not ARN) of the role to attach the policy to. This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@- .. epigraph:: If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.
        :param users: The name (friendly name, not ARN) of the IAM user to attach the policy to. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # policy_document: Any
            
            cfn_managed_policy_props = iam.CfnManagedPolicyProps(
                policy_document=policy_document,
            
                # the properties below are optional
                description="description",
                groups=["groups"],
                managed_policy_name="managedPolicyName",
                path="path",
                roles=["roles"],
                users=["users"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "policy_document": policy_document,
        }
        if description is not None:
            self._values["description"] = description
        if groups is not None:
            self._values["groups"] = groups
        if managed_policy_name is not None:
            self._values["managed_policy_name"] = managed_policy_name
        if path is not None:
            self._values["path"] = path
        if roles is not None:
            self._values["roles"] = roles
        if users is not None:
            self._values["users"] = users

    @builtins.property
    def policy_document(self) -> typing.Any:
        '''The JSON policy document that you want to use as the content for the new policy.

        You must provide policies in JSON format in IAM. However, for AWS CloudFormation templates formatted in YAML, you can provide the policy in JSON or YAML format. AWS CloudFormation always converts a YAML policy to JSON format before submitting it to IAM.

        The maximum length of the policy document that you can pass in this operation, including whitespace, is listed below. To view the maximum character counts of a managed policy with no whitespaces, see `IAM and AWS STS character quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html#reference_iam-quotas-entity-length>`_ .

        To learn more about JSON policy grammar, see `Grammar of the IAM JSON policy language <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html>`_ in the *IAM User Guide* .

        The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following:

        - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range
        - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` )
        - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-policydocument
        '''
        result = self._values.get("policy_document")
        assert result is not None, "Required property 'policy_document' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A friendly description of the policy.

        Typically used to store information about the permissions defined in the policy. For example, "Grants access to production DynamoDB tables."

        The policy description is immutable. After a value is assigned, it cannot be changed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name (friendly name, not ARN) of the group to attach the policy to.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-groups
        '''
        result = self._values.get("groups")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def managed_policy_name(self) -> typing.Optional[builtins.str]:
        '''The friendly name of the policy.

        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ .
        .. epigraph::

           Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-managedpolicyname
        '''
        result = self._values.get("managed_policy_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the policy.

        For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        .. epigraph::

           You cannot use an asterisk (*) in the path name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-ec2-dhcpoptions-path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def roles(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name (friendly name, not ARN) of the role to attach the policy to.

        This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        .. epigraph::

           If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-roles
        '''
        result = self._values.get("roles")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def users(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name (friendly name, not ARN) of the IAM user to attach the policy to.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-managedpolicy.html#cfn-iam-managedpolicy-users
        '''
        result = self._values.get("users")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnManagedPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnOIDCProvider(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnOIDCProvider",
):
    '''A CloudFormation ``AWS::IAM::OIDCProvider``.

    Creates an IAM entity to describe an identity provider (IdP) that supports `OpenID Connect (OIDC) <https://docs.aws.amazon.com/http://openid.net/connect/>`_ .

    The OIDC provider that you create with this operation can be used as a principal in a role's trust policy. Such a policy establishes a trust relationship between AWS and the OIDC provider.

    When you create the IAM OIDC provider, you specify the following:

    - The URL of the OIDC identity provider (IdP) to trust
    - A list of client IDs (also known as audiences) that identify the application or applications that are allowed to authenticate using the OIDC provider
    - A list of thumbprints of one or more server certificates that the IdP uses

    You get all of this information from the OIDC IdP that you want to use to access AWS .
    .. epigraph::

       The trust for the OIDC provider is derived from the IAM provider that this operation creates. Therefore, it is best to limit access to the `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ operation to highly privileged users.

    :cloudformationResource: AWS::IAM::OIDCProvider
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        cfn_oIDCProvider = iam.CfnOIDCProvider(self, "MyCfnOIDCProvider",
            thumbprint_list=["thumbprintList"],
        
            # the properties below are optional
            client_id_list=["clientIdList"],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            url="url"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        thumbprint_list: typing.Sequence[builtins.str],
        client_id_list: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::OIDCProvider``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param thumbprint_list: A list of certificate thumbprints that are associated with the specified IAM OIDC provider resource object. For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .
        :param client_id_list: A list of client IDs (also known as audiences) that are associated with the specified IAM OIDC provider resource object. For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .
        :param tags: A list of tags that are attached to the specified IAM OIDC provider. The returned list of tags is sorted by tag key. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        :param url: The URL that the IAM OIDC provider resource object is associated with. For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .
        '''
        props = CfnOIDCProviderProps(
            thumbprint_list=thumbprint_list,
            client_id_list=client_id_list,
            tags=tags,
            url=url,
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
        '''Returns the Amazon Resource Name (ARN) for the specified ``AWS::IAM::OIDCProvider`` resource.

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
        '''A list of tags that are attached to the specified IAM OIDC provider.

        The returned list of tags is sorted by tag key. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html#cfn-iam-oidcprovider-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="thumbprintList")
    def thumbprint_list(self) -> typing.List[builtins.str]:
        '''A list of certificate thumbprints that are associated with the specified IAM OIDC provider resource object.

        For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html#cfn-iam-oidcprovider-thumbprintlist
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "thumbprintList"))

    @thumbprint_list.setter
    def thumbprint_list(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "thumbprintList", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clientIdList")
    def client_id_list(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of client IDs (also known as audiences) that are associated with the specified IAM OIDC provider resource object.

        For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html#cfn-iam-oidcprovider-clientidlist
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "clientIdList"))

    @client_id_list.setter
    def client_id_list(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "clientIdList", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="url")
    def url(self) -> typing.Optional[builtins.str]:
        '''The URL that the IAM OIDC provider resource object is associated with.

        For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html#cfn-iam-oidcprovider-url
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "url"))

    @url.setter
    def url(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "url", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnOIDCProviderProps",
    jsii_struct_bases=[],
    name_mapping={
        "thumbprint_list": "thumbprintList",
        "client_id_list": "clientIdList",
        "tags": "tags",
        "url": "url",
    },
)
class CfnOIDCProviderProps:
    def __init__(
        self,
        *,
        thumbprint_list: typing.Sequence[builtins.str],
        client_id_list: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnOIDCProvider``.

        :param thumbprint_list: A list of certificate thumbprints that are associated with the specified IAM OIDC provider resource object. For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .
        :param client_id_list: A list of client IDs (also known as audiences) that are associated with the specified IAM OIDC provider resource object. For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .
        :param tags: A list of tags that are attached to the specified IAM OIDC provider. The returned list of tags is sorted by tag key. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        :param url: The URL that the IAM OIDC provider resource object is associated with. For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            cfn_oIDCProvider_props = iam.CfnOIDCProviderProps(
                thumbprint_list=["thumbprintList"],
            
                # the properties below are optional
                client_id_list=["clientIdList"],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                url="url"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "thumbprint_list": thumbprint_list,
        }
        if client_id_list is not None:
            self._values["client_id_list"] = client_id_list
        if tags is not None:
            self._values["tags"] = tags
        if url is not None:
            self._values["url"] = url

    @builtins.property
    def thumbprint_list(self) -> typing.List[builtins.str]:
        '''A list of certificate thumbprints that are associated with the specified IAM OIDC provider resource object.

        For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html#cfn-iam-oidcprovider-thumbprintlist
        '''
        result = self._values.get("thumbprint_list")
        assert result is not None, "Required property 'thumbprint_list' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def client_id_list(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of client IDs (also known as audiences) that are associated with the specified IAM OIDC provider resource object.

        For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html#cfn-iam-oidcprovider-clientidlist
        '''
        result = self._values.get("client_id_list")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags that are attached to the specified IAM OIDC provider.

        The returned list of tags is sorted by tag key. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html#cfn-iam-oidcprovider-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def url(self) -> typing.Optional[builtins.str]:
        '''The URL that the IAM OIDC provider resource object is associated with.

        For more information, see `CreateOpenIDConnectProvider <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-oidcprovider.html#cfn-iam-oidcprovider-url
        '''
        result = self._values.get("url")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnOIDCProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnPolicy",
):
    '''A CloudFormation ``AWS::IAM::Policy``.

    Adds or updates an inline policy document that is embedded in the specified IAM user, group, or role.

    An IAM user can also have a managed policy attached to it. For information about policies, see `Managed Policies and Inline Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* .

    The Groups, Roles, and Users properties are optional. However, you must specify at least one of these properties.

    For information about limits on the number of inline policies that you can embed in an identity, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .

    :cloudformationResource: AWS::IAM::Policy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # policy_document: Any
        
        cfn_policy = iam.CfnPolicy(self, "MyCfnPolicy",
            policy_document=policy_document,
            policy_name="policyName",
        
            # the properties below are optional
            groups=["groups"],
            roles=["roles"],
            users=["users"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        policy_document: typing.Any,
        policy_name: builtins.str,
        groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        roles: typing.Optional[typing.Sequence[builtins.str]] = None,
        users: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::Policy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param policy_document: The policy document. You must provide policies in JSON format in IAM. However, for AWS CloudFormation templates formatted in YAML, you can provide the policy in JSON or YAML format. AWS CloudFormation always converts a YAML policy to JSON format before submitting it to IAM. The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following: - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` ) - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )
        :param policy_name: The name of the policy document. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param groups: The name of the group to associate the policy with. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-.
        :param roles: The name of the role to associate the policy with. This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@- .. epigraph:: If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.
        :param users: The name of the user to associate the policy with. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        '''
        props = CfnPolicyProps(
            policy_document=policy_document,
            policy_name=policy_name,
            groups=groups,
            roles=roles,
            users=users,
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
    @jsii.member(jsii_name="policyDocument")
    def policy_document(self) -> typing.Any:
        '''The policy document.

        You must provide policies in JSON format in IAM. However, for AWS CloudFormation templates formatted in YAML, you can provide the policy in JSON or YAML format. AWS CloudFormation always converts a YAML policy to JSON format before submitting it to IAM.

        The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following:

        - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range
        - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` )
        - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-policydocument
        '''
        return typing.cast(typing.Any, jsii.get(self, "policyDocument"))

    @policy_document.setter
    def policy_document(self, value: typing.Any) -> None:
        jsii.set(self, "policyDocument", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyName")
    def policy_name(self) -> builtins.str:
        '''The name of the policy document.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-policyname
        '''
        return typing.cast(builtins.str, jsii.get(self, "policyName"))

    @policy_name.setter
    def policy_name(self, value: builtins.str) -> None:
        jsii.set(self, "policyName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groups")
    def groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name of the group to associate the policy with.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-groups
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "groups"))

    @groups.setter
    def groups(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "groups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roles")
    def roles(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name of the role to associate the policy with.

        This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        .. epigraph::

           If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-roles
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "roles"))

    @roles.setter
    def roles(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "roles", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="users")
    def users(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name of the user to associate the policy with.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-users
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "users"))

    @users.setter
    def users(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "users", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnPolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "policy_document": "policyDocument",
        "policy_name": "policyName",
        "groups": "groups",
        "roles": "roles",
        "users": "users",
    },
)
class CfnPolicyProps:
    def __init__(
        self,
        *,
        policy_document: typing.Any,
        policy_name: builtins.str,
        groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        roles: typing.Optional[typing.Sequence[builtins.str]] = None,
        users: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPolicy``.

        :param policy_document: The policy document. You must provide policies in JSON format in IAM. However, for AWS CloudFormation templates formatted in YAML, you can provide the policy in JSON or YAML format. AWS CloudFormation always converts a YAML policy to JSON format before submitting it to IAM. The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following: - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` ) - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )
        :param policy_name: The name of the policy document. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param groups: The name of the group to associate the policy with. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-.
        :param roles: The name of the role to associate the policy with. This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@- .. epigraph:: If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.
        :param users: The name of the user to associate the policy with. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # policy_document: Any
            
            cfn_policy_props = iam.CfnPolicyProps(
                policy_document=policy_document,
                policy_name="policyName",
            
                # the properties below are optional
                groups=["groups"],
                roles=["roles"],
                users=["users"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "policy_document": policy_document,
            "policy_name": policy_name,
        }
        if groups is not None:
            self._values["groups"] = groups
        if roles is not None:
            self._values["roles"] = roles
        if users is not None:
            self._values["users"] = users

    @builtins.property
    def policy_document(self) -> typing.Any:
        '''The policy document.

        You must provide policies in JSON format in IAM. However, for AWS CloudFormation templates formatted in YAML, you can provide the policy in JSON or YAML format. AWS CloudFormation always converts a YAML policy to JSON format before submitting it to IAM.

        The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following:

        - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range
        - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` )
        - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-policydocument
        '''
        result = self._values.get("policy_document")
        assert result is not None, "Required property 'policy_document' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def policy_name(self) -> builtins.str:
        '''The name of the policy document.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-policyname
        '''
        result = self._values.get("policy_name")
        assert result is not None, "Required property 'policy_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name of the group to associate the policy with.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-groups
        '''
        result = self._values.get("groups")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def roles(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name of the role to associate the policy with.

        This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        .. epigraph::

           If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-roles
        '''
        result = self._values.get("roles")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def users(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The name of the user to associate the policy with.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-users
        '''
        result = self._values.get("users")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRole(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnRole",
):
    '''A CloudFormation ``AWS::IAM::Role``.

    Creates a new role for your AWS account . For more information about roles, see `IAM roles <https://docs.aws.amazon.com/IAM/latest/UserGuide/WorkingWithRoles.html>`_ . For information about quotas for role names and the number of roles you can create, see `IAM and AWS STS quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>`_ in the *IAM User Guide* .

    :cloudformationResource: AWS::IAM::Role
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # assume_role_policy_document: Any
        # policy_document: Any
        
        cfn_role = iam.CfnRole(self, "MyCfnRole",
            assume_role_policy_document=assume_role_policy_document,
        
            # the properties below are optional
            description="description",
            managed_policy_arns=["managedPolicyArns"],
            max_session_duration=123,
            path="path",
            permissions_boundary="permissionsBoundary",
            policies=[iam.CfnRole.PolicyProperty(
                policy_document=policy_document,
                policy_name="policyName"
            )],
            role_name="roleName",
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
        assume_role_policy_document: typing.Any,
        description: typing.Optional[builtins.str] = None,
        managed_policy_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        max_session_duration: typing.Optional[jsii.Number] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[builtins.str] = None,
        policies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRole.PolicyProperty", _IResolvable_da3f097b]]]] = None,
        role_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::Role``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param assume_role_policy_document: The trust policy that is associated with this role. Trust policies define which entities can assume the role. You can associate only one trust policy with a role. For an example of a policy that can be used to assume a role, see `Template Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#aws-resource-iam-role--examples>`_ . For more information about the elements that you can use in an IAM policy, see `IAM Policy Elements Reference <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html>`_ in the *IAM User Guide* .
        :param description: A description of the role that you provide.
        :param managed_policy_arns: A list of Amazon Resource Names (ARNs) of the IAM managed policies that you want to attach to the role. For more information about ARNs, see `Amazon Resource Names (ARNs) and AWS Service Namespaces <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .
        :param max_session_duration: The maximum session duration (in seconds) that you want to set for the specified role. If you do not specify a value for this setting, the default maximum of one hour is applied. This setting can have a value from 1 hour to 12 hours. Anyone who assumes the role from the or API can use the ``DurationSeconds`` API parameter or the ``duration-seconds`` CLI parameter to request a longer session. The ``MaxSessionDuration`` setting determines the maximum duration that can be requested using the ``DurationSeconds`` parameter. If users don't specify a value for the ``DurationSeconds`` parameter, their security credentials are valid for one hour by default. This applies when you use the ``AssumeRole*`` API operations or the ``assume-role*`` CLI operations but does not apply when you use those operations to create a console URL. For more information, see `Using IAM roles <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html>`_ in the *IAM User Guide* .
        :param path: The path to the role. For more information about paths, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        :param permissions_boundary: The ARN of the policy used to set the permissions boundary for the role. For more information about permissions boundaries, see `Permissions boundaries for IAM identities <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html>`_ in the *IAM User Guide* .
        :param policies: Adds or updates an inline policy document that is embedded in the specified IAM role. When you embed an inline policy in a role, the inline policy is used as part of the role's access (permissions) policy. The role's trust policy is created at the same time as the role. You can update a role's trust policy later. For more information about IAM roles, go to `Using Roles to Delegate Permissions and Federate Identities <https://docs.aws.amazon.com/IAM/latest/UserGuide/roles-toplevel.html>`_ . A role can also have an attached managed policy. For information about policies, see `Managed Policies and Inline Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* . For information about limits on the number of inline policies that you can embed with a role, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* . .. epigraph:: If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.
        :param role_name: A name for the IAM role, up to 64 characters in length. For valid values, see the ``RoleName`` parameter for the ```CreateRole`` <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html>`_ action in the *IAM User Guide* . This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. The role name must be unique within the account. Role names are not distinguished by case. For example, you cannot create roles named both "Role1" and "role1". If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the role name. If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ . .. epigraph:: Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .
        :param tags: A list of tags that are attached to the role. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        '''
        props = CfnRoleProps(
            assume_role_policy_document=assume_role_policy_document,
            description=description,
            managed_policy_arns=managed_policy_arns,
            max_session_duration=max_session_duration,
            path=path,
            permissions_boundary=permissions_boundary,
            policies=policies,
            role_name=role_name,
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
        '''Returns the Amazon Resource Name (ARN) for the role. For example:.

        ``{"Fn::GetAtt" : ["MyRole", "Arn"] }``

        This will return a value such as ``arn:aws:iam::1234567890:role/MyRole-AJJHDSKSDF`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRoleId")
    def attr_role_id(self) -> builtins.str:
        '''Returns the stable and unique string identifying the role. For example, ``AIDAJQABLZS4A3QDU576Q`` .

        For more information about IDs, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html>`_ in the *IAM User Guide* .

        :cloudformationAttribute: RoleId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRoleId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A list of tags that are attached to the role.

        For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRolePolicyDocument")
    def assume_role_policy_document(self) -> typing.Any:
        '''The trust policy that is associated with this role.

        Trust policies define which entities can assume the role. You can associate only one trust policy with a role. For an example of a policy that can be used to assume a role, see `Template Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#aws-resource-iam-role--examples>`_ . For more information about the elements that you can use in an IAM policy, see `IAM Policy Elements Reference <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-assumerolepolicydocument
        '''
        return typing.cast(typing.Any, jsii.get(self, "assumeRolePolicyDocument"))

    @assume_role_policy_document.setter
    def assume_role_policy_document(self, value: typing.Any) -> None:
        jsii.set(self, "assumeRolePolicyDocument", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the role that you provide.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedPolicyArns")
    def managed_policy_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Amazon Resource Names (ARNs) of the IAM managed policies that you want to attach to the role.

        For more information about ARNs, see `Amazon Resource Names (ARNs) and AWS Service Namespaces <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-managepolicyarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "managedPolicyArns"))

    @managed_policy_arns.setter
    def managed_policy_arns(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "managedPolicyArns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxSessionDuration")
    def max_session_duration(self) -> typing.Optional[jsii.Number]:
        '''The maximum session duration (in seconds) that you want to set for the specified role.

        If you do not specify a value for this setting, the default maximum of one hour is applied. This setting can have a value from 1 hour to 12 hours.

        Anyone who assumes the role from the or API can use the ``DurationSeconds`` API parameter or the ``duration-seconds`` CLI parameter to request a longer session. The ``MaxSessionDuration`` setting determines the maximum duration that can be requested using the ``DurationSeconds`` parameter. If users don't specify a value for the ``DurationSeconds`` parameter, their security credentials are valid for one hour by default. This applies when you use the ``AssumeRole*`` API operations or the ``assume-role*`` CLI operations but does not apply when you use those operations to create a console URL. For more information, see `Using IAM roles <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-maxsessionduration
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxSessionDuration"))

    @max_session_duration.setter
    def max_session_duration(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxSessionDuration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> typing.Optional[builtins.str]:
        '''The path to the role. For more information about paths, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "path"))

    @path.setter
    def path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissionsBoundary")
    def permissions_boundary(self) -> typing.Optional[builtins.str]:
        '''The ARN of the policy used to set the permissions boundary for the role.

        For more information about permissions boundaries, see `Permissions boundaries for IAM identities <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-permissionsboundary
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "permissionsBoundary"))

    @permissions_boundary.setter
    def permissions_boundary(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "permissionsBoundary", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policies")
    def policies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRole.PolicyProperty", _IResolvable_da3f097b]]]]:
        '''Adds or updates an inline policy document that is embedded in the specified IAM role.

        When you embed an inline policy in a role, the inline policy is used as part of the role's access (permissions) policy. The role's trust policy is created at the same time as the role. You can update a role's trust policy later. For more information about IAM roles, go to `Using Roles to Delegate Permissions and Federate Identities <https://docs.aws.amazon.com/IAM/latest/UserGuide/roles-toplevel.html>`_ .

        A role can also have an attached managed policy. For information about policies, see `Managed Policies and Inline Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* .

        For information about limits on the number of inline policies that you can embed with a role, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .
        .. epigraph::

           If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-policies
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRole.PolicyProperty", _IResolvable_da3f097b]]]], jsii.get(self, "policies"))

    @policies.setter
    def policies(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRole.PolicyProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "policies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleName")
    def role_name(self) -> typing.Optional[builtins.str]:
        '''A name for the IAM role, up to 64 characters in length.

        For valid values, see the ``RoleName`` parameter for the ```CreateRole`` <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html>`_ action in the *IAM User Guide* .

        This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. The role name must be unique within the account. Role names are not distinguished by case. For example, you cannot create roles named both "Role1" and "role1".

        If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the role name.

        If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ .
        .. epigraph::

           Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-rolename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "roleName"))

    @role_name.setter
    def role_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "roleName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iam.CfnRole.PolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "policy_document": "policyDocument",
            "policy_name": "policyName",
        },
    )
    class PolicyProperty:
        def __init__(
            self,
            *,
            policy_document: typing.Any,
            policy_name: builtins.str,
        ) -> None:
            '''Contains information about an attached policy.

            An attached policy is a managed policy that has been attached to a user, group, or role.

            For more information about managed policies, refer to `Managed Policies and Inline Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* .

            :param policy_document: The policy document.
            :param policy_name: The friendly name (not ARN) identifying the policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iam as iam
                
                # policy_document: Any
                
                policy_property = iam.CfnRole.PolicyProperty(
                    policy_document=policy_document,
                    policy_name="policyName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "policy_document": policy_document,
                "policy_name": policy_name,
            }

        @builtins.property
        def policy_document(self) -> typing.Any:
            '''The policy document.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html#cfn-iam-policies-policydocument
            '''
            result = self._values.get("policy_document")
            assert result is not None, "Required property 'policy_document' is missing"
            return typing.cast(typing.Any, result)

        @builtins.property
        def policy_name(self) -> builtins.str:
            '''The friendly name (not ARN) identifying the policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html#cfn-iam-policies-policyname
            '''
            result = self._values.get("policy_name")
            assert result is not None, "Required property 'policy_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnRoleProps",
    jsii_struct_bases=[],
    name_mapping={
        "assume_role_policy_document": "assumeRolePolicyDocument",
        "description": "description",
        "managed_policy_arns": "managedPolicyArns",
        "max_session_duration": "maxSessionDuration",
        "path": "path",
        "permissions_boundary": "permissionsBoundary",
        "policies": "policies",
        "role_name": "roleName",
        "tags": "tags",
    },
)
class CfnRoleProps:
    def __init__(
        self,
        *,
        assume_role_policy_document: typing.Any,
        description: typing.Optional[builtins.str] = None,
        managed_policy_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        max_session_duration: typing.Optional[jsii.Number] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[builtins.str] = None,
        policies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnRole.PolicyProperty, _IResolvable_da3f097b]]]] = None,
        role_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRole``.

        :param assume_role_policy_document: The trust policy that is associated with this role. Trust policies define which entities can assume the role. You can associate only one trust policy with a role. For an example of a policy that can be used to assume a role, see `Template Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#aws-resource-iam-role--examples>`_ . For more information about the elements that you can use in an IAM policy, see `IAM Policy Elements Reference <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html>`_ in the *IAM User Guide* .
        :param description: A description of the role that you provide.
        :param managed_policy_arns: A list of Amazon Resource Names (ARNs) of the IAM managed policies that you want to attach to the role. For more information about ARNs, see `Amazon Resource Names (ARNs) and AWS Service Namespaces <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .
        :param max_session_duration: The maximum session duration (in seconds) that you want to set for the specified role. If you do not specify a value for this setting, the default maximum of one hour is applied. This setting can have a value from 1 hour to 12 hours. Anyone who assumes the role from the or API can use the ``DurationSeconds`` API parameter or the ``duration-seconds`` CLI parameter to request a longer session. The ``MaxSessionDuration`` setting determines the maximum duration that can be requested using the ``DurationSeconds`` parameter. If users don't specify a value for the ``DurationSeconds`` parameter, their security credentials are valid for one hour by default. This applies when you use the ``AssumeRole*`` API operations or the ``assume-role*`` CLI operations but does not apply when you use those operations to create a console URL. For more information, see `Using IAM roles <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html>`_ in the *IAM User Guide* .
        :param path: The path to the role. For more information about paths, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        :param permissions_boundary: The ARN of the policy used to set the permissions boundary for the role. For more information about permissions boundaries, see `Permissions boundaries for IAM identities <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html>`_ in the *IAM User Guide* .
        :param policies: Adds or updates an inline policy document that is embedded in the specified IAM role. When you embed an inline policy in a role, the inline policy is used as part of the role's access (permissions) policy. The role's trust policy is created at the same time as the role. You can update a role's trust policy later. For more information about IAM roles, go to `Using Roles to Delegate Permissions and Federate Identities <https://docs.aws.amazon.com/IAM/latest/UserGuide/roles-toplevel.html>`_ . A role can also have an attached managed policy. For information about policies, see `Managed Policies and Inline Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* . For information about limits on the number of inline policies that you can embed with a role, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* . .. epigraph:: If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.
        :param role_name: A name for the IAM role, up to 64 characters in length. For valid values, see the ``RoleName`` parameter for the ```CreateRole`` <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html>`_ action in the *IAM User Guide* . This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. The role name must be unique within the account. Role names are not distinguished by case. For example, you cannot create roles named both "Role1" and "role1". If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the role name. If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ . .. epigraph:: Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .
        :param tags: A list of tags that are attached to the role. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # assume_role_policy_document: Any
            # policy_document: Any
            
            cfn_role_props = iam.CfnRoleProps(
                assume_role_policy_document=assume_role_policy_document,
            
                # the properties below are optional
                description="description",
                managed_policy_arns=["managedPolicyArns"],
                max_session_duration=123,
                path="path",
                permissions_boundary="permissionsBoundary",
                policies=[iam.CfnRole.PolicyProperty(
                    policy_document=policy_document,
                    policy_name="policyName"
                )],
                role_name="roleName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "assume_role_policy_document": assume_role_policy_document,
        }
        if description is not None:
            self._values["description"] = description
        if managed_policy_arns is not None:
            self._values["managed_policy_arns"] = managed_policy_arns
        if max_session_duration is not None:
            self._values["max_session_duration"] = max_session_duration
        if path is not None:
            self._values["path"] = path
        if permissions_boundary is not None:
            self._values["permissions_boundary"] = permissions_boundary
        if policies is not None:
            self._values["policies"] = policies
        if role_name is not None:
            self._values["role_name"] = role_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def assume_role_policy_document(self) -> typing.Any:
        '''The trust policy that is associated with this role.

        Trust policies define which entities can assume the role. You can associate only one trust policy with a role. For an example of a policy that can be used to assume a role, see `Template Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#aws-resource-iam-role--examples>`_ . For more information about the elements that you can use in an IAM policy, see `IAM Policy Elements Reference <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-assumerolepolicydocument
        '''
        result = self._values.get("assume_role_policy_document")
        assert result is not None, "Required property 'assume_role_policy_document' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the role that you provide.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def managed_policy_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Amazon Resource Names (ARNs) of the IAM managed policies that you want to attach to the role.

        For more information about ARNs, see `Amazon Resource Names (ARNs) and AWS Service Namespaces <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-managepolicyarns
        '''
        result = self._values.get("managed_policy_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def max_session_duration(self) -> typing.Optional[jsii.Number]:
        '''The maximum session duration (in seconds) that you want to set for the specified role.

        If you do not specify a value for this setting, the default maximum of one hour is applied. This setting can have a value from 1 hour to 12 hours.

        Anyone who assumes the role from the or API can use the ``DurationSeconds`` API parameter or the ``duration-seconds`` CLI parameter to request a longer session. The ``MaxSessionDuration`` setting determines the maximum duration that can be requested using the ``DurationSeconds`` parameter. If users don't specify a value for the ``DurationSeconds`` parameter, their security credentials are valid for one hour by default. This applies when you use the ``AssumeRole*`` API operations or the ``assume-role*`` CLI operations but does not apply when you use those operations to create a console URL. For more information, see `Using IAM roles <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-maxsessionduration
        '''
        result = self._values.get("max_session_duration")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path to the role. For more information about paths, see `IAM Identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions_boundary(self) -> typing.Optional[builtins.str]:
        '''The ARN of the policy used to set the permissions boundary for the role.

        For more information about permissions boundaries, see `Permissions boundaries for IAM identities <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-permissionsboundary
        '''
        result = self._values.get("permissions_boundary")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def policies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRole.PolicyProperty, _IResolvable_da3f097b]]]]:
        '''Adds or updates an inline policy document that is embedded in the specified IAM role.

        When you embed an inline policy in a role, the inline policy is used as part of the role's access (permissions) policy. The role's trust policy is created at the same time as the role. You can update a role's trust policy later. For more information about IAM roles, go to `Using Roles to Delegate Permissions and Federate Identities <https://docs.aws.amazon.com/IAM/latest/UserGuide/roles-toplevel.html>`_ .

        A role can also have an attached managed policy. For information about policies, see `Managed Policies and Inline Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* .

        For information about limits on the number of inline policies that you can embed with a role, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .
        .. epigraph::

           If an external policy (such as ``AWS::IAM::Policy`` or ``AWS::IAM::ManagedPolicy`` ) has a ``Ref`` to a role and if a resource (such as ``AWS::ECS::Service`` ) also has a ``Ref`` to the same role, add a ``DependsOn`` attribute to the resource to make the resource depend on the external policy. This dependency ensures that the role's policy is available throughout the resource's lifecycle. For example, when you delete a stack with an ``AWS::ECS::Service`` resource, the ``DependsOn`` attribute ensures that AWS CloudFormation deletes the ``AWS::ECS::Service`` resource before deleting its role's policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-policies
        '''
        result = self._values.get("policies")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRole.PolicyProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def role_name(self) -> typing.Optional[builtins.str]:
        '''A name for the IAM role, up to 64 characters in length.

        For valid values, see the ``RoleName`` parameter for the ```CreateRole`` <https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html>`_ action in the *IAM User Guide* .

        This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. The role name must be unique within the account. Role names are not distinguished by case. For example, you cannot create roles named both "Role1" and "role1".

        If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the role name.

        If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ .
        .. epigraph::

           Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-rolename
        '''
        result = self._values.get("role_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags that are attached to the role.

        For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html#cfn-iam-role-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRoleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSAMLProvider(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnSAMLProvider",
):
    '''A CloudFormation ``AWS::IAM::SAMLProvider``.

    Creates an IAM resource that describes an identity provider (IdP) that supports SAML 2.0.

    The SAML provider resource that you create with this operation can be used as a principal in an IAM role's trust policy. Such a policy can enable federated users who sign in using the SAML IdP to assume the role. You can create an IAM role that supports Web-based single sign-on (SSO) to the AWS Management Console or one that supports API access to AWS .

    When you create the SAML provider resource, you upload a SAML metadata document that you get from your IdP. That document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that the IdP sends. You must generate the metadata document using the identity management software that is used as your organization's IdP.
    .. epigraph::

       This operation requires `Signature Version 4 <https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html>`_ .

    For more information, see `Enabling SAML 2.0 federated users to access the AWS Management Console <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-saml.html>`_ and `About SAML 2.0-based federation <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html>`_ in the *IAM User Guide* .

    :cloudformationResource: AWS::IAM::SAMLProvider
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-samlprovider.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        cfn_sAMLProvider = iam.CfnSAMLProvider(self, "MyCfnSAMLProvider",
            saml_metadata_document="samlMetadataDocument",
        
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
        saml_metadata_document: builtins.str,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::SAMLProvider``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param saml_metadata_document: An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your organization's IdP. For more information, see `About SAML 2.0-based federation <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html>`_ in the *IAM User Guide*
        :param name: The name of the provider to create. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param tags: A list of tags that you want to attach to the new IAM SAML provider. Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* . .. epigraph:: If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.
        '''
        props = CfnSAMLProviderProps(
            saml_metadata_document=saml_metadata_document, name=name, tags=tags
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
        '''Returns the Amazon Resource Name (ARN) for the specified ``AWS::IAM::SAMLProvider`` resource.

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
        '''A list of tags that you want to attach to the new IAM SAML provider.

        Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        .. epigraph::

           If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-samlprovider.html#cfn-iam-samlprovider-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="samlMetadataDocument")
    def saml_metadata_document(self) -> builtins.str:
        '''An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your organization's IdP.

        For more information, see `About SAML 2.0-based federation <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html>`_ in the *IAM User Guide*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-samlprovider.html#cfn-iam-samlprovider-samlmetadatadocument
        '''
        return typing.cast(builtins.str, jsii.get(self, "samlMetadataDocument"))

    @saml_metadata_document.setter
    def saml_metadata_document(self, value: builtins.str) -> None:
        jsii.set(self, "samlMetadataDocument", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the provider to create.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-samlprovider.html#cfn-iam-samlprovider-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnSAMLProviderProps",
    jsii_struct_bases=[],
    name_mapping={
        "saml_metadata_document": "samlMetadataDocument",
        "name": "name",
        "tags": "tags",
    },
)
class CfnSAMLProviderProps:
    def __init__(
        self,
        *,
        saml_metadata_document: builtins.str,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSAMLProvider``.

        :param saml_metadata_document: An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your organization's IdP. For more information, see `About SAML 2.0-based federation <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html>`_ in the *IAM User Guide*
        :param name: The name of the provider to create. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param tags: A list of tags that you want to attach to the new IAM SAML provider. Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* . .. epigraph:: If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-samlprovider.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            cfn_sAMLProvider_props = iam.CfnSAMLProviderProps(
                saml_metadata_document="samlMetadataDocument",
            
                # the properties below are optional
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "saml_metadata_document": saml_metadata_document,
        }
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def saml_metadata_document(self) -> builtins.str:
        '''An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your organization's IdP.

        For more information, see `About SAML 2.0-based federation <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html>`_ in the *IAM User Guide*

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-samlprovider.html#cfn-iam-samlprovider-samlmetadatadocument
        '''
        result = self._values.get("saml_metadata_document")
        assert result is not None, "Required property 'saml_metadata_document' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the provider to create.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-samlprovider.html#cfn-iam-samlprovider-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags that you want to attach to the new IAM SAML provider.

        Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        .. epigraph::

           If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-samlprovider.html#cfn-iam-samlprovider-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSAMLProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnServerCertificate(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnServerCertificate",
):
    '''A CloudFormation ``AWS::IAM::ServerCertificate``.

    Uploads a server certificate entity for the AWS account . The server certificate entity includes a public key certificate, a private key, and an optional certificate chain, which should all be PEM-encoded.

    We recommend that you use `AWS Certificate Manager <https://docs.aws.amazon.com/acm/>`_ to provision, manage, and deploy your server certificates. With ACM you can request a certificate, deploy it to AWS resources, and let ACM handle certificate renewals for you. Certificates provided by ACM are free. For more information about using ACM, see the `AWS Certificate Manager User Guide <https://docs.aws.amazon.com/acm/latest/userguide/>`_ .

    For more information about working with server certificates, see `Working with server certificates <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html>`_ in the *IAM User Guide* . This topic includes a list of AWS services that can use the server certificates that you manage with IAM.

    For information about the number of server certificates you can upload, see `IAM and AWS STS quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>`_ in the *IAM User Guide* .
    .. epigraph::

       Because the body of the public key certificate, private key, and the certificate chain can be large, you should use POST rather than GET when calling ``UploadServerCertificate`` . For information about setting up signatures and authorization through the API, see `Signing AWS API requests <https://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html>`_ in the *AWS General Reference* . For general information about using the Query API with IAM, see `Calling the API by making HTTP query requests <https://docs.aws.amazon.com/IAM/latest/UserGuide/programming.html>`_ in the *IAM User Guide* .

    :cloudformationResource: AWS::IAM::ServerCertificate
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        cfn_server_certificate = iam.CfnServerCertificate(self, "MyCfnServerCertificate",
            certificate_body="certificateBody",
            certificate_chain="certificateChain",
            path="path",
            private_key="privateKey",
            server_certificate_name="serverCertificateName",
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
        certificate_body: typing.Optional[builtins.str] = None,
        certificate_chain: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        private_key: typing.Optional[builtins.str] = None,
        server_certificate_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::ServerCertificate``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param certificate_body: The contents of the public key certificate.
        :param certificate_chain: The contents of the public key certificate chain.
        :param path: The path for the server certificate. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters. .. epigraph:: If you are uploading a server certificate specifically for use with Amazon CloudFront distributions, you must specify a path using the ``path`` parameter. The path must begin with ``/cloudfront`` and must include a trailing slash (for example, ``/cloudfront/test/`` ).
        :param private_key: The contents of the private key in PEM-encoded format. The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following: - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` ) - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )
        :param server_certificate_name: The name for the server certificate. Do not include the path in this value. The name of the certificate cannot contain any spaces. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param tags: A list of tags that are attached to the server certificate. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        '''
        props = CfnServerCertificateProps(
            certificate_body=certificate_body,
            certificate_chain=certificate_chain,
            path=path,
            private_key=private_key,
            server_certificate_name=server_certificate_name,
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
        '''Returns the Amazon Resource Name (ARN) for the specified ``AWS::IAM::ServerCertificate`` resource.

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
        '''A list of tags that are attached to the server certificate.

        For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateBody")
    def certificate_body(self) -> typing.Optional[builtins.str]:
        '''The contents of the public key certificate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-certificatebody
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificateBody"))

    @certificate_body.setter
    def certificate_body(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "certificateBody", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateChain")
    def certificate_chain(self) -> typing.Optional[builtins.str]:
        '''The contents of the public key certificate chain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-certificatechain
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "certificateChain"))

    @certificate_chain.setter
    def certificate_chain(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "certificateChain", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the server certificate.

        For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        .. epigraph::

           If you are uploading a server certificate specifically for use with Amazon CloudFront distributions, you must specify a path using the ``path`` parameter. The path must begin with ``/cloudfront`` and must include a trailing slash (for example, ``/cloudfront/test/`` ).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "path"))

    @path.setter
    def path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="privateKey")
    def private_key(self) -> typing.Optional[builtins.str]:
        '''The contents of the private key in PEM-encoded format.

        The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following:

        - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range
        - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` )
        - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-privatekey
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "privateKey"))

    @private_key.setter
    def private_key(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "privateKey", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serverCertificateName")
    def server_certificate_name(self) -> typing.Optional[builtins.str]:
        '''The name for the server certificate.

        Do not include the path in this value. The name of the certificate cannot contain any spaces.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-servercertificatename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "serverCertificateName"))

    @server_certificate_name.setter
    def server_certificate_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "serverCertificateName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnServerCertificateProps",
    jsii_struct_bases=[],
    name_mapping={
        "certificate_body": "certificateBody",
        "certificate_chain": "certificateChain",
        "path": "path",
        "private_key": "privateKey",
        "server_certificate_name": "serverCertificateName",
        "tags": "tags",
    },
)
class CfnServerCertificateProps:
    def __init__(
        self,
        *,
        certificate_body: typing.Optional[builtins.str] = None,
        certificate_chain: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        private_key: typing.Optional[builtins.str] = None,
        server_certificate_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnServerCertificate``.

        :param certificate_body: The contents of the public key certificate.
        :param certificate_chain: The contents of the public key certificate chain.
        :param path: The path for the server certificate. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters. .. epigraph:: If you are uploading a server certificate specifically for use with Amazon CloudFront distributions, you must specify a path using the ``path`` parameter. The path must begin with ``/cloudfront`` and must include a trailing slash (for example, ``/cloudfront/test/`` ).
        :param private_key: The contents of the private key in PEM-encoded format. The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following: - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` ) - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )
        :param server_certificate_name: The name for the server certificate. Do not include the path in this value. The name of the certificate cannot contain any spaces. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param tags: A list of tags that are attached to the server certificate. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            cfn_server_certificate_props = iam.CfnServerCertificateProps(
                certificate_body="certificateBody",
                certificate_chain="certificateChain",
                path="path",
                private_key="privateKey",
                server_certificate_name="serverCertificateName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if certificate_body is not None:
            self._values["certificate_body"] = certificate_body
        if certificate_chain is not None:
            self._values["certificate_chain"] = certificate_chain
        if path is not None:
            self._values["path"] = path
        if private_key is not None:
            self._values["private_key"] = private_key
        if server_certificate_name is not None:
            self._values["server_certificate_name"] = server_certificate_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def certificate_body(self) -> typing.Optional[builtins.str]:
        '''The contents of the public key certificate.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-certificatebody
        '''
        result = self._values.get("certificate_body")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def certificate_chain(self) -> typing.Optional[builtins.str]:
        '''The contents of the public key certificate chain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-certificatechain
        '''
        result = self._values.get("certificate_chain")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the server certificate.

        For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        .. epigraph::

           If you are uploading a server certificate specifically for use with Amazon CloudFront distributions, you must specify a path using the ``path`` parameter. The path must begin with ``/cloudfront`` and must include a trailing slash (for example, ``/cloudfront/test/`` ).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def private_key(self) -> typing.Optional[builtins.str]:
        '''The contents of the private key in PEM-encoded format.

        The `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ used to validate this parameter is a string of characters consisting of the following:

        - Any printable ASCII character ranging from the space character ( ``\\ u0020`` ) through the end of the ASCII character range
        - The printable characters in the Basic Latin and Latin-1 Supplement character set (through ``\\ u00FF`` )
        - The special characters tab ( ``\\ u0009`` ), line feed ( ``\\ u000A`` ), and carriage return ( ``\\ u000D`` )

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-privatekey
        '''
        result = self._values.get("private_key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def server_certificate_name(self) -> typing.Optional[builtins.str]:
        '''The name for the server certificate.

        Do not include the path in this value. The name of the certificate cannot contain any spaces.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-servercertificatename
        '''
        result = self._values.get("server_certificate_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags that are attached to the server certificate.

        For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servercertificate.html#cfn-iam-servercertificate-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnServerCertificateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnServiceLinkedRole(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnServiceLinkedRole",
):
    '''A CloudFormation ``AWS::IAM::ServiceLinkedRole``.

    Creates an IAM role that is linked to a specific AWS service. The service controls the attached policies and when the role can be deleted. This helps ensure that the service is not broken by an unexpectedly changed or deleted role, which could put your AWS resources into an unknown state. Allowing the service to control the role helps improve service stability and proper cleanup when a service and its role are no longer needed. For more information, see `Using service-linked roles <https://docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html>`_ in the *IAM User Guide* .

    To attach a policy to this service-linked role, you must make the request using the AWS service that depends on this role.

    :cloudformationResource: AWS::IAM::ServiceLinkedRole
    :exampleMetadata: infused
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servicelinkedrole.html

    Example::

        slr = iam.CfnServiceLinkedRole(self, "ElasticSLR",
            aws_service_name="es.amazonaws.com"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        aws_service_name: builtins.str,
        custom_suffix: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::ServiceLinkedRole``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param aws_service_name: The service principal for the AWS service to which this role is attached. You use a string similar to a URL but without the http:// in front. For example: ``elasticbeanstalk.amazonaws.com`` . Service principals are unique and case-sensitive. To find the exact service principal for your service-linked role, see `AWS services that work with IAM <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html>`_ in the *IAM User Guide* . Look for the services that have *Yes* in the *Service-Linked Role* column. Choose the *Yes* link to view the service-linked role documentation for that service.
        :param custom_suffix: A string that you provide, which is combined with the service-provided prefix to form the complete role name. If you make multiple requests for the same service, then you must supply a different ``CustomSuffix`` for each request. Otherwise the request fails with a duplicate role name error. For example, you could add ``-1`` or ``-debug`` to the suffix. Some services do not support the ``CustomSuffix`` parameter. If you provide an optional suffix and the operation fails, try the operation again without the suffix.
        :param description: The description of the role.
        '''
        props = CfnServiceLinkedRoleProps(
            aws_service_name=aws_service_name,
            custom_suffix=custom_suffix,
            description=description,
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
    @jsii.member(jsii_name="awsServiceName")
    def aws_service_name(self) -> builtins.str:
        '''The service principal for the AWS service to which this role is attached.

        You use a string similar to a URL but without the http:// in front. For example: ``elasticbeanstalk.amazonaws.com`` .

        Service principals are unique and case-sensitive. To find the exact service principal for your service-linked role, see `AWS services that work with IAM <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html>`_ in the *IAM User Guide* . Look for the services that have *Yes* in the *Service-Linked Role* column. Choose the *Yes* link to view the service-linked role documentation for that service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servicelinkedrole.html#cfn-iam-servicelinkedrole-awsservicename
        '''
        return typing.cast(builtins.str, jsii.get(self, "awsServiceName"))

    @aws_service_name.setter
    def aws_service_name(self, value: builtins.str) -> None:
        jsii.set(self, "awsServiceName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="customSuffix")
    def custom_suffix(self) -> typing.Optional[builtins.str]:
        '''A string that you provide, which is combined with the service-provided prefix to form the complete role name.

        If you make multiple requests for the same service, then you must supply a different ``CustomSuffix`` for each request. Otherwise the request fails with a duplicate role name error. For example, you could add ``-1`` or ``-debug`` to the suffix.

        Some services do not support the ``CustomSuffix`` parameter. If you provide an optional suffix and the operation fails, try the operation again without the suffix.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servicelinkedrole.html#cfn-iam-servicelinkedrole-customsuffix
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "customSuffix"))

    @custom_suffix.setter
    def custom_suffix(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "customSuffix", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the role.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servicelinkedrole.html#cfn-iam-servicelinkedrole-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnServiceLinkedRoleProps",
    jsii_struct_bases=[],
    name_mapping={
        "aws_service_name": "awsServiceName",
        "custom_suffix": "customSuffix",
        "description": "description",
    },
)
class CfnServiceLinkedRoleProps:
    def __init__(
        self,
        *,
        aws_service_name: builtins.str,
        custom_suffix: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnServiceLinkedRole``.

        :param aws_service_name: The service principal for the AWS service to which this role is attached. You use a string similar to a URL but without the http:// in front. For example: ``elasticbeanstalk.amazonaws.com`` . Service principals are unique and case-sensitive. To find the exact service principal for your service-linked role, see `AWS services that work with IAM <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html>`_ in the *IAM User Guide* . Look for the services that have *Yes* in the *Service-Linked Role* column. Choose the *Yes* link to view the service-linked role documentation for that service.
        :param custom_suffix: A string that you provide, which is combined with the service-provided prefix to form the complete role name. If you make multiple requests for the same service, then you must supply a different ``CustomSuffix`` for each request. Otherwise the request fails with a duplicate role name error. For example, you could add ``-1`` or ``-debug`` to the suffix. Some services do not support the ``CustomSuffix`` parameter. If you provide an optional suffix and the operation fails, try the operation again without the suffix.
        :param description: The description of the role.

        :exampleMetadata: infused
        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servicelinkedrole.html

        Example::

            slr = iam.CfnServiceLinkedRole(self, "ElasticSLR",
                aws_service_name="es.amazonaws.com"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "aws_service_name": aws_service_name,
        }
        if custom_suffix is not None:
            self._values["custom_suffix"] = custom_suffix
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def aws_service_name(self) -> builtins.str:
        '''The service principal for the AWS service to which this role is attached.

        You use a string similar to a URL but without the http:// in front. For example: ``elasticbeanstalk.amazonaws.com`` .

        Service principals are unique and case-sensitive. To find the exact service principal for your service-linked role, see `AWS services that work with IAM <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html>`_ in the *IAM User Guide* . Look for the services that have *Yes* in the *Service-Linked Role* column. Choose the *Yes* link to view the service-linked role documentation for that service.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servicelinkedrole.html#cfn-iam-servicelinkedrole-awsservicename
        '''
        result = self._values.get("aws_service_name")
        assert result is not None, "Required property 'aws_service_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def custom_suffix(self) -> typing.Optional[builtins.str]:
        '''A string that you provide, which is combined with the service-provided prefix to form the complete role name.

        If you make multiple requests for the same service, then you must supply a different ``CustomSuffix`` for each request. Otherwise the request fails with a duplicate role name error. For example, you could add ``-1`` or ``-debug`` to the suffix.

        Some services do not support the ``CustomSuffix`` parameter. If you provide an optional suffix and the operation fails, try the operation again without the suffix.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servicelinkedrole.html#cfn-iam-servicelinkedrole-customsuffix
        '''
        result = self._values.get("custom_suffix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the role.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-servicelinkedrole.html#cfn-iam-servicelinkedrole-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnServiceLinkedRoleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUser(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnUser",
):
    '''A CloudFormation ``AWS::IAM::User``.

    Creates a new IAM user for your AWS account .

    For information about quotas for the number of IAM users you can create, see `IAM and AWS STS quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>`_ in the *IAM User Guide* .

    :cloudformationResource: AWS::IAM::User
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # policy_document: Any
        
        cfn_user = iam.CfnUser(self, "MyCfnUser",
            groups=["groups"],
            login_profile=iam.CfnUser.LoginProfileProperty(
                password="password",
        
                # the properties below are optional
                password_reset_required=False
            ),
            managed_policy_arns=["managedPolicyArns"],
            path="path",
            permissions_boundary="permissionsBoundary",
            policies=[iam.CfnUser.PolicyProperty(
                policy_document=policy_document,
                policy_name="policyName"
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            user_name="userName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        login_profile: typing.Optional[typing.Union["CfnUser.LoginProfileProperty", _IResolvable_da3f097b]] = None,
        managed_policy_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[builtins.str] = None,
        policies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnUser.PolicyProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        user_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::User``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param groups: A list of group names to which you want to add the user.
        :param login_profile: Creates a password for the specified IAM user. A password allows an IAM user to access AWS services through the AWS Management Console . You can use the AWS CLI , the AWS API, or the *Users* page in the IAM console to create a password for any IAM user. Use `ChangePassword <https://docs.aws.amazon.com/IAM/latest/APIReference/API_ChangePassword.html>`_ to update your own existing password in the *My Security Credentials* page in the AWS Management Console . For more information about managing passwords, see `Managing passwords <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingLogins.html>`_ in the *IAM User Guide* .
        :param managed_policy_arns: A list of Amazon Resource Names (ARNs) of the IAM managed policies that you want to attach to the user. For more information about ARNs, see `Amazon Resource Names (ARNs) and AWS Service Namespaces <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .
        :param path: The path for the user name. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        :param permissions_boundary: The ARN of the policy that is used to set the permissions boundary for the user.
        :param policies: Adds or updates an inline policy document that is embedded in the specified IAM user. To view AWS::IAM::User snippets, see `Declaring an IAM User Resource <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-user>`_ . .. epigraph:: The name of each policy for a role, user, or group must be unique. If you don't choose unique names, updates to the IAM identity will fail. For information about limits on the number of inline policies that you can embed in a user, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .
        :param tags: A list of tags that you want to attach to the new user. Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* . .. epigraph:: If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.
        :param user_name: The name of the user to create. Do not include the path in this value. This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. The user name must be unique within the account. User names are not distinguished by case. For example, you cannot create users named both "John" and "john". If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the user name. If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ . .. epigraph:: Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .
        '''
        props = CfnUserProps(
            groups=groups,
            login_profile=login_profile,
            managed_policy_arns=managed_policy_arns,
            path=path,
            permissions_boundary=permissions_boundary,
            policies=policies,
            tags=tags,
            user_name=user_name,
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
        '''Returns the Amazon Resource Name (ARN) for the specified ``AWS::IAM::User`` resource.

        For example: ``arn:aws:iam::123456789012:user/mystack-myuser-1CCXAFG2H2U4D`` .

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
        '''A list of tags that you want to attach to the new user.

        Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        .. epigraph::

           If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groups")
    def groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of group names to which you want to add the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-groups
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "groups"))

    @groups.setter
    def groups(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "groups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loginProfile")
    def login_profile(
        self,
    ) -> typing.Optional[typing.Union["CfnUser.LoginProfileProperty", _IResolvable_da3f097b]]:
        '''Creates a password for the specified IAM user.

        A password allows an IAM user to access AWS services through the AWS Management Console .

        You can use the AWS CLI , the AWS API, or the *Users* page in the IAM console to create a password for any IAM user. Use `ChangePassword <https://docs.aws.amazon.com/IAM/latest/APIReference/API_ChangePassword.html>`_ to update your own existing password in the *My Security Credentials* page in the AWS Management Console .

        For more information about managing passwords, see `Managing passwords <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingLogins.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-loginprofile
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUser.LoginProfileProperty", _IResolvable_da3f097b]], jsii.get(self, "loginProfile"))

    @login_profile.setter
    def login_profile(
        self,
        value: typing.Optional[typing.Union["CfnUser.LoginProfileProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "loginProfile", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedPolicyArns")
    def managed_policy_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Amazon Resource Names (ARNs) of the IAM managed policies that you want to attach to the user.

        For more information about ARNs, see `Amazon Resource Names (ARNs) and AWS Service Namespaces <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-managepolicyarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "managedPolicyArns"))

    @managed_policy_arns.setter
    def managed_policy_arns(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "managedPolicyArns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the user name.

        For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "path"))

    @path.setter
    def path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissionsBoundary")
    def permissions_boundary(self) -> typing.Optional[builtins.str]:
        '''The ARN of the policy that is used to set the permissions boundary for the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-permissionsboundary
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "permissionsBoundary"))

    @permissions_boundary.setter
    def permissions_boundary(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "permissionsBoundary", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policies")
    def policies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUser.PolicyProperty", _IResolvable_da3f097b]]]]:
        '''Adds or updates an inline policy document that is embedded in the specified IAM user.

        To view AWS::IAM::User snippets, see `Declaring an IAM User Resource <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-user>`_ .
        .. epigraph::

           The name of each policy for a role, user, or group must be unique. If you don't choose unique names, updates to the IAM identity will fail.

        For information about limits on the number of inline policies that you can embed in a user, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-policies
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUser.PolicyProperty", _IResolvable_da3f097b]]]], jsii.get(self, "policies"))

    @policies.setter
    def policies(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUser.PolicyProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "policies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> typing.Optional[builtins.str]:
        '''The name of the user to create. Do not include the path in this value.

        This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. The user name must be unique within the account. User names are not distinguished by case. For example, you cannot create users named both "John" and "john".

        If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the user name.

        If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ .
        .. epigraph::

           Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-username
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "userName"))

    @user_name.setter
    def user_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "userName", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iam.CfnUser.LoginProfileProperty",
        jsii_struct_bases=[],
        name_mapping={
            "password": "password",
            "password_reset_required": "passwordResetRequired",
        },
    )
    class LoginProfileProperty:
        def __init__(
            self,
            *,
            password: builtins.str,
            password_reset_required: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Creates a password for the specified user, giving the user the ability to access AWS services through the AWS Management Console .

            For more information about managing passwords, see `Managing Passwords <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingLogins.html>`_ in the *IAM User Guide* .

            :param password: The user's password.
            :param password_reset_required: Specifies whether the user is required to set a new password on next sign-in.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user-loginprofile.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iam as iam
                
                login_profile_property = iam.CfnUser.LoginProfileProperty(
                    password="password",
                
                    # the properties below are optional
                    password_reset_required=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
            }
            if password_reset_required is not None:
                self._values["password_reset_required"] = password_reset_required

        @builtins.property
        def password(self) -> builtins.str:
            '''The user's password.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user-loginprofile.html#cfn-iam-user-loginprofile-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def password_reset_required(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether the user is required to set a new password on next sign-in.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user-loginprofile.html#cfn-iam-user-loginprofile-passwordresetrequired
            '''
            result = self._values.get("password_reset_required")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoginProfileProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_iam.CfnUser.PolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "policy_document": "policyDocument",
            "policy_name": "policyName",
        },
    )
    class PolicyProperty:
        def __init__(
            self,
            *,
            policy_document: typing.Any,
            policy_name: builtins.str,
        ) -> None:
            '''Contains information about an attached policy.

            An attached policy is a managed policy that has been attached to a user, group, or role.

            For more information about managed policies, refer to `Managed Policies and Inline Policies <https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html>`_ in the *IAM User Guide* .

            :param policy_document: The policy document.
            :param policy_name: The friendly name (not ARN) identifying the policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_iam as iam
                
                # policy_document: Any
                
                policy_property = iam.CfnUser.PolicyProperty(
                    policy_document=policy_document,
                    policy_name="policyName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "policy_document": policy_document,
                "policy_name": policy_name,
            }

        @builtins.property
        def policy_document(self) -> typing.Any:
            '''The policy document.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html#cfn-iam-policies-policydocument
            '''
            result = self._values.get("policy_document")
            assert result is not None, "Required property 'policy_document' is missing"
            return typing.cast(typing.Any, result)

        @builtins.property
        def policy_name(self) -> builtins.str:
            '''The friendly name (not ARN) identifying the policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html#cfn-iam-policies-policyname
            '''
            result = self._values.get("policy_name")
            assert result is not None, "Required property 'policy_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnUserProps",
    jsii_struct_bases=[],
    name_mapping={
        "groups": "groups",
        "login_profile": "loginProfile",
        "managed_policy_arns": "managedPolicyArns",
        "path": "path",
        "permissions_boundary": "permissionsBoundary",
        "policies": "policies",
        "tags": "tags",
        "user_name": "userName",
    },
)
class CfnUserProps:
    def __init__(
        self,
        *,
        groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        login_profile: typing.Optional[typing.Union[CfnUser.LoginProfileProperty, _IResolvable_da3f097b]] = None,
        managed_policy_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[builtins.str] = None,
        policies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnUser.PolicyProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        user_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnUser``.

        :param groups: A list of group names to which you want to add the user.
        :param login_profile: Creates a password for the specified IAM user. A password allows an IAM user to access AWS services through the AWS Management Console . You can use the AWS CLI , the AWS API, or the *Users* page in the IAM console to create a password for any IAM user. Use `ChangePassword <https://docs.aws.amazon.com/IAM/latest/APIReference/API_ChangePassword.html>`_ to update your own existing password in the *My Security Credentials* page in the AWS Management Console . For more information about managing passwords, see `Managing passwords <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingLogins.html>`_ in the *IAM User Guide* .
        :param managed_policy_arns: A list of Amazon Resource Names (ARNs) of the IAM managed policies that you want to attach to the user. For more information about ARNs, see `Amazon Resource Names (ARNs) and AWS Service Namespaces <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .
        :param path: The path for the user name. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        :param permissions_boundary: The ARN of the policy that is used to set the permissions boundary for the user.
        :param policies: Adds or updates an inline policy document that is embedded in the specified IAM user. To view AWS::IAM::User snippets, see `Declaring an IAM User Resource <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-user>`_ . .. epigraph:: The name of each policy for a role, user, or group must be unique. If you don't choose unique names, updates to the IAM identity will fail. For information about limits on the number of inline policies that you can embed in a user, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .
        :param tags: A list of tags that you want to attach to the new user. Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* . .. epigraph:: If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.
        :param user_name: The name of the user to create. Do not include the path in this value. This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. The user name must be unique within the account. User names are not distinguished by case. For example, you cannot create users named both "John" and "john". If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the user name. If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ . .. epigraph:: Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # policy_document: Any
            
            cfn_user_props = iam.CfnUserProps(
                groups=["groups"],
                login_profile=iam.CfnUser.LoginProfileProperty(
                    password="password",
            
                    # the properties below are optional
                    password_reset_required=False
                ),
                managed_policy_arns=["managedPolicyArns"],
                path="path",
                permissions_boundary="permissionsBoundary",
                policies=[iam.CfnUser.PolicyProperty(
                    policy_document=policy_document,
                    policy_name="policyName"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                user_name="userName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if groups is not None:
            self._values["groups"] = groups
        if login_profile is not None:
            self._values["login_profile"] = login_profile
        if managed_policy_arns is not None:
            self._values["managed_policy_arns"] = managed_policy_arns
        if path is not None:
            self._values["path"] = path
        if permissions_boundary is not None:
            self._values["permissions_boundary"] = permissions_boundary
        if policies is not None:
            self._values["policies"] = policies
        if tags is not None:
            self._values["tags"] = tags
        if user_name is not None:
            self._values["user_name"] = user_name

    @builtins.property
    def groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of group names to which you want to add the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-groups
        '''
        result = self._values.get("groups")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def login_profile(
        self,
    ) -> typing.Optional[typing.Union[CfnUser.LoginProfileProperty, _IResolvable_da3f097b]]:
        '''Creates a password for the specified IAM user.

        A password allows an IAM user to access AWS services through the AWS Management Console .

        You can use the AWS CLI , the AWS API, or the *Users* page in the IAM console to create a password for any IAM user. Use `ChangePassword <https://docs.aws.amazon.com/IAM/latest/APIReference/API_ChangePassword.html>`_ to update your own existing password in the *My Security Credentials* page in the AWS Management Console .

        For more information about managing passwords, see `Managing passwords <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingLogins.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-loginprofile
        '''
        result = self._values.get("login_profile")
        return typing.cast(typing.Optional[typing.Union[CfnUser.LoginProfileProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def managed_policy_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Amazon Resource Names (ARNs) of the IAM managed policies that you want to attach to the user.

        For more information about ARNs, see `Amazon Resource Names (ARNs) and AWS Service Namespaces <https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html>`_ in the *AWS General Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-managepolicyarns
        '''
        result = self._values.get("managed_policy_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the user name.

        For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions_boundary(self) -> typing.Optional[builtins.str]:
        '''The ARN of the policy that is used to set the permissions boundary for the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-permissionsboundary
        '''
        result = self._values.get("permissions_boundary")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def policies(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUser.PolicyProperty, _IResolvable_da3f097b]]]]:
        '''Adds or updates an inline policy document that is embedded in the specified IAM user.

        To view AWS::IAM::User snippets, see `Declaring an IAM User Resource <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-user>`_ .
        .. epigraph::

           The name of each policy for a role, user, or group must be unique. If you don't choose unique names, updates to the IAM identity will fail.

        For information about limits on the number of inline policies that you can embed in a user, see `Limitations on IAM Entities <https://docs.aws.amazon.com/IAM/latest/UserGuide/LimitationsOnEntities.html>`_ in the *IAM User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-policies
        '''
        result = self._values.get("policies")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUser.PolicyProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags that you want to attach to the new user.

        Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        .. epigraph::

           If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def user_name(self) -> typing.Optional[builtins.str]:
        '''The name of the user to create. Do not include the path in this value.

        This parameter allows (per its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-. The user name must be unique within the account. User names are not distinguished by case. For example, you cannot create users named both "John" and "john".

        If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the user name.

        If you specify a name, you must specify the ``CAPABILITY_NAMED_IAM`` value to acknowledge your template's capabilities. For more information, see `Acknowledging IAM Resources in AWS CloudFormation Templates <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#using-iam-capabilities>`_ .
        .. epigraph::

           Naming an IAM resource can cause an unrecoverable error if you reuse the same template in multiple Regions. To prevent this, we recommend using ``Fn::Join`` and ``AWS::Region`` to create a Region-specific name, as in the following example: ``{"Fn::Join": ["", [{"Ref": "AWS::Region"}, {"Ref": "MyResourceName"}]]}`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html#cfn-iam-user-username
        '''
        result = self._values.get("user_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserToGroupAddition(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnUserToGroupAddition",
):
    '''A CloudFormation ``AWS::IAM::UserToGroupAddition``.

    Adds the specified user to the specified group.

    :cloudformationResource: AWS::IAM::UserToGroupAddition
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        cfn_user_to_group_addition = iam.CfnUserToGroupAddition(self, "MyCfnUserToGroupAddition",
            group_name="groupName",
            users=["users"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        group_name: builtins.str,
        users: typing.Sequence[builtins.str],
    ) -> None:
        '''Create a new ``AWS::IAM::UserToGroupAddition``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param group_name: The name of the group to update. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param users: A list of the names of the users that you want to add to the group.
        '''
        props = CfnUserToGroupAdditionProps(group_name=group_name, users=users)

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
    @jsii.member(jsii_name="groupName")
    def group_name(self) -> builtins.str:
        '''The name of the group to update.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html#cfn-iam-addusertogroup-groupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "groupName"))

    @group_name.setter
    def group_name(self, value: builtins.str) -> None:
        jsii.set(self, "groupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="users")
    def users(self) -> typing.List[builtins.str]:
        '''A list of the names of the users that you want to add to the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html#cfn-iam-addusertogroup-users
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "users"))

    @users.setter
    def users(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "users", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnUserToGroupAdditionProps",
    jsii_struct_bases=[],
    name_mapping={"group_name": "groupName", "users": "users"},
)
class CfnUserToGroupAdditionProps:
    def __init__(
        self,
        *,
        group_name: builtins.str,
        users: typing.Sequence[builtins.str],
    ) -> None:
        '''Properties for defining a ``CfnUserToGroupAddition``.

        :param group_name: The name of the group to update. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        :param users: A list of the names of the users that you want to add to the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            cfn_user_to_group_addition_props = iam.CfnUserToGroupAdditionProps(
                group_name="groupName",
                users=["users"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "group_name": group_name,
            "users": users,
        }

    @builtins.property
    def group_name(self) -> builtins.str:
        '''The name of the group to update.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html#cfn-iam-addusertogroup-groupname
        '''
        result = self._values.get("group_name")
        assert result is not None, "Required property 'group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def users(self) -> typing.List[builtins.str]:
        '''A list of the names of the users that you want to add to the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html#cfn-iam-addusertogroup-users
        '''
        result = self._values.get("users")
        assert result is not None, "Required property 'users' is missing"
        return typing.cast(typing.List[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserToGroupAdditionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnVirtualMFADevice(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CfnVirtualMFADevice",
):
    '''A CloudFormation ``AWS::IAM::VirtualMFADevice``.

    Creates a new virtual MFA device for the AWS account . After creating the virtual MFA, use `EnableMFADevice <https://docs.aws.amazon.com/IAM/latest/APIReference/API_EnableMFADevice.html>`_ to attach the MFA device to an IAM user. For more information about creating and working with virtual MFA devices, see `Using a virtual MFA device <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_VirtualMFA.html>`_ in the *IAM User Guide* .

    For information about the maximum number of MFA devices you can create, see `IAM and AWS STS quotas <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html>`_ in the *IAM User Guide* .
    .. epigraph::

       The seed information contained in the QR code and the Base32 string should be treated like any other secret access information. In other words, protect the seed information as you would your AWS access keys or your passwords. After you provision your virtual device, you should ensure that the information is destroyed following secure procedures.

    :cloudformationResource: AWS::IAM::VirtualMFADevice
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        cfn_virtual_mFADevice = iam.CfnVirtualMFADevice(self, "MyCfnVirtualMFADevice",
            users=["users"],
        
            # the properties below are optional
            path="path",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            virtual_mfa_device_name="virtualMfaDeviceName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        users: typing.Sequence[builtins.str],
        path: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        virtual_mfa_device_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::IAM::VirtualMFADevice``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param users: The IAM user associated with this virtual MFA device.
        :param path: The path for the virtual MFA device. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        :param tags: A list of tags that you want to attach to the new IAM virtual MFA device. Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* . .. epigraph:: If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.
        :param virtual_mfa_device_name: The name of the virtual MFA device. Use with path to uniquely identify a virtual MFA device. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-
        '''
        props = CfnVirtualMFADeviceProps(
            users=users,
            path=path,
            tags=tags,
            virtual_mfa_device_name=virtual_mfa_device_name,
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
    @jsii.member(jsii_name="attrSerialNumber")
    def attr_serial_number(self) -> builtins.str:
        '''Returns the serial number for the specified ``AWS::IAM::VirtualMFADevice`` resource.

        :cloudformationAttribute: SerialNumber
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSerialNumber"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A list of tags that you want to attach to the new IAM virtual MFA device.

        Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        .. epigraph::

           If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html#cfn-iam-virtualmfadevice-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="users")
    def users(self) -> typing.List[builtins.str]:
        '''The IAM user associated with this virtual MFA device.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html#cfn-iam-virtualmfadevice-users
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "users"))

    @users.setter
    def users(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "users", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the virtual MFA device.

        For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html#cfn-iam-virtualmfadevice-path
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "path"))

    @path.setter
    def path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "path", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="virtualMfaDeviceName")
    def virtual_mfa_device_name(self) -> typing.Optional[builtins.str]:
        '''The name of the virtual MFA device. Use with path to uniquely identify a virtual MFA device.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html#cfn-iam-virtualmfadevice-virtualmfadevicename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "virtualMfaDeviceName"))

    @virtual_mfa_device_name.setter
    def virtual_mfa_device_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "virtualMfaDeviceName", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CfnVirtualMFADeviceProps",
    jsii_struct_bases=[],
    name_mapping={
        "users": "users",
        "path": "path",
        "tags": "tags",
        "virtual_mfa_device_name": "virtualMfaDeviceName",
    },
)
class CfnVirtualMFADeviceProps:
    def __init__(
        self,
        *,
        users: typing.Sequence[builtins.str],
        path: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        virtual_mfa_device_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnVirtualMFADevice``.

        :param users: The IAM user associated with this virtual MFA device.
        :param path: The path for the virtual MFA device. For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* . This parameter is optional. If it is not included, it defaults to a slash (/). This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.
        :param tags: A list of tags that you want to attach to the new IAM virtual MFA device. Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* . .. epigraph:: If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.
        :param virtual_mfa_device_name: The name of the virtual MFA device. Use with path to uniquely identify a virtual MFA device. This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            cfn_virtual_mFADevice_props = iam.CfnVirtualMFADeviceProps(
                users=["users"],
            
                # the properties below are optional
                path="path",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                virtual_mfa_device_name="virtualMfaDeviceName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "users": users,
        }
        if path is not None:
            self._values["path"] = path
        if tags is not None:
            self._values["tags"] = tags
        if virtual_mfa_device_name is not None:
            self._values["virtual_mfa_device_name"] = virtual_mfa_device_name

    @builtins.property
    def users(self) -> typing.List[builtins.str]:
        '''The IAM user associated with this virtual MFA device.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html#cfn-iam-virtualmfadevice-users
        '''
        result = self._values.get("users")
        assert result is not None, "Required property 'users' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the virtual MFA device.

        For more information about paths, see `IAM identifiers <https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html>`_ in the *IAM User Guide* .

        This parameter is optional. If it is not included, it defaults to a slash (/).

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! ( ``\\ u0021`` ) through the DEL character ( ``\\ u007F`` ), including most punctuation characters, digits, and upper and lowercased letters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html#cfn-iam-virtualmfadevice-path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags that you want to attach to the new IAM virtual MFA device.

        Each tag consists of a key name and an associated value. For more information about tagging, see `Tagging IAM resources <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html>`_ in the *IAM User Guide* .
        .. epigraph::

           If any one of the tags is invalid or if you exceed the allowed maximum number of tags, then the entire request fails and the resource is not created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html#cfn-iam-virtualmfadevice-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def virtual_mfa_device_name(self) -> typing.Optional[builtins.str]:
        '''The name of the virtual MFA device. Use with path to uniquely identify a virtual MFA device.

        This parameter allows (through its `regex pattern <https://docs.aws.amazon.com/http://wikipedia.org/wiki/regex>`_ ) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-virtualmfadevice.html#cfn-iam-virtualmfadevice-virtualmfadevicename
        '''
        result = self._values.get("virtual_mfa_device_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnVirtualMFADeviceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.CommonGrantOptions",
    jsii_struct_bases=[],
    name_mapping={
        "actions": "actions",
        "grantee": "grantee",
        "resource_arns": "resourceArns",
    },
)
class CommonGrantOptions:
    def __init__(
        self,
        *,
        actions: typing.Sequence[builtins.str],
        grantee: "IGrantable",
        resource_arns: typing.Sequence[builtins.str],
    ) -> None:
        '''Basic options for a grant operation.

        :param actions: The actions to grant.
        :param grantee: The principal to grant to. Default: if principal is undefined, no work is done.
        :param resource_arns: The resource ARNs to grant to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # grantable: iam.IGrantable
            
            common_grant_options = iam.CommonGrantOptions(
                actions=["actions"],
                grantee=grantable,
                resource_arns=["resourceArns"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "actions": actions,
            "grantee": grantee,
            "resource_arns": resource_arns,
        }

    @builtins.property
    def actions(self) -> typing.List[builtins.str]:
        '''The actions to grant.'''
        result = self._values.get("actions")
        assert result is not None, "Required property 'actions' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def grantee(self) -> "IGrantable":
        '''The principal to grant to.

        :default: if principal is undefined, no work is done.
        '''
        result = self._values.get("grantee")
        assert result is not None, "Required property 'grantee' is missing"
        return typing.cast("IGrantable", result)

    @builtins.property
    def resource_arns(self) -> typing.List[builtins.str]:
        '''The resource ARNs to grant to.'''
        result = self._values.get("resource_arns")
        assert result is not None, "Required property 'resource_arns' is missing"
        return typing.cast(typing.List[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CommonGrantOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(constructs.IDependable)
class CompositeDependable(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CompositeDependable",
):
    '''Composite dependable.

    Not as simple as eagerly getting the dependency roots from the
    inner dependables, as they may be mutable so we need to defer
    the query.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        import constructs as constructs
        
        # dependable: constructs.IDependable
        
        composite_dependable = iam.CompositeDependable(dependable)
    '''

    def __init__(self, *dependables: constructs.IDependable) -> None:
        '''
        :param dependables: -
        '''
        jsii.create(self.__class__, self, [*dependables])


@jsii.enum(jsii_type="aws-cdk-lib.aws_iam.Effect")
class Effect(enum.Enum):
    '''The Effect element of an IAM policy.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_effect.html
    :exampleMetadata: infused

    Example::

        # books: apigateway.Resource
        # iam_user: iam.User
        
        
        get_books = books.add_method("GET", apigateway.HttpIntegration("http://amazon.com"),
            authorization_type=apigateway.AuthorizationType.IAM
        )
        
        iam_user.attach_inline_policy(iam.Policy(self, "AllowBooks",
            statements=[
                iam.PolicyStatement(
                    actions=["execute-api:Invoke"],
                    effect=iam.Effect.ALLOW,
                    resources=[get_books.method_arn]
                )
            ]
        ))
    '''

    ALLOW = "ALLOW"
    '''Allows access to a resource in an IAM policy statement.

    By default, access to resources are denied.
    '''
    DENY = "DENY"
    '''Explicitly deny access to a resource.

    By default, all requests are denied implicitly.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    '''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.FromRoleArnOptions",
    jsii_struct_bases=[],
    name_mapping={
        "add_grants_to_resources": "addGrantsToResources",
        "mutable": "mutable",
    },
)
class FromRoleArnOptions:
    def __init__(
        self,
        *,
        add_grants_to_resources: typing.Optional[builtins.bool] = None,
        mutable: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Options allowing customizing the behavior of {@link Role.fromRoleArn}.

        :param add_grants_to_resources: For immutable roles: add grants to resources instead of dropping them. If this is ``false`` or not specified, grant permissions added to this role are ignored. It is your own responsibility to make sure the role has the required permissions. If this is ``true``, any grant permissions will be added to the resource instead. Default: false
        :param mutable: Whether the imported role can be modified by attaching policy resources to it. Default: true

        :exampleMetadata: infused

        Example::

            role = iam.Role.from_role_arn(self, "Role", "arn:aws:iam::123456789012:role/MyExistingRole",
                # Set 'mutable' to 'false' to use the role as-is and prevent adding new
                # policies to it. The default is 'true', which means the role may be
                # modified as part of the deployment.
                mutable=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if add_grants_to_resources is not None:
            self._values["add_grants_to_resources"] = add_grants_to_resources
        if mutable is not None:
            self._values["mutable"] = mutable

    @builtins.property
    def add_grants_to_resources(self) -> typing.Optional[builtins.bool]:
        '''For immutable roles: add grants to resources instead of dropping them.

        If this is ``false`` or not specified, grant permissions added to this role are ignored.
        It is your own responsibility to make sure the role has the required permissions.

        If this is ``true``, any grant permissions will be added to the resource instead.

        :default: false
        '''
        result = self._values.get("add_grants_to_resources")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def mutable(self) -> typing.Optional[builtins.bool]:
        '''Whether the imported role can be modified by attaching policy resources to it.

        :default: true
        '''
        result = self._values.get("mutable")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FromRoleArnOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(constructs.IDependable)
class Grant(metaclass=jsii.JSIIMeta, jsii_type="aws-cdk-lib.aws_iam.Grant"):
    '''Result of a grant() operation.

    This class is not instantiable by consumers on purpose, so that they will be
    required to call the Grant factory functions.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        # instance: ec2.Instance
        # volume: ec2.Volume
        
        
        attach_grant = volume.grant_attach_volume_by_resource_tag(instance.grant_principal, [instance])
        detach_grant = volume.grant_detach_volume_by_resource_tag(instance.grant_principal, [instance])
    '''

    @jsii.member(jsii_name="addToPrincipal") # type: ignore[misc]
    @builtins.classmethod
    def add_to_principal(
        cls,
        *,
        scope: typing.Optional[constructs.IConstruct] = None,
        actions: typing.Sequence[builtins.str],
        grantee: "IGrantable",
        resource_arns: typing.Sequence[builtins.str],
    ) -> "Grant":
        '''Try to grant the given permissions to the given principal.

        Absence of a principal leads to a warning, but failing to add
        the permissions to a present principal is not an error.

        :param scope: Construct to report warnings on in case grant could not be registered. Default: - the construct in which this construct is defined
        :param actions: The actions to grant.
        :param grantee: The principal to grant to. Default: if principal is undefined, no work is done.
        :param resource_arns: The resource ARNs to grant to.
        '''
        options = GrantOnPrincipalOptions(
            scope=scope, actions=actions, grantee=grantee, resource_arns=resource_arns
        )

        return typing.cast("Grant", jsii.sinvoke(cls, "addToPrincipal", [options]))

    @jsii.member(jsii_name="addToPrincipalAndResource") # type: ignore[misc]
    @builtins.classmethod
    def add_to_principal_and_resource(
        cls,
        *,
        resource: "IResourceWithPolicy",
        resource_policy_principal: typing.Optional["IPrincipal"] = None,
        resource_self_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        actions: typing.Sequence[builtins.str],
        grantee: "IGrantable",
        resource_arns: typing.Sequence[builtins.str],
    ) -> "Grant":
        '''Add a grant both on the principal and on the resource.

        As long as any principal is given, granting on the principal may fail (in
        case of a non-identity principal), but granting on the resource will
        never fail.

        Statement will be the resource statement.

        :param resource: The resource with a resource policy. The statement will always be added to the resource policy.
        :param resource_policy_principal: The principal to use in the statement for the resource policy. Default: - the principal of the grantee will be used
        :param resource_self_arns: When referring to the resource in a resource policy, use this as ARN. (Depending on the resource type, this needs to be '*' in a resource policy). Default: Same as regular resource ARNs
        :param actions: The actions to grant.
        :param grantee: The principal to grant to. Default: if principal is undefined, no work is done.
        :param resource_arns: The resource ARNs to grant to.
        '''
        options = GrantOnPrincipalAndResourceOptions(
            resource=resource,
            resource_policy_principal=resource_policy_principal,
            resource_self_arns=resource_self_arns,
            actions=actions,
            grantee=grantee,
            resource_arns=resource_arns,
        )

        return typing.cast("Grant", jsii.sinvoke(cls, "addToPrincipalAndResource", [options]))

    @jsii.member(jsii_name="addToPrincipalOrResource") # type: ignore[misc]
    @builtins.classmethod
    def add_to_principal_or_resource(
        cls,
        *,
        resource: "IResourceWithPolicy",
        resource_self_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        actions: typing.Sequence[builtins.str],
        grantee: "IGrantable",
        resource_arns: typing.Sequence[builtins.str],
    ) -> "Grant":
        '''Grant the given permissions to the principal.

        The permissions will be added to the principal policy primarily, falling
        back to the resource policy if necessary. The permissions must be granted
        somewhere.

        - Trying to grant permissions to a principal that does not admit adding to
          the principal policy while not providing a resource with a resource policy
          is an error.
        - Trying to grant permissions to an absent principal (possible in the
          case of imported resources) leads to a warning being added to the
          resource construct.

        :param resource: The resource with a resource policy. The statement will be added to the resource policy if it couldn't be added to the principal policy.
        :param resource_self_arns: When referring to the resource in a resource policy, use this as ARN. (Depending on the resource type, this needs to be '*' in a resource policy). Default: Same as regular resource ARNs
        :param actions: The actions to grant.
        :param grantee: The principal to grant to. Default: if principal is undefined, no work is done.
        :param resource_arns: The resource ARNs to grant to.
        '''
        options = GrantWithResourceOptions(
            resource=resource,
            resource_self_arns=resource_self_arns,
            actions=actions,
            grantee=grantee,
            resource_arns=resource_arns,
        )

        return typing.cast("Grant", jsii.sinvoke(cls, "addToPrincipalOrResource", [options]))

    @jsii.member(jsii_name="drop") # type: ignore[misc]
    @builtins.classmethod
    def drop(cls, grantee: "IGrantable", _intent: builtins.str) -> "Grant":
        '''Returns a "no-op" ``Grant`` object which represents a "dropped grant".

        This can be used for e.g. imported resources where you may not be able to modify
        the resource's policy or some underlying policy which you don't know about.

        :param grantee: The intended grantee.
        :param _intent: The user's intent (will be ignored at the moment).
        '''
        return typing.cast("Grant", jsii.sinvoke(cls, "drop", [grantee, _intent]))

    @jsii.member(jsii_name="applyBefore")
    def apply_before(self, *constructs: constructs.IConstruct) -> None:
        '''Make sure this grant is applied before the given constructs are deployed.

        The same as construct.node.addDependency(grant), but slightly nicer to read.

        :param constructs: -
        '''
        return typing.cast(None, jsii.invoke(self, "applyBefore", [*constructs]))

    @jsii.member(jsii_name="assertSuccess")
    def assert_success(self) -> None:
        '''Throw an error if this grant wasn't successful.'''
        return typing.cast(None, jsii.invoke(self, "assertSuccess", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="success")
    def success(self) -> builtins.bool:
        '''Whether the grant operation was successful.'''
        return typing.cast(builtins.bool, jsii.get(self, "success"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalStatement")
    def principal_statement(self) -> typing.Optional["PolicyStatement"]:
        '''The statement that was added to the principal's policy.

        Can be accessed to (e.g.) add additional conditions to the statement.
        '''
        return typing.cast(typing.Optional["PolicyStatement"], jsii.get(self, "principalStatement"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourceStatement")
    def resource_statement(self) -> typing.Optional["PolicyStatement"]:
        '''The statement that was added to the resource policy.

        Can be accessed to (e.g.) add additional conditions to the statement.
        '''
        return typing.cast(typing.Optional["PolicyStatement"], jsii.get(self, "resourceStatement"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.GrantOnPrincipalAndResourceOptions",
    jsii_struct_bases=[CommonGrantOptions],
    name_mapping={
        "actions": "actions",
        "grantee": "grantee",
        "resource_arns": "resourceArns",
        "resource": "resource",
        "resource_policy_principal": "resourcePolicyPrincipal",
        "resource_self_arns": "resourceSelfArns",
    },
)
class GrantOnPrincipalAndResourceOptions(CommonGrantOptions):
    def __init__(
        self,
        *,
        actions: typing.Sequence[builtins.str],
        grantee: "IGrantable",
        resource_arns: typing.Sequence[builtins.str],
        resource: "IResourceWithPolicy",
        resource_policy_principal: typing.Optional["IPrincipal"] = None,
        resource_self_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Options for a grant operation to both identity and resource.

        :param actions: The actions to grant.
        :param grantee: The principal to grant to. Default: if principal is undefined, no work is done.
        :param resource_arns: The resource ARNs to grant to.
        :param resource: The resource with a resource policy. The statement will always be added to the resource policy.
        :param resource_policy_principal: The principal to use in the statement for the resource policy. Default: - the principal of the grantee will be used
        :param resource_self_arns: When referring to the resource in a resource policy, use this as ARN. (Depending on the resource type, this needs to be '*' in a resource policy). Default: Same as regular resource ARNs

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # grantable: iam.IGrantable
            # principal: iam.IPrincipal
            # resource_with_policy: iam.IResourceWithPolicy
            
            grant_on_principal_and_resource_options = iam.GrantOnPrincipalAndResourceOptions(
                actions=["actions"],
                grantee=grantable,
                resource=resource_with_policy,
                resource_arns=["resourceArns"],
            
                # the properties below are optional
                resource_policy_principal=principal,
                resource_self_arns=["resourceSelfArns"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "actions": actions,
            "grantee": grantee,
            "resource_arns": resource_arns,
            "resource": resource,
        }
        if resource_policy_principal is not None:
            self._values["resource_policy_principal"] = resource_policy_principal
        if resource_self_arns is not None:
            self._values["resource_self_arns"] = resource_self_arns

    @builtins.property
    def actions(self) -> typing.List[builtins.str]:
        '''The actions to grant.'''
        result = self._values.get("actions")
        assert result is not None, "Required property 'actions' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def grantee(self) -> "IGrantable":
        '''The principal to grant to.

        :default: if principal is undefined, no work is done.
        '''
        result = self._values.get("grantee")
        assert result is not None, "Required property 'grantee' is missing"
        return typing.cast("IGrantable", result)

    @builtins.property
    def resource_arns(self) -> typing.List[builtins.str]:
        '''The resource ARNs to grant to.'''
        result = self._values.get("resource_arns")
        assert result is not None, "Required property 'resource_arns' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def resource(self) -> "IResourceWithPolicy":
        '''The resource with a resource policy.

        The statement will always be added to the resource policy.
        '''
        result = self._values.get("resource")
        assert result is not None, "Required property 'resource' is missing"
        return typing.cast("IResourceWithPolicy", result)

    @builtins.property
    def resource_policy_principal(self) -> typing.Optional["IPrincipal"]:
        '''The principal to use in the statement for the resource policy.

        :default: - the principal of the grantee will be used
        '''
        result = self._values.get("resource_policy_principal")
        return typing.cast(typing.Optional["IPrincipal"], result)

    @builtins.property
    def resource_self_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''When referring to the resource in a resource policy, use this as ARN.

        (Depending on the resource type, this needs to be '*' in a resource policy).

        :default: Same as regular resource ARNs
        '''
        result = self._values.get("resource_self_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrantOnPrincipalAndResourceOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.GrantOnPrincipalOptions",
    jsii_struct_bases=[CommonGrantOptions],
    name_mapping={
        "actions": "actions",
        "grantee": "grantee",
        "resource_arns": "resourceArns",
        "scope": "scope",
    },
)
class GrantOnPrincipalOptions(CommonGrantOptions):
    def __init__(
        self,
        *,
        actions: typing.Sequence[builtins.str],
        grantee: "IGrantable",
        resource_arns: typing.Sequence[builtins.str],
        scope: typing.Optional[constructs.IConstruct] = None,
    ) -> None:
        '''Options for a grant operation that only applies to principals.

        :param actions: The actions to grant.
        :param grantee: The principal to grant to. Default: if principal is undefined, no work is done.
        :param resource_arns: The resource ARNs to grant to.
        :param scope: Construct to report warnings on in case grant could not be registered. Default: - the construct in which this construct is defined

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            import constructs as constructs
            
            # construct: constructs.Construct
            # grantable: iam.IGrantable
            
            grant_on_principal_options = iam.GrantOnPrincipalOptions(
                actions=["actions"],
                grantee=grantable,
                resource_arns=["resourceArns"],
            
                # the properties below are optional
                scope=construct
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "actions": actions,
            "grantee": grantee,
            "resource_arns": resource_arns,
        }
        if scope is not None:
            self._values["scope"] = scope

    @builtins.property
    def actions(self) -> typing.List[builtins.str]:
        '''The actions to grant.'''
        result = self._values.get("actions")
        assert result is not None, "Required property 'actions' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def grantee(self) -> "IGrantable":
        '''The principal to grant to.

        :default: if principal is undefined, no work is done.
        '''
        result = self._values.get("grantee")
        assert result is not None, "Required property 'grantee' is missing"
        return typing.cast("IGrantable", result)

    @builtins.property
    def resource_arns(self) -> typing.List[builtins.str]:
        '''The resource ARNs to grant to.'''
        result = self._values.get("resource_arns")
        assert result is not None, "Required property 'resource_arns' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def scope(self) -> typing.Optional[constructs.IConstruct]:
        '''Construct to report warnings on in case grant could not be registered.

        :default: - the construct in which this construct is defined
        '''
        result = self._values.get("scope")
        return typing.cast(typing.Optional[constructs.IConstruct], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrantOnPrincipalOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.GrantWithResourceOptions",
    jsii_struct_bases=[CommonGrantOptions],
    name_mapping={
        "actions": "actions",
        "grantee": "grantee",
        "resource_arns": "resourceArns",
        "resource": "resource",
        "resource_self_arns": "resourceSelfArns",
    },
)
class GrantWithResourceOptions(CommonGrantOptions):
    def __init__(
        self,
        *,
        actions: typing.Sequence[builtins.str],
        grantee: "IGrantable",
        resource_arns: typing.Sequence[builtins.str],
        resource: "IResourceWithPolicy",
        resource_self_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Options for a grant operation.

        :param actions: The actions to grant.
        :param grantee: The principal to grant to. Default: if principal is undefined, no work is done.
        :param resource_arns: The resource ARNs to grant to.
        :param resource: The resource with a resource policy. The statement will be added to the resource policy if it couldn't be added to the principal policy.
        :param resource_self_arns: When referring to the resource in a resource policy, use this as ARN. (Depending on the resource type, this needs to be '*' in a resource policy). Default: Same as regular resource ARNs

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # grantable: iam.IGrantable
            # resource_with_policy: iam.IResourceWithPolicy
            
            grant_with_resource_options = iam.GrantWithResourceOptions(
                actions=["actions"],
                grantee=grantable,
                resource=resource_with_policy,
                resource_arns=["resourceArns"],
            
                # the properties below are optional
                resource_self_arns=["resourceSelfArns"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "actions": actions,
            "grantee": grantee,
            "resource_arns": resource_arns,
            "resource": resource,
        }
        if resource_self_arns is not None:
            self._values["resource_self_arns"] = resource_self_arns

    @builtins.property
    def actions(self) -> typing.List[builtins.str]:
        '''The actions to grant.'''
        result = self._values.get("actions")
        assert result is not None, "Required property 'actions' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def grantee(self) -> "IGrantable":
        '''The principal to grant to.

        :default: if principal is undefined, no work is done.
        '''
        result = self._values.get("grantee")
        assert result is not None, "Required property 'grantee' is missing"
        return typing.cast("IGrantable", result)

    @builtins.property
    def resource_arns(self) -> typing.List[builtins.str]:
        '''The resource ARNs to grant to.'''
        result = self._values.get("resource_arns")
        assert result is not None, "Required property 'resource_arns' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def resource(self) -> "IResourceWithPolicy":
        '''The resource with a resource policy.

        The statement will be added to the resource policy if it couldn't be
        added to the principal policy.
        '''
        result = self._values.get("resource")
        assert result is not None, "Required property 'resource' is missing"
        return typing.cast("IResourceWithPolicy", result)

    @builtins.property
    def resource_self_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''When referring to the resource in a resource policy, use this as ARN.

        (Depending on the resource type, this needs to be '*' in a resource policy).

        :default: Same as regular resource ARNs
        '''
        result = self._values.get("resource_self_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrantWithResourceOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.GroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "group_name": "groupName",
        "managed_policies": "managedPolicies",
        "path": "path",
    },
)
class GroupProps:
    def __init__(
        self,
        *,
        group_name: typing.Optional[builtins.str] = None,
        managed_policies: typing.Optional[typing.Sequence["IManagedPolicy"]] = None,
        path: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining an IAM group.

        :param group_name: A name for the IAM group. For valid values, see the GroupName parameter for the CreateGroup action in the IAM API Reference. If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the group name. If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to acknowledge your template's capabilities. For more information, see Acknowledging IAM Resources in AWS CloudFormation Templates. Default: Generated by CloudFormation (recommended)
        :param managed_policies: A list of managed policies associated with this role. You can add managed policies later using ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``. Default: - No managed policies.
        :param path: The path to the group. For more information about paths, see `IAM Identifiers <http://docs.aws.amazon.com/IAM/latest/UserGuide/index.html?Using_Identifiers.html>`_ in the IAM User Guide. Default: /

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # managed_policy: iam.ManagedPolicy
            
            group_props = iam.GroupProps(
                group_name="groupName",
                managed_policies=[managed_policy],
                path="path"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if group_name is not None:
            self._values["group_name"] = group_name
        if managed_policies is not None:
            self._values["managed_policies"] = managed_policies
        if path is not None:
            self._values["path"] = path

    @builtins.property
    def group_name(self) -> typing.Optional[builtins.str]:
        '''A name for the IAM group.

        For valid values, see the GroupName parameter
        for the CreateGroup action in the IAM API Reference. If you don't specify
        a name, AWS CloudFormation generates a unique physical ID and uses that
        ID for the group name.

        If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to
        acknowledge your template's capabilities. For more information, see
        Acknowledging IAM Resources in AWS CloudFormation Templates.

        :default: Generated by CloudFormation (recommended)
        '''
        result = self._values.get("group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def managed_policies(self) -> typing.Optional[typing.List["IManagedPolicy"]]:
        '''A list of managed policies associated with this role.

        You can add managed policies later using
        ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``.

        :default: - No managed policies.
        '''
        result = self._values.get("managed_policies")
        return typing.cast(typing.Optional[typing.List["IManagedPolicy"]], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path to the group.

        For more information about paths, see `IAM
        Identifiers <http://docs.aws.amazon.com/IAM/latest/UserGuide/index.html?Using_Identifiers.html>`_
        in the IAM User Guide.

        :default: /
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IAccessKey")
class IAccessKey(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents an IAM Access Key.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    '''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessKeyId")
    def access_key_id(self) -> builtins.str:
        '''The Access Key ID.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretAccessKey")
    def secret_access_key(self) -> _SecretValue_3dd0ddae:
        '''The Secret Access Key.

        :attribute: true
        '''
        ...


class _IAccessKeyProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents an IAM Access Key.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    '''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IAccessKey"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessKeyId")
    def access_key_id(self) -> builtins.str:
        '''The Access Key ID.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "accessKeyId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretAccessKey")
    def secret_access_key(self) -> _SecretValue_3dd0ddae:
        '''The Secret Access Key.

        :attribute: true
        '''
        return typing.cast(_SecretValue_3dd0ddae, jsii.get(self, "secretAccessKey"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IAccessKey).__jsii_proxy_class__ = lambda : _IAccessKeyProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IGrantable")
class IGrantable(typing_extensions.Protocol):
    '''Any object that has an associated principal that a permission can be granted to.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> "IPrincipal":
        '''The principal to grant permissions to.'''
        ...


class _IGrantableProxy:
    '''Any object that has an associated principal that a permission can be granted to.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IGrantable"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> "IPrincipal":
        '''The principal to grant permissions to.'''
        return typing.cast("IPrincipal", jsii.get(self, "grantPrincipal"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IGrantable).__jsii_proxy_class__ = lambda : _IGrantableProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IManagedPolicy")
class IManagedPolicy(typing_extensions.Protocol):
    '''A managed policy.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedPolicyArn")
    def managed_policy_arn(self) -> builtins.str:
        '''The ARN of the managed policy.

        :attribute: true
        '''
        ...


class _IManagedPolicyProxy:
    '''A managed policy.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IManagedPolicy"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedPolicyArn")
    def managed_policy_arn(self) -> builtins.str:
        '''The ARN of the managed policy.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "managedPolicyArn"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IManagedPolicy).__jsii_proxy_class__ = lambda : _IManagedPolicyProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IOpenIdConnectProvider")
class IOpenIdConnectProvider(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents an IAM OpenID Connect provider.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProviderArn")
    def open_id_connect_provider_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM OpenID Connect provider.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProviderIssuer")
    def open_id_connect_provider_issuer(self) -> builtins.str:
        '''The issuer for OIDC Provider.'''
        ...


class _IOpenIdConnectProviderProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents an IAM OpenID Connect provider.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IOpenIdConnectProvider"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProviderArn")
    def open_id_connect_provider_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM OpenID Connect provider.'''
        return typing.cast(builtins.str, jsii.get(self, "openIdConnectProviderArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProviderIssuer")
    def open_id_connect_provider_issuer(self) -> builtins.str:
        '''The issuer for OIDC Provider.'''
        return typing.cast(builtins.str, jsii.get(self, "openIdConnectProviderIssuer"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IOpenIdConnectProvider).__jsii_proxy_class__ = lambda : _IOpenIdConnectProviderProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IPolicy")
class IPolicy(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents an IAM Policy.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage.html
    '''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyName")
    def policy_name(self) -> builtins.str:
        '''The name of this policy.

        :attribute: true
        '''
        ...


class _IPolicyProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents an IAM Policy.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage.html
    '''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IPolicy"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyName")
    def policy_name(self) -> builtins.str:
        '''The name of this policy.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "policyName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IPolicy).__jsii_proxy_class__ = lambda : _IPolicyProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IPrincipal")
class IPrincipal(IGrantable, typing_extensions.Protocol):
    '''Represents a logical IAM principal.

    An IPrincipal describes a logical entity that can perform AWS API calls
    against sets of resources, optionally under certain conditions.

    Examples of simple principals are IAM objects that you create, such
    as Users or Roles.

    An example of a more complex principals is a ``ServicePrincipal`` (such as
    ``new ServicePrincipal("sns.amazonaws.com")``, which represents the Simple
    Notifications Service).

    A single logical Principal may also map to a set of physical principals.
    For example, ``new OrganizationPrincipal('o-1234')`` represents all
    identities that are part of the given AWS Organization.
    '''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> "PrincipalPolicyFragment":
        '''Return the policy fragment that identifies this principal in a Policy.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        ...

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: "PolicyStatement",
    ) -> AddToPrincipalPolicyResult:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        ...


class _IPrincipalProxy(
    jsii.proxy_for(IGrantable) # type: ignore[misc]
):
    '''Represents a logical IAM principal.

    An IPrincipal describes a logical entity that can perform AWS API calls
    against sets of resources, optionally under certain conditions.

    Examples of simple principals are IAM objects that you create, such
    as Users or Roles.

    An example of a more complex principals is a ``ServicePrincipal`` (such as
    ``new ServicePrincipal("sns.amazonaws.com")``, which represents the Simple
    Notifications Service).

    A single logical Principal may also map to a set of physical principals.
    For example, ``new OrganizationPrincipal('o-1234')`` represents all
    identities that are part of the given AWS Organization.
    '''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IPrincipal"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> "PrincipalPolicyFragment":
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast("PrincipalPolicyFragment", jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: "PolicyStatement",
    ) -> AddToPrincipalPolicyResult:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IPrincipal).__jsii_proxy_class__ = lambda : _IPrincipalProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IResourceWithPolicy")
class IResourceWithPolicy(_IResource_c80c4260, typing_extensions.Protocol):
    '''A resource with a resource policy that can be added to.'''

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: "PolicyStatement",
    ) -> AddToResourcePolicyResult:
        '''Add a statement to the resource's resource policy.

        :param statement: -
        '''
        ...


class _IResourceWithPolicyProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A resource with a resource policy that can be added to.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IResourceWithPolicy"

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        statement: "PolicyStatement",
    ) -> AddToResourcePolicyResult:
        '''Add a statement to the resource's resource policy.

        :param statement: -
        '''
        return typing.cast(AddToResourcePolicyResult, jsii.invoke(self, "addToResourcePolicy", [statement]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IResourceWithPolicy).__jsii_proxy_class__ = lambda : _IResourceWithPolicyProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.ISamlProvider")
class ISamlProvider(_IResource_c80c4260, typing_extensions.Protocol):
    '''A SAML provider.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="samlProviderArn")
    def saml_provider_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the provider.

        :attribute: true
        '''
        ...


class _ISamlProviderProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A SAML provider.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.ISamlProvider"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="samlProviderArn")
    def saml_provider_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the provider.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "samlProviderArn"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ISamlProvider).__jsii_proxy_class__ = lambda : _ISamlProviderProxy


@jsii.implements(IManagedPolicy)
class ManagedPolicy(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.ManagedPolicy",
):
    '''Managed policy.

    :exampleMetadata: infused

    Example::

        my_role = iam.Role(self, "My Role",
            assumed_by=iam.ServicePrincipal("sns.amazonaws.com")
        )
        
        fn = lambda_.Function(self, "MyFunction",
            runtime=lambda_.Runtime.NODEJS_12_X,
            handler="index.handler",
            code=lambda_.Code.from_asset(path.join(__dirname, "lambda-handler")),
            role=my_role
        )
        
        my_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        my_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        document: typing.Optional["PolicyDocument"] = None,
        groups: typing.Optional[typing.Sequence["IGroup"]] = None,
        managed_policy_name: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        roles: typing.Optional[typing.Sequence["IRole"]] = None,
        statements: typing.Optional[typing.Sequence["PolicyStatement"]] = None,
        users: typing.Optional[typing.Sequence["IUser"]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param description: A description of the managed policy. Typically used to store information about the permissions defined in the policy. For example, "Grants access to production DynamoDB tables." The policy description is immutable. After a value is assigned, it cannot be changed. Default: - empty
        :param document: Initial PolicyDocument to use for this ManagedPolicy. If omited, any ``PolicyStatement`` provided in the ``statements`` property will be applied against the empty default ``PolicyDocument``. Default: - An empty policy.
        :param groups: Groups to attach this policy to. You can also use ``attachToGroup(group)`` to attach this policy to a group. Default: - No groups.
        :param managed_policy_name: The name of the managed policy. If you specify multiple policies for an entity, specify unique names. For example, if you specify a list of policies for an IAM role, each policy must have a unique name. Default: - A name is automatically generated.
        :param path: The path for the policy. This parameter allows (through its regex pattern) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (\\u0021) through the DEL character (\\u007F), including most punctuation characters, digits, and upper and lowercased letters. For more information about paths, see IAM Identifiers in the IAM User Guide. Default: - "/"
        :param roles: Roles to attach this policy to. You can also use ``attachToRole(role)`` to attach this policy to a role. Default: - No roles.
        :param statements: Initial set of permissions to add to this policy document. You can also use ``addPermission(statement)`` to add permissions later. Default: - No statements.
        :param users: Users to attach this policy to. You can also use ``attachToUser(user)`` to attach this policy to a user. Default: - No users.
        '''
        props = ManagedPolicyProps(
            description=description,
            document=document,
            groups=groups,
            managed_policy_name=managed_policy_name,
            path=path,
            roles=roles,
            statements=statements,
            users=users,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromAwsManagedPolicyName") # type: ignore[misc]
    @builtins.classmethod
    def from_aws_managed_policy_name(
        cls,
        managed_policy_name: builtins.str,
    ) -> IManagedPolicy:
        '''Import a managed policy from one of the policies that AWS manages.

        For this managed policy, you only need to know the name to be able to use it.

        Some managed policy names start with "service-role/", some start with
        "job-function/", and some don't start with anything. Include the
        prefix when constructing this object.

        :param managed_policy_name: -
        '''
        return typing.cast(IManagedPolicy, jsii.sinvoke(cls, "fromAwsManagedPolicyName", [managed_policy_name]))

    @jsii.member(jsii_name="fromManagedPolicyArn") # type: ignore[misc]
    @builtins.classmethod
    def from_managed_policy_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        managed_policy_arn: builtins.str,
    ) -> IManagedPolicy:
        '''Import an external managed policy by ARN.

        For this managed policy, you only need to know the ARN to be able to use it.
        This can be useful if you got the ARN from a CloudFormation Export.

        If the imported Managed Policy ARN is a Token (such as a
        ``CfnParameter.valueAsString`` or a ``Fn.importValue()``) *and* the referenced
        managed policy has a ``path`` (like ``arn:...:policy/AdminPolicy/AdminAllow``), the
        ``managedPolicyName`` property will not resolve to the correct value. Instead it
        will resolve to the first path component. We unfortunately cannot express
        the correct calculation of the full path name as a CloudFormation
        expression. In this scenario the Managed Policy ARN should be supplied without the
        ``path`` in order to resolve the correct managed policy resource.

        :param scope: construct scope.
        :param id: construct id.
        :param managed_policy_arn: the ARN of the managed policy to import.
        '''
        return typing.cast(IManagedPolicy, jsii.sinvoke(cls, "fromManagedPolicyArn", [scope, id, managed_policy_arn]))

    @jsii.member(jsii_name="fromManagedPolicyName") # type: ignore[misc]
    @builtins.classmethod
    def from_managed_policy_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        managed_policy_name: builtins.str,
    ) -> IManagedPolicy:
        '''Import a customer managed policy from the managedPolicyName.

        For this managed policy, you only need to know the name to be able to use it.

        :param scope: -
        :param id: -
        :param managed_policy_name: -
        '''
        return typing.cast(IManagedPolicy, jsii.sinvoke(cls, "fromManagedPolicyName", [scope, id, managed_policy_name]))

    @jsii.member(jsii_name="addStatements")
    def add_statements(self, *statement: "PolicyStatement") -> None:
        '''Adds a statement to the policy document.

        :param statement: -
        '''
        return typing.cast(None, jsii.invoke(self, "addStatements", [*statement]))

    @jsii.member(jsii_name="attachToGroup")
    def attach_to_group(self, group: "IGroup") -> None:
        '''Attaches this policy to a group.

        :param group: -
        '''
        return typing.cast(None, jsii.invoke(self, "attachToGroup", [group]))

    @jsii.member(jsii_name="attachToRole")
    def attach_to_role(self, role: "IRole") -> None:
        '''Attaches this policy to a role.

        :param role: -
        '''
        return typing.cast(None, jsii.invoke(self, "attachToRole", [role]))

    @jsii.member(jsii_name="attachToUser")
    def attach_to_user(self, user: "IUser") -> None:
        '''Attaches this policy to a user.

        :param user: -
        '''
        return typing.cast(None, jsii.invoke(self, "attachToUser", [user]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> builtins.str:
        '''The description of this policy.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "description"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="document")
    def document(self) -> "PolicyDocument":
        '''The policy document.'''
        return typing.cast("PolicyDocument", jsii.get(self, "document"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedPolicyArn")
    def managed_policy_arn(self) -> builtins.str:
        '''Returns the ARN of this managed policy.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "managedPolicyArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="managedPolicyName")
    def managed_policy_name(self) -> builtins.str:
        '''The name of this policy.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "managedPolicyName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> builtins.str:
        '''The path of this policy.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "path"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.ManagedPolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "document": "document",
        "groups": "groups",
        "managed_policy_name": "managedPolicyName",
        "path": "path",
        "roles": "roles",
        "statements": "statements",
        "users": "users",
    },
)
class ManagedPolicyProps:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        document: typing.Optional["PolicyDocument"] = None,
        groups: typing.Optional[typing.Sequence["IGroup"]] = None,
        managed_policy_name: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        roles: typing.Optional[typing.Sequence["IRole"]] = None,
        statements: typing.Optional[typing.Sequence["PolicyStatement"]] = None,
        users: typing.Optional[typing.Sequence["IUser"]] = None,
    ) -> None:
        '''Properties for defining an IAM managed policy.

        :param description: A description of the managed policy. Typically used to store information about the permissions defined in the policy. For example, "Grants access to production DynamoDB tables." The policy description is immutable. After a value is assigned, it cannot be changed. Default: - empty
        :param document: Initial PolicyDocument to use for this ManagedPolicy. If omited, any ``PolicyStatement`` provided in the ``statements`` property will be applied against the empty default ``PolicyDocument``. Default: - An empty policy.
        :param groups: Groups to attach this policy to. You can also use ``attachToGroup(group)`` to attach this policy to a group. Default: - No groups.
        :param managed_policy_name: The name of the managed policy. If you specify multiple policies for an entity, specify unique names. For example, if you specify a list of policies for an IAM role, each policy must have a unique name. Default: - A name is automatically generated.
        :param path: The path for the policy. This parameter allows (through its regex pattern) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (\\u0021) through the DEL character (\\u007F), including most punctuation characters, digits, and upper and lowercased letters. For more information about paths, see IAM Identifiers in the IAM User Guide. Default: - "/"
        :param roles: Roles to attach this policy to. You can also use ``attachToRole(role)`` to attach this policy to a role. Default: - No roles.
        :param statements: Initial set of permissions to add to this policy document. You can also use ``addPermission(statement)`` to add permissions later. Default: - No statements.
        :param users: Users to attach this policy to. You can also use ``attachToUser(user)`` to attach this policy to a user. Default: - No users.

        :exampleMetadata: infused

        Example::

            policy_document = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "FirstStatement",
                    "Effect": "Allow",
                    "Action": ["iam:ChangePassword"],
                    "Resource": "*"
                }, {
                    "Sid": "SecondStatement",
                    "Effect": "Allow",
                    "Action": "s3:ListAllMyBuckets",
                    "Resource": "*"
                }, {
                    "Sid": "ThirdStatement",
                    "Effect": "Allow",
                    "Action": ["s3:List*", "s3:Get*"
                    ],
                    "Resource": ["arn:aws:s3:::confidential-data", "arn:aws:s3:::confidential-data/*"
                    ],
                    "Condition": {"Bool": {"aws:_multi_factor_auth_present": "true"}}
                }
                ]
            }
            
            custom_policy_document = iam.PolicyDocument.from_json(policy_document)
            
            # You can pass this document as an initial document to a ManagedPolicy
            # or inline Policy.
            new_managed_policy = iam.ManagedPolicy(self, "MyNewManagedPolicy",
                document=custom_policy_document
            )
            new_policy = iam.Policy(self, "MyNewPolicy",
                document=custom_policy_document
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if document is not None:
            self._values["document"] = document
        if groups is not None:
            self._values["groups"] = groups
        if managed_policy_name is not None:
            self._values["managed_policy_name"] = managed_policy_name
        if path is not None:
            self._values["path"] = path
        if roles is not None:
            self._values["roles"] = roles
        if statements is not None:
            self._values["statements"] = statements
        if users is not None:
            self._values["users"] = users

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the managed policy.

        Typically used to store information about the
        permissions defined in the policy. For example, "Grants access to production DynamoDB tables."
        The policy description is immutable. After a value is assigned, it cannot be changed.

        :default: - empty
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def document(self) -> typing.Optional["PolicyDocument"]:
        '''Initial PolicyDocument to use for this ManagedPolicy.

        If omited, any
        ``PolicyStatement`` provided in the ``statements`` property will be applied
        against the empty default ``PolicyDocument``.

        :default: - An empty policy.
        '''
        result = self._values.get("document")
        return typing.cast(typing.Optional["PolicyDocument"], result)

    @builtins.property
    def groups(self) -> typing.Optional[typing.List["IGroup"]]:
        '''Groups to attach this policy to.

        You can also use ``attachToGroup(group)`` to attach this policy to a group.

        :default: - No groups.
        '''
        result = self._values.get("groups")
        return typing.cast(typing.Optional[typing.List["IGroup"]], result)

    @builtins.property
    def managed_policy_name(self) -> typing.Optional[builtins.str]:
        '''The name of the managed policy.

        If you specify multiple policies for an entity,
        specify unique names. For example, if you specify a list of policies for
        an IAM role, each policy must have a unique name.

        :default: - A name is automatically generated.
        '''
        result = self._values.get("managed_policy_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the policy.

        This parameter allows (through its regex pattern) a string of characters
        consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes.
        In addition, it can contain any ASCII character from the ! (\\u0021) through the DEL character (\\u007F),
        including most punctuation characters, digits, and upper and lowercased letters.

        For more information about paths, see IAM Identifiers in the IAM User Guide.

        :default: - "/"
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def roles(self) -> typing.Optional[typing.List["IRole"]]:
        '''Roles to attach this policy to.

        You can also use ``attachToRole(role)`` to attach this policy to a role.

        :default: - No roles.
        '''
        result = self._values.get("roles")
        return typing.cast(typing.Optional[typing.List["IRole"]], result)

    @builtins.property
    def statements(self) -> typing.Optional[typing.List["PolicyStatement"]]:
        '''Initial set of permissions to add to this policy document.

        You can also use ``addPermission(statement)`` to add permissions later.

        :default: - No statements.
        '''
        result = self._values.get("statements")
        return typing.cast(typing.Optional[typing.List["PolicyStatement"]], result)

    @builtins.property
    def users(self) -> typing.Optional[typing.List["IUser"]]:
        '''Users to attach this policy to.

        You can also use ``attachToUser(user)`` to attach this policy to a user.

        :default: - No users.
        '''
        result = self._values.get("users")
        return typing.cast(typing.Optional[typing.List["IUser"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ManagedPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IOpenIdConnectProvider)
class OpenIdConnectProvider(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.OpenIdConnectProvider",
):
    '''IAM OIDC identity providers are entities in IAM that describe an external identity provider (IdP) service that supports the OpenID Connect (OIDC) standard, such as Google or Salesforce.

    You use an IAM OIDC identity provider
    when you want to establish trust between an OIDC-compatible IdP and your AWS
    account. This is useful when creating a mobile app or web application that
    requires access to AWS resources, but you don't want to create custom sign-in
    code or manage your own user identities.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
    :exampleMetadata: infused
    :resource: AWS::CloudFormation::CustomResource

    Example::

        provider = iam.OpenIdConnectProvider(self, "MyProvider",
            url="https://openid/connect",
            client_ids=["myclient1", "myclient2"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        url: builtins.str,
        client_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        thumbprints: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Defines an OpenID Connect provider.

        :param scope: The definition scope.
        :param id: Construct ID.
        :param url: The URL of the identity provider. The URL must begin with https:// and should correspond to the iss claim in the provider's OpenID Connect ID tokens. Per the OIDC standard, path components are allowed but query parameters are not. Typically the URL consists of only a hostname, like https://server.example.org or https://example.com. You cannot register the same provider multiple times in a single AWS account. If you try to submit a URL that has already been used for an OpenID Connect provider in the AWS account, you will get an error.
        :param client_ids: A list of client IDs (also known as audiences). When a mobile or web app registers with an OpenID Connect provider, they establish a value that identifies the application. (This is the value that's sent as the client_id parameter on OAuth requests.) You can register multiple client IDs with the same provider. For example, you might have multiple applications that use the same OIDC provider. You cannot register more than 100 client IDs with a single IAM OIDC provider. Client IDs are up to 255 characters long. Default: - no clients are allowed
        :param thumbprints: A list of server certificate thumbprints for the OpenID Connect (OIDC) identity provider's server certificates. Typically this list includes only one entry. However, IAM lets you have up to five thumbprints for an OIDC provider. This lets you maintain multiple thumbprints if the identity provider is rotating certificates. The server certificate thumbprint is the hex-encoded SHA-1 hash value of the X.509 certificate used by the domain where the OpenID Connect provider makes its keys available. It is always a 40-character string. You must provide at least one thumbprint when creating an IAM OIDC provider. For example, assume that the OIDC provider is server.example.com and the provider stores its keys at https://keys.server.example.com/openid-connect. In that case, the thumbprint string would be the hex-encoded SHA-1 hash value of the certificate used by https://keys.server.example.com. Default: - If no thumbprints are specified (an empty array or ``undefined``), the thumbprint of the root certificate authority will be obtained from the provider's server as described in https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html
        '''
        props = OpenIdConnectProviderProps(
            url=url, client_ids=client_ids, thumbprints=thumbprints
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromOpenIdConnectProviderArn") # type: ignore[misc]
    @builtins.classmethod
    def from_open_id_connect_provider_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        open_id_connect_provider_arn: builtins.str,
    ) -> IOpenIdConnectProvider:
        '''Imports an Open ID connect provider from an ARN.

        :param scope: The definition scope.
        :param id: ID of the construct.
        :param open_id_connect_provider_arn: the ARN to import.
        '''
        return typing.cast(IOpenIdConnectProvider, jsii.sinvoke(cls, "fromOpenIdConnectProviderArn", [scope, id, open_id_connect_provider_arn]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProviderArn")
    def open_id_connect_provider_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM OpenID Connect provider.'''
        return typing.cast(builtins.str, jsii.get(self, "openIdConnectProviderArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProviderIssuer")
    def open_id_connect_provider_issuer(self) -> builtins.str:
        '''The issuer for OIDC Provider.'''
        return typing.cast(builtins.str, jsii.get(self, "openIdConnectProviderIssuer"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.OpenIdConnectProviderProps",
    jsii_struct_bases=[],
    name_mapping={
        "url": "url",
        "client_ids": "clientIds",
        "thumbprints": "thumbprints",
    },
)
class OpenIdConnectProviderProps:
    def __init__(
        self,
        *,
        url: builtins.str,
        client_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        thumbprints: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Initialization properties for ``OpenIdConnectProvider``.

        :param url: The URL of the identity provider. The URL must begin with https:// and should correspond to the iss claim in the provider's OpenID Connect ID tokens. Per the OIDC standard, path components are allowed but query parameters are not. Typically the URL consists of only a hostname, like https://server.example.org or https://example.com. You cannot register the same provider multiple times in a single AWS account. If you try to submit a URL that has already been used for an OpenID Connect provider in the AWS account, you will get an error.
        :param client_ids: A list of client IDs (also known as audiences). When a mobile or web app registers with an OpenID Connect provider, they establish a value that identifies the application. (This is the value that's sent as the client_id parameter on OAuth requests.) You can register multiple client IDs with the same provider. For example, you might have multiple applications that use the same OIDC provider. You cannot register more than 100 client IDs with a single IAM OIDC provider. Client IDs are up to 255 characters long. Default: - no clients are allowed
        :param thumbprints: A list of server certificate thumbprints for the OpenID Connect (OIDC) identity provider's server certificates. Typically this list includes only one entry. However, IAM lets you have up to five thumbprints for an OIDC provider. This lets you maintain multiple thumbprints if the identity provider is rotating certificates. The server certificate thumbprint is the hex-encoded SHA-1 hash value of the X.509 certificate used by the domain where the OpenID Connect provider makes its keys available. It is always a 40-character string. You must provide at least one thumbprint when creating an IAM OIDC provider. For example, assume that the OIDC provider is server.example.com and the provider stores its keys at https://keys.server.example.com/openid-connect. In that case, the thumbprint string would be the hex-encoded SHA-1 hash value of the certificate used by https://keys.server.example.com. Default: - If no thumbprints are specified (an empty array or ``undefined``), the thumbprint of the root certificate authority will be obtained from the provider's server as described in https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html

        :exampleMetadata: infused

        Example::

            provider = iam.OpenIdConnectProvider(self, "MyProvider",
                url="https://openid/connect",
                client_ids=["myclient1", "myclient2"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "url": url,
        }
        if client_ids is not None:
            self._values["client_ids"] = client_ids
        if thumbprints is not None:
            self._values["thumbprints"] = thumbprints

    @builtins.property
    def url(self) -> builtins.str:
        '''The URL of the identity provider.

        The URL must begin with https:// and
        should correspond to the iss claim in the provider's OpenID Connect ID
        tokens. Per the OIDC standard, path components are allowed but query
        parameters are not. Typically the URL consists of only a hostname, like
        https://server.example.org or https://example.com.

        You cannot register the same provider multiple times in a single AWS
        account. If you try to submit a URL that has already been used for an
        OpenID Connect provider in the AWS account, you will get an error.
        '''
        result = self._values.get("url")
        assert result is not None, "Required property 'url' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of client IDs (also known as audiences).

        When a mobile or web app
        registers with an OpenID Connect provider, they establish a value that
        identifies the application. (This is the value that's sent as the client_id
        parameter on OAuth requests.)

        You can register multiple client IDs with the same provider. For example,
        you might have multiple applications that use the same OIDC provider. You
        cannot register more than 100 client IDs with a single IAM OIDC provider.

        Client IDs are up to 255 characters long.

        :default: - no clients are allowed
        '''
        result = self._values.get("client_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def thumbprints(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of server certificate thumbprints for the OpenID Connect (OIDC) identity provider's server certificates.

        Typically this list includes only one entry. However, IAM lets you have up
        to five thumbprints for an OIDC provider. This lets you maintain multiple
        thumbprints if the identity provider is rotating certificates.

        The server certificate thumbprint is the hex-encoded SHA-1 hash value of
        the X.509 certificate used by the domain where the OpenID Connect provider
        makes its keys available. It is always a 40-character string.

        You must provide at least one thumbprint when creating an IAM OIDC
        provider. For example, assume that the OIDC provider is server.example.com
        and the provider stores its keys at
        https://keys.server.example.com/openid-connect. In that case, the
        thumbprint string would be the hex-encoded SHA-1 hash value of the
        certificate used by https://keys.server.example.com.

        :default:

        - If no thumbprints are specified (an empty array or ``undefined``),
        the thumbprint of the root certificate authority will be obtained from the
        provider's server as described in https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html
        '''
        result = self._values.get("thumbprints")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OpenIdConnectProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class PermissionsBoundary(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.PermissionsBoundary",
):
    '''Modify the Permissions Boundaries of Users and Roles in a construct tree.

    Example::

       policy = iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess")
       iam.PermissionsBoundary.of(self).apply(policy)

    :exampleMetadata: infused

    Example::

        # project: codebuild.Project
        
        iam.PermissionsBoundary.of(project).apply(codebuild.UntrustedCodeBoundaryPolicy(self, "Boundary"))
    '''

    @jsii.member(jsii_name="of") # type: ignore[misc]
    @builtins.classmethod
    def of(cls, scope: constructs.IConstruct) -> "PermissionsBoundary":
        '''Access the Permissions Boundaries of a construct tree.

        :param scope: -
        '''
        return typing.cast("PermissionsBoundary", jsii.sinvoke(cls, "of", [scope]))

    @jsii.member(jsii_name="apply")
    def apply(self, boundary_policy: IManagedPolicy) -> None:
        '''Apply the given policy as Permissions Boundary to all Roles and Users in the scope.

        Will override any Permissions Boundaries configured previously; in case
        a Permission Boundary is applied in multiple scopes, the Boundary applied
        closest to the Role wins.

        :param boundary_policy: -
        '''
        return typing.cast(None, jsii.invoke(self, "apply", [boundary_policy]))

    @jsii.member(jsii_name="clear")
    def clear(self) -> None:
        '''Remove previously applied Permissions Boundaries.'''
        return typing.cast(None, jsii.invoke(self, "clear", []))


@jsii.implements(IPolicy)
class Policy(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.Policy",
):
    '''The AWS::IAM::Policy resource associates an IAM policy with IAM users, roles, or groups.

    For more information about IAM policies, see `Overview of IAM
    Policies <http://docs.aws.amazon.com/IAM/latest/UserGuide/policies_overview.html>`_
    in the IAM User Guide guide.

    :exampleMetadata: infused

    Example::

        # post_auth_fn: lambda.Function
        
        
        userpool = cognito.UserPool(self, "myuserpool",
            lambda_triggers=cognito.UserPoolTriggers(
                post_authentication=post_auth_fn
            )
        )
        
        # provide permissions to describe the user pool scoped to the ARN the user pool
        post_auth_fn.role.attach_inline_policy(iam.Policy(self, "userpool-policy",
            statements=[iam.PolicyStatement(
                actions=["cognito-idp:DescribeUserPool"],
                resources=[userpool.user_pool_arn]
            )]
        ))
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        document: typing.Optional["PolicyDocument"] = None,
        force: typing.Optional[builtins.bool] = None,
        groups: typing.Optional[typing.Sequence["IGroup"]] = None,
        policy_name: typing.Optional[builtins.str] = None,
        roles: typing.Optional[typing.Sequence["IRole"]] = None,
        statements: typing.Optional[typing.Sequence["PolicyStatement"]] = None,
        users: typing.Optional[typing.Sequence["IUser"]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param document: Initial PolicyDocument to use for this Policy. If omited, any ``PolicyStatement`` provided in the ``statements`` property will be applied against the empty default ``PolicyDocument``. Default: - An empty policy.
        :param force: Force creation of an ``AWS::IAM::Policy``. Unless set to ``true``, this ``Policy`` construct will not materialize to an ``AWS::IAM::Policy`` CloudFormation resource in case it would have no effect (for example, if it remains unattached to an IAM identity or if it has no statements). This is generally desired behavior, since it prevents creating invalid--and hence undeployable--CloudFormation templates. In cases where you know the policy must be created and it is actually an error if no statements have been added to it, you can set this to ``true``. Default: false
        :param groups: Groups to attach this policy to. You can also use ``attachToGroup(group)`` to attach this policy to a group. Default: - No groups.
        :param policy_name: The name of the policy. If you specify multiple policies for an entity, specify unique names. For example, if you specify a list of policies for an IAM role, each policy must have a unique name. Default: - Uses the logical ID of the policy resource, which is ensured to be unique within the stack.
        :param roles: Roles to attach this policy to. You can also use ``attachToRole(role)`` to attach this policy to a role. Default: - No roles.
        :param statements: Initial set of permissions to add to this policy document. You can also use ``addStatements(...statement)`` to add permissions later. Default: - No statements.
        :param users: Users to attach this policy to. You can also use ``attachToUser(user)`` to attach this policy to a user. Default: - No users.
        '''
        props = PolicyProps(
            document=document,
            force=force,
            groups=groups,
            policy_name=policy_name,
            roles=roles,
            statements=statements,
            users=users,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromPolicyName") # type: ignore[misc]
    @builtins.classmethod
    def from_policy_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        policy_name: builtins.str,
    ) -> IPolicy:
        '''Import a policy in this app based on its name.

        :param scope: -
        :param id: -
        :param policy_name: -
        '''
        return typing.cast(IPolicy, jsii.sinvoke(cls, "fromPolicyName", [scope, id, policy_name]))

    @jsii.member(jsii_name="addStatements")
    def add_statements(self, *statement: "PolicyStatement") -> None:
        '''Adds a statement to the policy document.

        :param statement: -
        '''
        return typing.cast(None, jsii.invoke(self, "addStatements", [*statement]))

    @jsii.member(jsii_name="attachToGroup")
    def attach_to_group(self, group: "IGroup") -> None:
        '''Attaches this policy to a group.

        :param group: -
        '''
        return typing.cast(None, jsii.invoke(self, "attachToGroup", [group]))

    @jsii.member(jsii_name="attachToRole")
    def attach_to_role(self, role: "IRole") -> None:
        '''Attaches this policy to a role.

        :param role: -
        '''
        return typing.cast(None, jsii.invoke(self, "attachToRole", [role]))

    @jsii.member(jsii_name="attachToUser")
    def attach_to_user(self, user: "IUser") -> None:
        '''Attaches this policy to a user.

        :param user: -
        '''
        return typing.cast(None, jsii.invoke(self, "attachToUser", [user]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="document")
    def document(self) -> "PolicyDocument":
        '''The policy document.'''
        return typing.cast("PolicyDocument", jsii.get(self, "document"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyName")
    def policy_name(self) -> builtins.str:
        '''The name of this policy.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "policyName"))


@jsii.implements(_IResolvable_da3f097b)
class PolicyDocument(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.PolicyDocument",
):
    '''A PolicyDocument is a collection of statements.

    :exampleMetadata: infused

    Example::

        my_trusted_admin_role = iam.Role.from_role_arn(self, "TrustedRole", "arn:aws:iam:....")
        # Creates a limited admin policy and assigns to the account root.
        my_custom_policy = iam.PolicyDocument(
            statements=[iam.PolicyStatement(
                actions=["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*"
                ],
                principals=[iam.AccountRootPrincipal()],
                resources=["*"]
            )]
        )
        key = kms.Key(self, "MyKey",
            policy=my_custom_policy
        )
    '''

    def __init__(
        self,
        *,
        assign_sids: typing.Optional[builtins.bool] = None,
        statements: typing.Optional[typing.Sequence["PolicyStatement"]] = None,
    ) -> None:
        '''
        :param assign_sids: Automatically assign Statement Ids to all statements. Default: false
        :param statements: Initial statements to add to the policy document. Default: - No statements
        '''
        props = PolicyDocumentProps(assign_sids=assign_sids, statements=statements)

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="fromJson") # type: ignore[misc]
    @builtins.classmethod
    def from_json(cls, obj: typing.Any) -> "PolicyDocument":
        '''Creates a new PolicyDocument based on the object provided.

        This will accept an object created from the ``.toJSON()`` call

        :param obj: the PolicyDocument in object form.
        '''
        return typing.cast("PolicyDocument", jsii.sinvoke(cls, "fromJson", [obj]))

    @jsii.member(jsii_name="addStatements")
    def add_statements(self, *statement: "PolicyStatement") -> None:
        '''Adds a statement to the policy document.

        :param statement: the statement to add.
        '''
        return typing.cast(None, jsii.invoke(self, "addStatements", [*statement]))

    @jsii.member(jsii_name="resolve")
    def resolve(self, context: _IResolveContext_b2df1921) -> typing.Any:
        '''Produce the Token's value at resolution time.

        :param context: -
        '''
        return typing.cast(typing.Any, jsii.invoke(self, "resolve", [context]))

    @jsii.member(jsii_name="toJSON")
    def to_json(self) -> typing.Any:
        '''JSON-ify the document.

        Used when JSON.stringify() is called
        '''
        return typing.cast(typing.Any, jsii.invoke(self, "toJSON", []))

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Encode the policy document as a string.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @jsii.member(jsii_name="validateForAnyPolicy")
    def validate_for_any_policy(self) -> typing.List[builtins.str]:
        '''Validate that all policy statements in the policy document satisfies the requirements for any policy.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json
        '''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateForAnyPolicy", []))

    @jsii.member(jsii_name="validateForIdentityPolicy")
    def validate_for_identity_policy(self) -> typing.List[builtins.str]:
        '''Validate that all policy statements in the policy document satisfies the requirements for an identity-based policy.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json
        '''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateForIdentityPolicy", []))

    @jsii.member(jsii_name="validateForResourcePolicy")
    def validate_for_resource_policy(self) -> typing.List[builtins.str]:
        '''Validate that all policy statements in the policy document satisfies the requirements for a resource-based policy.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json
        '''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateForResourcePolicy", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="creationStack")
    def creation_stack(self) -> typing.List[builtins.str]:
        '''The creation stack of this resolvable which will be appended to errors thrown during resolution.

        This may return an array with a single informational element indicating how
        to get this property populated, if it was skipped for performance reasons.
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "creationStack"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isEmpty")
    def is_empty(self) -> builtins.bool:
        '''Whether the policy document contains any statements.'''
        return typing.cast(builtins.bool, jsii.get(self, "isEmpty"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="statementCount")
    def statement_count(self) -> jsii.Number:
        '''The number of statements already added to this policy.

        Can be used, for example, to generate unique "sid"s within the policy.
        '''
        return typing.cast(jsii.Number, jsii.get(self, "statementCount"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.PolicyDocumentProps",
    jsii_struct_bases=[],
    name_mapping={"assign_sids": "assignSids", "statements": "statements"},
)
class PolicyDocumentProps:
    def __init__(
        self,
        *,
        assign_sids: typing.Optional[builtins.bool] = None,
        statements: typing.Optional[typing.Sequence["PolicyStatement"]] = None,
    ) -> None:
        '''Properties for a new PolicyDocument.

        :param assign_sids: Automatically assign Statement Ids to all statements. Default: false
        :param statements: Initial statements to add to the policy document. Default: - No statements

        :exampleMetadata: infused

        Example::

            my_trusted_admin_role = iam.Role.from_role_arn(self, "TrustedRole", "arn:aws:iam:....")
            # Creates a limited admin policy and assigns to the account root.
            my_custom_policy = iam.PolicyDocument(
                statements=[iam.PolicyStatement(
                    actions=["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*"
                    ],
                    principals=[iam.AccountRootPrincipal()],
                    resources=["*"]
                )]
            )
            key = kms.Key(self, "MyKey",
                policy=my_custom_policy
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if assign_sids is not None:
            self._values["assign_sids"] = assign_sids
        if statements is not None:
            self._values["statements"] = statements

    @builtins.property
    def assign_sids(self) -> typing.Optional[builtins.bool]:
        '''Automatically assign Statement Ids to all statements.

        :default: false
        '''
        result = self._values.get("assign_sids")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def statements(self) -> typing.Optional[typing.List["PolicyStatement"]]:
        '''Initial statements to add to the policy document.

        :default: - No statements
        '''
        result = self._values.get("statements")
        return typing.cast(typing.Optional[typing.List["PolicyStatement"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PolicyDocumentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.PolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "document": "document",
        "force": "force",
        "groups": "groups",
        "policy_name": "policyName",
        "roles": "roles",
        "statements": "statements",
        "users": "users",
    },
)
class PolicyProps:
    def __init__(
        self,
        *,
        document: typing.Optional[PolicyDocument] = None,
        force: typing.Optional[builtins.bool] = None,
        groups: typing.Optional[typing.Sequence["IGroup"]] = None,
        policy_name: typing.Optional[builtins.str] = None,
        roles: typing.Optional[typing.Sequence["IRole"]] = None,
        statements: typing.Optional[typing.Sequence["PolicyStatement"]] = None,
        users: typing.Optional[typing.Sequence["IUser"]] = None,
    ) -> None:
        '''Properties for defining an IAM inline policy document.

        :param document: Initial PolicyDocument to use for this Policy. If omited, any ``PolicyStatement`` provided in the ``statements`` property will be applied against the empty default ``PolicyDocument``. Default: - An empty policy.
        :param force: Force creation of an ``AWS::IAM::Policy``. Unless set to ``true``, this ``Policy`` construct will not materialize to an ``AWS::IAM::Policy`` CloudFormation resource in case it would have no effect (for example, if it remains unattached to an IAM identity or if it has no statements). This is generally desired behavior, since it prevents creating invalid--and hence undeployable--CloudFormation templates. In cases where you know the policy must be created and it is actually an error if no statements have been added to it, you can set this to ``true``. Default: false
        :param groups: Groups to attach this policy to. You can also use ``attachToGroup(group)`` to attach this policy to a group. Default: - No groups.
        :param policy_name: The name of the policy. If you specify multiple policies for an entity, specify unique names. For example, if you specify a list of policies for an IAM role, each policy must have a unique name. Default: - Uses the logical ID of the policy resource, which is ensured to be unique within the stack.
        :param roles: Roles to attach this policy to. You can also use ``attachToRole(role)`` to attach this policy to a role. Default: - No roles.
        :param statements: Initial set of permissions to add to this policy document. You can also use ``addStatements(...statement)`` to add permissions later. Default: - No statements.
        :param users: Users to attach this policy to. You can also use ``attachToUser(user)`` to attach this policy to a user. Default: - No users.

        :exampleMetadata: infused

        Example::

            # post_auth_fn: lambda.Function
            
            
            userpool = cognito.UserPool(self, "myuserpool",
                lambda_triggers=cognito.UserPoolTriggers(
                    post_authentication=post_auth_fn
                )
            )
            
            # provide permissions to describe the user pool scoped to the ARN the user pool
            post_auth_fn.role.attach_inline_policy(iam.Policy(self, "userpool-policy",
                statements=[iam.PolicyStatement(
                    actions=["cognito-idp:DescribeUserPool"],
                    resources=[userpool.user_pool_arn]
                )]
            ))
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if document is not None:
            self._values["document"] = document
        if force is not None:
            self._values["force"] = force
        if groups is not None:
            self._values["groups"] = groups
        if policy_name is not None:
            self._values["policy_name"] = policy_name
        if roles is not None:
            self._values["roles"] = roles
        if statements is not None:
            self._values["statements"] = statements
        if users is not None:
            self._values["users"] = users

    @builtins.property
    def document(self) -> typing.Optional[PolicyDocument]:
        '''Initial PolicyDocument to use for this Policy.

        If omited, any
        ``PolicyStatement`` provided in the ``statements`` property will be applied
        against the empty default ``PolicyDocument``.

        :default: - An empty policy.
        '''
        result = self._values.get("document")
        return typing.cast(typing.Optional[PolicyDocument], result)

    @builtins.property
    def force(self) -> typing.Optional[builtins.bool]:
        '''Force creation of an ``AWS::IAM::Policy``.

        Unless set to ``true``, this ``Policy`` construct will not materialize to an
        ``AWS::IAM::Policy`` CloudFormation resource in case it would have no effect
        (for example, if it remains unattached to an IAM identity or if it has no
        statements). This is generally desired behavior, since it prevents
        creating invalid--and hence undeployable--CloudFormation templates.

        In cases where you know the policy must be created and it is actually
        an error if no statements have been added to it, you can set this to ``true``.

        :default: false
        '''
        result = self._values.get("force")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def groups(self) -> typing.Optional[typing.List["IGroup"]]:
        '''Groups to attach this policy to.

        You can also use ``attachToGroup(group)`` to attach this policy to a group.

        :default: - No groups.
        '''
        result = self._values.get("groups")
        return typing.cast(typing.Optional[typing.List["IGroup"]], result)

    @builtins.property
    def policy_name(self) -> typing.Optional[builtins.str]:
        '''The name of the policy.

        If you specify multiple policies for an entity,
        specify unique names. For example, if you specify a list of policies for
        an IAM role, each policy must have a unique name.

        :default:

        - Uses the logical ID of the policy resource, which is ensured
        to be unique within the stack.
        '''
        result = self._values.get("policy_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def roles(self) -> typing.Optional[typing.List["IRole"]]:
        '''Roles to attach this policy to.

        You can also use ``attachToRole(role)`` to attach this policy to a role.

        :default: - No roles.
        '''
        result = self._values.get("roles")
        return typing.cast(typing.Optional[typing.List["IRole"]], result)

    @builtins.property
    def statements(self) -> typing.Optional[typing.List["PolicyStatement"]]:
        '''Initial set of permissions to add to this policy document.

        You can also use ``addStatements(...statement)`` to add permissions later.

        :default: - No statements.
        '''
        result = self._values.get("statements")
        return typing.cast(typing.Optional[typing.List["PolicyStatement"]], result)

    @builtins.property
    def users(self) -> typing.Optional[typing.List["IUser"]]:
        '''Users to attach this policy to.

        You can also use ``attachToUser(user)`` to attach this policy to a user.

        :default: - No users.
        '''
        result = self._values.get("users")
        return typing.cast(typing.Optional[typing.List["IUser"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class PolicyStatement(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.PolicyStatement",
):
    '''Represents a statement in an IAM policy document.

    :exampleMetadata: infused

    Example::

        # post_auth_fn: lambda.Function
        
        
        userpool = cognito.UserPool(self, "myuserpool",
            lambda_triggers=cognito.UserPoolTriggers(
                post_authentication=post_auth_fn
            )
        )
        
        # provide permissions to describe the user pool scoped to the ARN the user pool
        post_auth_fn.role.attach_inline_policy(iam.Policy(self, "userpool-policy",
            statements=[iam.PolicyStatement(
                actions=["cognito-idp:DescribeUserPool"],
                resources=[userpool.user_pool_arn]
            )]
        ))
    '''

    def __init__(
        self,
        *,
        actions: typing.Optional[typing.Sequence[builtins.str]] = None,
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        effect: typing.Optional[Effect] = None,
        not_actions: typing.Optional[typing.Sequence[builtins.str]] = None,
        not_principals: typing.Optional[typing.Sequence[IPrincipal]] = None,
        not_resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        principals: typing.Optional[typing.Sequence[IPrincipal]] = None,
        resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        sid: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param actions: List of actions to add to the statement. Default: - no actions
        :param conditions: Conditions to add to the statement. Default: - no condition
        :param effect: Whether to allow or deny the actions in this statement. Default: Effect.ALLOW
        :param not_actions: List of not actions to add to the statement. Default: - no not-actions
        :param not_principals: List of not principals to add to the statement. Default: - no not principals
        :param not_resources: NotResource ARNs to add to the statement. Default: - no not-resources
        :param principals: List of principals to add to the statement. Default: - no principals
        :param resources: Resource ARNs to add to the statement. Default: - no resources
        :param sid: The Sid (statement ID) is an optional identifier that you provide for the policy statement. You can assign a Sid value to each statement in a statement array. In services that let you specify an ID element, such as SQS and SNS, the Sid value is just a sub-ID of the policy document's ID. In IAM, the Sid value must be unique within a JSON policy. Default: - no sid
        '''
        props = PolicyStatementProps(
            actions=actions,
            conditions=conditions,
            effect=effect,
            not_actions=not_actions,
            not_principals=not_principals,
            not_resources=not_resources,
            principals=principals,
            resources=resources,
            sid=sid,
        )

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="fromJson") # type: ignore[misc]
    @builtins.classmethod
    def from_json(cls, obj: typing.Any) -> "PolicyStatement":
        '''Creates a new PolicyStatement based on the object provided.

        This will accept an object created from the ``.toJSON()`` call

        :param obj: the PolicyStatement in object form.
        '''
        return typing.cast("PolicyStatement", jsii.sinvoke(cls, "fromJson", [obj]))

    @jsii.member(jsii_name="addAccountCondition")
    def add_account_condition(self, account_id: builtins.str) -> None:
        '''Add a condition that limits to a given account.

        :param account_id: -
        '''
        return typing.cast(None, jsii.invoke(self, "addAccountCondition", [account_id]))

    @jsii.member(jsii_name="addAccountRootPrincipal")
    def add_account_root_principal(self) -> None:
        '''Adds an AWS account root user principal to this policy statement.'''
        return typing.cast(None, jsii.invoke(self, "addAccountRootPrincipal", []))

    @jsii.member(jsii_name="addActions")
    def add_actions(self, *actions: builtins.str) -> None:
        '''Specify allowed actions into the "Action" section of the policy statement.

        :param actions: actions that will be allowed.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html
        '''
        return typing.cast(None, jsii.invoke(self, "addActions", [*actions]))

    @jsii.member(jsii_name="addAllResources")
    def add_all_resources(self) -> None:
        '''Adds a ``"*"`` resource to this statement.'''
        return typing.cast(None, jsii.invoke(self, "addAllResources", []))

    @jsii.member(jsii_name="addAnyPrincipal")
    def add_any_principal(self) -> None:
        '''Adds all identities in all accounts ("*") to this policy statement.'''
        return typing.cast(None, jsii.invoke(self, "addAnyPrincipal", []))

    @jsii.member(jsii_name="addArnPrincipal")
    def add_arn_principal(self, arn: builtins.str) -> None:
        '''Specify a principal using the ARN  identifier of the principal.

        You cannot specify IAM groups and instance profiles as principals.

        :param arn: ARN identifier of AWS account, IAM user, or IAM role (i.e. arn:aws:iam::123456789012:user/user-name).
        '''
        return typing.cast(None, jsii.invoke(self, "addArnPrincipal", [arn]))

    @jsii.member(jsii_name="addAwsAccountPrincipal")
    def add_aws_account_principal(self, account_id: builtins.str) -> None:
        '''Specify AWS account ID as the principal entity to the "Principal" section of a policy statement.

        :param account_id: -
        '''
        return typing.cast(None, jsii.invoke(self, "addAwsAccountPrincipal", [account_id]))

    @jsii.member(jsii_name="addCanonicalUserPrincipal")
    def add_canonical_user_principal(self, canonical_user_id: builtins.str) -> None:
        '''Adds a canonical user ID principal to this policy document.

        :param canonical_user_id: unique identifier assigned by AWS for every account.
        '''
        return typing.cast(None, jsii.invoke(self, "addCanonicalUserPrincipal", [canonical_user_id]))

    @jsii.member(jsii_name="addCondition")
    def add_condition(self, key: builtins.str, value: typing.Any) -> None:
        '''Add a condition to the Policy.

        :param key: -
        :param value: -
        '''
        return typing.cast(None, jsii.invoke(self, "addCondition", [key, value]))

    @jsii.member(jsii_name="addConditions")
    def add_conditions(
        self,
        conditions: typing.Mapping[builtins.str, typing.Any],
    ) -> None:
        '''Add multiple conditions to the Policy.

        :param conditions: -
        '''
        return typing.cast(None, jsii.invoke(self, "addConditions", [conditions]))

    @jsii.member(jsii_name="addFederatedPrincipal")
    def add_federated_principal(
        self,
        federated: typing.Any,
        conditions: typing.Mapping[builtins.str, typing.Any],
    ) -> None:
        '''Adds a federated identity provider such as Amazon Cognito to this policy statement.

        :param federated: federated identity provider (i.e. 'cognito-identity.amazonaws.com').
        :param conditions: The conditions under which the policy is in effect. See `the IAM documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`_.
        '''
        return typing.cast(None, jsii.invoke(self, "addFederatedPrincipal", [federated, conditions]))

    @jsii.member(jsii_name="addNotActions")
    def add_not_actions(self, *not_actions: builtins.str) -> None:
        '''Explicitly allow all actions except the specified list of actions into the "NotAction" section of the policy document.

        :param not_actions: actions that will be denied. All other actions will be permitted.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html
        '''
        return typing.cast(None, jsii.invoke(self, "addNotActions", [*not_actions]))

    @jsii.member(jsii_name="addNotPrincipals")
    def add_not_principals(self, *not_principals: IPrincipal) -> None:
        '''Specify principals that is not allowed or denied access to the "NotPrincipal" section of a policy statement.

        :param not_principals: IAM principals that will be denied access.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
        '''
        return typing.cast(None, jsii.invoke(self, "addNotPrincipals", [*not_principals]))

    @jsii.member(jsii_name="addNotResources")
    def add_not_resources(self, *arns: builtins.str) -> None:
        '''Specify resources that this policy statement will not apply to in the "NotResource" section of this policy statement.

        All resources except the specified list will be matched.

        :param arns: Amazon Resource Names (ARNs) of the resources that this policy statement does not apply to.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html
        '''
        return typing.cast(None, jsii.invoke(self, "addNotResources", [*arns]))

    @jsii.member(jsii_name="addPrincipals")
    def add_principals(self, *principals: IPrincipal) -> None:
        '''Adds principals to the "Principal" section of a policy statement.

        :param principals: IAM principals that will be added.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
        '''
        return typing.cast(None, jsii.invoke(self, "addPrincipals", [*principals]))

    @jsii.member(jsii_name="addResources")
    def add_resources(self, *arns: builtins.str) -> None:
        '''Specify resources that this policy statement applies into the "Resource" section of this policy statement.

        :param arns: Amazon Resource Names (ARNs) of the resources that this policy statement applies to.

        :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
        '''
        return typing.cast(None, jsii.invoke(self, "addResources", [*arns]))

    @jsii.member(jsii_name="addServicePrincipal")
    def add_service_principal(
        self,
        service: builtins.str,
        *,
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        region: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Adds a service principal to this policy statement.

        :param service: the service name for which a service principal is requested (e.g: ``s3.amazonaws.com``).
        :param conditions: Additional conditions to add to the Service Principal. Default: - No conditions
        :param region: (deprecated) The region in which the service is operating. Default: the current Stack's region.
        '''
        opts = ServicePrincipalOpts(conditions=conditions, region=region)

        return typing.cast(None, jsii.invoke(self, "addServicePrincipal", [service, opts]))

    @jsii.member(jsii_name="toJSON")
    def to_json(self) -> typing.Any:
        '''JSON-ify the statement.

        Used when JSON.stringify() is called
        '''
        return typing.cast(typing.Any, jsii.invoke(self, "toJSON", []))

    @jsii.member(jsii_name="toStatementJson")
    def to_statement_json(self) -> typing.Any:
        '''JSON-ify the policy statement.

        Used when JSON.stringify() is called
        '''
        return typing.cast(typing.Any, jsii.invoke(self, "toStatementJson", []))

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''String representation of this policy statement.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @jsii.member(jsii_name="validateForAnyPolicy")
    def validate_for_any_policy(self) -> typing.List[builtins.str]:
        '''Validate that the policy statement satisfies base requirements for a policy.'''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateForAnyPolicy", []))

    @jsii.member(jsii_name="validateForIdentityPolicy")
    def validate_for_identity_policy(self) -> typing.List[builtins.str]:
        '''Validate that the policy statement satisfies all requirements for an identity-based policy.'''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateForIdentityPolicy", []))

    @jsii.member(jsii_name="validateForResourcePolicy")
    def validate_for_resource_policy(self) -> typing.List[builtins.str]:
        '''Validate that the policy statement satisfies all requirements for a resource-based policy.'''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateForResourcePolicy", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hasPrincipal")
    def has_principal(self) -> builtins.bool:
        '''Indicates if this permission has a "Principal" section.'''
        return typing.cast(builtins.bool, jsii.get(self, "hasPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="hasResource")
    def has_resource(self) -> builtins.bool:
        '''Indicates if this permission has at least one resource associated with it.'''
        return typing.cast(builtins.bool, jsii.get(self, "hasResource"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="effect")
    def effect(self) -> Effect:
        '''Whether to allow or deny the actions in this statement.'''
        return typing.cast(Effect, jsii.get(self, "effect"))

    @effect.setter
    def effect(self, value: Effect) -> None:
        jsii.set(self, "effect", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sid")
    def sid(self) -> typing.Optional[builtins.str]:
        '''Statement ID for this statement.'''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "sid"))

    @sid.setter
    def sid(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "sid", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.PolicyStatementProps",
    jsii_struct_bases=[],
    name_mapping={
        "actions": "actions",
        "conditions": "conditions",
        "effect": "effect",
        "not_actions": "notActions",
        "not_principals": "notPrincipals",
        "not_resources": "notResources",
        "principals": "principals",
        "resources": "resources",
        "sid": "sid",
    },
)
class PolicyStatementProps:
    def __init__(
        self,
        *,
        actions: typing.Optional[typing.Sequence[builtins.str]] = None,
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        effect: typing.Optional[Effect] = None,
        not_actions: typing.Optional[typing.Sequence[builtins.str]] = None,
        not_principals: typing.Optional[typing.Sequence[IPrincipal]] = None,
        not_resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        principals: typing.Optional[typing.Sequence[IPrincipal]] = None,
        resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        sid: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Interface for creating a policy statement.

        :param actions: List of actions to add to the statement. Default: - no actions
        :param conditions: Conditions to add to the statement. Default: - no condition
        :param effect: Whether to allow or deny the actions in this statement. Default: Effect.ALLOW
        :param not_actions: List of not actions to add to the statement. Default: - no not-actions
        :param not_principals: List of not principals to add to the statement. Default: - no not principals
        :param not_resources: NotResource ARNs to add to the statement. Default: - no not-resources
        :param principals: List of principals to add to the statement. Default: - no principals
        :param resources: Resource ARNs to add to the statement. Default: - no resources
        :param sid: The Sid (statement ID) is an optional identifier that you provide for the policy statement. You can assign a Sid value to each statement in a statement array. In services that let you specify an ID element, such as SQS and SNS, the Sid value is just a sub-ID of the policy document's ID. In IAM, the Sid value must be unique within a JSON policy. Default: - no sid

        :exampleMetadata: infused

        Example::

            # post_auth_fn: lambda.Function
            
            
            userpool = cognito.UserPool(self, "myuserpool",
                lambda_triggers=cognito.UserPoolTriggers(
                    post_authentication=post_auth_fn
                )
            )
            
            # provide permissions to describe the user pool scoped to the ARN the user pool
            post_auth_fn.role.attach_inline_policy(iam.Policy(self, "userpool-policy",
                statements=[iam.PolicyStatement(
                    actions=["cognito-idp:DescribeUserPool"],
                    resources=[userpool.user_pool_arn]
                )]
            ))
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if actions is not None:
            self._values["actions"] = actions
        if conditions is not None:
            self._values["conditions"] = conditions
        if effect is not None:
            self._values["effect"] = effect
        if not_actions is not None:
            self._values["not_actions"] = not_actions
        if not_principals is not None:
            self._values["not_principals"] = not_principals
        if not_resources is not None:
            self._values["not_resources"] = not_resources
        if principals is not None:
            self._values["principals"] = principals
        if resources is not None:
            self._values["resources"] = resources
        if sid is not None:
            self._values["sid"] = sid

    @builtins.property
    def actions(self) -> typing.Optional[typing.List[builtins.str]]:
        '''List of actions to add to the statement.

        :default: - no actions
        '''
        result = self._values.get("actions")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def conditions(self) -> typing.Optional[typing.Mapping[builtins.str, typing.Any]]:
        '''Conditions to add to the statement.

        :default: - no condition
        '''
        result = self._values.get("conditions")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, typing.Any]], result)

    @builtins.property
    def effect(self) -> typing.Optional[Effect]:
        '''Whether to allow or deny the actions in this statement.

        :default: Effect.ALLOW
        '''
        result = self._values.get("effect")
        return typing.cast(typing.Optional[Effect], result)

    @builtins.property
    def not_actions(self) -> typing.Optional[typing.List[builtins.str]]:
        '''List of not actions to add to the statement.

        :default: - no not-actions
        '''
        result = self._values.get("not_actions")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def not_principals(self) -> typing.Optional[typing.List[IPrincipal]]:
        '''List of not principals to add to the statement.

        :default: - no not principals
        '''
        result = self._values.get("not_principals")
        return typing.cast(typing.Optional[typing.List[IPrincipal]], result)

    @builtins.property
    def not_resources(self) -> typing.Optional[typing.List[builtins.str]]:
        '''NotResource ARNs to add to the statement.

        :default: - no not-resources
        '''
        result = self._values.get("not_resources")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def principals(self) -> typing.Optional[typing.List[IPrincipal]]:
        '''List of principals to add to the statement.

        :default: - no principals
        '''
        result = self._values.get("principals")
        return typing.cast(typing.Optional[typing.List[IPrincipal]], result)

    @builtins.property
    def resources(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Resource ARNs to add to the statement.

        :default: - no resources
        '''
        result = self._values.get("resources")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def sid(self) -> typing.Optional[builtins.str]:
        '''The Sid (statement ID) is an optional identifier that you provide for the policy statement.

        You can assign a Sid value to each statement in a
        statement array. In services that let you specify an ID element, such as
        SQS and SNS, the Sid value is just a sub-ID of the policy document's ID. In
        IAM, the Sid value must be unique within a JSON policy.

        :default: - no sid
        '''
        result = self._values.get("sid")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PolicyStatementProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class PrincipalPolicyFragment(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.PrincipalPolicyFragment",
):
    '''A collection of the fields in a PolicyStatement that can be used to identify a principal.

    This consists of the JSON used in the "Principal" field, and optionally a
    set of "Condition"s that need to be applied to the policy.

    Generally, a principal looks like::

        { '<TYPE>': ['ID', 'ID', ...] }

    And this is also the type of the field ``principalJson``.  However, there is a
    special type of principal that is just the string '*', which is treated
    differently by some services. To represent that principal, ``principalJson``
    should contain ``{ 'LiteralString': ['*'] }``.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # conditions: Any
        
        principal_policy_fragment = iam.PrincipalPolicyFragment({
            "principal_json_key": ["principalJson"]
        }, {
            "conditions_key": conditions
        })
    '''

    def __init__(
        self,
        principal_json: typing.Mapping[builtins.str, typing.Sequence[builtins.str]],
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
    ) -> None:
        '''
        :param principal_json: JSON of the "Principal" section in a policy statement.
        :param conditions: The conditions under which the policy is in effect. See `the IAM documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`_. conditions that need to be applied to this policy
        '''
        jsii.create(self.__class__, self, [principal_json, conditions])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="conditions")
    def conditions(self) -> typing.Mapping[builtins.str, typing.Any]:
        '''The conditions under which the policy is in effect.

        See `the IAM documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`_.
        conditions that need to be applied to this policy
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "conditions"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalJson")
    def principal_json(self) -> typing.Mapping[builtins.str, typing.List[builtins.str]]:
        '''JSON of the "Principal" section in a policy statement.'''
        return typing.cast(typing.Mapping[builtins.str, typing.List[builtins.str]], jsii.get(self, "principalJson"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.RoleProps",
    jsii_struct_bases=[],
    name_mapping={
        "assumed_by": "assumedBy",
        "description": "description",
        "external_ids": "externalIds",
        "inline_policies": "inlinePolicies",
        "managed_policies": "managedPolicies",
        "max_session_duration": "maxSessionDuration",
        "path": "path",
        "permissions_boundary": "permissionsBoundary",
        "role_name": "roleName",
    },
)
class RoleProps:
    def __init__(
        self,
        *,
        assumed_by: IPrincipal,
        description: typing.Optional[builtins.str] = None,
        external_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        inline_policies: typing.Optional[typing.Mapping[builtins.str, PolicyDocument]] = None,
        managed_policies: typing.Optional[typing.Sequence[IManagedPolicy]] = None,
        max_session_duration: typing.Optional[_Duration_4839e8c3] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[IManagedPolicy] = None,
        role_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining an IAM Role.

        :param assumed_by: The IAM principal (i.e. ``new ServicePrincipal('sns.amazonaws.com')``) which can assume this role. You can later modify the assume role policy document by accessing it via the ``assumeRolePolicy`` property.
        :param description: A description of the role. It can be up to 1000 characters long. Default: - No description.
        :param external_ids: List of IDs that the role assumer needs to provide one of when assuming this role. If the configured and provided external IDs do not match, the AssumeRole operation will fail. Default: No external ID required
        :param inline_policies: A list of named policies to inline into this role. These policies will be created with the role, whereas those added by ``addToPolicy`` are added using a separate CloudFormation resource (allowing a way around circular dependencies that could otherwise be introduced). Default: - No policy is inlined in the Role resource.
        :param managed_policies: A list of managed policies associated with this role. You can add managed policies later using ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``. Default: - No managed policies.
        :param max_session_duration: The maximum session duration that you want to set for the specified role. This setting can have a value from 1 hour (3600sec) to 12 (43200sec) hours. Anyone who assumes the role from the AWS CLI or API can use the DurationSeconds API parameter or the duration-seconds CLI parameter to request a longer session. The MaxSessionDuration setting determines the maximum duration that can be requested using the DurationSeconds parameter. If users don't specify a value for the DurationSeconds parameter, their security credentials are valid for one hour by default. This applies when you use the AssumeRole* API operations or the assume-role* CLI operations but does not apply when you use those operations to create a console URL. Default: Duration.hours(1)
        :param path: The path associated with this role. For information about IAM paths, see Friendly Names and Paths in IAM User Guide. Default: /
        :param permissions_boundary: AWS supports permissions boundaries for IAM entities (users or roles). A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. An entity's permissions boundary allows it to perform only the actions that are allowed by both its identity-based policies and its permissions boundaries. Default: - No permissions boundary.
        :param role_name: A name for the IAM role. For valid values, see the RoleName parameter for the CreateRole action in the IAM API Reference. IMPORTANT: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to acknowledge your template's capabilities. For more information, see Acknowledging IAM Resources in AWS CloudFormation Templates. Default: - AWS CloudFormation generates a unique physical ID and uses that ID for the role name.

        :exampleMetadata: infused

        Example::

            lambda_role = iam.Role(self, "Role",
                assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                description="Example role..."
            )
            
            stream = kinesis.Stream(self, "MyEncryptedStream",
                encryption=kinesis.StreamEncryption.KMS
            )
            
            # give lambda permissions to read stream
            stream.grant_read(lambda_role)
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "assumed_by": assumed_by,
        }
        if description is not None:
            self._values["description"] = description
        if external_ids is not None:
            self._values["external_ids"] = external_ids
        if inline_policies is not None:
            self._values["inline_policies"] = inline_policies
        if managed_policies is not None:
            self._values["managed_policies"] = managed_policies
        if max_session_duration is not None:
            self._values["max_session_duration"] = max_session_duration
        if path is not None:
            self._values["path"] = path
        if permissions_boundary is not None:
            self._values["permissions_boundary"] = permissions_boundary
        if role_name is not None:
            self._values["role_name"] = role_name

    @builtins.property
    def assumed_by(self) -> IPrincipal:
        '''The IAM principal (i.e. ``new ServicePrincipal('sns.amazonaws.com')``) which can assume this role.

        You can later modify the assume role policy document by accessing it via
        the ``assumeRolePolicy`` property.
        '''
        result = self._values.get("assumed_by")
        assert result is not None, "Required property 'assumed_by' is missing"
        return typing.cast(IPrincipal, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the role.

        It can be up to 1000 characters long.

        :default: - No description.
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def external_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''List of IDs that the role assumer needs to provide one of when assuming this role.

        If the configured and provided external IDs do not match, the
        AssumeRole operation will fail.

        :default: No external ID required
        '''
        result = self._values.get("external_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def inline_policies(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, PolicyDocument]]:
        '''A list of named policies to inline into this role.

        These policies will be
        created with the role, whereas those added by ``addToPolicy`` are added
        using a separate CloudFormation resource (allowing a way around circular
        dependencies that could otherwise be introduced).

        :default: - No policy is inlined in the Role resource.
        '''
        result = self._values.get("inline_policies")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, PolicyDocument]], result)

    @builtins.property
    def managed_policies(self) -> typing.Optional[typing.List[IManagedPolicy]]:
        '''A list of managed policies associated with this role.

        You can add managed policies later using
        ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``.

        :default: - No managed policies.
        '''
        result = self._values.get("managed_policies")
        return typing.cast(typing.Optional[typing.List[IManagedPolicy]], result)

    @builtins.property
    def max_session_duration(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The maximum session duration that you want to set for the specified role.

        This setting can have a value from 1 hour (3600sec) to 12 (43200sec) hours.

        Anyone who assumes the role from the AWS CLI or API can use the
        DurationSeconds API parameter or the duration-seconds CLI parameter to
        request a longer session. The MaxSessionDuration setting determines the
        maximum duration that can be requested using the DurationSeconds
        parameter.

        If users don't specify a value for the DurationSeconds parameter, their
        security credentials are valid for one hour by default. This applies when
        you use the AssumeRole* API operations or the assume-role* CLI operations
        but does not apply when you use those operations to create a console URL.

        :default: Duration.hours(1)

        :link: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html
        '''
        result = self._values.get("max_session_duration")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path associated with this role.

        For information about IAM paths, see
        Friendly Names and Paths in IAM User Guide.

        :default: /
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions_boundary(self) -> typing.Optional[IManagedPolicy]:
        '''AWS supports permissions boundaries for IAM entities (users or roles).

        A permissions boundary is an advanced feature for using a managed policy
        to set the maximum permissions that an identity-based policy can grant to
        an IAM entity. An entity's permissions boundary allows it to perform only
        the actions that are allowed by both its identity-based policies and its
        permissions boundaries.

        :default: - No permissions boundary.

        :link: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
        '''
        result = self._values.get("permissions_boundary")
        return typing.cast(typing.Optional[IManagedPolicy], result)

    @builtins.property
    def role_name(self) -> typing.Optional[builtins.str]:
        '''A name for the IAM role.

        For valid values, see the RoleName parameter for
        the CreateRole action in the IAM API Reference.

        IMPORTANT: If you specify a name, you cannot perform updates that require
        replacement of this resource. You can perform updates that require no or
        some interruption. If you must replace the resource, specify a new name.

        If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to
        acknowledge your template's capabilities. For more information, see
        Acknowledging IAM Resources in AWS CloudFormation Templates.

        :default:

        - AWS CloudFormation generates a unique physical ID and uses that ID
        for the role name.
        '''
        result = self._values.get("role_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RoleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class SamlMetadataDocument(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_iam.SamlMetadataDocument",
):
    '''A SAML metadata document.

    :exampleMetadata: infused

    Example::

        provider = iam.SamlProvider(self, "Provider",
            metadata_document=iam.SamlMetadataDocument.from_file("/path/to/saml-metadata-document.xml")
        )
        principal = iam.SamlPrincipal(provider, {
            "StringEquals": {
                "SAML:iss": "issuer"
            }
        })
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="fromFile") # type: ignore[misc]
    @builtins.classmethod
    def from_file(cls, path: builtins.str) -> "SamlMetadataDocument":
        '''Create a SAML metadata document from a XML file.

        :param path: -
        '''
        return typing.cast("SamlMetadataDocument", jsii.sinvoke(cls, "fromFile", [path]))

    @jsii.member(jsii_name="fromXml") # type: ignore[misc]
    @builtins.classmethod
    def from_xml(cls, xml: builtins.str) -> "SamlMetadataDocument":
        '''Create a SAML metadata document from a XML string.

        :param xml: -
        '''
        return typing.cast("SamlMetadataDocument", jsii.sinvoke(cls, "fromXml", [xml]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="xml")
    @abc.abstractmethod
    def xml(self) -> builtins.str:
        '''The XML content of the metadata document.'''
        ...


class _SamlMetadataDocumentProxy(SamlMetadataDocument):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="xml")
    def xml(self) -> builtins.str:
        '''The XML content of the metadata document.'''
        return typing.cast(builtins.str, jsii.get(self, "xml"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, SamlMetadataDocument).__jsii_proxy_class__ = lambda : _SamlMetadataDocumentProxy


@jsii.implements(ISamlProvider)
class SamlProvider(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.SamlProvider",
):
    '''A SAML provider.

    :exampleMetadata: infused

    Example::

        provider = iam.SamlProvider(self, "Provider",
            metadata_document=iam.SamlMetadataDocument.from_file("/path/to/saml-metadata-document.xml")
        )
        iam.Role(self, "Role",
            assumed_by=iam.SamlConsolePrincipal(provider)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        metadata_document: SamlMetadataDocument,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param metadata_document: An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your organization's IdP.
        :param name: The name of the provider to create. This parameter allows a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@- Length must be between 1 and 128 characters. Default: - a CloudFormation generated name
        '''
        props = SamlProviderProps(metadata_document=metadata_document, name=name)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromSamlProviderArn") # type: ignore[misc]
    @builtins.classmethod
    def from_saml_provider_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        saml_provider_arn: builtins.str,
    ) -> ISamlProvider:
        '''Import an existing provider.

        :param scope: -
        :param id: -
        :param saml_provider_arn: -
        '''
        return typing.cast(ISamlProvider, jsii.sinvoke(cls, "fromSamlProviderArn", [scope, id, saml_provider_arn]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="samlProviderArn")
    def saml_provider_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the provider.'''
        return typing.cast(builtins.str, jsii.get(self, "samlProviderArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.SamlProviderProps",
    jsii_struct_bases=[],
    name_mapping={"metadata_document": "metadataDocument", "name": "name"},
)
class SamlProviderProps:
    def __init__(
        self,
        *,
        metadata_document: SamlMetadataDocument,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for a SAML provider.

        :param metadata_document: An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your organization's IdP.
        :param name: The name of the provider to create. This parameter allows a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@- Length must be between 1 and 128 characters. Default: - a CloudFormation generated name

        :exampleMetadata: infused

        Example::

            provider = iam.SamlProvider(self, "Provider",
                metadata_document=iam.SamlMetadataDocument.from_file("/path/to/saml-metadata-document.xml")
            )
            iam.Role(self, "Role",
                assumed_by=iam.SamlConsolePrincipal(provider)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "metadata_document": metadata_document,
        }
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def metadata_document(self) -> SamlMetadataDocument:
        '''An XML document generated by an identity provider (IdP) that supports SAML 2.0. The document includes the issuer's name, expiration information, and keys that can be used to validate the SAML authentication response (assertions) that are received from the IdP. You must generate the metadata document using the identity management software that is used as your organization's IdP.'''
        result = self._values.get("metadata_document")
        assert result is not None, "Required property 'metadata_document' is missing"
        return typing.cast(SamlMetadataDocument, result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the provider to create.

        This parameter allows a string of characters consisting of upper and
        lowercase alphanumeric characters with no spaces. You can also include
        any of the following characters: _+=,.@-

        Length must be between 1 and 128 characters.

        :default: - a CloudFormation generated name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SamlProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.ServicePrincipalOpts",
    jsii_struct_bases=[],
    name_mapping={"conditions": "conditions", "region": "region"},
)
class ServicePrincipalOpts:
    def __init__(
        self,
        *,
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        region: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options for a service principal.

        :param conditions: Additional conditions to add to the Service Principal. Default: - No conditions
        :param region: (deprecated) The region in which the service is operating. Default: the current Stack's region.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            # conditions: Any
            
            service_principal_opts = iam.ServicePrincipalOpts(
                conditions={
                    "conditions_key": conditions
                },
                region="region"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if conditions is not None:
            self._values["conditions"] = conditions
        if region is not None:
            self._values["region"] = region

    @builtins.property
    def conditions(self) -> typing.Optional[typing.Mapping[builtins.str, typing.Any]]:
        '''Additional conditions to add to the Service Principal.

        :default: - No conditions
        '''
        result = self._values.get("conditions")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, typing.Any]], result)

    @builtins.property
    def region(self) -> typing.Optional[builtins.str]:
        '''(deprecated) The region in which the service is operating.

        :default: the current Stack's region.

        :deprecated: You should not need to set this. The stack's region is always correct.

        :stability: deprecated
        '''
        result = self._values.get("region")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ServicePrincipalOpts(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IPrincipal)
class UnknownPrincipal(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.UnknownPrincipal",
):
    '''A principal for use in resources that need to have a role but it's unknown.

    Some resources have roles associated with them which they assume, such as
    Lambda Functions, CodeBuild projects, StepFunctions machines, etc.

    When those resources are imported, their actual roles are not always
    imported with them. When that happens, we use an instance of this class
    instead, which will add user warnings when statements are attempted to be
    added to it.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        import constructs as constructs
        
        # construct: constructs.Construct
        
        unknown_principal = iam.UnknownPrincipal(
            resource=construct
        )
    '''

    def __init__(self, *, resource: constructs.IConstruct) -> None:
        '''
        :param resource: The resource the role proxy is for.
        '''
        props = UnknownPrincipalProps(resource=resource)

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: PolicyStatement) -> builtins.bool:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: PolicyStatement,
    ) -> AddToPrincipalPolicyResult:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> IPrincipal:
        '''The principal to grant permissions to.'''
        return typing.cast(IPrincipal, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.UnknownPrincipalProps",
    jsii_struct_bases=[],
    name_mapping={"resource": "resource"},
)
class UnknownPrincipalProps:
    def __init__(self, *, resource: constructs.IConstruct) -> None:
        '''Properties for an UnknownPrincipal.

        :param resource: The resource the role proxy is for.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            import constructs as constructs
            
            # construct: constructs.Construct
            
            unknown_principal_props = iam.UnknownPrincipalProps(
                resource=construct
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resource": resource,
        }

    @builtins.property
    def resource(self) -> constructs.IConstruct:
        '''The resource the role proxy is for.'''
        result = self._values.get("resource")
        assert result is not None, "Required property 'resource' is missing"
        return typing.cast(constructs.IConstruct, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UnknownPrincipalProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.UserAttributes",
    jsii_struct_bases=[],
    name_mapping={"user_arn": "userArn"},
)
class UserAttributes:
    def __init__(self, *, user_arn: builtins.str) -> None:
        '''Represents a user defined outside of this stack.

        :param user_arn: The ARN of the user. Format: arn::iam:::user/

        :exampleMetadata: infused

        Example::

            user = iam.User.from_user_attributes(self, "MyImportedUserByAttributes",
                user_arn="arn:aws:iam::123456789012:user/johnsmith"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "user_arn": user_arn,
        }

    @builtins.property
    def user_arn(self) -> builtins.str:
        '''The ARN of the user.

        Format: arn::iam:::user/
        '''
        result = self._values.get("user_arn")
        assert result is not None, "Required property 'user_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.UserProps",
    jsii_struct_bases=[],
    name_mapping={
        "groups": "groups",
        "managed_policies": "managedPolicies",
        "password": "password",
        "password_reset_required": "passwordResetRequired",
        "path": "path",
        "permissions_boundary": "permissionsBoundary",
        "user_name": "userName",
    },
)
class UserProps:
    def __init__(
        self,
        *,
        groups: typing.Optional[typing.Sequence["IGroup"]] = None,
        managed_policies: typing.Optional[typing.Sequence[IManagedPolicy]] = None,
        password: typing.Optional[_SecretValue_3dd0ddae] = None,
        password_reset_required: typing.Optional[builtins.bool] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[IManagedPolicy] = None,
        user_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining an IAM user.

        :param groups: Groups to add this user to. You can also use ``addToGroup`` to add this user to a group. Default: - No groups.
        :param managed_policies: A list of managed policies associated with this role. You can add managed policies later using ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``. Default: - No managed policies.
        :param password: The password for the user. This is required so the user can access the AWS Management Console. You can use ``SecretValue.plainText`` to specify a password in plain text or use ``secretsmanager.Secret.fromSecretAttributes`` to reference a secret in Secrets Manager. Default: - User won't be able to access the management console without a password.
        :param password_reset_required: Specifies whether the user is required to set a new password the next time the user logs in to the AWS Management Console. If this is set to 'true', you must also specify "initialPassword". Default: false
        :param path: The path for the user name. For more information about paths, see IAM Identifiers in the IAM User Guide. Default: /
        :param permissions_boundary: AWS supports permissions boundaries for IAM entities (users or roles). A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. An entity's permissions boundary allows it to perform only the actions that are allowed by both its identity-based policies and its permissions boundaries. Default: - No permissions boundary.
        :param user_name: A name for the IAM user. For valid values, see the UserName parameter for the CreateUser action in the IAM API Reference. If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the user name. If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to acknowledge your template's capabilities. For more information, see Acknowledging IAM Resources in AWS CloudFormation Templates. Default: - Generated by CloudFormation (recommended)

        :exampleMetadata: lit=aws-iam/test/example.attaching.lit.ts infused

        Example::

            user = User(self, "MyUser", password=SecretValue.plain_text("1234"))
            group = Group(self, "MyGroup")
            
            policy = Policy(self, "MyPolicy")
            policy.attach_to_user(user)
            group.attach_inline_policy(policy)
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if groups is not None:
            self._values["groups"] = groups
        if managed_policies is not None:
            self._values["managed_policies"] = managed_policies
        if password is not None:
            self._values["password"] = password
        if password_reset_required is not None:
            self._values["password_reset_required"] = password_reset_required
        if path is not None:
            self._values["path"] = path
        if permissions_boundary is not None:
            self._values["permissions_boundary"] = permissions_boundary
        if user_name is not None:
            self._values["user_name"] = user_name

    @builtins.property
    def groups(self) -> typing.Optional[typing.List["IGroup"]]:
        '''Groups to add this user to.

        You can also use ``addToGroup`` to add this
        user to a group.

        :default: - No groups.
        '''
        result = self._values.get("groups")
        return typing.cast(typing.Optional[typing.List["IGroup"]], result)

    @builtins.property
    def managed_policies(self) -> typing.Optional[typing.List[IManagedPolicy]]:
        '''A list of managed policies associated with this role.

        You can add managed policies later using
        ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``.

        :default: - No managed policies.
        '''
        result = self._values.get("managed_policies")
        return typing.cast(typing.Optional[typing.List[IManagedPolicy]], result)

    @builtins.property
    def password(self) -> typing.Optional[_SecretValue_3dd0ddae]:
        '''The password for the user. This is required so the user can access the AWS Management Console.

        You can use ``SecretValue.plainText`` to specify a password in plain text or
        use ``secretsmanager.Secret.fromSecretAttributes`` to reference a secret in
        Secrets Manager.

        :default: - User won't be able to access the management console without a password.
        '''
        result = self._values.get("password")
        return typing.cast(typing.Optional[_SecretValue_3dd0ddae], result)

    @builtins.property
    def password_reset_required(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the user is required to set a new password the next time the user logs in to the AWS Management Console.

        If this is set to 'true', you must also specify "initialPassword".

        :default: false
        '''
        result = self._values.get("password_reset_required")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path for the user name.

        For more information about paths, see IAM
        Identifiers in the IAM User Guide.

        :default: /
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions_boundary(self) -> typing.Optional[IManagedPolicy]:
        '''AWS supports permissions boundaries for IAM entities (users or roles).

        A permissions boundary is an advanced feature for using a managed policy
        to set the maximum permissions that an identity-based policy can grant to
        an IAM entity. An entity's permissions boundary allows it to perform only
        the actions that are allowed by both its identity-based policies and its
        permissions boundaries.

        :default: - No permissions boundary.

        :link: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
        '''
        result = self._values.get("permissions_boundary")
        return typing.cast(typing.Optional[IManagedPolicy], result)

    @builtins.property
    def user_name(self) -> typing.Optional[builtins.str]:
        '''A name for the IAM user.

        For valid values, see the UserName parameter for
        the CreateUser action in the IAM API Reference. If you don't specify a
        name, AWS CloudFormation generates a unique physical ID and uses that ID
        for the user name.

        If you specify a name, you cannot perform updates that require
        replacement of this resource. You can perform updates that require no or
        some interruption. If you must replace the resource, specify a new name.

        If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to
        acknowledge your template's capabilities. For more information, see
        Acknowledging IAM Resources in AWS CloudFormation Templates.

        :default: - Generated by CloudFormation (recommended)
        '''
        result = self._values.get("user_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.WithoutPolicyUpdatesOptions",
    jsii_struct_bases=[],
    name_mapping={"add_grants_to_resources": "addGrantsToResources"},
)
class WithoutPolicyUpdatesOptions:
    def __init__(
        self,
        *,
        add_grants_to_resources: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Options for the ``withoutPolicyUpdates()`` modifier of a Role.

        :param add_grants_to_resources: Add grants to resources instead of dropping them. If this is ``false`` or not specified, grant permissions added to this role are ignored. It is your own responsibility to make sure the role has the required permissions. If this is ``true``, any grant permissions will be added to the resource instead. Default: false

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_iam as iam
            
            without_policy_updates_options = iam.WithoutPolicyUpdatesOptions(
                add_grants_to_resources=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if add_grants_to_resources is not None:
            self._values["add_grants_to_resources"] = add_grants_to_resources

    @builtins.property
    def add_grants_to_resources(self) -> typing.Optional[builtins.bool]:
        '''Add grants to resources instead of dropping them.

        If this is ``false`` or not specified, grant permissions added to this role are ignored.
        It is your own responsibility to make sure the role has the required permissions.

        If this is ``true``, any grant permissions will be added to the resource instead.

        :default: false
        '''
        result = self._values.get("add_grants_to_resources")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WithoutPolicyUpdatesOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IAccessKey)
class AccessKey(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.AccessKey",
):
    '''Define a new IAM Access Key.

    :exampleMetadata: infused

    Example::

        user = iam.User(self, "MyUser")
        access_key = iam.AccessKey(self, "MyAccessKey", user=user, serial=1)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user: "IUser",
        serial: typing.Optional[jsii.Number] = None,
        status: typing.Optional[AccessKeyStatus] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param user: The IAM user this key will belong to. Changing this value will result in the access key being deleted and a new access key (with a different ID and secret value) being assigned to the new user.
        :param serial: A CloudFormation-specific value that signifies the access key should be replaced/rotated. This value can only be incremented. Incrementing this value will cause CloudFormation to replace the Access Key resource. Default: - No serial value
        :param status: The status of the access key. An Active access key is allowed to be used to make API calls; An Inactive key cannot. Default: - The access key is active
        '''
        props = AccessKeyProps(user=user, serial=serial, status=status)

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessKeyId")
    def access_key_id(self) -> builtins.str:
        '''The Access Key ID.'''
        return typing.cast(builtins.str, jsii.get(self, "accessKeyId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="secretAccessKey")
    def secret_access_key(self) -> _SecretValue_3dd0ddae:
        '''The Secret Access Key.'''
        return typing.cast(_SecretValue_3dd0ddae, jsii.get(self, "secretAccessKey"))


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IAssumeRolePrincipal")
class IAssumeRolePrincipal(IPrincipal, typing_extensions.Protocol):
    '''A type of principal that has more control over its own representation in AssumeRolePolicyDocuments.

    More complex types of identity providers need more control over Role's policy documents
    than simply ``{ Effect: 'Allow', Action: 'AssumeRole', Principal: <Whatever> }``.

    If that control is necessary, they can implement ``IAssumeRolePrincipal`` to get full
    access to a Role's AssumeRolePolicyDocument.
    '''

    @jsii.member(jsii_name="addToAssumeRolePolicy")
    def add_to_assume_role_policy(self, document: PolicyDocument) -> None:
        '''Add the princpial to the AssumeRolePolicyDocument.

        Add the statements to the AssumeRolePolicyDocument necessary to give this principal
        permissions to assume the given role.

        :param document: -
        '''
        ...


class _IAssumeRolePrincipalProxy(
    jsii.proxy_for(IPrincipal) # type: ignore[misc]
):
    '''A type of principal that has more control over its own representation in AssumeRolePolicyDocuments.

    More complex types of identity providers need more control over Role's policy documents
    than simply ``{ Effect: 'Allow', Action: 'AssumeRole', Principal: <Whatever> }``.

    If that control is necessary, they can implement ``IAssumeRolePrincipal`` to get full
    access to a Role's AssumeRolePolicyDocument.
    '''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IAssumeRolePrincipal"

    @jsii.member(jsii_name="addToAssumeRolePolicy")
    def add_to_assume_role_policy(self, document: PolicyDocument) -> None:
        '''Add the princpial to the AssumeRolePolicyDocument.

        Add the statements to the AssumeRolePolicyDocument necessary to give this principal
        permissions to assume the given role.

        :param document: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToAssumeRolePolicy", [document]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IAssumeRolePrincipal).__jsii_proxy_class__ = lambda : _IAssumeRolePrincipalProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IIdentity")
class IIdentity(IPrincipal, _IResource_c80c4260, typing_extensions.Protocol):
    '''A construct that represents an IAM principal, such as a user, group or role.'''

    @jsii.member(jsii_name="addManagedPolicy")
    def add_managed_policy(self, policy: IManagedPolicy) -> None:
        '''Attaches a managed policy to this principal.

        :param policy: The managed policy.
        '''
        ...

    @jsii.member(jsii_name="attachInlinePolicy")
    def attach_inline_policy(self, policy: Policy) -> None:
        '''Attaches an inline policy to this principal.

        This is the same as calling ``policy.addToXxx(principal)``.

        :param policy: The policy resource to attach to this principal [disable-awslint:ref-via-interface].
        '''
        ...


class _IIdentityProxy(
    jsii.proxy_for(IPrincipal), # type: ignore[misc]
    jsii.proxy_for(_IResource_c80c4260), # type: ignore[misc]
):
    '''A construct that represents an IAM principal, such as a user, group or role.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IIdentity"

    @jsii.member(jsii_name="addManagedPolicy")
    def add_managed_policy(self, policy: IManagedPolicy) -> None:
        '''Attaches a managed policy to this principal.

        :param policy: The managed policy.
        '''
        return typing.cast(None, jsii.invoke(self, "addManagedPolicy", [policy]))

    @jsii.member(jsii_name="attachInlinePolicy")
    def attach_inline_policy(self, policy: Policy) -> None:
        '''Attaches an inline policy to this principal.

        This is the same as calling ``policy.addToXxx(principal)``.

        :param policy: The policy resource to attach to this principal [disable-awslint:ref-via-interface].
        '''
        return typing.cast(None, jsii.invoke(self, "attachInlinePolicy", [policy]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IIdentity).__jsii_proxy_class__ = lambda : _IIdentityProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IRole")
class IRole(IIdentity, typing_extensions.Protocol):
    '''A Role object.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''Returns the ARN of this role.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleName")
    def role_name(self) -> builtins.str:
        '''Returns the name of this role.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="grant")
    def grant(self, grantee: IPrincipal, *actions: builtins.str) -> Grant:
        '''Grant the actions defined in actions to the identity Principal on this resource.

        :param grantee: -
        :param actions: -
        '''
        ...

    @jsii.member(jsii_name="grantPassRole")
    def grant_pass_role(self, grantee: IPrincipal) -> Grant:
        '''Grant permissions to the given principal to pass this role.

        :param grantee: -
        '''
        ...


class _IRoleProxy(
    jsii.proxy_for(IIdentity) # type: ignore[misc]
):
    '''A Role object.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IRole"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''Returns the ARN of this role.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleName")
    def role_name(self) -> builtins.str:
        '''Returns the name of this role.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleName"))

    @jsii.member(jsii_name="grant")
    def grant(self, grantee: IPrincipal, *actions: builtins.str) -> Grant:
        '''Grant the actions defined in actions to the identity Principal on this resource.

        :param grantee: -
        :param actions: -
        '''
        return typing.cast(Grant, jsii.invoke(self, "grant", [grantee, *actions]))

    @jsii.member(jsii_name="grantPassRole")
    def grant_pass_role(self, grantee: IPrincipal) -> Grant:
        '''Grant permissions to the given principal to pass this role.

        :param grantee: -
        '''
        return typing.cast(Grant, jsii.invoke(self, "grantPassRole", [grantee]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IRole).__jsii_proxy_class__ = lambda : _IRoleProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IUser")
class IUser(IIdentity, typing_extensions.Protocol):
    '''Represents an IAM user.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html
    '''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userArn")
    def user_arn(self) -> builtins.str:
        '''The user's ARN.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> builtins.str:
        '''The user's name.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="addToGroup")
    def add_to_group(self, group: "IGroup") -> None:
        '''Adds this user to a group.

        :param group: -
        '''
        ...


class _IUserProxy(
    jsii.proxy_for(IIdentity) # type: ignore[misc]
):
    '''Represents an IAM user.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html
    '''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IUser"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userArn")
    def user_arn(self) -> builtins.str:
        '''The user's ARN.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> builtins.str:
        '''The user's name.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userName"))

    @jsii.member(jsii_name="addToGroup")
    def add_to_group(self, group: "IGroup") -> None:
        '''Adds this user to a group.

        :param group: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToGroup", [group]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IUser).__jsii_proxy_class__ = lambda : _IUserProxy


@jsii.implements(IRole)
class LazyRole(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.LazyRole",
):
    '''An IAM role that only gets attached to the construct tree once it gets used, not before.

    This construct can be used to simplify logic in other constructs
    which need to create a role but only if certain configurations occur
    (such as when AutoScaling is configured). The role can be configured in one
    place, but if it never gets used it doesn't get instantiated and will
    not be synthesized or deployed.

    :resource: AWS::IAM::Role
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_iam as iam
        
        # managed_policy: iam.ManagedPolicy
        # policy_document: iam.PolicyDocument
        # principal: iam.IPrincipal
        
        lazy_role = iam.LazyRole(self, "MyLazyRole",
            assumed_by=principal,
        
            # the properties below are optional
            description="description",
            external_ids=["externalIds"],
            inline_policies={
                "inline_policies_key": policy_document
            },
            managed_policies=[managed_policy],
            max_session_duration=cdk.Duration.minutes(30),
            path="path",
            permissions_boundary=managed_policy,
            role_name="roleName"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        assumed_by: IPrincipal,
        description: typing.Optional[builtins.str] = None,
        external_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        inline_policies: typing.Optional[typing.Mapping[builtins.str, PolicyDocument]] = None,
        managed_policies: typing.Optional[typing.Sequence[IManagedPolicy]] = None,
        max_session_duration: typing.Optional[_Duration_4839e8c3] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[IManagedPolicy] = None,
        role_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param assumed_by: The IAM principal (i.e. ``new ServicePrincipal('sns.amazonaws.com')``) which can assume this role. You can later modify the assume role policy document by accessing it via the ``assumeRolePolicy`` property.
        :param description: A description of the role. It can be up to 1000 characters long. Default: - No description.
        :param external_ids: List of IDs that the role assumer needs to provide one of when assuming this role. If the configured and provided external IDs do not match, the AssumeRole operation will fail. Default: No external ID required
        :param inline_policies: A list of named policies to inline into this role. These policies will be created with the role, whereas those added by ``addToPolicy`` are added using a separate CloudFormation resource (allowing a way around circular dependencies that could otherwise be introduced). Default: - No policy is inlined in the Role resource.
        :param managed_policies: A list of managed policies associated with this role. You can add managed policies later using ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``. Default: - No managed policies.
        :param max_session_duration: The maximum session duration that you want to set for the specified role. This setting can have a value from 1 hour (3600sec) to 12 (43200sec) hours. Anyone who assumes the role from the AWS CLI or API can use the DurationSeconds API parameter or the duration-seconds CLI parameter to request a longer session. The MaxSessionDuration setting determines the maximum duration that can be requested using the DurationSeconds parameter. If users don't specify a value for the DurationSeconds parameter, their security credentials are valid for one hour by default. This applies when you use the AssumeRole* API operations or the assume-role* CLI operations but does not apply when you use those operations to create a console URL. Default: Duration.hours(1)
        :param path: The path associated with this role. For information about IAM paths, see Friendly Names and Paths in IAM User Guide. Default: /
        :param permissions_boundary: AWS supports permissions boundaries for IAM entities (users or roles). A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. An entity's permissions boundary allows it to perform only the actions that are allowed by both its identity-based policies and its permissions boundaries. Default: - No permissions boundary.
        :param role_name: A name for the IAM role. For valid values, see the RoleName parameter for the CreateRole action in the IAM API Reference. IMPORTANT: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to acknowledge your template's capabilities. For more information, see Acknowledging IAM Resources in AWS CloudFormation Templates. Default: - AWS CloudFormation generates a unique physical ID and uses that ID for the role name.
        '''
        props = LazyRoleProps(
            assumed_by=assumed_by,
            description=description,
            external_ids=external_ids,
            inline_policies=inline_policies,
            managed_policies=managed_policies,
            max_session_duration=max_session_duration,
            path=path,
            permissions_boundary=permissions_boundary,
            role_name=role_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addManagedPolicy")
    def add_managed_policy(self, policy: IManagedPolicy) -> None:
        '''Attaches a managed policy to this role.

        :param policy: The managed policy to attach.
        '''
        return typing.cast(None, jsii.invoke(self, "addManagedPolicy", [policy]))

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: PolicyStatement) -> builtins.bool:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: PolicyStatement,
    ) -> AddToPrincipalPolicyResult:
        '''Adds a permission to the role's default policy document.

        If there is no default policy attached to this role, it will be created.

        :param statement: The permission statement to add to the policy document.
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

    @jsii.member(jsii_name="attachInlinePolicy")
    def attach_inline_policy(self, policy: Policy) -> None:
        '''Attaches a policy to this role.

        :param policy: The policy to attach.
        '''
        return typing.cast(None, jsii.invoke(self, "attachInlinePolicy", [policy]))

    @jsii.member(jsii_name="grant")
    def grant(self, identity: IPrincipal, *actions: builtins.str) -> Grant:
        '''Grant the actions defined in actions to the identity Principal on this resource.

        :param identity: -
        :param actions: -
        '''
        return typing.cast(Grant, jsii.invoke(self, "grant", [identity, *actions]))

    @jsii.member(jsii_name="grantPassRole")
    def grant_pass_role(self, identity: IPrincipal) -> Grant:
        '''Grant permissions to the given principal to pass this role.

        :param identity: -
        '''
        return typing.cast(Grant, jsii.invoke(self, "grantPassRole", [identity]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> IPrincipal:
        '''The principal to grant permissions to.'''
        return typing.cast(IPrincipal, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''Returns the ARN of this role.'''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleId")
    def role_id(self) -> builtins.str:
        '''Returns the stable and unique string identifying the role (i.e. AIDAJQABLZS4A3QDU576Q).

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleName")
    def role_name(self) -> builtins.str:
        '''Returns the name of this role.'''
        return typing.cast(builtins.str, jsii.get(self, "roleName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_iam.LazyRoleProps",
    jsii_struct_bases=[RoleProps],
    name_mapping={
        "assumed_by": "assumedBy",
        "description": "description",
        "external_ids": "externalIds",
        "inline_policies": "inlinePolicies",
        "managed_policies": "managedPolicies",
        "max_session_duration": "maxSessionDuration",
        "path": "path",
        "permissions_boundary": "permissionsBoundary",
        "role_name": "roleName",
    },
)
class LazyRoleProps(RoleProps):
    def __init__(
        self,
        *,
        assumed_by: IPrincipal,
        description: typing.Optional[builtins.str] = None,
        external_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        inline_policies: typing.Optional[typing.Mapping[builtins.str, PolicyDocument]] = None,
        managed_policies: typing.Optional[typing.Sequence[IManagedPolicy]] = None,
        max_session_duration: typing.Optional[_Duration_4839e8c3] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[IManagedPolicy] = None,
        role_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a LazyRole.

        :param assumed_by: The IAM principal (i.e. ``new ServicePrincipal('sns.amazonaws.com')``) which can assume this role. You can later modify the assume role policy document by accessing it via the ``assumeRolePolicy`` property.
        :param description: A description of the role. It can be up to 1000 characters long. Default: - No description.
        :param external_ids: List of IDs that the role assumer needs to provide one of when assuming this role. If the configured and provided external IDs do not match, the AssumeRole operation will fail. Default: No external ID required
        :param inline_policies: A list of named policies to inline into this role. These policies will be created with the role, whereas those added by ``addToPolicy`` are added using a separate CloudFormation resource (allowing a way around circular dependencies that could otherwise be introduced). Default: - No policy is inlined in the Role resource.
        :param managed_policies: A list of managed policies associated with this role. You can add managed policies later using ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``. Default: - No managed policies.
        :param max_session_duration: The maximum session duration that you want to set for the specified role. This setting can have a value from 1 hour (3600sec) to 12 (43200sec) hours. Anyone who assumes the role from the AWS CLI or API can use the DurationSeconds API parameter or the duration-seconds CLI parameter to request a longer session. The MaxSessionDuration setting determines the maximum duration that can be requested using the DurationSeconds parameter. If users don't specify a value for the DurationSeconds parameter, their security credentials are valid for one hour by default. This applies when you use the AssumeRole* API operations or the assume-role* CLI operations but does not apply when you use those operations to create a console URL. Default: Duration.hours(1)
        :param path: The path associated with this role. For information about IAM paths, see Friendly Names and Paths in IAM User Guide. Default: /
        :param permissions_boundary: AWS supports permissions boundaries for IAM entities (users or roles). A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. An entity's permissions boundary allows it to perform only the actions that are allowed by both its identity-based policies and its permissions boundaries. Default: - No permissions boundary.
        :param role_name: A name for the IAM role. For valid values, see the RoleName parameter for the CreateRole action in the IAM API Reference. IMPORTANT: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to acknowledge your template's capabilities. For more information, see Acknowledging IAM Resources in AWS CloudFormation Templates. Default: - AWS CloudFormation generates a unique physical ID and uses that ID for the role name.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_iam as iam
            
            # managed_policy: iam.ManagedPolicy
            # policy_document: iam.PolicyDocument
            # principal: iam.IPrincipal
            
            lazy_role_props = iam.LazyRoleProps(
                assumed_by=principal,
            
                # the properties below are optional
                description="description",
                external_ids=["externalIds"],
                inline_policies={
                    "inline_policies_key": policy_document
                },
                managed_policies=[managed_policy],
                max_session_duration=cdk.Duration.minutes(30),
                path="path",
                permissions_boundary=managed_policy,
                role_name="roleName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "assumed_by": assumed_by,
        }
        if description is not None:
            self._values["description"] = description
        if external_ids is not None:
            self._values["external_ids"] = external_ids
        if inline_policies is not None:
            self._values["inline_policies"] = inline_policies
        if managed_policies is not None:
            self._values["managed_policies"] = managed_policies
        if max_session_duration is not None:
            self._values["max_session_duration"] = max_session_duration
        if path is not None:
            self._values["path"] = path
        if permissions_boundary is not None:
            self._values["permissions_boundary"] = permissions_boundary
        if role_name is not None:
            self._values["role_name"] = role_name

    @builtins.property
    def assumed_by(self) -> IPrincipal:
        '''The IAM principal (i.e. ``new ServicePrincipal('sns.amazonaws.com')``) which can assume this role.

        You can later modify the assume role policy document by accessing it via
        the ``assumeRolePolicy`` property.
        '''
        result = self._values.get("assumed_by")
        assert result is not None, "Required property 'assumed_by' is missing"
        return typing.cast(IPrincipal, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the role.

        It can be up to 1000 characters long.

        :default: - No description.
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def external_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''List of IDs that the role assumer needs to provide one of when assuming this role.

        If the configured and provided external IDs do not match, the
        AssumeRole operation will fail.

        :default: No external ID required
        '''
        result = self._values.get("external_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def inline_policies(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, PolicyDocument]]:
        '''A list of named policies to inline into this role.

        These policies will be
        created with the role, whereas those added by ``addToPolicy`` are added
        using a separate CloudFormation resource (allowing a way around circular
        dependencies that could otherwise be introduced).

        :default: - No policy is inlined in the Role resource.
        '''
        result = self._values.get("inline_policies")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, PolicyDocument]], result)

    @builtins.property
    def managed_policies(self) -> typing.Optional[typing.List[IManagedPolicy]]:
        '''A list of managed policies associated with this role.

        You can add managed policies later using
        ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``.

        :default: - No managed policies.
        '''
        result = self._values.get("managed_policies")
        return typing.cast(typing.Optional[typing.List[IManagedPolicy]], result)

    @builtins.property
    def max_session_duration(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The maximum session duration that you want to set for the specified role.

        This setting can have a value from 1 hour (3600sec) to 12 (43200sec) hours.

        Anyone who assumes the role from the AWS CLI or API can use the
        DurationSeconds API parameter or the duration-seconds CLI parameter to
        request a longer session. The MaxSessionDuration setting determines the
        maximum duration that can be requested using the DurationSeconds
        parameter.

        If users don't specify a value for the DurationSeconds parameter, their
        security credentials are valid for one hour by default. This applies when
        you use the AssumeRole* API operations or the assume-role* CLI operations
        but does not apply when you use those operations to create a console URL.

        :default: Duration.hours(1)

        :link: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html
        '''
        result = self._values.get("max_session_duration")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The path associated with this role.

        For information about IAM paths, see
        Friendly Names and Paths in IAM User Guide.

        :default: /
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permissions_boundary(self) -> typing.Optional[IManagedPolicy]:
        '''AWS supports permissions boundaries for IAM entities (users or roles).

        A permissions boundary is an advanced feature for using a managed policy
        to set the maximum permissions that an identity-based policy can grant to
        an IAM entity. An entity's permissions boundary allows it to perform only
        the actions that are allowed by both its identity-based policies and its
        permissions boundaries.

        :default: - No permissions boundary.

        :link: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
        '''
        result = self._values.get("permissions_boundary")
        return typing.cast(typing.Optional[IManagedPolicy], result)

    @builtins.property
    def role_name(self) -> typing.Optional[builtins.str]:
        '''A name for the IAM role.

        For valid values, see the RoleName parameter for
        the CreateRole action in the IAM API Reference.

        IMPORTANT: If you specify a name, you cannot perform updates that require
        replacement of this resource. You can perform updates that require no or
        some interruption. If you must replace the resource, specify a new name.

        If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to
        acknowledge your template's capabilities. For more information, see
        Acknowledging IAM Resources in AWS CloudFormation Templates.

        :default:

        - AWS CloudFormation generates a unique physical ID and uses that ID
        for the role name.
        '''
        result = self._values.get("role_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LazyRoleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IAssumeRolePrincipal)
class PrincipalBase(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_iam.PrincipalBase",
):
    '''Base class for policy principals.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        tag_param = CfnParameter(self, "TagName")
        
        string_equals = CfnJson(self, "ConditionJson",
            value={
                f"aws:PrincipalTag/{tagParam.valueAsString}": True
            }
        )
        
        principal = iam.AccountRootPrincipal().with_conditions({
            "StringEquals": string_equals
        })
        
        iam.Role(self, "MyRole", assumed_by=principal)
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="addToAssumeRolePolicy")
    def add_to_assume_role_policy(self, document: PolicyDocument) -> None:
        '''Add the princpial to the AssumeRolePolicyDocument.

        Add the statements to the AssumeRolePolicyDocument necessary to give this principal
        permissions to assume the given role.

        :param document: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToAssumeRolePolicy", [document]))

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: PolicyStatement) -> builtins.bool:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        _statement: PolicyStatement,
    ) -> AddToPrincipalPolicyResult:
        '''Add to the policy of this principal.

        :param _statement: -
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [_statement]))

    @jsii.member(jsii_name="toJSON")
    def to_json(self) -> typing.Mapping[builtins.str, typing.List[builtins.str]]:
        '''JSON-ify the principal.

        Used when JSON.stringify() is called
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.List[builtins.str]], jsii.invoke(self, "toJSON", []))

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @jsii.member(jsii_name="withConditions")
    def with_conditions(
        self,
        conditions: typing.Mapping[builtins.str, typing.Any],
    ) -> "PrincipalBase":
        '''Returns a new PrincipalWithConditions using this principal as the base, with the passed conditions added.

        When there is a value for the same operator and key in both the principal and the
        conditions parameter, the value from the conditions parameter will be used.

        :param conditions: -

        :return: a new PrincipalWithConditions object.
        '''
        return typing.cast("PrincipalBase", jsii.invoke(self, "withConditions", [conditions]))

    @jsii.member(jsii_name="withSessionTags")
    def with_session_tags(self) -> "PrincipalBase":
        '''Returns a new principal using this principal as the base, with session tags enabled.

        :return: a new SessionTagsPrincipal object.
        '''
        return typing.cast("PrincipalBase", jsii.invoke(self, "withSessionTags", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> IPrincipal:
        '''The principal to grant permissions to.'''
        return typing.cast(IPrincipal, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    @abc.abstractmethod
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))


class _PrincipalBaseProxy(PrincipalBase):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, PrincipalBase).__jsii_proxy_class__ = lambda : _PrincipalBaseProxy


class PrincipalWithConditions(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.PrincipalWithConditions",
):
    '''An IAM principal with additional conditions specifying when the policy is in effect.

    For more information about conditions, see:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # conditions: Any
        # principal: iam.IPrincipal
        
        principal_with_conditions = iam.PrincipalWithConditions(principal, {
            "conditions_key": conditions
        })
    '''

    def __init__(
        self,
        principal: IPrincipal,
        conditions: typing.Mapping[builtins.str, typing.Any],
    ) -> None:
        '''
        :param principal: -
        :param conditions: -
        '''
        jsii.create(self.__class__, self, [principal, conditions])

    @jsii.member(jsii_name="addCondition")
    def add_condition(self, key: builtins.str, value: typing.Any) -> None:
        '''Add a condition to the principal.

        :param key: -
        :param value: -
        '''
        return typing.cast(None, jsii.invoke(self, "addCondition", [key, value]))

    @jsii.member(jsii_name="addConditions")
    def add_conditions(
        self,
        conditions: typing.Mapping[builtins.str, typing.Any],
    ) -> None:
        '''Adds multiple conditions to the principal.

        Values from the conditions parameter will overwrite existing values with the same operator
        and key.

        :param conditions: -
        '''
        return typing.cast(None, jsii.invoke(self, "addConditions", [conditions]))

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: PolicyStatement) -> builtins.bool:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: PolicyStatement,
    ) -> AddToPrincipalPolicyResult:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

    @jsii.member(jsii_name="toJSON")
    def to_json(self) -> typing.Mapping[builtins.str, typing.List[builtins.str]]:
        '''JSON-ify the principal.

        Used when JSON.stringify() is called
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.List[builtins.str]], jsii.invoke(self, "toJSON", []))

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="conditions")
    def conditions(self) -> typing.Mapping[builtins.str, typing.Any]:
        '''The conditions under which the policy is in effect.

        See `the IAM documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`_.
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "conditions"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))


@jsii.implements(IRole)
class Role(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.Role",
):
    '''IAM Role.

    Defines an IAM role. The role is created with an assume policy document associated with
    the specified AWS service principal defined in ``serviceAssumeRole``.

    :exampleMetadata: infused

    Example::

        lambda_role = iam.Role(self, "Role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Example role..."
        )
        
        stream = kinesis.Stream(self, "MyEncryptedStream",
            encryption=kinesis.StreamEncryption.KMS
        )
        
        # give lambda permissions to read stream
        stream.grant_read(lambda_role)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        assumed_by: IPrincipal,
        description: typing.Optional[builtins.str] = None,
        external_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        inline_policies: typing.Optional[typing.Mapping[builtins.str, PolicyDocument]] = None,
        managed_policies: typing.Optional[typing.Sequence[IManagedPolicy]] = None,
        max_session_duration: typing.Optional[_Duration_4839e8c3] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[IManagedPolicy] = None,
        role_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param assumed_by: The IAM principal (i.e. ``new ServicePrincipal('sns.amazonaws.com')``) which can assume this role. You can later modify the assume role policy document by accessing it via the ``assumeRolePolicy`` property.
        :param description: A description of the role. It can be up to 1000 characters long. Default: - No description.
        :param external_ids: List of IDs that the role assumer needs to provide one of when assuming this role. If the configured and provided external IDs do not match, the AssumeRole operation will fail. Default: No external ID required
        :param inline_policies: A list of named policies to inline into this role. These policies will be created with the role, whereas those added by ``addToPolicy`` are added using a separate CloudFormation resource (allowing a way around circular dependencies that could otherwise be introduced). Default: - No policy is inlined in the Role resource.
        :param managed_policies: A list of managed policies associated with this role. You can add managed policies later using ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``. Default: - No managed policies.
        :param max_session_duration: The maximum session duration that you want to set for the specified role. This setting can have a value from 1 hour (3600sec) to 12 (43200sec) hours. Anyone who assumes the role from the AWS CLI or API can use the DurationSeconds API parameter or the duration-seconds CLI parameter to request a longer session. The MaxSessionDuration setting determines the maximum duration that can be requested using the DurationSeconds parameter. If users don't specify a value for the DurationSeconds parameter, their security credentials are valid for one hour by default. This applies when you use the AssumeRole* API operations or the assume-role* CLI operations but does not apply when you use those operations to create a console URL. Default: Duration.hours(1)
        :param path: The path associated with this role. For information about IAM paths, see Friendly Names and Paths in IAM User Guide. Default: /
        :param permissions_boundary: AWS supports permissions boundaries for IAM entities (users or roles). A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. An entity's permissions boundary allows it to perform only the actions that are allowed by both its identity-based policies and its permissions boundaries. Default: - No permissions boundary.
        :param role_name: A name for the IAM role. For valid values, see the RoleName parameter for the CreateRole action in the IAM API Reference. IMPORTANT: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to acknowledge your template's capabilities. For more information, see Acknowledging IAM Resources in AWS CloudFormation Templates. Default: - AWS CloudFormation generates a unique physical ID and uses that ID for the role name.
        '''
        props = RoleProps(
            assumed_by=assumed_by,
            description=description,
            external_ids=external_ids,
            inline_policies=inline_policies,
            managed_policies=managed_policies,
            max_session_duration=max_session_duration,
            path=path,
            permissions_boundary=permissions_boundary,
            role_name=role_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromRoleArn") # type: ignore[misc]
    @builtins.classmethod
    def from_role_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        role_arn: builtins.str,
        *,
        add_grants_to_resources: typing.Optional[builtins.bool] = None,
        mutable: typing.Optional[builtins.bool] = None,
    ) -> IRole:
        '''Import an external role by ARN.

        If the imported Role ARN is a Token (such as a
        ``CfnParameter.valueAsString`` or a ``Fn.importValue()``) *and* the referenced
        role has a ``path`` (like ``arn:...:role/AdminRoles/Alice``), the
        ``roleName`` property will not resolve to the correct value. Instead it
        will resolve to the first path component. We unfortunately cannot express
        the correct calculation of the full path name as a CloudFormation
        expression. In this scenario the Role ARN should be supplied without the
        ``path`` in order to resolve the correct role resource.

        :param scope: construct scope.
        :param id: construct id.
        :param role_arn: the ARN of the role to import.
        :param add_grants_to_resources: For immutable roles: add grants to resources instead of dropping them. If this is ``false`` or not specified, grant permissions added to this role are ignored. It is your own responsibility to make sure the role has the required permissions. If this is ``true``, any grant permissions will be added to the resource instead. Default: false
        :param mutable: Whether the imported role can be modified by attaching policy resources to it. Default: true
        '''
        options = FromRoleArnOptions(
            add_grants_to_resources=add_grants_to_resources, mutable=mutable
        )

        return typing.cast(IRole, jsii.sinvoke(cls, "fromRoleArn", [scope, id, role_arn, options]))

    @jsii.member(jsii_name="fromRoleName") # type: ignore[misc]
    @builtins.classmethod
    def from_role_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        role_name: builtins.str,
    ) -> IRole:
        '''Import an external role by name.

        The imported role is assumed to exist in the same account as the account
        the scope's containing Stack is being deployed to.

        :param scope: -
        :param id: -
        :param role_name: -
        '''
        return typing.cast(IRole, jsii.sinvoke(cls, "fromRoleName", [scope, id, role_name]))

    @jsii.member(jsii_name="addManagedPolicy")
    def add_managed_policy(self, policy: IManagedPolicy) -> None:
        '''Attaches a managed policy to this role.

        :param policy: The the managed policy to attach.
        '''
        return typing.cast(None, jsii.invoke(self, "addManagedPolicy", [policy]))

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: PolicyStatement) -> builtins.bool:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: PolicyStatement,
    ) -> AddToPrincipalPolicyResult:
        '''Adds a permission to the role's default policy document.

        If there is no default policy attached to this role, it will be created.

        :param statement: The permission statement to add to the policy document.
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

    @jsii.member(jsii_name="attachInlinePolicy")
    def attach_inline_policy(self, policy: Policy) -> None:
        '''Attaches a policy to this role.

        :param policy: The policy to attach.
        '''
        return typing.cast(None, jsii.invoke(self, "attachInlinePolicy", [policy]))

    @jsii.member(jsii_name="grant")
    def grant(self, grantee: IPrincipal, *actions: builtins.str) -> Grant:
        '''Grant the actions defined in actions to the identity Principal on this resource.

        :param grantee: -
        :param actions: -
        '''
        return typing.cast(Grant, jsii.invoke(self, "grant", [grantee, *actions]))

    @jsii.member(jsii_name="grantPassRole")
    def grant_pass_role(self, identity: IPrincipal) -> Grant:
        '''Grant permissions to the given principal to pass this role.

        :param identity: -
        '''
        return typing.cast(Grant, jsii.invoke(self, "grantPassRole", [identity]))

    @jsii.member(jsii_name="withoutPolicyUpdates")
    def without_policy_updates(
        self,
        *,
        add_grants_to_resources: typing.Optional[builtins.bool] = None,
    ) -> IRole:
        '''Return a copy of this Role object whose Policies will not be updated.

        Use the object returned by this method if you want this Role to be used by
        a construct without it automatically updating the Role's Policies.

        If you do, you are responsible for adding the correct statements to the
        Role's policies yourself.

        :param add_grants_to_resources: Add grants to resources instead of dropping them. If this is ``false`` or not specified, grant permissions added to this role are ignored. It is your own responsibility to make sure the role has the required permissions. If this is ``true``, any grant permissions will be added to the resource instead. Default: false
        '''
        options = WithoutPolicyUpdatesOptions(
            add_grants_to_resources=add_grants_to_resources
        )

        return typing.cast(IRole, jsii.invoke(self, "withoutPolicyUpdates", [options]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> IPrincipal:
        '''The principal to grant permissions to.'''
        return typing.cast(IPrincipal, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Returns the role.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''Returns the ARN of this role.'''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleId")
    def role_id(self) -> builtins.str:
        '''Returns the stable and unique string identifying the role.

        For example,
        AIDAJQABLZS4A3QDU576Q.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleName")
    def role_name(self) -> builtins.str:
        '''Returns the name of the role.'''
        return typing.cast(builtins.str, jsii.get(self, "roleName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRolePolicy")
    def assume_role_policy(self) -> typing.Optional[PolicyDocument]:
        '''The assume role policy document associated with this role.'''
        return typing.cast(typing.Optional[PolicyDocument], jsii.get(self, "assumeRolePolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissionsBoundary")
    def permissions_boundary(self) -> typing.Optional[IManagedPolicy]:
        '''Returns the permissions boundary attached to this role.'''
        return typing.cast(typing.Optional[IManagedPolicy], jsii.get(self, "permissionsBoundary"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))


class ServicePrincipal(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.ServicePrincipal",
):
    '''An IAM principal that represents an AWS service (i.e. sqs.amazonaws.com).

    :exampleMetadata: infused

    Example::

        lambda_role = iam.Role(self, "Role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Example role..."
        )
        
        stream = kinesis.Stream(self, "MyEncryptedStream",
            encryption=kinesis.StreamEncryption.KMS
        )
        
        # give lambda permissions to read stream
        stream.grant_read(lambda_role)
    '''

    def __init__(
        self,
        service: builtins.str,
        *,
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        region: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param service: AWS service (i.e. sqs.amazonaws.com).
        :param conditions: Additional conditions to add to the Service Principal. Default: - No conditions
        :param region: (deprecated) The region in which the service is operating. Default: the current Stack's region.
        '''
        opts = ServicePrincipalOpts(conditions=conditions, region=region)

        jsii.create(self.__class__, self, [service, opts])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="service")
    def service(self) -> builtins.str:
        '''AWS service (i.e. sqs.amazonaws.com).'''
        return typing.cast(builtins.str, jsii.get(self, "service"))


class SessionTagsPrincipal(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.SessionTagsPrincipal",
):
    '''Enables session tags on role assumptions from a principal.

    For more information on session tags, see:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # principal: iam.IPrincipal
        
        session_tags_principal = iam.SessionTagsPrincipal(principal)
    '''

    def __init__(self, principal: IPrincipal) -> None:
        '''
        :param principal: -
        '''
        jsii.create(self.__class__, self, [principal])

    @jsii.member(jsii_name="addToAssumeRolePolicy")
    def add_to_assume_role_policy(self, doc: PolicyDocument) -> None:
        '''Add the princpial to the AssumeRolePolicyDocument.

        Add the statements to the AssumeRolePolicyDocument necessary to give this principal
        permissions to assume the given role.

        :param doc: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToAssumeRolePolicy", [doc]))

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: PolicyStatement) -> builtins.bool:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: PolicyStatement,
    ) -> AddToPrincipalPolicyResult:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))


class StarPrincipal(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.StarPrincipal",
):
    '''A principal that uses a literal '*' in the IAM JSON language.

    Some services behave differently when you specify ``Principal: "*"``
    or ``Principal: { AWS: "*" }`` in their resource policy.

    ``StarPrincipal`` renders to ``Principal: *``. Most of the time, you
    should use ``AnyPrincipal`` instead.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        star_principal = iam.StarPrincipal()
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


@jsii.implements(IIdentity, IUser)
class User(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.User",
):
    '''Define a new IAM user.

    :exampleMetadata: infused

    Example::

        user = iam.User(self, "MyUser") # or User.fromUserName(stack, 'User', 'johnsmith');
        group = iam.Group(self, "MyGroup") # or Group.fromGroupArn(stack, 'Group', 'arn:aws:iam::account-id:group/group-name');
        
        user.add_to_group(group)
        # or
        group.add_user(user)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        groups: typing.Optional[typing.Sequence["IGroup"]] = None,
        managed_policies: typing.Optional[typing.Sequence[IManagedPolicy]] = None,
        password: typing.Optional[_SecretValue_3dd0ddae] = None,
        password_reset_required: typing.Optional[builtins.bool] = None,
        path: typing.Optional[builtins.str] = None,
        permissions_boundary: typing.Optional[IManagedPolicy] = None,
        user_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param groups: Groups to add this user to. You can also use ``addToGroup`` to add this user to a group. Default: - No groups.
        :param managed_policies: A list of managed policies associated with this role. You can add managed policies later using ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``. Default: - No managed policies.
        :param password: The password for the user. This is required so the user can access the AWS Management Console. You can use ``SecretValue.plainText`` to specify a password in plain text or use ``secretsmanager.Secret.fromSecretAttributes`` to reference a secret in Secrets Manager. Default: - User won't be able to access the management console without a password.
        :param password_reset_required: Specifies whether the user is required to set a new password the next time the user logs in to the AWS Management Console. If this is set to 'true', you must also specify "initialPassword". Default: false
        :param path: The path for the user name. For more information about paths, see IAM Identifiers in the IAM User Guide. Default: /
        :param permissions_boundary: AWS supports permissions boundaries for IAM entities (users or roles). A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. An entity's permissions boundary allows it to perform only the actions that are allowed by both its identity-based policies and its permissions boundaries. Default: - No permissions boundary.
        :param user_name: A name for the IAM user. For valid values, see the UserName parameter for the CreateUser action in the IAM API Reference. If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the user name. If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name. If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to acknowledge your template's capabilities. For more information, see Acknowledging IAM Resources in AWS CloudFormation Templates. Default: - Generated by CloudFormation (recommended)
        '''
        props = UserProps(
            groups=groups,
            managed_policies=managed_policies,
            password=password,
            password_reset_required=password_reset_required,
            path=path,
            permissions_boundary=permissions_boundary,
            user_name=user_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromUserArn") # type: ignore[misc]
    @builtins.classmethod
    def from_user_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        user_arn: builtins.str,
    ) -> IUser:
        '''Import an existing user given a user ARN.

        If the ARN comes from a Token, the User cannot have a path; if so, any attempt
        to reference its username will fail.

        :param scope: construct scope.
        :param id: construct id.
        :param user_arn: the ARN of an existing user to import.
        '''
        return typing.cast(IUser, jsii.sinvoke(cls, "fromUserArn", [scope, id, user_arn]))

    @jsii.member(jsii_name="fromUserAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_user_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user_arn: builtins.str,
    ) -> IUser:
        '''Import an existing user given user attributes.

        If the ARN comes from a Token, the User cannot have a path; if so, any attempt
        to reference its username will fail.

        :param scope: construct scope.
        :param id: construct id.
        :param user_arn: The ARN of the user. Format: arn::iam:::user/
        '''
        attrs = UserAttributes(user_arn=user_arn)

        return typing.cast(IUser, jsii.sinvoke(cls, "fromUserAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromUserName") # type: ignore[misc]
    @builtins.classmethod
    def from_user_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        user_name: builtins.str,
    ) -> IUser:
        '''Import an existing user given a username.

        :param scope: construct scope.
        :param id: construct id.
        :param user_name: the username of the existing user to import.
        '''
        return typing.cast(IUser, jsii.sinvoke(cls, "fromUserName", [scope, id, user_name]))

    @jsii.member(jsii_name="addManagedPolicy")
    def add_managed_policy(self, policy: IManagedPolicy) -> None:
        '''Attaches a managed policy to the user.

        :param policy: The managed policy to attach.
        '''
        return typing.cast(None, jsii.invoke(self, "addManagedPolicy", [policy]))

    @jsii.member(jsii_name="addToGroup")
    def add_to_group(self, group: "IGroup") -> None:
        '''Adds this user to a group.

        :param group: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToGroup", [group]))

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: PolicyStatement) -> builtins.bool:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: PolicyStatement,
    ) -> AddToPrincipalPolicyResult:
        '''Adds an IAM statement to the default policy.

        :param statement: -

        :return: true
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

    @jsii.member(jsii_name="attachInlinePolicy")
    def attach_inline_policy(self, policy: Policy) -> None:
        '''Attaches a policy to this user.

        :param policy: -
        '''
        return typing.cast(None, jsii.invoke(self, "attachInlinePolicy", [policy]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> IPrincipal:
        '''The principal to grant permissions to.'''
        return typing.cast(IPrincipal, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userArn")
    def user_arn(self) -> builtins.str:
        '''An attribute that represents the user's ARN.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userName")
    def user_name(self) -> builtins.str:
        '''An attribute that represents the user name.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissionsBoundary")
    def permissions_boundary(self) -> typing.Optional[IManagedPolicy]:
        '''Returns the permissions boundary attached  to this user.'''
        return typing.cast(typing.Optional[IManagedPolicy], jsii.get(self, "permissionsBoundary"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))


class ArnPrincipal(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.ArnPrincipal",
):
    '''Specify a principal by the Amazon Resource Name (ARN).

    You can specify AWS accounts, IAM users, Federated SAML users, IAM roles, and specific assumed-role sessions.
    You cannot specify IAM groups or instance profiles as principals

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        # network_load_balancer1: elbv2.NetworkLoadBalancer
        # network_load_balancer2: elbv2.NetworkLoadBalancer
        
        
        ec2.VpcEndpointService(self, "EndpointService",
            vpc_endpoint_service_load_balancers=[network_load_balancer1, network_load_balancer2],
            acceptance_required=True,
            allowed_principals=[iam.ArnPrincipal("arn:aws:iam::123456789012:root")]
        )
    '''

    def __init__(self, arn: builtins.str) -> None:
        '''
        :param arn: Amazon Resource Name (ARN) of the principal entity (i.e. arn:aws:iam::123456789012:user/user-name).
        '''
        jsii.create(self.__class__, self, [arn])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="arn")
    def arn(self) -> builtins.str:
        '''Amazon Resource Name (ARN) of the principal entity (i.e. arn:aws:iam::123456789012:user/user-name).'''
        return typing.cast(builtins.str, jsii.get(self, "arn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


class CanonicalUserPrincipal(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CanonicalUserPrincipal",
):
    '''A policy principal for canonicalUserIds - useful for S3 bucket policies that use Origin Access identities.

    See https://docs.aws.amazon.com/general/latest/gr/acct-identifiers.html

    and

    https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html

    for more details.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        canonical_user_principal = iam.CanonicalUserPrincipal("canonicalUserId")
    '''

    def __init__(self, canonical_user_id: builtins.str) -> None:
        '''
        :param canonical_user_id: unique identifier assigned by AWS for every account. root user and IAM users for an account all see the same ID. (i.e. 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be)
        '''
        jsii.create(self.__class__, self, [canonical_user_id])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="canonicalUserId")
    def canonical_user_id(self) -> builtins.str:
        '''unique identifier assigned by AWS for every account.

        root user and IAM users for an account all see the same ID.
        (i.e. 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be)
        '''
        return typing.cast(builtins.str, jsii.get(self, "canonicalUserId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


class CompositePrincipal(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.CompositePrincipal",
):
    '''Represents a principal that has multiple types of principals.

    A composite principal cannot
    have conditions. i.e. multiple ServicePrincipals that form a composite principal

    :exampleMetadata: infused

    Example::

        role = iam.Role(self, "MyRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("ec2.amazonaws.com"),
                iam.AccountPrincipal("1818188181818187272"))
        )
    '''

    def __init__(self, *principals: IPrincipal) -> None:
        '''
        :param principals: -
        '''
        jsii.create(self.__class__, self, [*principals])

    @jsii.member(jsii_name="addPrincipals")
    def add_principals(self, *principals: IPrincipal) -> "CompositePrincipal":
        '''Adds IAM principals to the composite principal.

        Composite principals cannot have
        conditions.

        :param principals: IAM principals that will be added to the composite principal.
        '''
        return typing.cast("CompositePrincipal", jsii.invoke(self, "addPrincipals", [*principals]))

    @jsii.member(jsii_name="addToAssumeRolePolicy")
    def add_to_assume_role_policy(self, doc: PolicyDocument) -> None:
        '''Add the princpial to the AssumeRolePolicyDocument.

        Add the statements to the AssumeRolePolicyDocument necessary to give this principal
        permissions to assume the given role.

        :param doc: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToAssumeRolePolicy", [doc]))

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


class FederatedPrincipal(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.FederatedPrincipal",
):
    '''Principal entity that represents a federated identity provider such as Amazon Cognito, that can be used to provide temporary security credentials to users who have been authenticated.

    Additional condition keys are available when the temporary security credentials are used to make a request.
    You can use these keys to write policies that limit the access of federated users.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-wif
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        # conditions: Any
        
        federated_principal = iam.FederatedPrincipal("federated", {
            "conditions_key": conditions
        }, "assumeRoleAction")
    '''

    def __init__(
        self,
        federated: builtins.str,
        conditions: typing.Mapping[builtins.str, typing.Any],
        assume_role_action: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param federated: federated identity provider (i.e. 'cognito-identity.amazonaws.com' for users authenticated through Cognito).
        :param conditions: The conditions under which the policy is in effect. See `the IAM documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`_.
        :param assume_role_action: -
        '''
        jsii.create(self.__class__, self, [federated, conditions, assume_role_action])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="conditions")
    def conditions(self) -> typing.Mapping[builtins.str, typing.Any]:
        '''The conditions under which the policy is in effect.

        See `the IAM documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`_.
        '''
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "conditions"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="federated")
    def federated(self) -> builtins.str:
        '''federated identity provider (i.e. 'cognito-identity.amazonaws.com' for users authenticated through Cognito).'''
        return typing.cast(builtins.str, jsii.get(self, "federated"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


@jsii.interface(jsii_type="aws-cdk-lib.aws_iam.IGroup")
class IGroup(IIdentity, typing_extensions.Protocol):
    '''Represents an IAM Group.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html
    '''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groupArn")
    def group_arn(self) -> builtins.str:
        '''Returns the IAM Group ARN.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groupName")
    def group_name(self) -> builtins.str:
        '''Returns the IAM Group Name.

        :attribute: true
        '''
        ...


class _IGroupProxy(
    jsii.proxy_for(IIdentity) # type: ignore[misc]
):
    '''Represents an IAM Group.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html
    '''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_iam.IGroup"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groupArn")
    def group_arn(self) -> builtins.str:
        '''Returns the IAM Group ARN.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "groupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groupName")
    def group_name(self) -> builtins.str:
        '''Returns the IAM Group Name.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "groupName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IGroup).__jsii_proxy_class__ = lambda : _IGroupProxy


class OrganizationPrincipal(
    PrincipalBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.OrganizationPrincipal",
):
    '''A principal that represents an AWS Organization.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_iam as iam
        
        organization_principal = iam.OrganizationPrincipal("organizationId")
    '''

    def __init__(self, organization_id: builtins.str) -> None:
        '''
        :param organization_id: The unique identifier (ID) of an organization (i.e. o-12345abcde).
        '''
        jsii.create(self.__class__, self, [organization_id])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="organizationId")
    def organization_id(self) -> builtins.str:
        '''The unique identifier (ID) of an organization (i.e. o-12345abcde).'''
        return typing.cast(builtins.str, jsii.get(self, "organizationId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


class SamlPrincipal(
    FederatedPrincipal,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.SamlPrincipal",
):
    '''Principal entity that represents a SAML federated identity provider.

    :exampleMetadata: infused

    Example::

        provider = iam.SamlProvider(self, "Provider",
            metadata_document=iam.SamlMetadataDocument.from_file("/path/to/saml-metadata-document.xml")
        )
        principal = iam.SamlPrincipal(provider, {
            "StringEquals": {
                "SAML:iss": "issuer"
            }
        })
    '''

    def __init__(
        self,
        saml_provider: ISamlProvider,
        conditions: typing.Mapping[builtins.str, typing.Any],
    ) -> None:
        '''
        :param saml_provider: -
        :param conditions: -
        '''
        jsii.create(self.__class__, self, [saml_provider, conditions])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))


class WebIdentityPrincipal(
    FederatedPrincipal,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.WebIdentityPrincipal",
):
    '''A principal that represents a federated identity provider as Web Identity such as Cognito, Amazon, Facebook, Google, etc.

    :exampleMetadata: infused

    Example::

        principal = iam.WebIdentityPrincipal("cognito-identity.amazonaws.com", {
            "StringEquals": {"cognito-identity.amazonaws.com:aud": "us-east-2:12345678-abcd-abcd-abcd-123456"},
            "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"}
        })
    '''

    def __init__(
        self,
        identity_provider: builtins.str,
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
    ) -> None:
        '''
        :param identity_provider: identity provider (i.e. 'cognito-identity.amazonaws.com' for users authenticated through Cognito).
        :param conditions: The conditions under which the policy is in effect. See `the IAM documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`_.
        '''
        jsii.create(self.__class__, self, [identity_provider, conditions])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


class AccountPrincipal(
    ArnPrincipal,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.AccountPrincipal",
):
    '''Specify AWS account ID as the principal entity in a policy to delegate authority to the account.

    :exampleMetadata: infused

    Example::

        cluster = neptune.DatabaseCluster(self, "Cluster",
            vpc=vpc,
            instance_type=neptune.InstanceType.R5_LARGE,
            iam_authentication=True
        )
        role = iam.Role(self, "DBRole", assumed_by=iam.AccountPrincipal(self.account))
        cluster.grant_connect(role)
    '''

    def __init__(self, account_id: typing.Any) -> None:
        '''
        :param account_id: AWS account ID (i.e. 123456789012).
        '''
        jsii.create(self.__class__, self, [account_id])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accountId")
    def account_id(self) -> typing.Any:
        '''AWS account ID (i.e. 123456789012).'''
        return typing.cast(typing.Any, jsii.get(self, "accountId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))


class AccountRootPrincipal(
    AccountPrincipal,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.AccountRootPrincipal",
):
    '''Use the AWS account into which a stack is deployed as the principal entity in a policy.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        bucket = s3.Bucket(self, "MyBucket")
        result = bucket.add_to_resource_policy(iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=[bucket.arn_for_objects("file.txt")],
            principals=[iam.AccountRootPrincipal()]
        ))
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))


class AnyPrincipal(
    ArnPrincipal,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.AnyPrincipal",
):
    '''A principal representing all AWS identities in all accounts.

    Some services behave differently when you specify ``Principal: '*'``
    or ``Principal: { AWS: "*" }`` in their resource policy.

    ``AnyPrincipal`` renders to ``Principal: { AWS: "*" }``. This is correct
    most of the time, but in cases where you need the other principal,
    use ``StarPrincipal`` instead.

    :exampleMetadata: infused

    Example::

        topic = sns.Topic(self, "Topic")
        topic_policy = sns.TopicPolicy(self, "TopicPolicy",
            topics=[topic]
        )
        
        topic_policy.document.add_statements(iam.PolicyStatement(
            actions=["sns:Subscribe"],
            principals=[iam.AnyPrincipal()],
            resources=[topic.topic_arn]
        ))
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))


@jsii.implements(IGroup)
class Group(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.Group",
):
    '''An IAM Group (collection of IAM users) lets you specify permissions for multiple users, which can make it easier to manage permissions for those users.

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html
    :exampleMetadata: lit=aws-iam/test/example.managedpolicy.lit.ts infused

    Example::

        group = Group(self, "MyGroup")
        group.add_managed_policy(ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess"))
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        group_name: typing.Optional[builtins.str] = None,
        managed_policies: typing.Optional[typing.Sequence[IManagedPolicy]] = None,
        path: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param group_name: A name for the IAM group. For valid values, see the GroupName parameter for the CreateGroup action in the IAM API Reference. If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the group name. If you specify a name, you must specify the CAPABILITY_NAMED_IAM value to acknowledge your template's capabilities. For more information, see Acknowledging IAM Resources in AWS CloudFormation Templates. Default: Generated by CloudFormation (recommended)
        :param managed_policies: A list of managed policies associated with this role. You can add managed policies later using ``addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName(policyName))``. Default: - No managed policies.
        :param path: The path to the group. For more information about paths, see `IAM Identifiers <http://docs.aws.amazon.com/IAM/latest/UserGuide/index.html?Using_Identifiers.html>`_ in the IAM User Guide. Default: /
        '''
        props = GroupProps(
            group_name=group_name, managed_policies=managed_policies, path=path
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromGroupArn") # type: ignore[misc]
    @builtins.classmethod
    def from_group_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        group_arn: builtins.str,
    ) -> IGroup:
        '''Import an external group by ARN.

        If the imported Group ARN is a Token (such as a
        ``CfnParameter.valueAsString`` or a ``Fn.importValue()``) *and* the referenced
        group has a ``path`` (like ``arn:...:group/AdminGroup/NetworkAdmin``), the
        ``groupName`` property will not resolve to the correct value. Instead it
        will resolve to the first path component. We unfortunately cannot express
        the correct calculation of the full path name as a CloudFormation
        expression. In this scenario the Group ARN should be supplied without the
        ``path`` in order to resolve the correct group resource.

        :param scope: construct scope.
        :param id: construct id.
        :param group_arn: the ARN of the group to import (e.g. ``arn:aws:iam::account-id:group/group-name``).
        '''
        return typing.cast(IGroup, jsii.sinvoke(cls, "fromGroupArn", [scope, id, group_arn]))

    @jsii.member(jsii_name="fromGroupName") # type: ignore[misc]
    @builtins.classmethod
    def from_group_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        group_name: builtins.str,
    ) -> IGroup:
        '''Import an existing group by given name (with path).

        This method has same caveats of ``fromGroupArn``

        :param scope: construct scope.
        :param id: construct id.
        :param group_name: the groupName (path included) of the existing group to import.
        '''
        return typing.cast(IGroup, jsii.sinvoke(cls, "fromGroupName", [scope, id, group_name]))

    @jsii.member(jsii_name="addManagedPolicy")
    def add_managed_policy(self, policy: IManagedPolicy) -> None:
        '''Attaches a managed policy to this group.

        :param policy: The managed policy to attach.
        '''
        return typing.cast(None, jsii.invoke(self, "addManagedPolicy", [policy]))

    @jsii.member(jsii_name="addToPolicy")
    def add_to_policy(self, statement: PolicyStatement) -> builtins.bool:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "addToPolicy", [statement]))

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: PolicyStatement,
    ) -> AddToPrincipalPolicyResult:
        '''Adds an IAM statement to the default policy.

        :param statement: -
        '''
        return typing.cast(AddToPrincipalPolicyResult, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

    @jsii.member(jsii_name="addUser")
    def add_user(self, user: IUser) -> None:
        '''Adds a user to this group.

        :param user: -
        '''
        return typing.cast(None, jsii.invoke(self, "addUser", [user]))

    @jsii.member(jsii_name="attachInlinePolicy")
    def attach_inline_policy(self, policy: Policy) -> None:
        '''Attaches a policy to this group.

        :param policy: The policy to attach.
        '''
        return typing.cast(None, jsii.invoke(self, "attachInlinePolicy", [policy]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> IPrincipal:
        '''The principal to grant permissions to.'''
        return typing.cast(IPrincipal, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groupArn")
    def group_arn(self) -> builtins.str:
        '''Returns the IAM Group ARN.'''
        return typing.cast(builtins.str, jsii.get(self, "groupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groupName")
    def group_name(self) -> builtins.str:
        '''Returns the IAM Group Name.'''
        return typing.cast(builtins.str, jsii.get(self, "groupName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principalAccount")
    def principal_account(self) -> typing.Optional[builtins.str]:
        '''The AWS account ID of this principal.

        Can be undefined when the account is not known
        (for example, for service principals).
        Can be a Token - in that case,
        it's assumed to be AWS::AccountId.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principalAccount"))


class OpenIdConnectPrincipal(
    WebIdentityPrincipal,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.OpenIdConnectPrincipal",
):
    '''A principal that represents a federated identity provider as from a OpenID Connect provider.

    :exampleMetadata: infused

    Example::

        provider = iam.OpenIdConnectProvider(self, "MyProvider",
            url="https://openid/connect",
            client_ids=["myclient1", "myclient2"]
        )
        principal = iam.OpenIdConnectPrincipal(provider)
    '''

    def __init__(
        self,
        open_id_connect_provider: IOpenIdConnectProvider,
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
    ) -> None:
        '''
        :param open_id_connect_provider: OpenID Connect provider.
        :param conditions: The conditions under which the policy is in effect. See `the IAM documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`_.
        '''
        jsii.create(self.__class__, self, [open_id_connect_provider, conditions])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> PrincipalPolicyFragment:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(PrincipalPolicyFragment, jsii.get(self, "policyFragment"))


class SamlConsolePrincipal(
    SamlPrincipal,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_iam.SamlConsolePrincipal",
):
    '''Principal entity that represents a SAML federated identity provider for programmatic and AWS Management Console access.

    :exampleMetadata: infused

    Example::

        provider = iam.SamlProvider(self, "Provider",
            metadata_document=iam.SamlMetadataDocument.from_file("/path/to/saml-metadata-document.xml")
        )
        iam.Role(self, "Role",
            assumed_by=iam.SamlConsolePrincipal(provider)
        )
    '''

    def __init__(
        self,
        saml_provider: ISamlProvider,
        conditions: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
    ) -> None:
        '''
        :param saml_provider: -
        :param conditions: -
        '''
        jsii.create(self.__class__, self, [saml_provider, conditions])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of an object.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))


__all__ = [
    "AccessKey",
    "AccessKeyProps",
    "AccessKeyStatus",
    "AccountPrincipal",
    "AccountRootPrincipal",
    "AddToPrincipalPolicyResult",
    "AddToResourcePolicyResult",
    "AnyPrincipal",
    "ArnPrincipal",
    "CanonicalUserPrincipal",
    "CfnAccessKey",
    "CfnAccessKeyProps",
    "CfnGroup",
    "CfnGroupProps",
    "CfnInstanceProfile",
    "CfnInstanceProfileProps",
    "CfnManagedPolicy",
    "CfnManagedPolicyProps",
    "CfnOIDCProvider",
    "CfnOIDCProviderProps",
    "CfnPolicy",
    "CfnPolicyProps",
    "CfnRole",
    "CfnRoleProps",
    "CfnSAMLProvider",
    "CfnSAMLProviderProps",
    "CfnServerCertificate",
    "CfnServerCertificateProps",
    "CfnServiceLinkedRole",
    "CfnServiceLinkedRoleProps",
    "CfnUser",
    "CfnUserProps",
    "CfnUserToGroupAddition",
    "CfnUserToGroupAdditionProps",
    "CfnVirtualMFADevice",
    "CfnVirtualMFADeviceProps",
    "CommonGrantOptions",
    "CompositeDependable",
    "CompositePrincipal",
    "Effect",
    "FederatedPrincipal",
    "FromRoleArnOptions",
    "Grant",
    "GrantOnPrincipalAndResourceOptions",
    "GrantOnPrincipalOptions",
    "GrantWithResourceOptions",
    "Group",
    "GroupProps",
    "IAccessKey",
    "IAssumeRolePrincipal",
    "IGrantable",
    "IGroup",
    "IIdentity",
    "IManagedPolicy",
    "IOpenIdConnectProvider",
    "IPolicy",
    "IPrincipal",
    "IResourceWithPolicy",
    "IRole",
    "ISamlProvider",
    "IUser",
    "LazyRole",
    "LazyRoleProps",
    "ManagedPolicy",
    "ManagedPolicyProps",
    "OpenIdConnectPrincipal",
    "OpenIdConnectProvider",
    "OpenIdConnectProviderProps",
    "OrganizationPrincipal",
    "PermissionsBoundary",
    "Policy",
    "PolicyDocument",
    "PolicyDocumentProps",
    "PolicyProps",
    "PolicyStatement",
    "PolicyStatementProps",
    "PrincipalBase",
    "PrincipalPolicyFragment",
    "PrincipalWithConditions",
    "Role",
    "RoleProps",
    "SamlConsolePrincipal",
    "SamlMetadataDocument",
    "SamlPrincipal",
    "SamlProvider",
    "SamlProviderProps",
    "ServicePrincipal",
    "ServicePrincipalOpts",
    "SessionTagsPrincipal",
    "StarPrincipal",
    "UnknownPrincipal",
    "UnknownPrincipalProps",
    "User",
    "UserAttributes",
    "UserProps",
    "WebIdentityPrincipal",
    "WithoutPolicyUpdatesOptions",
]

publication.publish()
