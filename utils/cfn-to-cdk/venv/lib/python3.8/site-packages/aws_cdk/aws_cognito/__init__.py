'''
# Amazon Cognito Construct Library

[Amazon Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html) provides
authentication, authorization, and user management for your web and mobile apps. Your users can sign in directly with a
user name and password, or through a third party such as Facebook, Amazon, Google or Apple.

The two main components of Amazon Cognito are [user
pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html) and [identity
pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html). User pools are user directories
that provide sign-up and sign-in options for your app users. Identity pools enable you to grant your users access to
other AWS services. Identity Pool L2 Constructs can be found [here](../aws-cognito-identitypool).

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

## Table of Contents

* [User Pools](#user-pools)

  * [Sign Up](#sign-up)
  * [Sign In](#sign-in)
  * [Attributes](#attributes)
  * [Security](#security)

    * [Multi-factor Authentication](#multi-factor-authentication-mfa)
    * [Account Recovery Settings](#account-recovery-settings)
  * [Emails](#emails)
  * [Device Tracking](#device-tracking)
  * [Lambda Triggers](#lambda-triggers)

    * [Trigger Permissions](#trigger-permissions)
  * [Import](#importing-user-pools)
  * [Identity Providers](#identity-providers)
  * [App Clients](#app-clients)
  * [Resource Servers](#resource-servers)
  * [Domains](#domains)

## User Pools

User pools allow creating and managing your own directory of users that can sign up and sign in. They enable easy
integration with social identity providers such as Facebook, Google, Amazon, Microsoft Active Directory, etc. through
SAML.

Using the CDK, a new user pool can be created as part of the stack using the construct's constructor. You may specify
the `userPoolName` to give your own identifier to the user pool. If not, CloudFormation will generate a name.

```python
cognito.UserPool(self, "myuserpool",
    user_pool_name="myawesomeapp-userpool"
)
```

The default set up for the user pool is configured such that only administrators will be allowed
to create users. Features such as Multi-factor authentication (MFAs) and Lambda Triggers are not
configured by default.

### Sign Up

Users can either be signed up by the app's administrators or can sign themselves up. Once a user has signed up, their
account needs to be confirmed. Cognito provides several ways to sign users up and confirm their accounts. Learn more
about [user sign up here](https://docs.aws.amazon.com/cognito/latest/developerguide/signing-up-users-in-your-app.html).

When a user signs up, email and SMS messages are used to verify their account and contact methods. The following code
snippet configures a user pool with properties relevant to these verification messages -

```python
cognito.UserPool(self, "myuserpool",
    # ...
    self_sign_up_enabled=True,
    user_verification=cognito.UserVerificationConfig(
        email_subject="Verify your email for our awesome app!",
        email_body="Thanks for signing up to our awesome app! Your verification code is {####}",
        email_style=cognito.VerificationEmailStyle.CODE,
        sms_message="Thanks for signing up to our awesome app! Your verification code is {####}"
    )
)
```

By default, self sign up is disabled. Learn more about [email and SMS verification messages
here](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-customizations.html).

Besides users signing themselves up, an administrator of any user pool can sign users up. The user then receives an
invitation to join the user pool. The following code snippet configures a user pool with properties relevant to the
invitation messages -

```python
cognito.UserPool(self, "myuserpool",
    # ...
    user_invitation=cognito.UserInvitationConfig(
        email_subject="Invite to join our awesome app!",
        email_body="Hello {username}, you have been invited to join our awesome app! Your temporary password is {####}",
        sms_message="Hello {username}, your temporary password for our awesome app is {####}"
    )
)
```

All email subjects, bodies and SMS messages for both invitation and verification support Cognito's message templating.
Learn more about [message templates
here](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-templates.html).

### Sign In

Users registering or signing in into your application can do so with multiple identifiers. There are 4 options
available:

* `username`: Allow signing in using the one time immutable user name that the user chose at the time of sign up.
* `email`: Allow signing in using the email address that is associated with the account.
* `phone`: Allow signing in using the phone number that is associated with the account.
* `preferredUsername`: Allow signing in with an alternate user name that the user can change at any time. However, this
  is not available if the `username` option is not chosen.

The following code sets up a user pool so that the user can sign in with either their username or their email address -

```python
cognito.UserPool(self, "myuserpool",
    # ...
    # ...
    sign_in_aliases=cognito.SignInAliases(
        username=True,
        email=True
    )
)
```

User pools can either be configured so that user name is primary sign in form, but also allows for the other three to be
used additionally; or it can be configured so that email and/or phone numbers are the only ways a user can register and
sign in. Read more about this
[here](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-aliases-settings).

⚠️ The Cognito service prevents changing the `signInAlias` property for an existing user pool.

To match with 'Option 1' in the above link, with a verified email, `signInAliases` should be set to
`{ username: true, email: true }`. To match with 'Option 2' in the above link with both a verified
email and phone number, this property should be set to `{ email: true, phone: true }`.

Cognito recommends that email and phone number be automatically verified, if they are one of the sign in methods for
the user pool. Read more about that
[here](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-aliases).
The CDK does this by default, when email and/or phone number are specified as part of `signInAliases`. This can be
overridden by specifying the `autoVerify` property.

The following code snippet sets up only email as a sign in alias, but both email and phone number to be auto-verified.

```python
cognito.UserPool(self, "myuserpool",
    # ...
    # ...
    sign_in_aliases=cognito.SignInAliases(username=True, email=True),
    auto_verify=cognito.AutoVerifiedAttrs(email=True, phone=True)
)
```

A user pool can optionally ignore case when evaluating sign-ins. When `signInCaseSensitive` is false, Cognito will not
check the capitalization of the alias when signing in. Default is true.

### Attributes

Attributes represent the various properties of each user that's collected and stored in the user pool. Cognito
provides a set of standard attributes that are available for all user pools. Users are allowed to select any of these
standard attributes to be required. Users will not be able to sign up to the user pool without providing the required
attributes. Besides these, additional attributes can be further defined, and are known as custom attributes.

Learn more on [attributes in Cognito's
documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html).

The following code configures a user pool with two standard attributes (name and address) as required and mutable, and adds
four custom attributes.

```python
cognito.UserPool(self, "myuserpool",
    # ...
    standard_attributes=cognito.StandardAttributes(
        fullname=cognito.StandardAttribute(
            required=True,
            mutable=False
        ),
        address=cognito.StandardAttribute(
            required=False,
            mutable=True
        )
    ),
    custom_attributes={
        "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
        "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
        "is_employee": cognito.BooleanAttribute(mutable=True),
        "joined_on": cognito.DateTimeAttribute()
    }
)
```

As shown in the code snippet, there are data types that are available for custom attributes. The 'String' and 'Number'
data types allow for further constraints on their length and values, respectively.

Custom attributes cannot be marked as required.

All custom attributes share the property `mutable` that specifies whether the value of the attribute can be changed.
The default value is `false`.

User pools come with two 'built-in' attributes - `email_verified` and `phone_number_verified`. These cannot be
configured (required-ness or mutability) as part of user pool creation. However, user pool administrators can modify
them for specific users using the [AdminUpdateUserAttributes API](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html).

### Security

Cognito sends various messages to its users via SMS, for different actions, ranging from account verification to
marketing. In order to send SMS messages, Cognito needs an IAM role that it can assume, with permissions that allow it
to send SMS messages.

By default, the CDK looks at all of the specified properties (and their defaults when not explicitly specified) and
automatically creates an SMS role, when needed. For example, if MFA second factor by SMS is enabled, the CDK will
create a new role. The `smsRole` property can be used to specify the user supplied role that should be used instead.
Additionally, the property `enableSmsRole` can be used to override the CDK's default behaviour to either enable or
suppress automatic role creation.

```python
pool_sms_role = iam.Role(self, "userpoolsmsrole",
    assumed_by=iam.ServicePrincipal("foo")
)

cognito.UserPool(self, "myuserpool",
    # ...
    sms_role=pool_sms_role,
    sms_role_external_id="c87467be-4f34-11ea-b77f-2e728ce88125"
)
```

When the `smsRole` property is specified, the `smsRoleExternalId` may also be specified. The value of
`smsRoleExternalId` will be used as the `sts:ExternalId` when the Cognito service assumes the role. In turn, the role's
assume role policy should be configured to accept this value as the ExternalId. Learn more about [ExternalId
here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html).

#### Multi-factor Authentication (MFA)

User pools can be configured to enable multi-factor authentication (MFA). It can either be turned off, set to optional
or made required. Setting MFA to optional means that individual users can choose to enable it.
Additionally, the MFA code can be sent either via SMS text message or via a time-based software token.
See the [documentation on MFA](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html) to
learn more.

The following code snippet marks MFA for the user pool as required. This means that all users are required to
configure an MFA token and use it for sign in. It also allows for the users to use both SMS based MFA, as well,
[time-based one time password
(TOTP)](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html).

```python
cognito.UserPool(self, "myuserpool",
    # ...
    mfa=cognito.Mfa.REQUIRED,
    mfa_second_factor=cognito.MfaSecondFactor(
        sms=True,
        otp=True
    )
)
```

User pools can be configured with policies around a user's password. This includes the password length and the
character sets that they must contain.

Further to this, it can also be configured with the validity of the auto-generated temporary password. A temporary
password is generated by the user pool either when an admin signs up a user or when a password reset is requested.
The validity of this password dictates how long to give the user to use this password before expiring it.

The following code snippet configures these properties -

```python
cognito.UserPool(self, "myuserpool",
    # ...
    password_policy=cognito.PasswordPolicy(
        min_length=12,
        require_lowercase=True,
        require_uppercase=True,
        require_digits=True,
        require_symbols=True,
        temp_password_validity=Duration.days(3)
    )
)
```

Note that, `tempPasswordValidity` can be specified only in whole days. Specifying fractional days would throw an error.

#### Account Recovery Settings

User pools can be configured on which method a user should use when recovering the password for their account. This
can either be email and/or SMS. Read more at [Recovering User Accounts](https://docs.aws.amazon.com/cognito/latest/developerguide/how-to-recover-a-user-account.html)

```python
cognito.UserPool(self, "UserPool",
    # ...
    account_recovery=cognito.AccountRecovery.EMAIL_ONLY
)
```

The default for account recovery is by phone if available and by email otherwise.
A user will not be allowed to reset their password via phone if they are also using it for MFA.

### Emails

Cognito sends emails to users in the user pool, when particular actions take place, such as welcome emails, invitation
emails, password resets, etc. The address from which these emails are sent can be configured on the user pool.
Read more at [Email settings for User Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-email.html).

By default, user pools are configured to use Cognito's built in email capability, which will send emails
from `no-reply@verificationemail.com`. If you want to use a custom email address you can configure
Cognito to send emails through Amazon SES, which is detailed below.

```python
cognito.UserPool(self, "myuserpool",
    email=cognito.UserPoolEmail.with_cognito("support@myawesomeapp.com")
)
```

For typical production environments, the default email limit is below the required delivery volume.
To enable a higher delivery volume, you can configure the UserPool to send emails through Amazon SES. To do
so, follow the steps in the [Cognito Developer Guide](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-email.html#user-pool-email-developer)
to verify an email address, move the account out of the SES sandbox, and grant Cognito email permissions via an
authorization policy.

Once the SES setup is complete, the UserPool can be configured to use the SES email.

```python
cognito.UserPool(self, "myuserpool",
    email=cognito.UserPoolEmail.with_sES(
        from_email="noreply@myawesomeapp.com",
        from_name="Awesome App",
        reply_to="support@myawesomeapp.com"
    )
)
```

Sending emails through SES requires that SES be configured (as described above) in a valid SES region.
If the UserPool is being created in a different region, `sesRegion` must be used to specify the correct SES region.

```python
cognito.UserPool(self, "myuserpool",
    email=cognito.UserPoolEmail.with_sES(
        ses_region="us-east-1",
        from_email="noreply@myawesomeapp.com",
        from_name="Awesome App",
        reply_to="support@myawesomeapp.com"
    )
)
```

### Device Tracking

User pools can be configured to track devices that users have logged in to.
Read more at [Device Tracking](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-device-tracking.html)

```python
cognito.UserPool(self, "myuserpool",
    # ...
    device_tracking=cognito.DeviceTracking(
        challenge_required_on_new_device=True,
        device_only_remembered_on_user_prompt=True
    )
)
```

The default is to not track devices.

### Lambda Triggers

User pools can be configured such that AWS Lambda functions can be triggered when certain user operations or actions
occur, such as, sign up, user confirmation, sign in, etc. They can also be used to add custom authentication
challenges, user migrations and custom verification messages. Learn more about triggers at [User Pool Workflows with
Triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html).

Lambda triggers can either be specified as part of the `UserPool` initialization, or it can be added later, via methods
on the construct, as so -

```python
auth_challenge_fn = lambda_.Function(self, "authChallengeFn",
    runtime=lambda_.Runtime.NODEJS_12_X,
    handler="index.handler",
    code=lambda_.Code.from_asset(path.join(__dirname, "path/to/asset"))
)

userpool = cognito.UserPool(self, "myuserpool",
    # ...
    lambda_triggers=cognito.UserPoolTriggers(
        create_auth_challenge=auth_challenge_fn
    )
)

userpool.add_trigger(cognito.UserPoolOperation.USER_MIGRATION, lambda_.Function(self, "userMigrationFn",
    runtime=lambda_.Runtime.NODEJS_12_X,
    handler="index.handler",
    code=lambda_.Code.from_asset(path.join(__dirname, "path/to/asset"))
))
```

The following table lists the set of triggers available, and their corresponding method to add it to the user pool.
For more information on the function of these triggers and how to configure them, read [User Pool Workflows with
Triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html).

#### Trigger Permissions

The `function.attachToRolePolicy()` API can be used to add additional IAM permissions to the lambda trigger
as necessary.

⚠️ Using the `attachToRolePolicy` API to provide permissions to your user pool will result in a circular dependency. See [aws/aws-cdk#7016](https://github.com/aws/aws-cdk/issues/7016).
Error message when running `cdk synth` or `cdk deploy`:

> Circular dependency between resources: [pool056F3F7E, fnPostAuthFnCognitoA630A2B1, ...]

To work around the circular dependency issue, use the `attachInlinePolicy()` API instead, as shown below.

```python
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
```

### Importing User Pools

Any user pool that has been created outside of this stack, can be imported into the CDK app. Importing a user pool
allows for it to be used in other parts of the CDK app that reference an `IUserPool`. However, imported user pools have
limited configurability. As a rule of thumb, none of the properties that are part of the
[`AWS::Cognito::UserPool`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html)
CloudFormation resource can be configured.

User pools can be imported either using their id via the `UserPool.fromUserPoolId()`, or by using their ARN, via the
`UserPool.fromUserPoolArn()` API.

```python
awesome_pool = cognito.UserPool.from_user_pool_id(self, "awesome-user-pool", "us-east-1_oiuR12Abd")

other_awesome_pool = cognito.UserPool.from_user_pool_arn(self, "other-awesome-user-pool", "arn:aws:cognito-idp:eu-west-1:123456789012:userpool/us-east-1_mtRyYQ14D")
```

### Identity Providers

Users that are part of a user pool can sign in either directly through a user pool, or federate through a third-party
identity provider. Once configured, the Cognito backend will take care of integrating with the third-party provider.
Read more about [Adding User Pool Sign-in Through a Third
Party](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-identity-federation.html).

The following third-party identity providers are currently supported in the CDK -

* [Login With Amazon](https://developer.amazon.com/apps-and-games/login-with-amazon)
* [Facebook Login](https://developers.facebook.com/docs/facebook-login/)
* [Google Login](https://developers.google.com/identity/sign-in/web/sign-in)
* [Sign In With Apple](https://developer.apple.com/sign-in-with-apple/get-started/)

The following code configures a user pool to federate with the third party provider, 'Login with Amazon'. The identity
provider needs to be configured with a set of credentials that the Cognito backend can use to federate with the
third-party identity provider.

```python
userpool = cognito.UserPool(self, "Pool")

provider = cognito.UserPoolIdentityProviderAmazon(self, "Amazon",
    client_id="amzn-client-id",
    client_secret="amzn-client-secret",
    user_pool=userpool
)
```

Attribute mapping allows mapping attributes provided by the third-party identity providers to [standard and custom
attributes](#Attributes) of the user pool. Learn more about [Specifying Identity Provider Attribute Mappings for Your
User Pool](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html).

The following code shows how different attributes provided by 'Login With Amazon' can be mapped to standard and custom
user pool attributes.

```python
userpool = cognito.UserPool(self, "Pool")

cognito.UserPoolIdentityProviderAmazon(self, "Amazon",
    client_id="amzn-client-id",
    client_secret="amzn-client-secret",
    user_pool=userpool,
    attribute_mapping=cognito.AttributeMapping(
        email=cognito.ProviderAttribute.AMAZON_EMAIL,
        website=cognito.ProviderAttribute.other("url"),  # use other() when an attribute is not pre-defined in the CDK
        custom={
            # custom user pool attributes go here
            "unique_id": cognito.ProviderAttribute.AMAZON_USER_ID
        }
    )
)
```

### App Clients

An app is an entity within a user pool that has permission to call unauthenticated APIs (APIs that do not have an
authenticated user), such as APIs to register, sign in, and handle forgotten passwords. To call these APIs, you need an
app client ID and an optional client secret. Read [Configuring a User Pool App
Client](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html) to learn more.

The following code creates an app client and retrieves the client id -

```python
pool = cognito.UserPool(self, "pool")
client = pool.add_client("customer-app-client")
client_id = client.user_pool_client_id
```

Existing app clients can be imported into the CDK app using the `UserPoolClient.fromUserPoolClientId()` API. For new
and imported user pools, clients can also be created via the `UserPoolClient` constructor, as so -

```python
imported_pool = cognito.UserPool.from_user_pool_id(self, "imported-pool", "us-east-1_oiuR12Abd")
cognito.UserPoolClient(self, "customer-app-client",
    user_pool=imported_pool
)
```

Clients can be configured with authentication flows. Authentication flows allow users on a client to be authenticated
with a user pool. Cognito user pools provide several different types of authentication, such as, SRP (Secure
Remote Password) authentication, username-and-password authentication, etc. Learn more about this at [UserPool Authentication
Flow](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html).

The following code configures a client to use both SRP and username-and-password authentication -

```python
pool = cognito.UserPool(self, "pool")
pool.add_client("app-client",
    auth_flows=cognito.AuthFlow(
        user_password=True,
        user_srp=True
    )
)
```

Custom authentication protocols can be configured by setting the `custom` property under `authFlow` and defining lambda
functions for the corresponding user pool [triggers](#lambda-triggers). Learn more at [Custom Authentication
Flow](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html#amazon-cognito-user-pools-custom-authentication-flow).

In addition to these authentication mechanisms, Cognito user pools also support using OAuth 2.0 framework for
authenticating users. User pool clients can be configured with OAuth 2.0 authorization flows and scopes. Learn more
about the [OAuth 2.0 authorization framework](https://tools.ietf.org/html/rfc6749) and [Cognito user pool's
implementation of
OAuth2.0](https://aws.amazon.com/blogs/mobile/understanding-amazon-cognito-user-pool-oauth-2-0-grants/).

The following code configures an app client with the authorization code grant flow and registers the the app's welcome
page as a callback (or redirect) URL. It also configures the access token scope to 'openid'. All of these concepts can
be found in the [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749).

```python
pool = cognito.UserPool(self, "Pool")
pool.add_client("app-client",
    o_auth=cognito.OAuthSettings(
        flows=cognito.OAuthFlows(
            authorization_code_grant=True
        ),
        scopes=[cognito.OAuthScope.OPENID],
        callback_urls=["https://my-app-domain.com/welcome"],
        logout_urls=["https://my-app-domain.com/signin"]
    )
)
```

An app client can be configured to prevent user existence errors. This
instructs the Cognito authentication API to return generic authentication
failure responses instead of an UserNotFoundException. By default, the flag
is not set, which means the CloudFormation default (false) will be used. See the
[documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html)
for the full details on the behavior of this flag.

```python
pool = cognito.UserPool(self, "Pool")
pool.add_client("app-client",
    prevent_user_existence_errors=True
)
```

All identity providers created in the CDK app are automatically registered into the corresponding user pool. All app
clients created in the CDK have all of the identity providers enabled by default. The 'Cognito' identity provider,
that allows users to register and sign in directly with the Cognito user pool, is also enabled by default.
Alternatively, the list of supported identity providers for a client can be explicitly specified -

```python
pool = cognito.UserPool(self, "Pool")
pool.add_client("app-client",
    # ...
    supported_identity_providers=[cognito.UserPoolClientIdentityProvider.AMAZON, cognito.UserPoolClientIdentityProvider.COGNITO
    ]
)
```

If the identity provider and the app client are created in the same stack, specify the dependency between both constructs to
make sure that the identity provider already exists when the app client will be created. The app client cannot handle the
dependency to the identity provider automatically because the client does not have access to the provider's construct.

```python
pool = cognito.UserPool(self, "Pool")
provider = cognito.UserPoolIdentityProviderAmazon(self, "Amazon",
    user_pool=pool,
    client_id="amzn-client-id",
    client_secret="amzn-client-secret"
)

client = pool.add_client("app-client",
    # ...
    supported_identity_providers=[cognito.UserPoolClientIdentityProvider.AMAZON
    ]
)

client.node.add_dependency(provider)
```

In accordance with the OIDC open standard, Cognito user pool clients provide access tokens, ID tokens and refresh tokens.
More information is available at [Using Tokens with User Pools](https://docs.aws.amazon.com/en_us/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html).
The expiration time for these tokens can be configured as shown below.

```python
pool = cognito.UserPool(self, "Pool")
pool.add_client("app-client",
    # ...
    access_token_validity=Duration.minutes(60),
    id_token_validity=Duration.minutes(60),
    refresh_token_validity=Duration.days(30)
)
```

Clients can (and should) be allowed to read and write relevant user attributes only. Usually every client can be allowed to
read the `given_name` attribute but not every client should be allowed to set the `email_verified` attribute.
The same criteria applies for both standard and custom attributes, more info is available at
[Attribute Permissions and Scopes](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-attribute-permissions-and-scopes).
The default behaviour is to allow read and write permissions on all attributes. The following code shows how this can be
configured for a client.

```python
pool = cognito.UserPool(self, "Pool")

client_write_attributes = (cognito.ClientAttributes()).with_standard_attributes(fullname=True, email=True).with_custom_attributes("favouritePizza", "favouriteBeverage")

client_read_attributes = client_write_attributes.with_standard_attributes(email_verified=True).with_custom_attributes("pointsEarned")

pool.add_client("app-client",
    # ...
    read_attributes=client_read_attributes,
    write_attributes=client_write_attributes
)
```

[Token revocation](https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html)
can be configured to be able to revoke refresh tokens in app clients. By default, token revocation is enabled for new user
pools. The property can be used to enable the token revocation in existing app clients or to change the default behavior.

```python
pool = cognito.UserPool(self, "Pool")
pool.add_client("app-client",
    # ...
    enable_token_revocation=True
)
```

### Resource Servers

A resource server is a server for access-protected resources. It handles authenticated requests from an app that has an
access token. See [Defining Resource
Servers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html)
for more information.

An application may choose to model custom permissions via OAuth. Resource Servers provide this capability via custom scopes
that are attached to an app client. The following example sets up a resource server for the 'users' resource for two different
app clients and configures the clients to use these scopes.

```python
pool = cognito.UserPool(self, "Pool")

read_only_scope = cognito.ResourceServerScope(scope_name="read", scope_description="Read-only access")
full_access_scope = cognito.ResourceServerScope(scope_name="*", scope_description="Full access")

user_server = pool.add_resource_server("ResourceServer",
    identifier="users",
    scopes=[read_only_scope, full_access_scope]
)

read_only_client = pool.add_client("read-only-client",
    # ...
    o_auth=cognito.OAuthSettings(
        # ...
        scopes=[cognito.OAuthScope.resource_server(user_server, read_only_scope)]
    )
)

full_access_client = pool.add_client("full-access-client",
    # ...
    o_auth=cognito.OAuthSettings(
        # ...
        scopes=[cognito.OAuthScope.resource_server(user_server, full_access_scope)]
    )
)
```

### Domains

After setting up an [app client](#app-clients), the address for the user pool's sign-up and sign-in webpages can be
configured using domains. There are two ways to set up a domain - either the Amazon Cognito hosted domain can be chosen
with an available domain prefix, or a custom domain name can be chosen. The custom domain must be one that is already
owned, and whose certificate is registered in AWS Certificate Manager.

The following code sets up a user pool domain in Amazon Cognito hosted domain with the prefix 'my-awesome-app', and
another domain with the custom domain 'user.myapp.com' -

```python
pool = cognito.UserPool(self, "Pool")

pool.add_domain("CognitoDomain",
    cognito_domain=cognito.CognitoDomainOptions(
        domain_prefix="my-awesome-app"
    )
)

certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/11-3336f1-44483d-adc7-9cd375c5169d"

domain_cert = certificatemanager.Certificate.from_certificate_arn(self, "domainCert", certificate_arn)
pool.add_domain("CustomDomain",
    custom_domain=cognito.CustomDomainOptions(
        domain_name="user.myapp.com",
        certificate=domain_cert
    )
)
```

Read more about [Using the Amazon Cognito
Domain](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain-prefix.html) and [Using Your Own
Domain](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-add-custom-domain.html).

The `signInUrl()` methods returns the fully qualified URL to the login page for the user pool. This page comes from the
hosted UI configured with Cognito. Learn more at [Hosted UI with the Amazon Cognito
Console](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-integration.html#cognito-user-pools-create-an-app-integration).

```python
userpool = cognito.UserPool(self, "UserPool")
client = userpool.add_client("Client",
    # ...
    o_auth=cognito.OAuthSettings(
        flows=cognito.OAuthFlows(
            implicit_code_grant=True
        ),
        callback_urls=["https://myapp.com/home", "https://myapp.com/users"
        ]
    )
)
domain = userpool.add_domain("Domain")
sign_in_url = domain.sign_in_url(client,
    redirect_uri="https://myapp.com/home"
)
```

Existing domains can be imported into CDK apps using `UserPoolDomain.fromDomainName()` API

```python
my_user_pool_domain = cognito.UserPoolDomain.from_domain_name(self, "my-user-pool-domain", "domain-name")
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
    Duration as _Duration_4839e8c3,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    IResource as _IResource_c80c4260,
    RemovalPolicy as _RemovalPolicy_9f93c814,
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_certificatemanager import ICertificate as _ICertificate_c194c70b
from ..aws_iam import IRole as _IRole_235f5d8e
from ..aws_kms import IKey as _IKey_5f11635f
from ..aws_lambda import IFunction as _IFunction_6adb0ab8


@jsii.enum(jsii_type="aws-cdk-lib.aws_cognito.AccountRecovery")
class AccountRecovery(enum.Enum):
    '''How will a user be able to recover their account?

    When a user forgets their password, they can have a code sent to their verified email or verified phone to recover their account.
    You can choose the preferred way to send codes below.
    We recommend not allowing phone to be used for both password resets and multi-factor authentication (MFA).

    :see: https://docs.aws.amazon.com/cognito/latest/developerguide/how-to-recover-a-user-account.html
    :exampleMetadata: infused

    Example::

        cognito.UserPool(self, "UserPool",
            # ...
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY
        )
    '''

    EMAIL_AND_PHONE_WITHOUT_MFA = "EMAIL_AND_PHONE_WITHOUT_MFA"
    '''Email if available, otherwise phone, but don’t allow a user to reset their password via phone if they are also using it for MFA.'''
    PHONE_WITHOUT_MFA_AND_EMAIL = "PHONE_WITHOUT_MFA_AND_EMAIL"
    '''Phone if available, otherwise email, but don’t allow a user to reset their password via phone if they are also using it for MFA.'''
    EMAIL_ONLY = "EMAIL_ONLY"
    '''Email only.'''
    PHONE_ONLY_WITHOUT_MFA = "PHONE_ONLY_WITHOUT_MFA"
    '''Phone only, but don’t allow a user to reset their password via phone if they are also using it for MFA.'''
    PHONE_AND_EMAIL = "PHONE_AND_EMAIL"
    '''(Not Recommended) Phone if available, otherwise email, and do allow a user to reset their password via phone if they are also using it for MFA.'''
    NONE = "NONE"
    '''None – users will have to contact an administrator to reset their passwords.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.AttributeMapping",
    jsii_struct_bases=[],
    name_mapping={
        "address": "address",
        "birthdate": "birthdate",
        "custom": "custom",
        "email": "email",
        "family_name": "familyName",
        "fullname": "fullname",
        "gender": "gender",
        "given_name": "givenName",
        "last_update_time": "lastUpdateTime",
        "locale": "locale",
        "middle_name": "middleName",
        "nickname": "nickname",
        "phone_number": "phoneNumber",
        "preferred_username": "preferredUsername",
        "profile_page": "profilePage",
        "profile_picture": "profilePicture",
        "timezone": "timezone",
        "website": "website",
    },
)
class AttributeMapping:
    def __init__(
        self,
        *,
        address: typing.Optional["ProviderAttribute"] = None,
        birthdate: typing.Optional["ProviderAttribute"] = None,
        custom: typing.Optional[typing.Mapping[builtins.str, "ProviderAttribute"]] = None,
        email: typing.Optional["ProviderAttribute"] = None,
        family_name: typing.Optional["ProviderAttribute"] = None,
        fullname: typing.Optional["ProviderAttribute"] = None,
        gender: typing.Optional["ProviderAttribute"] = None,
        given_name: typing.Optional["ProviderAttribute"] = None,
        last_update_time: typing.Optional["ProviderAttribute"] = None,
        locale: typing.Optional["ProviderAttribute"] = None,
        middle_name: typing.Optional["ProviderAttribute"] = None,
        nickname: typing.Optional["ProviderAttribute"] = None,
        phone_number: typing.Optional["ProviderAttribute"] = None,
        preferred_username: typing.Optional["ProviderAttribute"] = None,
        profile_page: typing.Optional["ProviderAttribute"] = None,
        profile_picture: typing.Optional["ProviderAttribute"] = None,
        timezone: typing.Optional["ProviderAttribute"] = None,
        website: typing.Optional["ProviderAttribute"] = None,
    ) -> None:
        '''The mapping of user pool attributes to the attributes provided by the identity providers.

        :param address: The user's postal address is a required attribute. Default: - not mapped
        :param birthdate: The user's birthday. Default: - not mapped
        :param custom: Specify custom attribute mapping here and mapping for any standard attributes not supported yet. Default: - no custom attribute mapping
        :param email: The user's e-mail address. Default: - not mapped
        :param family_name: The surname or last name of user. Default: - not mapped
        :param fullname: The user's full name in displayable form. Default: - not mapped
        :param gender: The user's gender. Default: - not mapped
        :param given_name: The user's first name or give name. Default: - not mapped
        :param last_update_time: Time, the user's information was last updated. Default: - not mapped
        :param locale: The user's locale. Default: - not mapped
        :param middle_name: The user's middle name. Default: - not mapped
        :param nickname: The user's nickname or casual name. Default: - not mapped
        :param phone_number: The user's telephone number. Default: - not mapped
        :param preferred_username: The user's preferred username. Default: - not mapped
        :param profile_page: The URL to the user's profile page. Default: - not mapped
        :param profile_picture: The URL to the user's profile picture. Default: - not mapped
        :param timezone: The user's time zone. Default: - not mapped
        :param website: The URL to the user's web page or blog. Default: - not mapped

        :exampleMetadata: infused

        Example::

            userpool = cognito.UserPool(self, "Pool")
            
            cognito.UserPoolIdentityProviderAmazon(self, "Amazon",
                client_id="amzn-client-id",
                client_secret="amzn-client-secret",
                user_pool=userpool,
                attribute_mapping=cognito.AttributeMapping(
                    email=cognito.ProviderAttribute.AMAZON_EMAIL,
                    website=cognito.ProviderAttribute.other("url"),  # use other() when an attribute is not pre-defined in the CDK
                    custom={
                        # custom user pool attributes go here
                        "unique_id": cognito.ProviderAttribute.AMAZON_USER_ID
                    }
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if address is not None:
            self._values["address"] = address
        if birthdate is not None:
            self._values["birthdate"] = birthdate
        if custom is not None:
            self._values["custom"] = custom
        if email is not None:
            self._values["email"] = email
        if family_name is not None:
            self._values["family_name"] = family_name
        if fullname is not None:
            self._values["fullname"] = fullname
        if gender is not None:
            self._values["gender"] = gender
        if given_name is not None:
            self._values["given_name"] = given_name
        if last_update_time is not None:
            self._values["last_update_time"] = last_update_time
        if locale is not None:
            self._values["locale"] = locale
        if middle_name is not None:
            self._values["middle_name"] = middle_name
        if nickname is not None:
            self._values["nickname"] = nickname
        if phone_number is not None:
            self._values["phone_number"] = phone_number
        if preferred_username is not None:
            self._values["preferred_username"] = preferred_username
        if profile_page is not None:
            self._values["profile_page"] = profile_page
        if profile_picture is not None:
            self._values["profile_picture"] = profile_picture
        if timezone is not None:
            self._values["timezone"] = timezone
        if website is not None:
            self._values["website"] = website

    @builtins.property
    def address(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's postal address is a required attribute.

        :default: - not mapped
        '''
        result = self._values.get("address")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def birthdate(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's birthday.

        :default: - not mapped
        '''
        result = self._values.get("birthdate")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def custom(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, "ProviderAttribute"]]:
        '''Specify custom attribute mapping here and mapping for any standard attributes not supported yet.

        :default: - no custom attribute mapping
        '''
        result = self._values.get("custom")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, "ProviderAttribute"]], result)

    @builtins.property
    def email(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's e-mail address.

        :default: - not mapped
        '''
        result = self._values.get("email")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def family_name(self) -> typing.Optional["ProviderAttribute"]:
        '''The surname or last name of user.

        :default: - not mapped
        '''
        result = self._values.get("family_name")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def fullname(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's full name in displayable form.

        :default: - not mapped
        '''
        result = self._values.get("fullname")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def gender(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's gender.

        :default: - not mapped
        '''
        result = self._values.get("gender")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def given_name(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's first name or give name.

        :default: - not mapped
        '''
        result = self._values.get("given_name")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def last_update_time(self) -> typing.Optional["ProviderAttribute"]:
        '''Time, the user's information was last updated.

        :default: - not mapped
        '''
        result = self._values.get("last_update_time")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def locale(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's locale.

        :default: - not mapped
        '''
        result = self._values.get("locale")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def middle_name(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's middle name.

        :default: - not mapped
        '''
        result = self._values.get("middle_name")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def nickname(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's nickname or casual name.

        :default: - not mapped
        '''
        result = self._values.get("nickname")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def phone_number(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's telephone number.

        :default: - not mapped
        '''
        result = self._values.get("phone_number")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def preferred_username(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's preferred username.

        :default: - not mapped
        '''
        result = self._values.get("preferred_username")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def profile_page(self) -> typing.Optional["ProviderAttribute"]:
        '''The URL to the user's profile page.

        :default: - not mapped
        '''
        result = self._values.get("profile_page")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def profile_picture(self) -> typing.Optional["ProviderAttribute"]:
        '''The URL to the user's profile picture.

        :default: - not mapped
        '''
        result = self._values.get("profile_picture")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def timezone(self) -> typing.Optional["ProviderAttribute"]:
        '''The user's time zone.

        :default: - not mapped
        '''
        result = self._values.get("timezone")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    @builtins.property
    def website(self) -> typing.Optional["ProviderAttribute"]:
        '''The URL to the user's web page or blog.

        :default: - not mapped
        '''
        result = self._values.get("website")
        return typing.cast(typing.Optional["ProviderAttribute"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AttributeMapping(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.AuthFlow",
    jsii_struct_bases=[],
    name_mapping={
        "admin_user_password": "adminUserPassword",
        "custom": "custom",
        "user_password": "userPassword",
        "user_srp": "userSrp",
    },
)
class AuthFlow:
    def __init__(
        self,
        *,
        admin_user_password: typing.Optional[builtins.bool] = None,
        custom: typing.Optional[builtins.bool] = None,
        user_password: typing.Optional[builtins.bool] = None,
        user_srp: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Types of authentication flow.

        :param admin_user_password: Enable admin based user password authentication flow. Default: false
        :param custom: Enable custom authentication flow. Default: false
        :param user_password: Enable auth using username & password. Default: false
        :param user_srp: Enable SRP based authentication. Default: false

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html
        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "pool")
            pool.add_client("app-client",
                auth_flows=cognito.AuthFlow(
                    user_password=True,
                    user_srp=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if admin_user_password is not None:
            self._values["admin_user_password"] = admin_user_password
        if custom is not None:
            self._values["custom"] = custom
        if user_password is not None:
            self._values["user_password"] = user_password
        if user_srp is not None:
            self._values["user_srp"] = user_srp

    @builtins.property
    def admin_user_password(self) -> typing.Optional[builtins.bool]:
        '''Enable admin based user password authentication flow.

        :default: false
        '''
        result = self._values.get("admin_user_password")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def custom(self) -> typing.Optional[builtins.bool]:
        '''Enable custom authentication flow.

        :default: false
        '''
        result = self._values.get("custom")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def user_password(self) -> typing.Optional[builtins.bool]:
        '''Enable auth using username & password.

        :default: false
        '''
        result = self._values.get("user_password")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def user_srp(self) -> typing.Optional[builtins.bool]:
        '''Enable SRP based authentication.

        :default: false
        '''
        result = self._values.get("user_srp")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AuthFlow(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.AutoVerifiedAttrs",
    jsii_struct_bases=[],
    name_mapping={"email": "email", "phone": "phone"},
)
class AutoVerifiedAttrs:
    def __init__(
        self,
        *,
        email: typing.Optional[builtins.bool] = None,
        phone: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Attributes that can be automatically verified for users in a user pool.

        :param email: Whether the email address of the user should be auto verified at sign up. Note: If both ``email`` and ``phone`` is set, Cognito only verifies the phone number. To also verify email, see here - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html Default: - true, if email is turned on for ``signIn``. false, otherwise.
        :param phone: Whether the phone number of the user should be auto verified at sign up. Default: - true, if phone is turned on for ``signIn``. false, otherwise.

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                # ...
                sign_in_aliases=cognito.SignInAliases(username=True, email=True),
                auto_verify=cognito.AutoVerifiedAttrs(email=True, phone=True)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if email is not None:
            self._values["email"] = email
        if phone is not None:
            self._values["phone"] = phone

    @builtins.property
    def email(self) -> typing.Optional[builtins.bool]:
        '''Whether the email address of the user should be auto verified at sign up.

        Note: If both ``email`` and ``phone`` is set, Cognito only verifies the phone number. To also verify email, see here -
        https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html

        :default: - true, if email is turned on for ``signIn``. false, otherwise.
        '''
        result = self._values.get("email")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def phone(self) -> typing.Optional[builtins.bool]:
        '''Whether the phone number of the user should be auto verified at sign up.

        :default: - true, if phone is turned on for ``signIn``. false, otherwise.
        '''
        result = self._values.get("phone")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AutoVerifiedAttrs(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnIdentityPool(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPool",
):
    '''A CloudFormation ``AWS::Cognito::IdentityPool``.

    The ``AWS::Cognito::IdentityPool`` resource creates an Amazon Cognito identity pool.

    To avoid deleting the resource accidentally from AWS CloudFormation , use `DeletionPolicy Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html>`_ and the `UpdateReplacePolicy Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatereplacepolicy.html>`_ to retain the resource on deletion or replacement.

    :cloudformationResource: AWS::Cognito::IdentityPool
    :exampleMetadata: infused
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html

    Example::

        import aws_cdk.aws_cognito as cognito
        
        # my_provider: iam.OpenIdConnectProvider
        
        cognito.CfnIdentityPool(self, "IdentityPool",
            open_id_connect_provider_arns=[my_provider.open_id_connect_provider_arn],
            # And the other properties for your identity pool
            allow_unauthenticated_identities=False
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        allow_unauthenticated_identities: typing.Union[builtins.bool, _IResolvable_da3f097b],
        allow_classic_flow: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        cognito_events: typing.Any = None,
        cognito_identity_providers: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnIdentityPool.CognitoIdentityProviderProperty", _IResolvable_da3f097b]]]] = None,
        cognito_streams: typing.Optional[typing.Union["CfnIdentityPool.CognitoStreamsProperty", _IResolvable_da3f097b]] = None,
        developer_provider_name: typing.Optional[builtins.str] = None,
        identity_pool_name: typing.Optional[builtins.str] = None,
        open_id_connect_provider_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        push_sync: typing.Optional[typing.Union["CfnIdentityPool.PushSyncProperty", _IResolvable_da3f097b]] = None,
        saml_provider_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        supported_login_providers: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::IdentityPool``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param allow_unauthenticated_identities: Specifies whether the identity pool supports unauthenticated logins.
        :param allow_classic_flow: Enables the Basic (Classic) authentication flow.
        :param cognito_events: The events to configure.
        :param cognito_identity_providers: The Amazon Cognito user pools and their client IDs.
        :param cognito_streams: Configuration options for configuring Amazon Cognito streams.
        :param developer_provider_name: The "domain" Amazon Cognito uses when referencing your users. This name acts as a placeholder that allows your backend and the Amazon Cognito service to communicate about the developer provider. For the ``DeveloperProviderName`` , you can use letters and periods (.), underscores (_), and dashes (-). *Minimum length* : 1 *Maximum length* : 100
        :param identity_pool_name: The name of your Amazon Cognito identity pool. *Minimum length* : 1 *Maximum length* : 128 *Pattern* : ``[\\w\\s+=,.@-]+``
        :param open_id_connect_provider_arns: The Amazon Resource Names (ARNs) of the OpenID connect providers.
        :param push_sync: The configuration options to be applied to the identity pool.
        :param saml_provider_arns: The Amazon Resource Names (ARNs) of the Security Assertion Markup Language (SAML) providers.
        :param supported_login_providers: Key-value pairs that map provider names to provider app IDs.
        '''
        props = CfnIdentityPoolProps(
            allow_unauthenticated_identities=allow_unauthenticated_identities,
            allow_classic_flow=allow_classic_flow,
            cognito_events=cognito_events,
            cognito_identity_providers=cognito_identity_providers,
            cognito_streams=cognito_streams,
            developer_provider_name=developer_provider_name,
            identity_pool_name=identity_pool_name,
            open_id_connect_provider_arns=open_id_connect_provider_arns,
            push_sync=push_sync,
            saml_provider_arns=saml_provider_arns,
            supported_login_providers=supported_login_providers,
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
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the Amazon Cognito identity pool, returned as a string.

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allowUnauthenticatedIdentities")
    def allow_unauthenticated_identities(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Specifies whether the identity pool supports unauthenticated logins.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-allowunauthenticatedidentities
        '''
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], jsii.get(self, "allowUnauthenticatedIdentities"))

    @allow_unauthenticated_identities.setter
    def allow_unauthenticated_identities(
        self,
        value: typing.Union[builtins.bool, _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "allowUnauthenticatedIdentities", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cognitoEvents")
    def cognito_events(self) -> typing.Any:
        '''The events to configure.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-cognitoevents
        '''
        return typing.cast(typing.Any, jsii.get(self, "cognitoEvents"))

    @cognito_events.setter
    def cognito_events(self, value: typing.Any) -> None:
        jsii.set(self, "cognitoEvents", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="supportedLoginProviders")
    def supported_login_providers(self) -> typing.Any:
        '''Key-value pairs that map provider names to provider app IDs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-supportedloginproviders
        '''
        return typing.cast(typing.Any, jsii.get(self, "supportedLoginProviders"))

    @supported_login_providers.setter
    def supported_login_providers(self, value: typing.Any) -> None:
        jsii.set(self, "supportedLoginProviders", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allowClassicFlow")
    def allow_classic_flow(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables the Basic (Classic) authentication flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-allowclassicflow
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "allowClassicFlow"))

    @allow_classic_flow.setter
    def allow_classic_flow(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "allowClassicFlow", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cognitoIdentityProviders")
    def cognito_identity_providers(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIdentityPool.CognitoIdentityProviderProperty", _IResolvable_da3f097b]]]]:
        '''The Amazon Cognito user pools and their client IDs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-cognitoidentityproviders
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIdentityPool.CognitoIdentityProviderProperty", _IResolvable_da3f097b]]]], jsii.get(self, "cognitoIdentityProviders"))

    @cognito_identity_providers.setter
    def cognito_identity_providers(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIdentityPool.CognitoIdentityProviderProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "cognitoIdentityProviders", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cognitoStreams")
    def cognito_streams(
        self,
    ) -> typing.Optional[typing.Union["CfnIdentityPool.CognitoStreamsProperty", _IResolvable_da3f097b]]:
        '''Configuration options for configuring Amazon Cognito streams.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-cognitostreams
        '''
        return typing.cast(typing.Optional[typing.Union["CfnIdentityPool.CognitoStreamsProperty", _IResolvable_da3f097b]], jsii.get(self, "cognitoStreams"))

    @cognito_streams.setter
    def cognito_streams(
        self,
        value: typing.Optional[typing.Union["CfnIdentityPool.CognitoStreamsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "cognitoStreams", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="developerProviderName")
    def developer_provider_name(self) -> typing.Optional[builtins.str]:
        '''The "domain" Amazon Cognito uses when referencing your users.

        This name acts as a placeholder that allows your backend and the Amazon Cognito service to communicate about the developer provider. For the ``DeveloperProviderName`` , you can use letters and periods (.), underscores (_), and dashes (-).

        *Minimum length* : 1

        *Maximum length* : 100

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-developerprovidername
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "developerProviderName"))

    @developer_provider_name.setter
    def developer_provider_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "developerProviderName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="identityPoolName")
    def identity_pool_name(self) -> typing.Optional[builtins.str]:
        '''The name of your Amazon Cognito identity pool.

        *Minimum length* : 1

        *Maximum length* : 128

        *Pattern* : ``[\\w\\s+=,.@-]+``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-identitypoolname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "identityPoolName"))

    @identity_pool_name.setter
    def identity_pool_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "identityPoolName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProviderArns")
    def open_id_connect_provider_arns(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''The Amazon Resource Names (ARNs) of the OpenID connect providers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-openidconnectproviderarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "openIdConnectProviderArns"))

    @open_id_connect_provider_arns.setter
    def open_id_connect_provider_arns(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "openIdConnectProviderArns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="pushSync")
    def push_sync(
        self,
    ) -> typing.Optional[typing.Union["CfnIdentityPool.PushSyncProperty", _IResolvable_da3f097b]]:
        '''The configuration options to be applied to the identity pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-pushsync
        '''
        return typing.cast(typing.Optional[typing.Union["CfnIdentityPool.PushSyncProperty", _IResolvable_da3f097b]], jsii.get(self, "pushSync"))

    @push_sync.setter
    def push_sync(
        self,
        value: typing.Optional[typing.Union["CfnIdentityPool.PushSyncProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "pushSync", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="samlProviderArns")
    def saml_provider_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The Amazon Resource Names (ARNs) of the Security Assertion Markup Language (SAML) providers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-samlproviderarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "samlProviderArns"))

    @saml_provider_arns.setter
    def saml_provider_arns(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "samlProviderArns", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPool.CognitoIdentityProviderProperty",
        jsii_struct_bases=[],
        name_mapping={
            "client_id": "clientId",
            "provider_name": "providerName",
            "server_side_token_check": "serverSideTokenCheck",
        },
    )
    class CognitoIdentityProviderProperty:
        def __init__(
            self,
            *,
            client_id: typing.Optional[builtins.str] = None,
            provider_name: typing.Optional[builtins.str] = None,
            server_side_token_check: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``CognitoIdentityProvider`` is a property of the `AWS::Cognito::IdentityPool <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html>`_ resource that represents an Amazon Cognito user pool and its client ID.

            :param client_id: The client ID for the Amazon Cognito user pool.
            :param provider_name: The provider name for an Amazon Cognito user pool. For example: ``cognito-idp.us-east-2.amazonaws.com/us-east-2_123456789`` .
            :param server_side_token_check: TRUE if server-side token validation is enabled for the identity provider’s token. After you set the ``ServerSideTokenCheck`` to TRUE for an identity pool, that identity pool checks with the integrated user pools to make sure the user has not been globally signed out or deleted before the identity pool provides an OIDC token or AWS credentials for the user. If the user is signed out or deleted, the identity pool returns a 400 Not Authorized error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitoidentityprovider.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                cognito_identity_provider_property = cognito.CfnIdentityPool.CognitoIdentityProviderProperty(
                    client_id="clientId",
                    provider_name="providerName",
                    server_side_token_check=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if client_id is not None:
                self._values["client_id"] = client_id
            if provider_name is not None:
                self._values["provider_name"] = provider_name
            if server_side_token_check is not None:
                self._values["server_side_token_check"] = server_side_token_check

        @builtins.property
        def client_id(self) -> typing.Optional[builtins.str]:
            '''The client ID for the Amazon Cognito user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitoidentityprovider.html#cfn-cognito-identitypool-cognitoidentityprovider-clientid
            '''
            result = self._values.get("client_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def provider_name(self) -> typing.Optional[builtins.str]:
            '''The provider name for an Amazon Cognito user pool.

            For example: ``cognito-idp.us-east-2.amazonaws.com/us-east-2_123456789`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitoidentityprovider.html#cfn-cognito-identitypool-cognitoidentityprovider-providername
            '''
            result = self._values.get("provider_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def server_side_token_check(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''TRUE if server-side token validation is enabled for the identity provider’s token.

            After you set the ``ServerSideTokenCheck`` to TRUE for an identity pool, that identity pool checks with the integrated user pools to make sure the user has not been globally signed out or deleted before the identity pool provides an OIDC token or AWS credentials for the user.

            If the user is signed out or deleted, the identity pool returns a 400 Not Authorized error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitoidentityprovider.html#cfn-cognito-identitypool-cognitoidentityprovider-serversidetokencheck
            '''
            result = self._values.get("server_side_token_check")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CognitoIdentityProviderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPool.CognitoStreamsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "role_arn": "roleArn",
            "streaming_status": "streamingStatus",
            "stream_name": "streamName",
        },
    )
    class CognitoStreamsProperty:
        def __init__(
            self,
            *,
            role_arn: typing.Optional[builtins.str] = None,
            streaming_status: typing.Optional[builtins.str] = None,
            stream_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``CognitoStreams`` is a property of the `AWS::Cognito::IdentityPool <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html>`_ resource that defines configuration options for Amazon Cognito streams.

            :param role_arn: The Amazon Resource Name (ARN) of the role Amazon Cognito can assume to publish to the stream. This role must grant access to Amazon Cognito (cognito-sync) to invoke ``PutRecord`` on your Amazon Cognito stream.
            :param streaming_status: Status of the Amazon Cognito streams. Valid values are: ``ENABLED`` or ``DISABLED`` .
            :param stream_name: The name of the Amazon Cognito stream to receive updates. This stream must be in the developer's account and in the same Region as the identity pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitostreams.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                cognito_streams_property = cognito.CfnIdentityPool.CognitoStreamsProperty(
                    role_arn="roleArn",
                    streaming_status="streamingStatus",
                    stream_name="streamName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if role_arn is not None:
                self._values["role_arn"] = role_arn
            if streaming_status is not None:
                self._values["streaming_status"] = streaming_status
            if stream_name is not None:
                self._values["stream_name"] = stream_name

        @builtins.property
        def role_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the role Amazon Cognito can assume to publish to the stream.

            This role must grant access to Amazon Cognito (cognito-sync) to invoke ``PutRecord`` on your Amazon Cognito stream.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitostreams.html#cfn-cognito-identitypool-cognitostreams-rolearn
            '''
            result = self._values.get("role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def streaming_status(self) -> typing.Optional[builtins.str]:
            '''Status of the Amazon Cognito streams.

            Valid values are: ``ENABLED`` or ``DISABLED`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitostreams.html#cfn-cognito-identitypool-cognitostreams-streamingstatus
            '''
            result = self._values.get("streaming_status")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def stream_name(self) -> typing.Optional[builtins.str]:
            '''The name of the Amazon Cognito stream to receive updates.

            This stream must be in the developer's account and in the same Region as the identity pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitostreams.html#cfn-cognito-identitypool-cognitostreams-streamname
            '''
            result = self._values.get("stream_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CognitoStreamsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPool.PushSyncProperty",
        jsii_struct_bases=[],
        name_mapping={"application_arns": "applicationArns", "role_arn": "roleArn"},
    )
    class PushSyncProperty:
        def __init__(
            self,
            *,
            application_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
            role_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``PushSync`` is a property of the `AWS::Cognito::IdentityPool <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html>`_ resource that defines the configuration options to be applied to an Amazon Cognito identity pool.

            :param application_arns: The ARNs of the Amazon SNS platform applications that could be used by clients.
            :param role_arn: An IAM role configured to allow Amazon Cognito to call Amazon SNS on behalf of the developer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-pushsync.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                push_sync_property = cognito.CfnIdentityPool.PushSyncProperty(
                    application_arns=["applicationArns"],
                    role_arn="roleArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if application_arns is not None:
                self._values["application_arns"] = application_arns
            if role_arn is not None:
                self._values["role_arn"] = role_arn

        @builtins.property
        def application_arns(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The ARNs of the Amazon SNS platform applications that could be used by clients.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-pushsync.html#cfn-cognito-identitypool-pushsync-applicationarns
            '''
            result = self._values.get("application_arns")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def role_arn(self) -> typing.Optional[builtins.str]:
            '''An IAM role configured to allow Amazon Cognito to call Amazon SNS on behalf of the developer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-pushsync.html#cfn-cognito-identitypool-pushsync-rolearn
            '''
            result = self._values.get("role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PushSyncProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPoolProps",
    jsii_struct_bases=[],
    name_mapping={
        "allow_unauthenticated_identities": "allowUnauthenticatedIdentities",
        "allow_classic_flow": "allowClassicFlow",
        "cognito_events": "cognitoEvents",
        "cognito_identity_providers": "cognitoIdentityProviders",
        "cognito_streams": "cognitoStreams",
        "developer_provider_name": "developerProviderName",
        "identity_pool_name": "identityPoolName",
        "open_id_connect_provider_arns": "openIdConnectProviderArns",
        "push_sync": "pushSync",
        "saml_provider_arns": "samlProviderArns",
        "supported_login_providers": "supportedLoginProviders",
    },
)
class CfnIdentityPoolProps:
    def __init__(
        self,
        *,
        allow_unauthenticated_identities: typing.Union[builtins.bool, _IResolvable_da3f097b],
        allow_classic_flow: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        cognito_events: typing.Any = None,
        cognito_identity_providers: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnIdentityPool.CognitoIdentityProviderProperty, _IResolvable_da3f097b]]]] = None,
        cognito_streams: typing.Optional[typing.Union[CfnIdentityPool.CognitoStreamsProperty, _IResolvable_da3f097b]] = None,
        developer_provider_name: typing.Optional[builtins.str] = None,
        identity_pool_name: typing.Optional[builtins.str] = None,
        open_id_connect_provider_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        push_sync: typing.Optional[typing.Union[CfnIdentityPool.PushSyncProperty, _IResolvable_da3f097b]] = None,
        saml_provider_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        supported_login_providers: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnIdentityPool``.

        :param allow_unauthenticated_identities: Specifies whether the identity pool supports unauthenticated logins.
        :param allow_classic_flow: Enables the Basic (Classic) authentication flow.
        :param cognito_events: The events to configure.
        :param cognito_identity_providers: The Amazon Cognito user pools and their client IDs.
        :param cognito_streams: Configuration options for configuring Amazon Cognito streams.
        :param developer_provider_name: The "domain" Amazon Cognito uses when referencing your users. This name acts as a placeholder that allows your backend and the Amazon Cognito service to communicate about the developer provider. For the ``DeveloperProviderName`` , you can use letters and periods (.), underscores (_), and dashes (-). *Minimum length* : 1 *Maximum length* : 100
        :param identity_pool_name: The name of your Amazon Cognito identity pool. *Minimum length* : 1 *Maximum length* : 128 *Pattern* : ``[\\w\\s+=,.@-]+``
        :param open_id_connect_provider_arns: The Amazon Resource Names (ARNs) of the OpenID connect providers.
        :param push_sync: The configuration options to be applied to the identity pool.
        :param saml_provider_arns: The Amazon Resource Names (ARNs) of the Security Assertion Markup Language (SAML) providers.
        :param supported_login_providers: Key-value pairs that map provider names to provider app IDs.

        :exampleMetadata: infused
        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html

        Example::

            import aws_cdk.aws_cognito as cognito
            
            # my_provider: iam.OpenIdConnectProvider
            
            cognito.CfnIdentityPool(self, "IdentityPool",
                open_id_connect_provider_arns=[my_provider.open_id_connect_provider_arn],
                # And the other properties for your identity pool
                allow_unauthenticated_identities=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "allow_unauthenticated_identities": allow_unauthenticated_identities,
        }
        if allow_classic_flow is not None:
            self._values["allow_classic_flow"] = allow_classic_flow
        if cognito_events is not None:
            self._values["cognito_events"] = cognito_events
        if cognito_identity_providers is not None:
            self._values["cognito_identity_providers"] = cognito_identity_providers
        if cognito_streams is not None:
            self._values["cognito_streams"] = cognito_streams
        if developer_provider_name is not None:
            self._values["developer_provider_name"] = developer_provider_name
        if identity_pool_name is not None:
            self._values["identity_pool_name"] = identity_pool_name
        if open_id_connect_provider_arns is not None:
            self._values["open_id_connect_provider_arns"] = open_id_connect_provider_arns
        if push_sync is not None:
            self._values["push_sync"] = push_sync
        if saml_provider_arns is not None:
            self._values["saml_provider_arns"] = saml_provider_arns
        if supported_login_providers is not None:
            self._values["supported_login_providers"] = supported_login_providers

    @builtins.property
    def allow_unauthenticated_identities(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Specifies whether the identity pool supports unauthenticated logins.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-allowunauthenticatedidentities
        '''
        result = self._values.get("allow_unauthenticated_identities")
        assert result is not None, "Required property 'allow_unauthenticated_identities' is missing"
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

    @builtins.property
    def allow_classic_flow(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Enables the Basic (Classic) authentication flow.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-allowclassicflow
        '''
        result = self._values.get("allow_classic_flow")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def cognito_events(self) -> typing.Any:
        '''The events to configure.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-cognitoevents
        '''
        result = self._values.get("cognito_events")
        return typing.cast(typing.Any, result)

    @builtins.property
    def cognito_identity_providers(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnIdentityPool.CognitoIdentityProviderProperty, _IResolvable_da3f097b]]]]:
        '''The Amazon Cognito user pools and their client IDs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-cognitoidentityproviders
        '''
        result = self._values.get("cognito_identity_providers")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnIdentityPool.CognitoIdentityProviderProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def cognito_streams(
        self,
    ) -> typing.Optional[typing.Union[CfnIdentityPool.CognitoStreamsProperty, _IResolvable_da3f097b]]:
        '''Configuration options for configuring Amazon Cognito streams.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-cognitostreams
        '''
        result = self._values.get("cognito_streams")
        return typing.cast(typing.Optional[typing.Union[CfnIdentityPool.CognitoStreamsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def developer_provider_name(self) -> typing.Optional[builtins.str]:
        '''The "domain" Amazon Cognito uses when referencing your users.

        This name acts as a placeholder that allows your backend and the Amazon Cognito service to communicate about the developer provider. For the ``DeveloperProviderName`` , you can use letters and periods (.), underscores (_), and dashes (-).

        *Minimum length* : 1

        *Maximum length* : 100

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-developerprovidername
        '''
        result = self._values.get("developer_provider_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def identity_pool_name(self) -> typing.Optional[builtins.str]:
        '''The name of your Amazon Cognito identity pool.

        *Minimum length* : 1

        *Maximum length* : 128

        *Pattern* : ``[\\w\\s+=,.@-]+``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-identitypoolname
        '''
        result = self._values.get("identity_pool_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def open_id_connect_provider_arns(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''The Amazon Resource Names (ARNs) of the OpenID connect providers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-openidconnectproviderarns
        '''
        result = self._values.get("open_id_connect_provider_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def push_sync(
        self,
    ) -> typing.Optional[typing.Union[CfnIdentityPool.PushSyncProperty, _IResolvable_da3f097b]]:
        '''The configuration options to be applied to the identity pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-pushsync
        '''
        result = self._values.get("push_sync")
        return typing.cast(typing.Optional[typing.Union[CfnIdentityPool.PushSyncProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def saml_provider_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The Amazon Resource Names (ARNs) of the Security Assertion Markup Language (SAML) providers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-samlproviderarns
        '''
        result = self._values.get("saml_provider_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def supported_login_providers(self) -> typing.Any:
        '''Key-value pairs that map provider names to provider app IDs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypool.html#cfn-cognito-identitypool-supportedloginproviders
        '''
        result = self._values.get("supported_login_providers")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnIdentityPoolProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnIdentityPoolRoleAttachment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPoolRoleAttachment",
):
    '''A CloudFormation ``AWS::Cognito::IdentityPoolRoleAttachment``.

    The ``AWS::Cognito::IdentityPoolRoleAttachment`` resource manages the role configuration for an Amazon Cognito identity pool.

    :cloudformationResource: AWS::Cognito::IdentityPoolRoleAttachment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        # roles: Any
        
        cfn_identity_pool_role_attachment = cognito.CfnIdentityPoolRoleAttachment(self, "MyCfnIdentityPoolRoleAttachment",
            identity_pool_id="identityPoolId",
        
            # the properties below are optional
            role_mappings={
                "role_mappings_key": cognito.CfnIdentityPoolRoleAttachment.RoleMappingProperty(
                    type="type",
        
                    # the properties below are optional
                    ambiguous_role_resolution="ambiguousRoleResolution",
                    identity_provider="identityProvider",
                    rules_configuration=cognito.CfnIdentityPoolRoleAttachment.RulesConfigurationTypeProperty(
                        rules=[cognito.CfnIdentityPoolRoleAttachment.MappingRuleProperty(
                            claim="claim",
                            match_type="matchType",
                            role_arn="roleArn",
                            value="value"
                        )]
                    )
                )
            },
            roles=roles
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        identity_pool_id: builtins.str,
        role_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnIdentityPoolRoleAttachment.RoleMappingProperty", _IResolvable_da3f097b]]]] = None,
        roles: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::IdentityPoolRoleAttachment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param identity_pool_id: An identity pool ID in the format ``REGION:GUID`` .
        :param role_mappings: How users for a specific identity provider are mapped to roles. This is a string to the ``RoleMapping`` object map. The string identifies the identity provider. For example: ``graph.facebook.com`` or ``cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefghi:app_client_id`` . If the ``IdentityProvider`` field isn't provided in this object, the string is used as the identity provider name. For more information, see the `RoleMapping property <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html>`_ .
        :param roles: The map of the roles associated with this pool. For a given role, the key is either "authenticated" or "unauthenticated". The value is the role ARN.
        '''
        props = CfnIdentityPoolRoleAttachmentProps(
            identity_pool_id=identity_pool_id, role_mappings=role_mappings, roles=roles
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
    @jsii.member(jsii_name="identityPoolId")
    def identity_pool_id(self) -> builtins.str:
        '''An identity pool ID in the format ``REGION:GUID`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html#cfn-cognito-identitypoolroleattachment-identitypoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "identityPoolId"))

    @identity_pool_id.setter
    def identity_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "identityPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roles")
    def roles(self) -> typing.Any:
        '''The map of the roles associated with this pool.

        For a given role, the key is either "authenticated" or "unauthenticated". The value is the role ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html#cfn-cognito-identitypoolroleattachment-roles
        '''
        return typing.cast(typing.Any, jsii.get(self, "roles"))

    @roles.setter
    def roles(self, value: typing.Any) -> None:
        jsii.set(self, "roles", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleMappings")
    def role_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnIdentityPoolRoleAttachment.RoleMappingProperty", _IResolvable_da3f097b]]]]:
        '''How users for a specific identity provider are mapped to roles.

        This is a string to the ``RoleMapping`` object map. The string identifies the identity provider. For example: ``graph.facebook.com`` or ``cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefghi:app_client_id`` .

        If the ``IdentityProvider`` field isn't provided in this object, the string is used as the identity provider name.

        For more information, see the `RoleMapping property <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html#cfn-cognito-identitypoolroleattachment-rolemappings
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnIdentityPoolRoleAttachment.RoleMappingProperty", _IResolvable_da3f097b]]]], jsii.get(self, "roleMappings"))

    @role_mappings.setter
    def role_mappings(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnIdentityPoolRoleAttachment.RoleMappingProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "roleMappings", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPoolRoleAttachment.MappingRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "claim": "claim",
            "match_type": "matchType",
            "role_arn": "roleArn",
            "value": "value",
        },
    )
    class MappingRuleProperty:
        def __init__(
            self,
            *,
            claim: builtins.str,
            match_type: builtins.str,
            role_arn: builtins.str,
            value: builtins.str,
        ) -> None:
            '''Defines how to map a claim to a role ARN.

            :param claim: The claim name that must be present in the token. For example: "isAdmin" or "paid".
            :param match_type: The match condition that specifies how closely the claim value in the IdP token must match ``Value`` . Valid values are: ``Equals`` , ``Contains`` , ``StartsWith`` , and ``NotEqual`` .
            :param role_arn: The Amazon Resource Name (ARN) of the role.
            :param value: A brief string that the claim must match. For example, "paid" or "yes".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-mappingrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                mapping_rule_property = cognito.CfnIdentityPoolRoleAttachment.MappingRuleProperty(
                    claim="claim",
                    match_type="matchType",
                    role_arn="roleArn",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "claim": claim,
                "match_type": match_type,
                "role_arn": role_arn,
                "value": value,
            }

        @builtins.property
        def claim(self) -> builtins.str:
            '''The claim name that must be present in the token.

            For example: "isAdmin" or "paid".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-mappingrule.html#cfn-cognito-identitypoolroleattachment-mappingrule-claim
            '''
            result = self._values.get("claim")
            assert result is not None, "Required property 'claim' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def match_type(self) -> builtins.str:
            '''The match condition that specifies how closely the claim value in the IdP token must match ``Value`` .

            Valid values are: ``Equals`` , ``Contains`` , ``StartsWith`` , and ``NotEqual`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-mappingrule.html#cfn-cognito-identitypoolroleattachment-mappingrule-matchtype
            '''
            result = self._values.get("match_type")
            assert result is not None, "Required property 'match_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def role_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the role.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-mappingrule.html#cfn-cognito-identitypoolroleattachment-mappingrule-rolearn
            '''
            result = self._values.get("role_arn")
            assert result is not None, "Required property 'role_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''A brief string that the claim must match.

            For example, "paid" or "yes".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-mappingrule.html#cfn-cognito-identitypoolroleattachment-mappingrule-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MappingRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPoolRoleAttachment.RoleMappingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "type": "type",
            "ambiguous_role_resolution": "ambiguousRoleResolution",
            "identity_provider": "identityProvider",
            "rules_configuration": "rulesConfiguration",
        },
    )
    class RoleMappingProperty:
        def __init__(
            self,
            *,
            type: builtins.str,
            ambiguous_role_resolution: typing.Optional[builtins.str] = None,
            identity_provider: typing.Optional[builtins.str] = None,
            rules_configuration: typing.Optional[typing.Union["CfnIdentityPoolRoleAttachment.RulesConfigurationTypeProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``RoleMapping`` is a property of the `AWS::Cognito::IdentityPoolRoleAttachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html>`_ resource that defines the role-mapping attributes of an Amazon Cognito identity pool.

            :param type: The role-mapping type. ``Token`` uses ``cognito:roles`` and ``cognito:preferred_role`` claims from the Amazon Cognito identity provider token to map groups to roles. ``Rules`` attempts to match claims from the token to map to a role. Valid values are ``Token`` or ``Rules`` .
            :param ambiguous_role_resolution: Specifies the action to be taken if either no rules match the claim value for the Rules type, or there is no ``cognito:preferred_role`` claim and there are multiple ``cognito:roles`` matches for the Token type. If you specify Token or Rules as the Type, AmbiguousRoleResolution is required. Valid values are ``AuthenticatedRole`` or ``Deny`` .
            :param identity_provider: Identifier for the identity provider for which the role is mapped. For example: ``graph.facebook.com`` or ``cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefghi:app_client_id (http://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefghi:app_client_id)`` . This is the identity provider that is used by the user for authentication. If the identity provider property isn't provided, the key of the entry in the ``RoleMappings`` map is used as the identity provider.
            :param rules_configuration: The rules to be used for mapping users to roles. If you specify "Rules" as the role-mapping type, RulesConfiguration is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                role_mapping_property = cognito.CfnIdentityPoolRoleAttachment.RoleMappingProperty(
                    type="type",
                
                    # the properties below are optional
                    ambiguous_role_resolution="ambiguousRoleResolution",
                    identity_provider="identityProvider",
                    rules_configuration=cognito.CfnIdentityPoolRoleAttachment.RulesConfigurationTypeProperty(
                        rules=[cognito.CfnIdentityPoolRoleAttachment.MappingRuleProperty(
                            claim="claim",
                            match_type="matchType",
                            role_arn="roleArn",
                            value="value"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "type": type,
            }
            if ambiguous_role_resolution is not None:
                self._values["ambiguous_role_resolution"] = ambiguous_role_resolution
            if identity_provider is not None:
                self._values["identity_provider"] = identity_provider
            if rules_configuration is not None:
                self._values["rules_configuration"] = rules_configuration

        @builtins.property
        def type(self) -> builtins.str:
            '''The role-mapping type.

            ``Token`` uses ``cognito:roles`` and ``cognito:preferred_role`` claims from the Amazon Cognito identity provider token to map groups to roles. ``Rules`` attempts to match claims from the token to map to a role.

            Valid values are ``Token`` or ``Rules`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html#cfn-cognito-identitypoolroleattachment-rolemapping-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ambiguous_role_resolution(self) -> typing.Optional[builtins.str]:
            '''Specifies the action to be taken if either no rules match the claim value for the Rules type, or there is no ``cognito:preferred_role`` claim and there are multiple ``cognito:roles`` matches for the Token type.

            If you specify Token or Rules as the Type, AmbiguousRoleResolution is required.

            Valid values are ``AuthenticatedRole`` or ``Deny`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html#cfn-cognito-identitypoolroleattachment-rolemapping-ambiguousroleresolution
            '''
            result = self._values.get("ambiguous_role_resolution")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def identity_provider(self) -> typing.Optional[builtins.str]:
            '''Identifier for the identity provider for which the role is mapped.

            For example: ``graph.facebook.com`` or ``cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefghi:app_client_id (http://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefghi:app_client_id)`` . This is the identity provider that is used by the user for authentication.

            If the identity provider property isn't provided, the key of the entry in the ``RoleMappings`` map is used as the identity provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html#cfn-cognito-identitypoolroleattachment-rolemapping-identityprovider
            '''
            result = self._values.get("identity_provider")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def rules_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnIdentityPoolRoleAttachment.RulesConfigurationTypeProperty", _IResolvable_da3f097b]]:
            '''The rules to be used for mapping users to roles.

            If you specify "Rules" as the role-mapping type, RulesConfiguration is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html#cfn-cognito-identitypoolroleattachment-rolemapping-rulesconfiguration
            '''
            result = self._values.get("rules_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnIdentityPoolRoleAttachment.RulesConfigurationTypeProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RoleMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPoolRoleAttachment.RulesConfigurationTypeProperty",
        jsii_struct_bases=[],
        name_mapping={"rules": "rules"},
    )
    class RulesConfigurationTypeProperty:
        def __init__(
            self,
            *,
            rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnIdentityPoolRoleAttachment.MappingRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''``RulesConfigurationType`` is a subproperty of the `RoleMapping <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html>`_ property that defines the rules to be used for mapping users to roles.

            :param rules: The rules. You can specify up to 25 rules per identity provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rulesconfigurationtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                rules_configuration_type_property = cognito.CfnIdentityPoolRoleAttachment.RulesConfigurationTypeProperty(
                    rules=[cognito.CfnIdentityPoolRoleAttachment.MappingRuleProperty(
                        claim="claim",
                        match_type="matchType",
                        role_arn="roleArn",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "rules": rules,
            }

        @builtins.property
        def rules(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIdentityPoolRoleAttachment.MappingRuleProperty", _IResolvable_da3f097b]]]:
            '''The rules.

            You can specify up to 25 rules per identity provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rulesconfigurationtype.html#cfn-cognito-identitypoolroleattachment-rulesconfigurationtype-rules
            '''
            result = self._values.get("rules")
            assert result is not None, "Required property 'rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIdentityPoolRoleAttachment.MappingRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RulesConfigurationTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnIdentityPoolRoleAttachmentProps",
    jsii_struct_bases=[],
    name_mapping={
        "identity_pool_id": "identityPoolId",
        "role_mappings": "roleMappings",
        "roles": "roles",
    },
)
class CfnIdentityPoolRoleAttachmentProps:
    def __init__(
        self,
        *,
        identity_pool_id: builtins.str,
        role_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnIdentityPoolRoleAttachment.RoleMappingProperty, _IResolvable_da3f097b]]]] = None,
        roles: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnIdentityPoolRoleAttachment``.

        :param identity_pool_id: An identity pool ID in the format ``REGION:GUID`` .
        :param role_mappings: How users for a specific identity provider are mapped to roles. This is a string to the ``RoleMapping`` object map. The string identifies the identity provider. For example: ``graph.facebook.com`` or ``cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefghi:app_client_id`` . If the ``IdentityProvider`` field isn't provided in this object, the string is used as the identity provider name. For more information, see the `RoleMapping property <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html>`_ .
        :param roles: The map of the roles associated with this pool. For a given role, the key is either "authenticated" or "unauthenticated". The value is the role ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # roles: Any
            
            cfn_identity_pool_role_attachment_props = cognito.CfnIdentityPoolRoleAttachmentProps(
                identity_pool_id="identityPoolId",
            
                # the properties below are optional
                role_mappings={
                    "role_mappings_key": cognito.CfnIdentityPoolRoleAttachment.RoleMappingProperty(
                        type="type",
            
                        # the properties below are optional
                        ambiguous_role_resolution="ambiguousRoleResolution",
                        identity_provider="identityProvider",
                        rules_configuration=cognito.CfnIdentityPoolRoleAttachment.RulesConfigurationTypeProperty(
                            rules=[cognito.CfnIdentityPoolRoleAttachment.MappingRuleProperty(
                                claim="claim",
                                match_type="matchType",
                                role_arn="roleArn",
                                value="value"
                            )]
                        )
                    )
                },
                roles=roles
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "identity_pool_id": identity_pool_id,
        }
        if role_mappings is not None:
            self._values["role_mappings"] = role_mappings
        if roles is not None:
            self._values["roles"] = roles

    @builtins.property
    def identity_pool_id(self) -> builtins.str:
        '''An identity pool ID in the format ``REGION:GUID`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html#cfn-cognito-identitypoolroleattachment-identitypoolid
        '''
        result = self._values.get("identity_pool_id")
        assert result is not None, "Required property 'identity_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnIdentityPoolRoleAttachment.RoleMappingProperty, _IResolvable_da3f097b]]]]:
        '''How users for a specific identity provider are mapped to roles.

        This is a string to the ``RoleMapping`` object map. The string identifies the identity provider. For example: ``graph.facebook.com`` or ``cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdefghi:app_client_id`` .

        If the ``IdentityProvider`` field isn't provided in this object, the string is used as the identity provider name.

        For more information, see the `RoleMapping property <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypoolroleattachment-rolemapping.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html#cfn-cognito-identitypoolroleattachment-rolemappings
        '''
        result = self._values.get("role_mappings")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnIdentityPoolRoleAttachment.RoleMappingProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def roles(self) -> typing.Any:
        '''The map of the roles associated with this pool.

        For a given role, the key is either "authenticated" or "unauthenticated". The value is the role ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-identitypoolroleattachment.html#cfn-cognito-identitypoolroleattachment-roles
        '''
        result = self._values.get("roles")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnIdentityPoolRoleAttachmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPool(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool",
):
    '''A CloudFormation ``AWS::Cognito::UserPool``.

    The ``AWS::Cognito::UserPool`` resource creates an Amazon Cognito user pool. For more information on working with Amazon Cognito user pools, see `Amazon Cognito User Pools <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html>`_ and `CreateUserPool <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>`_ .

    :cloudformationResource: AWS::Cognito::UserPool
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        # user_pool_tags: Any
        
        cfn_user_pool = cognito.CfnUserPool(self, "MyCfnUserPool",
            account_recovery_setting=cognito.CfnUserPool.AccountRecoverySettingProperty(
                recovery_mechanisms=[cognito.CfnUserPool.RecoveryOptionProperty(
                    name="name",
                    priority=123
                )]
            ),
            admin_create_user_config=cognito.CfnUserPool.AdminCreateUserConfigProperty(
                allow_admin_create_user_only=False,
                invite_message_template=cognito.CfnUserPool.InviteMessageTemplateProperty(
                    email_message="emailMessage",
                    email_subject="emailSubject",
                    sms_message="smsMessage"
                ),
                unused_account_validity_days=123
            ),
            alias_attributes=["aliasAttributes"],
            auto_verified_attributes=["autoVerifiedAttributes"],
            device_configuration=cognito.CfnUserPool.DeviceConfigurationProperty(
                challenge_required_on_new_device=False,
                device_only_remembered_on_user_prompt=False
            ),
            email_configuration=cognito.CfnUserPool.EmailConfigurationProperty(
                configuration_set="configurationSet",
                email_sending_account="emailSendingAccount",
                from="from",
                reply_to_email_address="replyToEmailAddress",
                source_arn="sourceArn"
            ),
            email_verification_message="emailVerificationMessage",
            email_verification_subject="emailVerificationSubject",
            enabled_mfas=["enabledMfas"],
            lambda_config=cognito.CfnUserPool.LambdaConfigProperty(
                create_auth_challenge="createAuthChallenge",
                custom_email_sender=cognito.CfnUserPool.CustomEmailSenderProperty(
                    lambda_arn="lambdaArn",
                    lambda_version="lambdaVersion"
                ),
                custom_message="customMessage",
                custom_sms_sender=cognito.CfnUserPool.CustomSMSSenderProperty(
                    lambda_arn="lambdaArn",
                    lambda_version="lambdaVersion"
                ),
                define_auth_challenge="defineAuthChallenge",
                kms_key_id="kmsKeyId",
                post_authentication="postAuthentication",
                post_confirmation="postConfirmation",
                pre_authentication="preAuthentication",
                pre_sign_up="preSignUp",
                pre_token_generation="preTokenGeneration",
                user_migration="userMigration",
                verify_auth_challenge_response="verifyAuthChallengeResponse"
            ),
            mfa_configuration="mfaConfiguration",
            policies=cognito.CfnUserPool.PoliciesProperty(
                password_policy=cognito.CfnUserPool.PasswordPolicyProperty(
                    minimum_length=123,
                    require_lowercase=False,
                    require_numbers=False,
                    require_symbols=False,
                    require_uppercase=False,
                    temporary_password_validity_days=123
                )
            ),
            schema=[cognito.CfnUserPool.SchemaAttributeProperty(
                attribute_data_type="attributeDataType",
                developer_only_attribute=False,
                mutable=False,
                name="name",
                number_attribute_constraints=cognito.CfnUserPool.NumberAttributeConstraintsProperty(
                    max_value="maxValue",
                    min_value="minValue"
                ),
                required=False,
                string_attribute_constraints=cognito.CfnUserPool.StringAttributeConstraintsProperty(
                    max_length="maxLength",
                    min_length="minLength"
                )
            )],
            sms_authentication_message="smsAuthenticationMessage",
            sms_configuration=cognito.CfnUserPool.SmsConfigurationProperty(
                external_id="externalId",
                sns_caller_arn="snsCallerArn",
                sns_region="snsRegion"
            ),
            sms_verification_message="smsVerificationMessage",
            username_attributes=["usernameAttributes"],
            username_configuration=cognito.CfnUserPool.UsernameConfigurationProperty(
                case_sensitive=False
            ),
            user_pool_add_ons=cognito.CfnUserPool.UserPoolAddOnsProperty(
                advanced_security_mode="advancedSecurityMode"
            ),
            user_pool_name="userPoolName",
            user_pool_tags=user_pool_tags,
            verification_message_template=cognito.CfnUserPool.VerificationMessageTemplateProperty(
                default_email_option="defaultEmailOption",
                email_message="emailMessage",
                email_message_by_link="emailMessageByLink",
                email_subject="emailSubject",
                email_subject_by_link="emailSubjectByLink",
                sms_message="smsMessage"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        account_recovery_setting: typing.Optional[typing.Union["CfnUserPool.AccountRecoverySettingProperty", _IResolvable_da3f097b]] = None,
        admin_create_user_config: typing.Optional[typing.Union["CfnUserPool.AdminCreateUserConfigProperty", _IResolvable_da3f097b]] = None,
        alias_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
        auto_verified_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
        device_configuration: typing.Optional[typing.Union["CfnUserPool.DeviceConfigurationProperty", _IResolvable_da3f097b]] = None,
        email_configuration: typing.Optional[typing.Union["CfnUserPool.EmailConfigurationProperty", _IResolvable_da3f097b]] = None,
        email_verification_message: typing.Optional[builtins.str] = None,
        email_verification_subject: typing.Optional[builtins.str] = None,
        enabled_mfas: typing.Optional[typing.Sequence[builtins.str]] = None,
        lambda_config: typing.Optional[typing.Union["CfnUserPool.LambdaConfigProperty", _IResolvable_da3f097b]] = None,
        mfa_configuration: typing.Optional[builtins.str] = None,
        policies: typing.Optional[typing.Union["CfnUserPool.PoliciesProperty", _IResolvable_da3f097b]] = None,
        schema: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnUserPool.SchemaAttributeProperty", _IResolvable_da3f097b]]]] = None,
        sms_authentication_message: typing.Optional[builtins.str] = None,
        sms_configuration: typing.Optional[typing.Union["CfnUserPool.SmsConfigurationProperty", _IResolvable_da3f097b]] = None,
        sms_verification_message: typing.Optional[builtins.str] = None,
        username_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
        username_configuration: typing.Optional[typing.Union["CfnUserPool.UsernameConfigurationProperty", _IResolvable_da3f097b]] = None,
        user_pool_add_ons: typing.Optional[typing.Union["CfnUserPool.UserPoolAddOnsProperty", _IResolvable_da3f097b]] = None,
        user_pool_name: typing.Optional[builtins.str] = None,
        user_pool_tags: typing.Any = None,
        verification_message_template: typing.Optional[typing.Union["CfnUserPool.VerificationMessageTemplateProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPool``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param account_recovery_setting: Use this setting to define which verified available method a user can use to recover their password when they call ``ForgotPassword`` . It allows you to define a preferred method when a user has more than one method available. With this setting, SMS does not qualify for a valid password recovery mechanism if the user also has SMS MFA enabled. In the absence of this setting, Cognito uses the legacy behavior to determine the recovery method where SMS is preferred over email.
        :param admin_create_user_config: The configuration for creating a new user profile.
        :param alias_attributes: Attributes supported as an alias for this user pool. Possible values: *phone_number* , *email* , or *preferred_username* . .. epigraph:: This user pool property cannot be updated.
        :param auto_verified_attributes: The attributes to be auto-verified. Possible values: *email* , *phone_number* .
        :param device_configuration: The device configuration.
        :param email_configuration: The email configuration.
        :param email_verification_message: A string representing the email verification message. EmailVerificationMessage is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
        :param email_verification_subject: A string representing the email verification subject. EmailVerificationSubject is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
        :param enabled_mfas: Enables MFA on a specified user pool. To disable all MFAs after it has been enabled, set MfaConfiguration to “OFF” and remove EnabledMfas. MFAs can only be all disabled if MfaConfiguration is OFF. Once SMS_MFA is enabled, SMS_MFA can only be disabled by setting MfaConfiguration to “OFF”. Can be one of the following values: - ``SMS_MFA`` - Enables SMS MFA for the user pool. SMS_MFA can only be enabled if SMS configuration is provided. - ``SOFTWARE_TOKEN_MFA`` - Enables software token MFA for the user pool. Allowed values: ``SMS_MFA`` | ``SOFTWARE_TOKEN_MFA``
        :param lambda_config: The Lambda trigger configuration information for the new user pool. .. epigraph:: In a push model, event sources (such as Amazon S3 and custom applications) need permission to invoke a function. So you must make an extra call to add permission for these event sources to invoke your Lambda function. For more information on using the Lambda API to add permission, see `AddPermission <https://docs.aws.amazon.com/lambda/latest/dg/API_AddPermission.html>`_ . For adding permission using the AWS CLI , see `add-permission <https://docs.aws.amazon.com/cli/latest/reference/lambda/add-permission.html>`_ .
        :param mfa_configuration: The multi-factor (MFA) configuration. Valid values include:. - ``OFF`` MFA won't be used for any users. - ``ON`` MFA is required for all users to sign in. - ``OPTIONAL`` MFA will be required only for individual users who have an MFA factor activated.
        :param policies: The policy associated with a user pool.
        :param schema: The schema attributes for the new user pool. These attributes can be standard or custom attributes. .. epigraph:: During a user pool update, you can add new schema attributes but you cannot modify or delete an existing schema attribute.
        :param sms_authentication_message: A string representing the SMS authentication message.
        :param sms_configuration: The SMS configuration.
        :param sms_verification_message: A string representing the SMS verification message.
        :param username_attributes: Determines whether email addresses or phone numbers can be specified as user names when a user signs up. Possible values: ``phone_number`` or ``email`` . This user pool property cannot be updated.
        :param username_configuration: You can choose to set case sensitivity on the username input for the selected sign-in option. For example, when this is set to ``False`` , users will be able to sign in using either "username" or "Username". This configuration is immutable once it has been set.
        :param user_pool_add_ons: Enables advanced security risk detection. Set the key ``AdvancedSecurityMode`` to the value "AUDIT".
        :param user_pool_name: A string used to name the user pool.
        :param user_pool_tags: The tag keys and values to assign to the user pool. A tag is a label that you can use to categorize and manage user pools in different ways, such as by purpose, owner, environment, or other criteria.
        :param verification_message_template: The template for the verification message that the user sees when the app requests permission to access the user's information.
        '''
        props = CfnUserPoolProps(
            account_recovery_setting=account_recovery_setting,
            admin_create_user_config=admin_create_user_config,
            alias_attributes=alias_attributes,
            auto_verified_attributes=auto_verified_attributes,
            device_configuration=device_configuration,
            email_configuration=email_configuration,
            email_verification_message=email_verification_message,
            email_verification_subject=email_verification_subject,
            enabled_mfas=enabled_mfas,
            lambda_config=lambda_config,
            mfa_configuration=mfa_configuration,
            policies=policies,
            schema=schema,
            sms_authentication_message=sms_authentication_message,
            sms_configuration=sms_configuration,
            sms_verification_message=sms_verification_message,
            username_attributes=username_attributes,
            username_configuration=username_configuration,
            user_pool_add_ons=user_pool_add_ons,
            user_pool_name=user_pool_name,
            user_pool_tags=user_pool_tags,
            verification_message_template=verification_message_template,
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
        '''The Amazon Resource Name (ARN) of the user pool, such as ``arn:aws:cognito-idp:us-east-1:123412341234:userpool/us-east-1_123412341`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrProviderName")
    def attr_provider_name(self) -> builtins.str:
        '''The provider name of the Amazon Cognito user pool, specified as a ``String`` .

        :cloudformationAttribute: ProviderName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrProviderName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrProviderUrl")
    def attr_provider_url(self) -> builtins.str:
        '''The URL of the provider of the Amazon Cognito user pool, specified as a ``String`` .

        :cloudformationAttribute: ProviderURL
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrProviderUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tag keys and values to assign to the user pool.

        A tag is a label that you can use to categorize and manage user pools in different ways, such as by purpose, owner, environment, or other criteria.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-userpooltags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accountRecoverySetting")
    def account_recovery_setting(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.AccountRecoverySettingProperty", _IResolvable_da3f097b]]:
        '''Use this setting to define which verified available method a user can use to recover their password when they call ``ForgotPassword`` .

        It allows you to define a preferred method when a user has more than one method available. With this setting, SMS does not qualify for a valid password recovery mechanism if the user also has SMS MFA enabled. In the absence of this setting, Cognito uses the legacy behavior to determine the recovery method where SMS is preferred over email.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-accountrecoverysetting
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.AccountRecoverySettingProperty", _IResolvable_da3f097b]], jsii.get(self, "accountRecoverySetting"))

    @account_recovery_setting.setter
    def account_recovery_setting(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.AccountRecoverySettingProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "accountRecoverySetting", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="adminCreateUserConfig")
    def admin_create_user_config(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.AdminCreateUserConfigProperty", _IResolvable_da3f097b]]:
        '''The configuration for creating a new user profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-admincreateuserconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.AdminCreateUserConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "adminCreateUserConfig"))

    @admin_create_user_config.setter
    def admin_create_user_config(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.AdminCreateUserConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "adminCreateUserConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="aliasAttributes")
    def alias_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Attributes supported as an alias for this user pool. Possible values: *phone_number* , *email* , or *preferred_username* .

        .. epigraph::

           This user pool property cannot be updated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-aliasattributes
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "aliasAttributes"))

    @alias_attributes.setter
    def alias_attributes(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "aliasAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoVerifiedAttributes")
    def auto_verified_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The attributes to be auto-verified.

        Possible values: *email* , *phone_number* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-autoverifiedattributes
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "autoVerifiedAttributes"))

    @auto_verified_attributes.setter
    def auto_verified_attributes(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "autoVerifiedAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deviceConfiguration")
    def device_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.DeviceConfigurationProperty", _IResolvable_da3f097b]]:
        '''The device configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-deviceconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.DeviceConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "deviceConfiguration"))

    @device_configuration.setter
    def device_configuration(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.DeviceConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "deviceConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="emailConfiguration")
    def email_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.EmailConfigurationProperty", _IResolvable_da3f097b]]:
        '''The email configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-emailconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.EmailConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "emailConfiguration"))

    @email_configuration.setter
    def email_configuration(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.EmailConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "emailConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="emailVerificationMessage")
    def email_verification_message(self) -> typing.Optional[builtins.str]:
        '''A string representing the email verification message.

        EmailVerificationMessage is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-emailverificationmessage
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "emailVerificationMessage"))

    @email_verification_message.setter
    def email_verification_message(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "emailVerificationMessage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="emailVerificationSubject")
    def email_verification_subject(self) -> typing.Optional[builtins.str]:
        '''A string representing the email verification subject.

        EmailVerificationSubject is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-emailverificationsubject
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "emailVerificationSubject"))

    @email_verification_subject.setter
    def email_verification_subject(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "emailVerificationSubject", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enabledMfas")
    def enabled_mfas(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Enables MFA on a specified user pool.

        To disable all MFAs after it has been enabled, set MfaConfiguration to “OFF” and remove EnabledMfas. MFAs can only be all disabled if MfaConfiguration is OFF. Once SMS_MFA is enabled, SMS_MFA can only be disabled by setting MfaConfiguration to “OFF”. Can be one of the following values:

        - ``SMS_MFA`` - Enables SMS MFA for the user pool. SMS_MFA can only be enabled if SMS configuration is provided.
        - ``SOFTWARE_TOKEN_MFA`` - Enables software token MFA for the user pool.

        Allowed values: ``SMS_MFA`` | ``SOFTWARE_TOKEN_MFA``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-enabledmfas
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "enabledMfas"))

    @enabled_mfas.setter
    def enabled_mfas(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "enabledMfas", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lambdaConfig")
    def lambda_config(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.LambdaConfigProperty", _IResolvable_da3f097b]]:
        '''The Lambda trigger configuration information for the new user pool.

        .. epigraph::

           In a push model, event sources (such as Amazon S3 and custom applications) need permission to invoke a function. So you must make an extra call to add permission for these event sources to invoke your Lambda function.

           For more information on using the Lambda API to add permission, see `AddPermission <https://docs.aws.amazon.com/lambda/latest/dg/API_AddPermission.html>`_ .

           For adding permission using the AWS CLI , see `add-permission <https://docs.aws.amazon.com/cli/latest/reference/lambda/add-permission.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-lambdaconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.LambdaConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "lambdaConfig"))

    @lambda_config.setter
    def lambda_config(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.LambdaConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "lambdaConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="mfaConfiguration")
    def mfa_configuration(self) -> typing.Optional[builtins.str]:
        '''The multi-factor (MFA) configuration. Valid values include:.

        - ``OFF`` MFA won't be used for any users.
        - ``ON`` MFA is required for all users to sign in.
        - ``OPTIONAL`` MFA will be required only for individual users who have an MFA factor activated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-mfaconfiguration
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "mfaConfiguration"))

    @mfa_configuration.setter
    def mfa_configuration(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "mfaConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policies")
    def policies(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.PoliciesProperty", _IResolvable_da3f097b]]:
        '''The policy associated with a user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-policies
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.PoliciesProperty", _IResolvable_da3f097b]], jsii.get(self, "policies"))

    @policies.setter
    def policies(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.PoliciesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "policies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schema")
    def schema(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPool.SchemaAttributeProperty", _IResolvable_da3f097b]]]]:
        '''The schema attributes for the new user pool. These attributes can be standard or custom attributes.

        .. epigraph::

           During a user pool update, you can add new schema attributes but you cannot modify or delete an existing schema attribute.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-schema
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPool.SchemaAttributeProperty", _IResolvable_da3f097b]]]], jsii.get(self, "schema"))

    @schema.setter
    def schema(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPool.SchemaAttributeProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "schema", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="smsAuthenticationMessage")
    def sms_authentication_message(self) -> typing.Optional[builtins.str]:
        '''A string representing the SMS authentication message.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-smsauthenticationmessage
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "smsAuthenticationMessage"))

    @sms_authentication_message.setter
    def sms_authentication_message(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "smsAuthenticationMessage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="smsConfiguration")
    def sms_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.SmsConfigurationProperty", _IResolvable_da3f097b]]:
        '''The SMS configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-smsconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.SmsConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "smsConfiguration"))

    @sms_configuration.setter
    def sms_configuration(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.SmsConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "smsConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="smsVerificationMessage")
    def sms_verification_message(self) -> typing.Optional[builtins.str]:
        '''A string representing the SMS verification message.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-smsverificationmessage
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "smsVerificationMessage"))

    @sms_verification_message.setter
    def sms_verification_message(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "smsVerificationMessage", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="usernameAttributes")
    def username_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Determines whether email addresses or phone numbers can be specified as user names when a user signs up.

        Possible values: ``phone_number`` or ``email`` .

        This user pool property cannot be updated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-usernameattributes
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "usernameAttributes"))

    @username_attributes.setter
    def username_attributes(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "usernameAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="usernameConfiguration")
    def username_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.UsernameConfigurationProperty", _IResolvable_da3f097b]]:
        '''You can choose to set case sensitivity on the username input for the selected sign-in option.

        For example, when this is set to ``False`` , users will be able to sign in using either "username" or "Username". This configuration is immutable once it has been set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-usernameconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.UsernameConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "usernameConfiguration"))

    @username_configuration.setter
    def username_configuration(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.UsernameConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "usernameConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolAddOns")
    def user_pool_add_ons(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.UserPoolAddOnsProperty", _IResolvable_da3f097b]]:
        '''Enables advanced security risk detection.

        Set the key ``AdvancedSecurityMode`` to the value "AUDIT".

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-userpooladdons
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.UserPoolAddOnsProperty", _IResolvable_da3f097b]], jsii.get(self, "userPoolAddOns"))

    @user_pool_add_ons.setter
    def user_pool_add_ons(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.UserPoolAddOnsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "userPoolAddOns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolName")
    def user_pool_name(self) -> typing.Optional[builtins.str]:
        '''A string used to name the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-userpoolname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "userPoolName"))

    @user_pool_name.setter
    def user_pool_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "userPoolName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="verificationMessageTemplate")
    def verification_message_template(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPool.VerificationMessageTemplateProperty", _IResolvable_da3f097b]]:
        '''The template for the verification message that the user sees when the app requests permission to access the user's information.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-verificationmessagetemplate
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPool.VerificationMessageTemplateProperty", _IResolvable_da3f097b]], jsii.get(self, "verificationMessageTemplate"))

    @verification_message_template.setter
    def verification_message_template(
        self,
        value: typing.Optional[typing.Union["CfnUserPool.VerificationMessageTemplateProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "verificationMessageTemplate", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.AccountRecoverySettingProperty",
        jsii_struct_bases=[],
        name_mapping={"recovery_mechanisms": "recoveryMechanisms"},
    )
    class AccountRecoverySettingProperty:
        def __init__(
            self,
            *,
            recovery_mechanisms: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnUserPool.RecoveryOptionProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Use this setting to define which verified available method a user can use to recover their password when they call ``ForgotPassword`` .

            It allows you to define a preferred method when a user has more than one method available. With this setting, SMS does not qualify for a valid password recovery mechanism if the user also has SMS MFA enabled. In the absence of this setting, Cognito uses the legacy behavior to determine the recovery method where SMS is preferred over email.

            :param recovery_mechanisms: The list of ``RecoveryOptionTypes`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-accountrecoverysetting.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                account_recovery_setting_property = cognito.CfnUserPool.AccountRecoverySettingProperty(
                    recovery_mechanisms=[cognito.CfnUserPool.RecoveryOptionProperty(
                        name="name",
                        priority=123
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if recovery_mechanisms is not None:
                self._values["recovery_mechanisms"] = recovery_mechanisms

        @builtins.property
        def recovery_mechanisms(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPool.RecoveryOptionProperty", _IResolvable_da3f097b]]]]:
            '''The list of ``RecoveryOptionTypes`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-accountrecoverysetting.html#cfn-cognito-userpool-accountrecoverysetting-recoverymechanisms
            '''
            result = self._values.get("recovery_mechanisms")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPool.RecoveryOptionProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccountRecoverySettingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.AdminCreateUserConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "allow_admin_create_user_only": "allowAdminCreateUserOnly",
            "invite_message_template": "inviteMessageTemplate",
            "unused_account_validity_days": "unusedAccountValidityDays",
        },
    )
    class AdminCreateUserConfigProperty:
        def __init__(
            self,
            *,
            allow_admin_create_user_only: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            invite_message_template: typing.Optional[typing.Union["CfnUserPool.InviteMessageTemplateProperty", _IResolvable_da3f097b]] = None,
            unused_account_validity_days: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The configuration for ``AdminCreateUser`` requests.

            :param allow_admin_create_user_only: Set to ``True`` if only the administrator is allowed to create user profiles. Set to ``False`` if users can sign themselves up via an app.
            :param invite_message_template: The message template to be used for the welcome message to new users. See also `Customizing User Invitation Messages <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-customizations.html#cognito-user-pool-settings-user-invitation-message-customization>`_ .
            :param unused_account_validity_days: The user account expiration limit, in days, after which the account is no longer usable. To reset the account after that time limit, you must call ``AdminCreateUser`` again, specifying ``"RESEND"`` for the ``MessageAction`` parameter. The default value for this parameter is 7. .. epigraph:: If you set a value for ``TemporaryPasswordValidityDays`` in ``PasswordPolicy`` , that value will be used, and ``UnusedAccountValidityDays`` will be no longer be an available parameter for that user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-admincreateuserconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                admin_create_user_config_property = cognito.CfnUserPool.AdminCreateUserConfigProperty(
                    allow_admin_create_user_only=False,
                    invite_message_template=cognito.CfnUserPool.InviteMessageTemplateProperty(
                        email_message="emailMessage",
                        email_subject="emailSubject",
                        sms_message="smsMessage"
                    ),
                    unused_account_validity_days=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if allow_admin_create_user_only is not None:
                self._values["allow_admin_create_user_only"] = allow_admin_create_user_only
            if invite_message_template is not None:
                self._values["invite_message_template"] = invite_message_template
            if unused_account_validity_days is not None:
                self._values["unused_account_validity_days"] = unused_account_validity_days

        @builtins.property
        def allow_admin_create_user_only(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Set to ``True`` if only the administrator is allowed to create user profiles.

            Set to ``False`` if users can sign themselves up via an app.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-admincreateuserconfig.html#cfn-cognito-userpool-admincreateuserconfig-allowadmincreateuseronly
            '''
            result = self._values.get("allow_admin_create_user_only")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def invite_message_template(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPool.InviteMessageTemplateProperty", _IResolvable_da3f097b]]:
            '''The message template to be used for the welcome message to new users.

            See also `Customizing User Invitation Messages <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-customizations.html#cognito-user-pool-settings-user-invitation-message-customization>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-admincreateuserconfig.html#cfn-cognito-userpool-admincreateuserconfig-invitemessagetemplate
            '''
            result = self._values.get("invite_message_template")
            return typing.cast(typing.Optional[typing.Union["CfnUserPool.InviteMessageTemplateProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def unused_account_validity_days(self) -> typing.Optional[jsii.Number]:
            '''The user account expiration limit, in days, after which the account is no longer usable.

            To reset the account after that time limit, you must call ``AdminCreateUser`` again, specifying ``"RESEND"`` for the ``MessageAction`` parameter. The default value for this parameter is 7.
            .. epigraph::

               If you set a value for ``TemporaryPasswordValidityDays`` in ``PasswordPolicy`` , that value will be used, and ``UnusedAccountValidityDays`` will be no longer be an available parameter for that user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-admincreateuserconfig.html#cfn-cognito-userpool-admincreateuserconfig-unusedaccountvaliditydays
            '''
            result = self._values.get("unused_account_validity_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AdminCreateUserConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.CustomEmailSenderProperty",
        jsii_struct_bases=[],
        name_mapping={"lambda_arn": "lambdaArn", "lambda_version": "lambdaVersion"},
    )
    class CustomEmailSenderProperty:
        def __init__(
            self,
            *,
            lambda_arn: typing.Optional[builtins.str] = None,
            lambda_version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A custom email sender AWS Lambda trigger.

            :param lambda_arn: The Amazon Resource Name (ARN) of the AWS Lambda function that Amazon Cognito triggers to send email notifications to users.
            :param lambda_version: The Lambda version represents the signature of the "request" attribute in the "event" information that Amazon Cognito passes to your custom email sender AWS Lambda function. The only supported value is ``V1_0`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-customemailsender.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                custom_email_sender_property = cognito.CfnUserPool.CustomEmailSenderProperty(
                    lambda_arn="lambdaArn",
                    lambda_version="lambdaVersion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if lambda_arn is not None:
                self._values["lambda_arn"] = lambda_arn
            if lambda_version is not None:
                self._values["lambda_version"] = lambda_version

        @builtins.property
        def lambda_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the AWS Lambda function that Amazon Cognito triggers to send email notifications to users.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-customemailsender.html#cfn-cognito-userpool-customemailsender-lambdaarn
            '''
            result = self._values.get("lambda_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def lambda_version(self) -> typing.Optional[builtins.str]:
            '''The Lambda version represents the signature of the "request" attribute in the "event" information that Amazon Cognito passes to your custom email sender AWS Lambda function.

            The only supported value is ``V1_0`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-customemailsender.html#cfn-cognito-userpool-customemailsender-lambdaversion
            '''
            result = self._values.get("lambda_version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomEmailSenderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.CustomSMSSenderProperty",
        jsii_struct_bases=[],
        name_mapping={"lambda_arn": "lambdaArn", "lambda_version": "lambdaVersion"},
    )
    class CustomSMSSenderProperty:
        def __init__(
            self,
            *,
            lambda_arn: typing.Optional[builtins.str] = None,
            lambda_version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A custom SMS sender AWS Lambda trigger.

            :param lambda_arn: The Amazon Resource Name (ARN) of the AWS Lambda function that Amazon Cognito triggers to send SMS notifications to users.
            :param lambda_version: The Lambda version represents the signature of the "request" attribute in the "event" information Amazon Cognito passes to your custom SMS sender Lambda function. The only supported value is ``V1_0`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-customsmssender.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                custom_sMSSender_property = cognito.CfnUserPool.CustomSMSSenderProperty(
                    lambda_arn="lambdaArn",
                    lambda_version="lambdaVersion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if lambda_arn is not None:
                self._values["lambda_arn"] = lambda_arn
            if lambda_version is not None:
                self._values["lambda_version"] = lambda_version

        @builtins.property
        def lambda_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the AWS Lambda function that Amazon Cognito triggers to send SMS notifications to users.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-customsmssender.html#cfn-cognito-userpool-customsmssender-lambdaarn
            '''
            result = self._values.get("lambda_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def lambda_version(self) -> typing.Optional[builtins.str]:
            '''The Lambda version represents the signature of the "request" attribute in the "event" information Amazon Cognito passes to your custom SMS sender Lambda function.

            The only supported value is ``V1_0`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-customsmssender.html#cfn-cognito-userpool-customsmssender-lambdaversion
            '''
            result = self._values.get("lambda_version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomSMSSenderProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.DeviceConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "challenge_required_on_new_device": "challengeRequiredOnNewDevice",
            "device_only_remembered_on_user_prompt": "deviceOnlyRememberedOnUserPrompt",
        },
    )
    class DeviceConfigurationProperty:
        def __init__(
            self,
            *,
            challenge_required_on_new_device: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            device_only_remembered_on_user_prompt: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The device tracking configuration for a user pool. A user pool with device tracking deactivated returns a null value.

            .. epigraph::

               When you provide values for any DeviceConfiguration field, you activate device tracking.

            :param challenge_required_on_new_device: When true, device authentication can replace SMS and time-based one-time password (TOTP) factors for multi-factor authentication (MFA). .. epigraph:: Users that sign in with devices that have not been confirmed or remembered will still have to provide a second factor, whether or not ChallengeRequiredOnNewDevice is true, when your user pool requires MFA.
            :param device_only_remembered_on_user_prompt: When true, users can opt in to remembering their device. Your app code must use callback functions to return the user's choice.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-deviceconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                device_configuration_property = cognito.CfnUserPool.DeviceConfigurationProperty(
                    challenge_required_on_new_device=False,
                    device_only_remembered_on_user_prompt=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if challenge_required_on_new_device is not None:
                self._values["challenge_required_on_new_device"] = challenge_required_on_new_device
            if device_only_remembered_on_user_prompt is not None:
                self._values["device_only_remembered_on_user_prompt"] = device_only_remembered_on_user_prompt

        @builtins.property
        def challenge_required_on_new_device(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When true, device authentication can replace SMS and time-based one-time password (TOTP) factors for multi-factor authentication (MFA).

            .. epigraph::

               Users that sign in with devices that have not been confirmed or remembered will still have to provide a second factor, whether or not ChallengeRequiredOnNewDevice is true, when your user pool requires MFA.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-deviceconfiguration.html#cfn-cognito-userpool-deviceconfiguration-challengerequiredonnewdevice
            '''
            result = self._values.get("challenge_required_on_new_device")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def device_only_remembered_on_user_prompt(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''When true, users can opt in to remembering their device.

            Your app code must use callback functions to return the user's choice.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-deviceconfiguration.html#cfn-cognito-userpool-deviceconfiguration-deviceonlyrememberedonuserprompt
            '''
            result = self._values.get("device_only_remembered_on_user_prompt")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeviceConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.EmailConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "configuration_set": "configurationSet",
            "email_sending_account": "emailSendingAccount",
            "from_": "from",
            "reply_to_email_address": "replyToEmailAddress",
            "source_arn": "sourceArn",
        },
    )
    class EmailConfigurationProperty:
        def __init__(
            self,
            *,
            configuration_set: typing.Optional[builtins.str] = None,
            email_sending_account: typing.Optional[builtins.str] = None,
            from_: typing.Optional[builtins.str] = None,
            reply_to_email_address: typing.Optional[builtins.str] = None,
            source_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The email configuration.

            :param configuration_set: The set of configuration rules that can be applied to emails sent using Amazon SES. A configuration set is applied to an email by including a reference to the configuration set in the headers of the email. Once applied, all of the rules in that configuration set are applied to the email. Configuration sets can be used to apply the following types of rules to emails: - Event publishing – Amazon SES can track the number of send, delivery, open, click, bounce, and complaint events for each email sent. Use event publishing to send information about these events to other AWS services such as SNS and CloudWatch. - IP pool management – When leasing dedicated IP addresses with Amazon SES, you can create groups of IP addresses, called dedicated IP pools. You can then associate the dedicated IP pools with configuration sets.
            :param email_sending_account: Specifies whether Amazon Cognito emails your users by using its built-in email functionality or your Amazon Simple Email Service email configuration. Specify one of the following values: - **COGNITO_DEFAULT** - When Amazon Cognito emails your users, it uses its built-in email functionality. When you use the default option, Amazon Cognito allows only a limited number of emails each day for your user pool. For typical production environments, the default email limit is less than the required delivery volume. To achieve a higher delivery volume, specify DEVELOPER to use your Amazon SES email configuration. To look up the email delivery limit for the default option, see `Limits in <https://docs.aws.amazon.com/cognito/latest/developerguide/limits.html>`_ in the *Developer Guide* . The default FROM address is ``no-reply@verificationemail.com`` . To customize the FROM address, provide the Amazon Resource Name (ARN) of an Amazon SES verified email address for the ``SourceArn`` parameter. If EmailSendingAccount is COGNITO_DEFAULT, you can't use the following parameters: - EmailVerificationMessage - EmailVerificationSubject - InviteMessageTemplate.EmailMessage - InviteMessageTemplate.EmailSubject - VerificationMessageTemplate.EmailMessage - VerificationMessageTemplate.EmailMessageByLink - VerificationMessageTemplate.EmailSubject, - VerificationMessageTemplate.EmailSubjectByLink .. epigraph:: DEVELOPER EmailSendingAccount is required. - **DEVELOPER** - When Amazon Cognito emails your users, it uses your Amazon SES configuration. Amazon Cognito calls Amazon SES on your behalf to send email from your verified email address. When you use this option, the email delivery limits are the same limits that apply to your Amazon SES verified email address in your AWS account . If you use this option, you must provide the ARN of an Amazon SES verified email address for the ``SourceArn`` parameter. Before Amazon Cognito can email your users, it requires additional permissions to call Amazon SES on your behalf. When you update your user pool with this option, Amazon Cognito creates a *service-linked role* , which is a type of role, in your AWS account . This role contains the permissions that allow to access Amazon SES and send email messages with your address. For more information about the service-linked role that Amazon Cognito creates, see `Using Service-Linked Roles for Amazon Cognito <https://docs.aws.amazon.com/cognito/latest/developerguide/using-service-linked-roles.html>`_ in the *Amazon Cognito Developer Guide* .
            :param from_: Identifies either the sender's email address or the sender's name with their email address. For example, ``testuser@example.com`` or ``Test User <testuser@example.com>`` . This address appears before the body of the email.
            :param reply_to_email_address: The destination to which the receiver of the email should reply.
            :param source_arn: The ARN of a verified email address in Amazon SES. Amazon Cognito uses this email address in one of the following ways, depending on the value that you specify for the ``EmailSendingAccount`` parameter: - If you specify ``COGNITO_DEFAULT`` , Amazon Cognito uses this address as the custom FROM address when it emails your users using its built-in email account. - If you specify ``DEVELOPER`` , Amazon Cognito emails your users with this address by calling Amazon SES on your behalf.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-emailconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                email_configuration_property = cognito.CfnUserPool.EmailConfigurationProperty(
                    configuration_set="configurationSet",
                    email_sending_account="emailSendingAccount",
                    from="from",
                    reply_to_email_address="replyToEmailAddress",
                    source_arn="sourceArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if configuration_set is not None:
                self._values["configuration_set"] = configuration_set
            if email_sending_account is not None:
                self._values["email_sending_account"] = email_sending_account
            if from_ is not None:
                self._values["from_"] = from_
            if reply_to_email_address is not None:
                self._values["reply_to_email_address"] = reply_to_email_address
            if source_arn is not None:
                self._values["source_arn"] = source_arn

        @builtins.property
        def configuration_set(self) -> typing.Optional[builtins.str]:
            '''The set of configuration rules that can be applied to emails sent using Amazon SES.

            A configuration set is applied to an email by including a reference to the configuration set in the headers of the email. Once applied, all of the rules in that configuration set are applied to the email. Configuration sets can be used to apply the following types of rules to emails:

            - Event publishing – Amazon SES can track the number of send, delivery, open, click, bounce, and complaint events for each email sent. Use event publishing to send information about these events to other AWS services such as SNS and CloudWatch.
            - IP pool management – When leasing dedicated IP addresses with Amazon SES, you can create groups of IP addresses, called dedicated IP pools. You can then associate the dedicated IP pools with configuration sets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-emailconfiguration.html#cfn-cognito-userpool-emailconfiguration-configurationset
            '''
            result = self._values.get("configuration_set")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def email_sending_account(self) -> typing.Optional[builtins.str]:
            '''Specifies whether Amazon Cognito emails your users by using its built-in email functionality or your Amazon Simple Email Service email configuration.

            Specify one of the following values:

            - **COGNITO_DEFAULT** - When Amazon Cognito emails your users, it uses its built-in email functionality. When you use the default option, Amazon Cognito allows only a limited number of emails each day for your user pool. For typical production environments, the default email limit is less than the required delivery volume. To achieve a higher delivery volume, specify DEVELOPER to use your Amazon SES email configuration.

            To look up the email delivery limit for the default option, see `Limits in <https://docs.aws.amazon.com/cognito/latest/developerguide/limits.html>`_ in the *Developer Guide* .

            The default FROM address is ``no-reply@verificationemail.com`` . To customize the FROM address, provide the Amazon Resource Name (ARN) of an Amazon SES verified email address for the ``SourceArn`` parameter.

            If EmailSendingAccount is COGNITO_DEFAULT, you can't use the following parameters:

            - EmailVerificationMessage
            - EmailVerificationSubject
            - InviteMessageTemplate.EmailMessage
            - InviteMessageTemplate.EmailSubject
            - VerificationMessageTemplate.EmailMessage
            - VerificationMessageTemplate.EmailMessageByLink
            - VerificationMessageTemplate.EmailSubject,
            - VerificationMessageTemplate.EmailSubjectByLink

            .. epigraph::

               DEVELOPER EmailSendingAccount is required.

            - **DEVELOPER** - When Amazon Cognito emails your users, it uses your Amazon SES configuration. Amazon Cognito calls Amazon SES on your behalf to send email from your verified email address. When you use this option, the email delivery limits are the same limits that apply to your Amazon SES verified email address in your AWS account .

            If you use this option, you must provide the ARN of an Amazon SES verified email address for the ``SourceArn`` parameter.

            Before Amazon Cognito can email your users, it requires additional permissions to call Amazon SES on your behalf. When you update your user pool with this option, Amazon Cognito creates a *service-linked role* , which is a type of role, in your AWS account . This role contains the permissions that allow to access Amazon SES and send email messages with your address. For more information about the service-linked role that Amazon Cognito creates, see `Using Service-Linked Roles for Amazon Cognito <https://docs.aws.amazon.com/cognito/latest/developerguide/using-service-linked-roles.html>`_ in the *Amazon Cognito Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-emailconfiguration.html#cfn-cognito-userpool-emailconfiguration-emailsendingaccount
            '''
            result = self._values.get("email_sending_account")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def from_(self) -> typing.Optional[builtins.str]:
            '''Identifies either the sender's email address or the sender's name with their email address.

            For example, ``testuser@example.com`` or ``Test User <testuser@example.com>`` . This address appears before the body of the email.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-emailconfiguration.html#cfn-cognito-userpool-emailconfiguration-from
            '''
            result = self._values.get("from_")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def reply_to_email_address(self) -> typing.Optional[builtins.str]:
            '''The destination to which the receiver of the email should reply.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-emailconfiguration.html#cfn-cognito-userpool-emailconfiguration-replytoemailaddress
            '''
            result = self._values.get("reply_to_email_address")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def source_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of a verified email address in Amazon SES.

            Amazon Cognito uses this email address in one of the following ways, depending on the value that you specify for the ``EmailSendingAccount`` parameter:

            - If you specify ``COGNITO_DEFAULT`` , Amazon Cognito uses this address as the custom FROM address when it emails your users using its built-in email account.
            - If you specify ``DEVELOPER`` , Amazon Cognito emails your users with this address by calling Amazon SES on your behalf.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-emailconfiguration.html#cfn-cognito-userpool-emailconfiguration-sourcearn
            '''
            result = self._values.get("source_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EmailConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.InviteMessageTemplateProperty",
        jsii_struct_bases=[],
        name_mapping={
            "email_message": "emailMessage",
            "email_subject": "emailSubject",
            "sms_message": "smsMessage",
        },
    )
    class InviteMessageTemplateProperty:
        def __init__(
            self,
            *,
            email_message: typing.Optional[builtins.str] = None,
            email_subject: typing.Optional[builtins.str] = None,
            sms_message: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The message template to be used for the welcome message to new users.

            See also `Customizing User Invitation Messages <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-customizations.html#cognito-user-pool-settings-user-invitation-message-customization>`_ .

            :param email_message: The message template for email messages. EmailMessage is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
            :param email_subject: The subject line for email messages. EmailSubject is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
            :param sms_message: The message template for SMS messages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-invitemessagetemplate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                invite_message_template_property = cognito.CfnUserPool.InviteMessageTemplateProperty(
                    email_message="emailMessage",
                    email_subject="emailSubject",
                    sms_message="smsMessage"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if email_message is not None:
                self._values["email_message"] = email_message
            if email_subject is not None:
                self._values["email_subject"] = email_subject
            if sms_message is not None:
                self._values["sms_message"] = sms_message

        @builtins.property
        def email_message(self) -> typing.Optional[builtins.str]:
            '''The message template for email messages.

            EmailMessage is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-invitemessagetemplate.html#cfn-cognito-userpool-invitemessagetemplate-emailmessage
            '''
            result = self._values.get("email_message")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def email_subject(self) -> typing.Optional[builtins.str]:
            '''The subject line for email messages.

            EmailSubject is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-invitemessagetemplate.html#cfn-cognito-userpool-invitemessagetemplate-emailsubject
            '''
            result = self._values.get("email_subject")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sms_message(self) -> typing.Optional[builtins.str]:
            '''The message template for SMS messages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-invitemessagetemplate.html#cfn-cognito-userpool-invitemessagetemplate-smsmessage
            '''
            result = self._values.get("sms_message")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InviteMessageTemplateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.LambdaConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "create_auth_challenge": "createAuthChallenge",
            "custom_email_sender": "customEmailSender",
            "custom_message": "customMessage",
            "custom_sms_sender": "customSmsSender",
            "define_auth_challenge": "defineAuthChallenge",
            "kms_key_id": "kmsKeyId",
            "post_authentication": "postAuthentication",
            "post_confirmation": "postConfirmation",
            "pre_authentication": "preAuthentication",
            "pre_sign_up": "preSignUp",
            "pre_token_generation": "preTokenGeneration",
            "user_migration": "userMigration",
            "verify_auth_challenge_response": "verifyAuthChallengeResponse",
        },
    )
    class LambdaConfigProperty:
        def __init__(
            self,
            *,
            create_auth_challenge: typing.Optional[builtins.str] = None,
            custom_email_sender: typing.Optional[typing.Union["CfnUserPool.CustomEmailSenderProperty", _IResolvable_da3f097b]] = None,
            custom_message: typing.Optional[builtins.str] = None,
            custom_sms_sender: typing.Optional[typing.Union["CfnUserPool.CustomSMSSenderProperty", _IResolvable_da3f097b]] = None,
            define_auth_challenge: typing.Optional[builtins.str] = None,
            kms_key_id: typing.Optional[builtins.str] = None,
            post_authentication: typing.Optional[builtins.str] = None,
            post_confirmation: typing.Optional[builtins.str] = None,
            pre_authentication: typing.Optional[builtins.str] = None,
            pre_sign_up: typing.Optional[builtins.str] = None,
            pre_token_generation: typing.Optional[builtins.str] = None,
            user_migration: typing.Optional[builtins.str] = None,
            verify_auth_challenge_response: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the configuration for AWS Lambda triggers.

            :param create_auth_challenge: Creates an authentication challenge.
            :param custom_email_sender: A custom email sender AWS Lambda trigger.
            :param custom_message: A custom Message AWS Lambda trigger.
            :param custom_sms_sender: A custom SMS sender AWS Lambda trigger.
            :param define_auth_challenge: Defines the authentication challenge.
            :param kms_key_id: The Amazon Resource Name of a AWS Key Management Service ( AWS KMS ) key. Amazon Cognito uses the key to encrypt codes and temporary passwords sent to ``CustomEmailSender`` and ``CustomSMSSender`` .
            :param post_authentication: A post-authentication AWS Lambda trigger.
            :param post_confirmation: A post-confirmation AWS Lambda trigger.
            :param pre_authentication: A pre-authentication AWS Lambda trigger.
            :param pre_sign_up: A pre-registration AWS Lambda trigger.
            :param pre_token_generation: A Lambda trigger that is invoked before token generation.
            :param user_migration: The user migration Lambda config type.
            :param verify_auth_challenge_response: Verifies the authentication challenge response.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                lambda_config_property = cognito.CfnUserPool.LambdaConfigProperty(
                    create_auth_challenge="createAuthChallenge",
                    custom_email_sender=cognito.CfnUserPool.CustomEmailSenderProperty(
                        lambda_arn="lambdaArn",
                        lambda_version="lambdaVersion"
                    ),
                    custom_message="customMessage",
                    custom_sms_sender=cognito.CfnUserPool.CustomSMSSenderProperty(
                        lambda_arn="lambdaArn",
                        lambda_version="lambdaVersion"
                    ),
                    define_auth_challenge="defineAuthChallenge",
                    kms_key_id="kmsKeyId",
                    post_authentication="postAuthentication",
                    post_confirmation="postConfirmation",
                    pre_authentication="preAuthentication",
                    pre_sign_up="preSignUp",
                    pre_token_generation="preTokenGeneration",
                    user_migration="userMigration",
                    verify_auth_challenge_response="verifyAuthChallengeResponse"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if create_auth_challenge is not None:
                self._values["create_auth_challenge"] = create_auth_challenge
            if custom_email_sender is not None:
                self._values["custom_email_sender"] = custom_email_sender
            if custom_message is not None:
                self._values["custom_message"] = custom_message
            if custom_sms_sender is not None:
                self._values["custom_sms_sender"] = custom_sms_sender
            if define_auth_challenge is not None:
                self._values["define_auth_challenge"] = define_auth_challenge
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id
            if post_authentication is not None:
                self._values["post_authentication"] = post_authentication
            if post_confirmation is not None:
                self._values["post_confirmation"] = post_confirmation
            if pre_authentication is not None:
                self._values["pre_authentication"] = pre_authentication
            if pre_sign_up is not None:
                self._values["pre_sign_up"] = pre_sign_up
            if pre_token_generation is not None:
                self._values["pre_token_generation"] = pre_token_generation
            if user_migration is not None:
                self._values["user_migration"] = user_migration
            if verify_auth_challenge_response is not None:
                self._values["verify_auth_challenge_response"] = verify_auth_challenge_response

        @builtins.property
        def create_auth_challenge(self) -> typing.Optional[builtins.str]:
            '''Creates an authentication challenge.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-createauthchallenge
            '''
            result = self._values.get("create_auth_challenge")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def custom_email_sender(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPool.CustomEmailSenderProperty", _IResolvable_da3f097b]]:
            '''A custom email sender AWS Lambda trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-customemailsender
            '''
            result = self._values.get("custom_email_sender")
            return typing.cast(typing.Optional[typing.Union["CfnUserPool.CustomEmailSenderProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def custom_message(self) -> typing.Optional[builtins.str]:
            '''A custom Message AWS Lambda trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-custommessage
            '''
            result = self._values.get("custom_message")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def custom_sms_sender(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPool.CustomSMSSenderProperty", _IResolvable_da3f097b]]:
            '''A custom SMS sender AWS Lambda trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-customsmssender
            '''
            result = self._values.get("custom_sms_sender")
            return typing.cast(typing.Optional[typing.Union["CfnUserPool.CustomSMSSenderProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def define_auth_challenge(self) -> typing.Optional[builtins.str]:
            '''Defines the authentication challenge.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-defineauthchallenge
            '''
            result = self._values.get("define_auth_challenge")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name of a AWS Key Management Service ( AWS KMS ) key.

            Amazon Cognito uses the key to encrypt codes and temporary passwords sent to ``CustomEmailSender`` and ``CustomSMSSender`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def post_authentication(self) -> typing.Optional[builtins.str]:
            '''A post-authentication AWS Lambda trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-postauthentication
            '''
            result = self._values.get("post_authentication")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def post_confirmation(self) -> typing.Optional[builtins.str]:
            '''A post-confirmation AWS Lambda trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-postconfirmation
            '''
            result = self._values.get("post_confirmation")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def pre_authentication(self) -> typing.Optional[builtins.str]:
            '''A pre-authentication AWS Lambda trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-preauthentication
            '''
            result = self._values.get("pre_authentication")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def pre_sign_up(self) -> typing.Optional[builtins.str]:
            '''A pre-registration AWS Lambda trigger.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-presignup
            '''
            result = self._values.get("pre_sign_up")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def pre_token_generation(self) -> typing.Optional[builtins.str]:
            '''A Lambda trigger that is invoked before token generation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-pretokengeneration
            '''
            result = self._values.get("pre_token_generation")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def user_migration(self) -> typing.Optional[builtins.str]:
            '''The user migration Lambda config type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-usermigration
            '''
            result = self._values.get("user_migration")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def verify_auth_challenge_response(self) -> typing.Optional[builtins.str]:
            '''Verifies the authentication challenge response.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-lambdaconfig.html#cfn-cognito-userpool-lambdaconfig-verifyauthchallengeresponse
            '''
            result = self._values.get("verify_auth_challenge_response")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.NumberAttributeConstraintsProperty",
        jsii_struct_bases=[],
        name_mapping={"max_value": "maxValue", "min_value": "minValue"},
    )
    class NumberAttributeConstraintsProperty:
        def __init__(
            self,
            *,
            max_value: typing.Optional[builtins.str] = None,
            min_value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The minimum and maximum values of an attribute that is of the number data type.

            :param max_value: The maximum value of an attribute that is of the number data type.
            :param min_value: The minimum value of an attribute that is of the number data type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-numberattributeconstraints.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                number_attribute_constraints_property = cognito.CfnUserPool.NumberAttributeConstraintsProperty(
                    max_value="maxValue",
                    min_value="minValue"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max_value is not None:
                self._values["max_value"] = max_value
            if min_value is not None:
                self._values["min_value"] = min_value

        @builtins.property
        def max_value(self) -> typing.Optional[builtins.str]:
            '''The maximum value of an attribute that is of the number data type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-numberattributeconstraints.html#cfn-cognito-userpool-numberattributeconstraints-maxvalue
            '''
            result = self._values.get("max_value")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def min_value(self) -> typing.Optional[builtins.str]:
            '''The minimum value of an attribute that is of the number data type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-numberattributeconstraints.html#cfn-cognito-userpool-numberattributeconstraints-minvalue
            '''
            result = self._values.get("min_value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NumberAttributeConstraintsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.PasswordPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "minimum_length": "minimumLength",
            "require_lowercase": "requireLowercase",
            "require_numbers": "requireNumbers",
            "require_symbols": "requireSymbols",
            "require_uppercase": "requireUppercase",
            "temporary_password_validity_days": "temporaryPasswordValidityDays",
        },
    )
    class PasswordPolicyProperty:
        def __init__(
            self,
            *,
            minimum_length: typing.Optional[jsii.Number] = None,
            require_lowercase: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            require_numbers: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            require_symbols: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            require_uppercase: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            temporary_password_validity_days: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The password policy type.

            :param minimum_length: The minimum length of the password in the policy that you have set. This value can't be less than 6.
            :param require_lowercase: In the password policy that you have set, refers to whether you have required users to use at least one lowercase letter in their password.
            :param require_numbers: In the password policy that you have set, refers to whether you have required users to use at least one number in their password.
            :param require_symbols: In the password policy that you have set, refers to whether you have required users to use at least one symbol in their password.
            :param require_uppercase: In the password policy that you have set, refers to whether you have required users to use at least one uppercase letter in their password.
            :param temporary_password_validity_days: The number of days a temporary password is valid in the password policy. If the user doesn't sign in during this time, an administrator must reset their password. .. epigraph:: When you set ``TemporaryPasswordValidityDays`` for a user pool, you can no longer set the deprecated ``UnusedAccountValidityDays`` value for that user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-passwordpolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                password_policy_property = cognito.CfnUserPool.PasswordPolicyProperty(
                    minimum_length=123,
                    require_lowercase=False,
                    require_numbers=False,
                    require_symbols=False,
                    require_uppercase=False,
                    temporary_password_validity_days=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if minimum_length is not None:
                self._values["minimum_length"] = minimum_length
            if require_lowercase is not None:
                self._values["require_lowercase"] = require_lowercase
            if require_numbers is not None:
                self._values["require_numbers"] = require_numbers
            if require_symbols is not None:
                self._values["require_symbols"] = require_symbols
            if require_uppercase is not None:
                self._values["require_uppercase"] = require_uppercase
            if temporary_password_validity_days is not None:
                self._values["temporary_password_validity_days"] = temporary_password_validity_days

        @builtins.property
        def minimum_length(self) -> typing.Optional[jsii.Number]:
            '''The minimum length of the password in the policy that you have set.

            This value can't be less than 6.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-passwordpolicy.html#cfn-cognito-userpool-passwordpolicy-minimumlength
            '''
            result = self._values.get("minimum_length")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def require_lowercase(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''In the password policy that you have set, refers to whether you have required users to use at least one lowercase letter in their password.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-passwordpolicy.html#cfn-cognito-userpool-passwordpolicy-requirelowercase
            '''
            result = self._values.get("require_lowercase")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def require_numbers(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''In the password policy that you have set, refers to whether you have required users to use at least one number in their password.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-passwordpolicy.html#cfn-cognito-userpool-passwordpolicy-requirenumbers
            '''
            result = self._values.get("require_numbers")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def require_symbols(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''In the password policy that you have set, refers to whether you have required users to use at least one symbol in their password.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-passwordpolicy.html#cfn-cognito-userpool-passwordpolicy-requiresymbols
            '''
            result = self._values.get("require_symbols")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def require_uppercase(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''In the password policy that you have set, refers to whether you have required users to use at least one uppercase letter in their password.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-passwordpolicy.html#cfn-cognito-userpool-passwordpolicy-requireuppercase
            '''
            result = self._values.get("require_uppercase")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def temporary_password_validity_days(self) -> typing.Optional[jsii.Number]:
            '''The number of days a temporary password is valid in the password policy.

            If the user doesn't sign in during this time, an administrator must reset their password.
            .. epigraph::

               When you set ``TemporaryPasswordValidityDays`` for a user pool, you can no longer set the deprecated ``UnusedAccountValidityDays`` value for that user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-passwordpolicy.html#cfn-cognito-userpool-passwordpolicy-temporarypasswordvaliditydays
            '''
            result = self._values.get("temporary_password_validity_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PasswordPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.PoliciesProperty",
        jsii_struct_bases=[],
        name_mapping={"password_policy": "passwordPolicy"},
    )
    class PoliciesProperty:
        def __init__(
            self,
            *,
            password_policy: typing.Optional[typing.Union["CfnUserPool.PasswordPolicyProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The policy associated with a user pool.

            :param password_policy: The password policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-policies.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                policies_property = cognito.CfnUserPool.PoliciesProperty(
                    password_policy=cognito.CfnUserPool.PasswordPolicyProperty(
                        minimum_length=123,
                        require_lowercase=False,
                        require_numbers=False,
                        require_symbols=False,
                        require_uppercase=False,
                        temporary_password_validity_days=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if password_policy is not None:
                self._values["password_policy"] = password_policy

        @builtins.property
        def password_policy(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPool.PasswordPolicyProperty", _IResolvable_da3f097b]]:
            '''The password policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-policies.html#cfn-cognito-userpool-policies-passwordpolicy
            '''
            result = self._values.get("password_policy")
            return typing.cast(typing.Optional[typing.Union["CfnUserPool.PasswordPolicyProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PoliciesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.RecoveryOptionProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "priority": "priority"},
    )
    class RecoveryOptionProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            priority: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''A map containing a priority as a key, and recovery method name as a value.

            :param name: Specifies the recovery method for a user.
            :param priority: A positive integer specifying priority of a method with 1 being the highest priority.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-recoveryoption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                recovery_option_property = cognito.CfnUserPool.RecoveryOptionProperty(
                    name="name",
                    priority=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if priority is not None:
                self._values["priority"] = priority

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''Specifies the recovery method for a user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-recoveryoption.html#cfn-cognito-userpool-recoveryoption-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def priority(self) -> typing.Optional[jsii.Number]:
            '''A positive integer specifying priority of a method with 1 being the highest priority.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-recoveryoption.html#cfn-cognito-userpool-recoveryoption-priority
            '''
            result = self._values.get("priority")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RecoveryOptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.SchemaAttributeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "attribute_data_type": "attributeDataType",
            "developer_only_attribute": "developerOnlyAttribute",
            "mutable": "mutable",
            "name": "name",
            "number_attribute_constraints": "numberAttributeConstraints",
            "required": "required",
            "string_attribute_constraints": "stringAttributeConstraints",
        },
    )
    class SchemaAttributeProperty:
        def __init__(
            self,
            *,
            attribute_data_type: typing.Optional[builtins.str] = None,
            developer_only_attribute: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            mutable: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            name: typing.Optional[builtins.str] = None,
            number_attribute_constraints: typing.Optional[typing.Union["CfnUserPool.NumberAttributeConstraintsProperty", _IResolvable_da3f097b]] = None,
            required: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            string_attribute_constraints: typing.Optional[typing.Union["CfnUserPool.StringAttributeConstraintsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Contains information about the schema attribute.

            :param attribute_data_type: The attribute data type.
            :param developer_only_attribute: .. epigraph:: We recommend that you use `WriteAttributes <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserPoolClientType.html#CognitoUserPools-Type-UserPoolClientType-WriteAttributes>`_ in the user pool client to control how attributes can be mutated for new use cases instead of using ``DeveloperOnlyAttribute`` . Specifies whether the attribute type is developer only. This attribute can only be modified by an administrator. Users will not be able to modify this attribute using their access token.
            :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that is mapped to an identity provider attribute, you must set this parameter to ``true`` . Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. For more information, see `Specifying Identity Provider Attribute Mappings for Your User Pool <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html>`_ .
            :param name: A schema attribute of the name type.
            :param number_attribute_constraints: Specifies the constraints for an attribute of the number type.
            :param required: Specifies whether a user pool attribute is required. If the attribute is required and the user doesn't provide a value, registration or sign-in will fail.
            :param string_attribute_constraints: Specifies the constraints for an attribute of the string type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                schema_attribute_property = cognito.CfnUserPool.SchemaAttributeProperty(
                    attribute_data_type="attributeDataType",
                    developer_only_attribute=False,
                    mutable=False,
                    name="name",
                    number_attribute_constraints=cognito.CfnUserPool.NumberAttributeConstraintsProperty(
                        max_value="maxValue",
                        min_value="minValue"
                    ),
                    required=False,
                    string_attribute_constraints=cognito.CfnUserPool.StringAttributeConstraintsProperty(
                        max_length="maxLength",
                        min_length="minLength"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if attribute_data_type is not None:
                self._values["attribute_data_type"] = attribute_data_type
            if developer_only_attribute is not None:
                self._values["developer_only_attribute"] = developer_only_attribute
            if mutable is not None:
                self._values["mutable"] = mutable
            if name is not None:
                self._values["name"] = name
            if number_attribute_constraints is not None:
                self._values["number_attribute_constraints"] = number_attribute_constraints
            if required is not None:
                self._values["required"] = required
            if string_attribute_constraints is not None:
                self._values["string_attribute_constraints"] = string_attribute_constraints

        @builtins.property
        def attribute_data_type(self) -> typing.Optional[builtins.str]:
            '''The attribute data type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html#cfn-cognito-userpool-schemaattribute-attributedatatype
            '''
            result = self._values.get("attribute_data_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def developer_only_attribute(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''.. epigraph::

   We recommend that you use `WriteAttributes <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UserPoolClientType.html#CognitoUserPools-Type-UserPoolClientType-WriteAttributes>`_ in the user pool client to control how attributes can be mutated for new use cases instead of using ``DeveloperOnlyAttribute`` .

            Specifies whether the attribute type is developer only. This attribute can only be modified by an administrator. Users will not be able to modify this attribute using their access token.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html#cfn-cognito-userpool-schemaattribute-developeronlyattribute
            '''
            result = self._values.get("developer_only_attribute")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def mutable(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether the value of the attribute can be changed.

            For any user pool attribute that is mapped to an identity provider attribute, you must set this parameter to ``true`` . Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. For more information, see `Specifying Identity Provider Attribute Mappings for Your User Pool <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html#cfn-cognito-userpool-schemaattribute-mutable
            '''
            result = self._values.get("mutable")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''A schema attribute of the name type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html#cfn-cognito-userpool-schemaattribute-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def number_attribute_constraints(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPool.NumberAttributeConstraintsProperty", _IResolvable_da3f097b]]:
            '''Specifies the constraints for an attribute of the number type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html#cfn-cognito-userpool-schemaattribute-numberattributeconstraints
            '''
            result = self._values.get("number_attribute_constraints")
            return typing.cast(typing.Optional[typing.Union["CfnUserPool.NumberAttributeConstraintsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def required(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether a user pool attribute is required.

            If the attribute is required and the user doesn't provide a value, registration or sign-in will fail.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html#cfn-cognito-userpool-schemaattribute-required
            '''
            result = self._values.get("required")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def string_attribute_constraints(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPool.StringAttributeConstraintsProperty", _IResolvable_da3f097b]]:
            '''Specifies the constraints for an attribute of the string type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html#cfn-cognito-userpool-schemaattribute-stringattributeconstraints
            '''
            result = self._values.get("string_attribute_constraints")
            return typing.cast(typing.Optional[typing.Union["CfnUserPool.StringAttributeConstraintsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SchemaAttributeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.SmsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "external_id": "externalId",
            "sns_caller_arn": "snsCallerArn",
            "sns_region": "snsRegion",
        },
    )
    class SmsConfigurationProperty:
        def __init__(
            self,
            *,
            external_id: typing.Optional[builtins.str] = None,
            sns_caller_arn: typing.Optional[builtins.str] = None,
            sns_region: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The SMS configuration type that includes the settings the Cognito User Pool needs to call for the Amazon SNS service to send an SMS message from your AWS account .

            The Cognito User Pool makes the request to the Amazon SNS Service by using an IAM role that you provide for your AWS account .

            :param external_id: The external ID is a value. We recommend you use ``ExternalId`` to add security to your IAM role, which is used to call Amazon SNS to send SMS messages for your user pool. If you provide an ``ExternalId`` , the Cognito User Pool uses it when attempting to assume your IAM role. You can also set your roles trust policy to require the ``ExternalID`` . If you use the Cognito Management Console to create a role for SMS MFA, Cognito creates a role with the required permissions and a trust policy that uses ``ExternalId`` .
            :param sns_caller_arn: The Amazon Resource Name (ARN) of the Amazon SNS caller. This is the ARN of the IAM role in your AWS account that Amazon Cognito will use to send SMS messages. SMS messages are subject to a `spending limit <https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html>`_ .
            :param sns_region: ``CfnUserPool.SmsConfigurationProperty.SnsRegion``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-smsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                sms_configuration_property = cognito.CfnUserPool.SmsConfigurationProperty(
                    external_id="externalId",
                    sns_caller_arn="snsCallerArn",
                    sns_region="snsRegion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if external_id is not None:
                self._values["external_id"] = external_id
            if sns_caller_arn is not None:
                self._values["sns_caller_arn"] = sns_caller_arn
            if sns_region is not None:
                self._values["sns_region"] = sns_region

        @builtins.property
        def external_id(self) -> typing.Optional[builtins.str]:
            '''The external ID is a value.

            We recommend you use ``ExternalId`` to add security to your IAM role, which is used to call Amazon SNS to send SMS messages for your user pool. If you provide an ``ExternalId`` , the Cognito User Pool uses it when attempting to assume your IAM role. You can also set your roles trust policy to require the ``ExternalID`` . If you use the Cognito Management Console to create a role for SMS MFA, Cognito creates a role with the required permissions and a trust policy that uses ``ExternalId`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-smsconfiguration.html#cfn-cognito-userpool-smsconfiguration-externalid
            '''
            result = self._values.get("external_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sns_caller_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the Amazon SNS caller.

            This is the ARN of the IAM role in your AWS account that Amazon Cognito will use to send SMS messages. SMS messages are subject to a `spending limit <https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-smsconfiguration.html#cfn-cognito-userpool-smsconfiguration-snscallerarn
            '''
            result = self._values.get("sns_caller_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sns_region(self) -> typing.Optional[builtins.str]:
            '''``CfnUserPool.SmsConfigurationProperty.SnsRegion``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-smsconfiguration.html#cfn-cognito-userpool-smsconfiguration-snsregion
            '''
            result = self._values.get("sns_region")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SmsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.StringAttributeConstraintsProperty",
        jsii_struct_bases=[],
        name_mapping={"max_length": "maxLength", "min_length": "minLength"},
    )
    class StringAttributeConstraintsProperty:
        def __init__(
            self,
            *,
            max_length: typing.Optional[builtins.str] = None,
            min_length: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The ``StringAttributeConstraints`` property type defines the string attribute constraints of an Amazon Cognito user pool.

            ``StringAttributeConstraints`` is a subproperty of the `SchemaAttribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-schemaattribute.html>`_ property type.

            :param max_length: The maximum length.
            :param min_length: The minimum length.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-stringattributeconstraints.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                string_attribute_constraints_property = cognito.CfnUserPool.StringAttributeConstraintsProperty(
                    max_length="maxLength",
                    min_length="minLength"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max_length is not None:
                self._values["max_length"] = max_length
            if min_length is not None:
                self._values["min_length"] = min_length

        @builtins.property
        def max_length(self) -> typing.Optional[builtins.str]:
            '''The maximum length.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-stringattributeconstraints.html#cfn-cognito-userpool-stringattributeconstraints-maxlength
            '''
            result = self._values.get("max_length")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def min_length(self) -> typing.Optional[builtins.str]:
            '''The minimum length.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-stringattributeconstraints.html#cfn-cognito-userpool-stringattributeconstraints-minlength
            '''
            result = self._values.get("min_length")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StringAttributeConstraintsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.UserPoolAddOnsProperty",
        jsii_struct_bases=[],
        name_mapping={"advanced_security_mode": "advancedSecurityMode"},
    )
    class UserPoolAddOnsProperty:
        def __init__(
            self,
            *,
            advanced_security_mode: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The user pool add-ons type.

            :param advanced_security_mode: The advanced security mode.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-userpooladdons.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                user_pool_add_ons_property = cognito.CfnUserPool.UserPoolAddOnsProperty(
                    advanced_security_mode="advancedSecurityMode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if advanced_security_mode is not None:
                self._values["advanced_security_mode"] = advanced_security_mode

        @builtins.property
        def advanced_security_mode(self) -> typing.Optional[builtins.str]:
            '''The advanced security mode.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-userpooladdons.html#cfn-cognito-userpool-userpooladdons-advancedsecuritymode
            '''
            result = self._values.get("advanced_security_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UserPoolAddOnsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.UsernameConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"case_sensitive": "caseSensitive"},
    )
    class UsernameConfigurationProperty:
        def __init__(
            self,
            *,
            case_sensitive: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The ``UsernameConfiguration`` property type specifies case sensitivity on the username input for the selected sign-in option.

            :param case_sensitive: Specifies whether username case sensitivity will be applied for all users in the user pool through Amazon Cognito APIs. Valid values include: - *``True``* : Enables case sensitivity for all username input. When this option is set to ``True`` , users must sign in using the exact capitalization of their given username, such as “UserName”. This is the default value. - *``False``* : Enables case insensitivity for all username input. For example, when this option is set to ``False`` , users can sign in using either "username" or "Username". This option also enables both ``preferred_username`` and ``email`` alias to be case insensitive, in addition to the ``username`` attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-usernameconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                username_configuration_property = cognito.CfnUserPool.UsernameConfigurationProperty(
                    case_sensitive=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if case_sensitive is not None:
                self._values["case_sensitive"] = case_sensitive

        @builtins.property
        def case_sensitive(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether username case sensitivity will be applied for all users in the user pool through Amazon Cognito APIs.

            Valid values include:

            - *``True``* : Enables case sensitivity for all username input. When this option is set to ``True`` , users must sign in using the exact capitalization of their given username, such as “UserName”. This is the default value.
            - *``False``* : Enables case insensitivity for all username input. For example, when this option is set to ``False`` , users can sign in using either "username" or "Username". This option also enables both ``preferred_username`` and ``email`` alias to be case insensitive, in addition to the ``username`` attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-usernameconfiguration.html#cfn-cognito-userpool-usernameconfiguration-casesensitive
            '''
            result = self._values.get("case_sensitive")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UsernameConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPool.VerificationMessageTemplateProperty",
        jsii_struct_bases=[],
        name_mapping={
            "default_email_option": "defaultEmailOption",
            "email_message": "emailMessage",
            "email_message_by_link": "emailMessageByLink",
            "email_subject": "emailSubject",
            "email_subject_by_link": "emailSubjectByLink",
            "sms_message": "smsMessage",
        },
    )
    class VerificationMessageTemplateProperty:
        def __init__(
            self,
            *,
            default_email_option: typing.Optional[builtins.str] = None,
            email_message: typing.Optional[builtins.str] = None,
            email_message_by_link: typing.Optional[builtins.str] = None,
            email_subject: typing.Optional[builtins.str] = None,
            email_subject_by_link: typing.Optional[builtins.str] = None,
            sms_message: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The template for verification messages.

            :param default_email_option: The default email option.
            :param email_message: The email message template. EmailMessage is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
            :param email_message_by_link: The email message template for sending a confirmation link to the user. EmailMessageByLink is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
            :param email_subject: The subject line for the email message template. EmailSubject is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
            :param email_subject_by_link: The subject line for the email message template for sending a confirmation link to the user. EmailSubjectByLink is allowed only `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
            :param sms_message: The SMS message template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-verificationmessagetemplate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                verification_message_template_property = cognito.CfnUserPool.VerificationMessageTemplateProperty(
                    default_email_option="defaultEmailOption",
                    email_message="emailMessage",
                    email_message_by_link="emailMessageByLink",
                    email_subject="emailSubject",
                    email_subject_by_link="emailSubjectByLink",
                    sms_message="smsMessage"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if default_email_option is not None:
                self._values["default_email_option"] = default_email_option
            if email_message is not None:
                self._values["email_message"] = email_message
            if email_message_by_link is not None:
                self._values["email_message_by_link"] = email_message_by_link
            if email_subject is not None:
                self._values["email_subject"] = email_subject
            if email_subject_by_link is not None:
                self._values["email_subject_by_link"] = email_subject_by_link
            if sms_message is not None:
                self._values["sms_message"] = sms_message

        @builtins.property
        def default_email_option(self) -> typing.Optional[builtins.str]:
            '''The default email option.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-verificationmessagetemplate.html#cfn-cognito-userpool-verificationmessagetemplate-defaultemailoption
            '''
            result = self._values.get("default_email_option")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def email_message(self) -> typing.Optional[builtins.str]:
            '''The email message template.

            EmailMessage is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-verificationmessagetemplate.html#cfn-cognito-userpool-verificationmessagetemplate-emailmessage
            '''
            result = self._values.get("email_message")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def email_message_by_link(self) -> typing.Optional[builtins.str]:
            '''The email message template for sending a confirmation link to the user.

            EmailMessageByLink is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-verificationmessagetemplate.html#cfn-cognito-userpool-verificationmessagetemplate-emailmessagebylink
            '''
            result = self._values.get("email_message_by_link")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def email_subject(self) -> typing.Optional[builtins.str]:
            '''The subject line for the email message template.

            EmailSubject is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-verificationmessagetemplate.html#cfn-cognito-userpool-verificationmessagetemplate-emailsubject
            '''
            result = self._values.get("email_subject")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def email_subject_by_link(self) -> typing.Optional[builtins.str]:
            '''The subject line for the email message template for sending a confirmation link to the user.

            EmailSubjectByLink is allowed only `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-verificationmessagetemplate.html#cfn-cognito-userpool-verificationmessagetemplate-emailsubjectbylink
            '''
            result = self._values.get("email_subject_by_link")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def sms_message(self) -> typing.Optional[builtins.str]:
            '''The SMS message template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-verificationmessagetemplate.html#cfn-cognito-userpool-verificationmessagetemplate-smsmessage
            '''
            result = self._values.get("sms_message")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VerificationMessageTemplateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolClient(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolClient",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolClient``.

    The ``AWS::Cognito::UserPoolClient`` resource specifies an Amazon Cognito user pool client.

    :cloudformationResource: AWS::Cognito::UserPoolClient
    :exampleMetadata: lit=aws-elasticloadbalancingv2-actions/test/integ.cognito.lit.ts infused
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html

    Example::

        import aws_cdk.aws_cognito as cognito
        import aws_cdk.aws_ec2 as ec2
        import aws_cdk.aws_elasticloadbalancingv2 as elbv2
        from aws_cdk import App, CfnOutput, Stack
        from constructs import Construct
        import aws_cdk as actions
        
        Stack): lb = elbv2.ApplicationLoadBalancer(self, "LB",
            vpc=vpc,
            internet_facing=True
        )
        
        user_pool = cognito.UserPool(self, "UserPool")
        user_pool_client = cognito.UserPoolClient(self, "Client",
            user_pool=user_pool,
        
            # Required minimal configuration for use with an ELB
            generate_secret=True,
            auth_flows=cognito.AuthFlow(
                user_password=True
            ),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True
                ),
                scopes=[cognito.OAuthScope.EMAIL],
                callback_urls=[f"https://{lb.loadBalancerDnsName}/oauth2/idpresponse"
                ]
            )
        )
        cfn_client = user_pool_client.node.default_child
        cfn_client.add_property_override("RefreshTokenValidity", 1)
        cfn_client.add_property_override("SupportedIdentityProviders", ["COGNITO"])
        
        user_pool_domain = cognito.UserPoolDomain(self, "Domain",
            user_pool=user_pool,
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix="test-cdk-prefix"
            )
        )
        
        lb.add_listener("Listener",
            port=443,
            certificates=[certificate],
            default_action=actions.AuthenticateCognitoAction(
                user_pool=user_pool,
                user_pool_client=user_pool_client,
                user_pool_domain=user_pool_domain,
                next=elbv2.ListenerAction.fixed_response(200,
                    content_type="text/plain",
                    message_body="Authenticated"
                )
            )
        )
        
        CfnOutput(self, "DNS",
            value=lb.load_balancer_dns_name
        )
        
        app = App()
        CognitoStack(app, "integ-cognito")
        app.synth()
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user_pool_id: builtins.str,
        access_token_validity: typing.Optional[jsii.Number] = None,
        allowed_o_auth_flows: typing.Optional[typing.Sequence[builtins.str]] = None,
        allowed_o_auth_flows_user_pool_client: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        allowed_o_auth_scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
        analytics_configuration: typing.Optional[typing.Union["CfnUserPoolClient.AnalyticsConfigurationProperty", _IResolvable_da3f097b]] = None,
        callback_ur_ls: typing.Optional[typing.Sequence[builtins.str]] = None,
        client_name: typing.Optional[builtins.str] = None,
        default_redirect_uri: typing.Optional[builtins.str] = None,
        enable_token_revocation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        explicit_auth_flows: typing.Optional[typing.Sequence[builtins.str]] = None,
        generate_secret: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        id_token_validity: typing.Optional[jsii.Number] = None,
        logout_ur_ls: typing.Optional[typing.Sequence[builtins.str]] = None,
        prevent_user_existence_errors: typing.Optional[builtins.str] = None,
        read_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
        refresh_token_validity: typing.Optional[jsii.Number] = None,
        supported_identity_providers: typing.Optional[typing.Sequence[builtins.str]] = None,
        token_validity_units: typing.Optional[typing.Union["CfnUserPoolClient.TokenValidityUnitsProperty", _IResolvable_da3f097b]] = None,
        write_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolClient``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param user_pool_id: The user pool ID for the user pool where you want to create a user pool client.
        :param access_token_validity: The time limit, after which the access token is no longer valid and cannot be used.
        :param allowed_o_auth_flows: The allowed OAuth flows. Set to ``code`` to initiate a code grant flow, which provides an authorization code as the response. This code can be exchanged for access tokens with the token endpoint. Set to ``implicit`` to specify that the client should get the access token (and, optionally, ID token, based on scopes) directly. Set to ``client_credentials`` to specify that the client should get the access token (and, optionally, ID token, based on scopes) from the token endpoint using a combination of client and client_secret.
        :param allowed_o_auth_flows_user_pool_client: Set to true if the client is allowed to follow the OAuth protocol when interacting with Amazon Cognito user pools.
        :param allowed_o_auth_scopes: The allowed OAuth scopes. Possible values provided by OAuth are: ``phone`` , ``email`` , ``openid`` , and ``profile`` . Possible values provided by AWS are: ``aws.cognito.signin.user.admin`` . Custom scopes created in Resource Servers are also supported.
        :param analytics_configuration: The Amazon Pinpoint analytics configuration for collecting metrics for this user pool. .. epigraph:: In AWS Regions where isn't available, User Pools only supports sending events to Amazon Pinpoint projects in AWS Region us-east-1. In Regions where is available, User Pools will support sending events to Amazon Pinpoint projects within that same Region.
        :param callback_ur_ls: A list of allowed redirect (callback) URLs for the identity providers. A redirect URI must: - Be an absolute URI. - Be registered with the authorization server. - Not include a fragment component. See `OAuth 2.0 - Redirection Endpoint <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6749#section-3.1.2>`_ . Amazon Cognito requires HTTPS over HTTP except for http://localhost for testing purposes only. App callback URLs such as myapp://example are also supported.
        :param client_name: The client name for the user pool client you would like to create.
        :param default_redirect_uri: The default redirect URI. Must be in the ``CallbackURLs`` list. A redirect URI must: - Be an absolute URI. - Be registered with the authorization server. - Not include a fragment component. See `OAuth 2.0 - Redirection Endpoint <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6749#section-3.1.2>`_ . Amazon Cognito requires HTTPS over HTTP except for http://localhost for testing purposes only. App callback URLs such as myapp://example are also supported.
        :param enable_token_revocation: Activates or deactivates token revocation. For more information about revoking tokens, see `RevokeToken <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RevokeToken.html>`_ . If you don't include this parameter, token revocation is automatically activated for the new user pool client.
        :param explicit_auth_flows: The authentication flows that are supported by the user pool clients. Flow names without the ``ALLOW_`` prefix are no longer supported, in favor of new names with the ``ALLOW_`` prefix. Note that values with ``ALLOW_`` prefix must be used only along with the ``ALLOW_`` prefix. Valid values include: - ``ALLOW_ADMIN_USER_PASSWORD_AUTH`` : Enable admin based user password authentication flow ``ADMIN_USER_PASSWORD_AUTH`` . This setting replaces the ``ADMIN_NO_SRP_AUTH`` setting. With this authentication flow, Amazon Cognito receives the password in the request instead of using the Secure Remote Password (SRP) protocol to verify passwords. - ``ALLOW_CUSTOM_AUTH`` : Enable AWS Lambda trigger based authentication. - ``ALLOW_USER_PASSWORD_AUTH`` : Enable user password-based authentication. In this flow, Amazon Cognito receives the password in the request instead of using the SRP protocol to verify passwords. - ``ALLOW_USER_SRP_AUTH`` : Enable SRP-based authentication. - ``ALLOW_REFRESH_TOKEN_AUTH`` : Enable authflow to refresh tokens.
        :param generate_secret: Boolean to specify whether you want to generate a secret for the user pool client being created.
        :param id_token_validity: The time limit, after which the ID token is no longer valid and cannot be used.
        :param logout_ur_ls: A list of allowed logout URLs for the identity providers.
        :param prevent_user_existence_errors: Use this setting to choose which errors and responses are returned by Cognito APIs during authentication, account confirmation, and password recovery when the user does not exist in the user pool. When set to ``ENABLED`` and the user does not exist, authentication returns an error indicating either the username or password was incorrect, and account confirmation and password recovery return a response indicating a code was sent to a simulated destination. When set to ``LEGACY`` , those APIs will return a ``UserNotFoundException`` exception if the user does not exist in the user pool.
        :param read_attributes: The read attributes.
        :param refresh_token_validity: The time limit, in days, after which the refresh token is no longer valid and can't be used.
        :param supported_identity_providers: A list of provider names for the identity providers that are supported on this client. The following are supported: ``COGNITO`` , ``Facebook`` , ``SignInWithApple`` , ``Google`` and ``LoginWithAmazon`` .
        :param token_validity_units: The units in which the validity times are represented in. Default for RefreshToken is days, and default for ID and access tokens are hours.
        :param write_attributes: The user pool attributes that the app client can write to. If your app client allows users to sign in through an identity provider, this array must include all attributes that are mapped to identity provider attributes. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If your app client lacks write access to a mapped attribute, Amazon Cognito throws an error when it tries to update the attribute. For more information, see `Specifying Identity Provider Attribute Mappings for Your User Pool <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html>`_ .
        '''
        props = CfnUserPoolClientProps(
            user_pool_id=user_pool_id,
            access_token_validity=access_token_validity,
            allowed_o_auth_flows=allowed_o_auth_flows,
            allowed_o_auth_flows_user_pool_client=allowed_o_auth_flows_user_pool_client,
            allowed_o_auth_scopes=allowed_o_auth_scopes,
            analytics_configuration=analytics_configuration,
            callback_ur_ls=callback_ur_ls,
            client_name=client_name,
            default_redirect_uri=default_redirect_uri,
            enable_token_revocation=enable_token_revocation,
            explicit_auth_flows=explicit_auth_flows,
            generate_secret=generate_secret,
            id_token_validity=id_token_validity,
            logout_ur_ls=logout_ur_ls,
            prevent_user_existence_errors=prevent_user_existence_errors,
            read_attributes=read_attributes,
            refresh_token_validity=refresh_token_validity,
            supported_identity_providers=supported_identity_providers,
            token_validity_units=token_validity_units,
            write_attributes=write_attributes,
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
    @jsii.member(jsii_name="attrClientSecret")
    def attr_client_secret(self) -> builtins.str:
        '''
        :cloudformationAttribute: ClientSecret
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrClientSecret"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''
        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool where you want to create a user pool client.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessTokenValidity")
    def access_token_validity(self) -> typing.Optional[jsii.Number]:
        '''The time limit, after which the access token is no longer valid and cannot be used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-accesstokenvalidity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "accessTokenValidity"))

    @access_token_validity.setter
    def access_token_validity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "accessTokenValidity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allowedOAuthFlows")
    def allowed_o_auth_flows(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The allowed OAuth flows.

        Set to ``code`` to initiate a code grant flow, which provides an authorization code as the response. This code can be exchanged for access tokens with the token endpoint.

        Set to ``implicit`` to specify that the client should get the access token (and, optionally, ID token, based on scopes) directly.

        Set to ``client_credentials`` to specify that the client should get the access token (and, optionally, ID token, based on scopes) from the token endpoint using a combination of client and client_secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-allowedoauthflows
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "allowedOAuthFlows"))

    @allowed_o_auth_flows.setter
    def allowed_o_auth_flows(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "allowedOAuthFlows", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allowedOAuthFlowsUserPoolClient")
    def allowed_o_auth_flows_user_pool_client(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Set to true if the client is allowed to follow the OAuth protocol when interacting with Amazon Cognito user pools.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-allowedoauthflowsuserpoolclient
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "allowedOAuthFlowsUserPoolClient"))

    @allowed_o_auth_flows_user_pool_client.setter
    def allowed_o_auth_flows_user_pool_client(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "allowedOAuthFlowsUserPoolClient", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allowedOAuthScopes")
    def allowed_o_auth_scopes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The allowed OAuth scopes.

        Possible values provided by OAuth are: ``phone`` , ``email`` , ``openid`` , and ``profile`` . Possible values provided by AWS are: ``aws.cognito.signin.user.admin`` . Custom scopes created in Resource Servers are also supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-allowedoauthscopes
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "allowedOAuthScopes"))

    @allowed_o_auth_scopes.setter
    def allowed_o_auth_scopes(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "allowedOAuthScopes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="analyticsConfiguration")
    def analytics_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPoolClient.AnalyticsConfigurationProperty", _IResolvable_da3f097b]]:
        '''The Amazon Pinpoint analytics configuration for collecting metrics for this user pool.

        .. epigraph::

           In AWS Regions where isn't available, User Pools only supports sending events to Amazon Pinpoint projects in AWS Region us-east-1. In Regions where is available, User Pools will support sending events to Amazon Pinpoint projects within that same Region.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-analyticsconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPoolClient.AnalyticsConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "analyticsConfiguration"))

    @analytics_configuration.setter
    def analytics_configuration(
        self,
        value: typing.Optional[typing.Union["CfnUserPoolClient.AnalyticsConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "analyticsConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="callbackUrLs")
    def callback_ur_ls(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of allowed redirect (callback) URLs for the identity providers.

        A redirect URI must:

        - Be an absolute URI.
        - Be registered with the authorization server.
        - Not include a fragment component.

        See `OAuth 2.0 - Redirection Endpoint <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6749#section-3.1.2>`_ .

        Amazon Cognito requires HTTPS over HTTP except for http://localhost for testing purposes only.

        App callback URLs such as myapp://example are also supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-callbackurls
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "callbackUrLs"))

    @callback_ur_ls.setter
    def callback_ur_ls(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "callbackUrLs", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clientName")
    def client_name(self) -> typing.Optional[builtins.str]:
        '''The client name for the user pool client you would like to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-clientname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "clientName"))

    @client_name.setter
    def client_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "clientName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultRedirectUri")
    def default_redirect_uri(self) -> typing.Optional[builtins.str]:
        '''The default redirect URI. Must be in the ``CallbackURLs`` list.

        A redirect URI must:

        - Be an absolute URI.
        - Be registered with the authorization server.
        - Not include a fragment component.

        See `OAuth 2.0 - Redirection Endpoint <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6749#section-3.1.2>`_ .

        Amazon Cognito requires HTTPS over HTTP except for http://localhost for testing purposes only.

        App callback URLs such as myapp://example are also supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-defaultredirecturi
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "defaultRedirectUri"))

    @default_redirect_uri.setter
    def default_redirect_uri(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "defaultRedirectUri", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="enableTokenRevocation")
    def enable_token_revocation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Activates or deactivates token revocation. For more information about revoking tokens, see `RevokeToken <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RevokeToken.html>`_ .

        If you don't include this parameter, token revocation is automatically activated for the new user pool client.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-enabletokenrevocation
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "enableTokenRevocation"))

    @enable_token_revocation.setter
    def enable_token_revocation(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "enableTokenRevocation", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="explicitAuthFlows")
    def explicit_auth_flows(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The authentication flows that are supported by the user pool clients.

        Flow names without the ``ALLOW_`` prefix are no longer supported, in favor of new names with the ``ALLOW_`` prefix. Note that values with ``ALLOW_`` prefix must be used only along with the ``ALLOW_`` prefix.

        Valid values include:

        - ``ALLOW_ADMIN_USER_PASSWORD_AUTH`` : Enable admin based user password authentication flow ``ADMIN_USER_PASSWORD_AUTH`` . This setting replaces the ``ADMIN_NO_SRP_AUTH`` setting. With this authentication flow, Amazon Cognito receives the password in the request instead of using the Secure Remote Password (SRP) protocol to verify passwords.
        - ``ALLOW_CUSTOM_AUTH`` : Enable AWS Lambda trigger based authentication.
        - ``ALLOW_USER_PASSWORD_AUTH`` : Enable user password-based authentication. In this flow, Amazon Cognito receives the password in the request instead of using the SRP protocol to verify passwords.
        - ``ALLOW_USER_SRP_AUTH`` : Enable SRP-based authentication.
        - ``ALLOW_REFRESH_TOKEN_AUTH`` : Enable authflow to refresh tokens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-explicitauthflows
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "explicitAuthFlows"))

    @explicit_auth_flows.setter
    def explicit_auth_flows(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "explicitAuthFlows", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="generateSecret")
    def generate_secret(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Boolean to specify whether you want to generate a secret for the user pool client being created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-generatesecret
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "generateSecret"))

    @generate_secret.setter
    def generate_secret(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "generateSecret", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="idTokenValidity")
    def id_token_validity(self) -> typing.Optional[jsii.Number]:
        '''The time limit, after which the ID token is no longer valid and cannot be used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-idtokenvalidity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "idTokenValidity"))

    @id_token_validity.setter
    def id_token_validity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "idTokenValidity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logoutUrLs")
    def logout_ur_ls(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of allowed logout URLs for the identity providers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-logouturls
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "logoutUrLs"))

    @logout_ur_ls.setter
    def logout_ur_ls(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "logoutUrLs", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="preventUserExistenceErrors")
    def prevent_user_existence_errors(self) -> typing.Optional[builtins.str]:
        '''Use this setting to choose which errors and responses are returned by Cognito APIs during authentication, account confirmation, and password recovery when the user does not exist in the user pool.

        When set to ``ENABLED`` and the user does not exist, authentication returns an error indicating either the username or password was incorrect, and account confirmation and password recovery return a response indicating a code was sent to a simulated destination. When set to ``LEGACY`` , those APIs will return a ``UserNotFoundException`` exception if the user does not exist in the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-preventuserexistenceerrors
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "preventUserExistenceErrors"))

    @prevent_user_existence_errors.setter
    def prevent_user_existence_errors(
        self,
        value: typing.Optional[builtins.str],
    ) -> None:
        jsii.set(self, "preventUserExistenceErrors", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="readAttributes")
    def read_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The read attributes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-readattributes
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "readAttributes"))

    @read_attributes.setter
    def read_attributes(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "readAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="refreshTokenValidity")
    def refresh_token_validity(self) -> typing.Optional[jsii.Number]:
        '''The time limit, in days, after which the refresh token is no longer valid and can't be used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-refreshtokenvalidity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "refreshTokenValidity"))

    @refresh_token_validity.setter
    def refresh_token_validity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "refreshTokenValidity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="supportedIdentityProviders")
    def supported_identity_providers(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of provider names for the identity providers that are supported on this client.

        The following are supported: ``COGNITO`` , ``Facebook`` , ``SignInWithApple`` , ``Google`` and ``LoginWithAmazon`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-supportedidentityproviders
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "supportedIdentityProviders"))

    @supported_identity_providers.setter
    def supported_identity_providers(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "supportedIdentityProviders", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tokenValidityUnits")
    def token_validity_units(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPoolClient.TokenValidityUnitsProperty", _IResolvable_da3f097b]]:
        '''The units in which the validity times are represented in.

        Default for RefreshToken is days, and default for ID and access tokens are hours.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-tokenvalidityunits
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPoolClient.TokenValidityUnitsProperty", _IResolvable_da3f097b]], jsii.get(self, "tokenValidityUnits"))

    @token_validity_units.setter
    def token_validity_units(
        self,
        value: typing.Optional[typing.Union["CfnUserPoolClient.TokenValidityUnitsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "tokenValidityUnits", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="writeAttributes")
    def write_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The user pool attributes that the app client can write to.

        If your app client allows users to sign in through an identity provider, this array must include all attributes that are mapped to identity provider attributes. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If your app client lacks write access to a mapped attribute, Amazon Cognito throws an error when it tries to update the attribute. For more information, see `Specifying Identity Provider Attribute Mappings for Your User Pool <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-writeattributes
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "writeAttributes"))

    @write_attributes.setter
    def write_attributes(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "writeAttributes", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolClient.AnalyticsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "application_arn": "applicationArn",
            "application_id": "applicationId",
            "external_id": "externalId",
            "role_arn": "roleArn",
            "user_data_shared": "userDataShared",
        },
    )
    class AnalyticsConfigurationProperty:
        def __init__(
            self,
            *,
            application_arn: typing.Optional[builtins.str] = None,
            application_id: typing.Optional[builtins.str] = None,
            external_id: typing.Optional[builtins.str] = None,
            role_arn: typing.Optional[builtins.str] = None,
            user_data_shared: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The Amazon Pinpoint analytics configuration for collecting metrics for a user pool.

            .. epigraph::

               In Regions where Pinpoint isn't available, User Pools only supports sending events to Amazon Pinpoint projects in us-east-1. In Regions where Pinpoint is available, User Pools will support sending events to Amazon Pinpoint projects within that same Region.

            :param application_arn: The Amazon Resource Name (ARN) of an Amazon Pinpoint project. You can use the Amazon Pinpoint project for integration with the chosen user pool client. Amazon Cognito publishes events to the Amazon Pinpoint project that the app ARN declares.
            :param application_id: The application ID for an Amazon Pinpoint application.
            :param external_id: The external ID.
            :param role_arn: The ARN of an AWS Identity and Access Management role that authorizes Amazon Cognito to publish events to Amazon Pinpoint analytics.
            :param user_data_shared: If ``UserDataShared`` is ``true`` , Amazon Cognito will include user data in the events it publishes to Amazon Pinpoint analytics.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-analyticsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                analytics_configuration_property = cognito.CfnUserPoolClient.AnalyticsConfigurationProperty(
                    application_arn="applicationArn",
                    application_id="applicationId",
                    external_id="externalId",
                    role_arn="roleArn",
                    user_data_shared=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if application_arn is not None:
                self._values["application_arn"] = application_arn
            if application_id is not None:
                self._values["application_id"] = application_id
            if external_id is not None:
                self._values["external_id"] = external_id
            if role_arn is not None:
                self._values["role_arn"] = role_arn
            if user_data_shared is not None:
                self._values["user_data_shared"] = user_data_shared

        @builtins.property
        def application_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of an Amazon Pinpoint project.

            You can use the Amazon Pinpoint project for integration with the chosen user pool client. Amazon Cognito publishes events to the Amazon Pinpoint project that the app ARN declares.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-analyticsconfiguration.html#cfn-cognito-userpoolclient-analyticsconfiguration-applicationarn
            '''
            result = self._values.get("application_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def application_id(self) -> typing.Optional[builtins.str]:
            '''The application ID for an Amazon Pinpoint application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-analyticsconfiguration.html#cfn-cognito-userpoolclient-analyticsconfiguration-applicationid
            '''
            result = self._values.get("application_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def external_id(self) -> typing.Optional[builtins.str]:
            '''The external ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-analyticsconfiguration.html#cfn-cognito-userpoolclient-analyticsconfiguration-externalid
            '''
            result = self._values.get("external_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def role_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of an AWS Identity and Access Management role that authorizes Amazon Cognito to publish events to Amazon Pinpoint analytics.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-analyticsconfiguration.html#cfn-cognito-userpoolclient-analyticsconfiguration-rolearn
            '''
            result = self._values.get("role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def user_data_shared(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If ``UserDataShared`` is ``true`` , Amazon Cognito will include user data in the events it publishes to Amazon Pinpoint analytics.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-analyticsconfiguration.html#cfn-cognito-userpoolclient-analyticsconfiguration-userdatashared
            '''
            result = self._values.get("user_data_shared")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AnalyticsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolClient.TokenValidityUnitsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "access_token": "accessToken",
            "id_token": "idToken",
            "refresh_token": "refreshToken",
        },
    )
    class TokenValidityUnitsProperty:
        def __init__(
            self,
            *,
            access_token: typing.Optional[builtins.str] = None,
            id_token: typing.Optional[builtins.str] = None,
            refresh_token: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The units in which the validity times are represented in.

            Default for RefreshToken is days, and default for ID and access tokens are hours.

            :param access_token: A time unit in “seconds”, “minutes”, “hours” or “days” for the value in AccessTokenValidity, defaults to hours.
            :param id_token: A time unit in “seconds”, “minutes”, “hours” or “days” for the value in IdTokenValidity, defaults to hours.
            :param refresh_token: A time unit in “seconds”, “minutes”, “hours” or “days” for the value in RefreshTokenValidity, defaults to days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-tokenvalidityunits.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                token_validity_units_property = cognito.CfnUserPoolClient.TokenValidityUnitsProperty(
                    access_token="accessToken",
                    id_token="idToken",
                    refresh_token="refreshToken"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if access_token is not None:
                self._values["access_token"] = access_token
            if id_token is not None:
                self._values["id_token"] = id_token
            if refresh_token is not None:
                self._values["refresh_token"] = refresh_token

        @builtins.property
        def access_token(self) -> typing.Optional[builtins.str]:
            '''A time unit in “seconds”, “minutes”, “hours” or “days” for the value in AccessTokenValidity, defaults to hours.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-tokenvalidityunits.html#cfn-cognito-userpoolclient-tokenvalidityunits-accesstoken
            '''
            result = self._values.get("access_token")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def id_token(self) -> typing.Optional[builtins.str]:
            '''A time unit in “seconds”, “minutes”, “hours” or “days” for the value in IdTokenValidity, defaults to hours.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-tokenvalidityunits.html#cfn-cognito-userpoolclient-tokenvalidityunits-idtoken
            '''
            result = self._values.get("id_token")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def refresh_token(self) -> typing.Optional[builtins.str]:
            '''A time unit in “seconds”, “minutes”, “hours” or “days” for the value in RefreshTokenValidity, defaults to days.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolclient-tokenvalidityunits.html#cfn-cognito-userpoolclient-tokenvalidityunits-refreshtoken
            '''
            result = self._values.get("refresh_token")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TokenValidityUnitsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolClientProps",
    jsii_struct_bases=[],
    name_mapping={
        "user_pool_id": "userPoolId",
        "access_token_validity": "accessTokenValidity",
        "allowed_o_auth_flows": "allowedOAuthFlows",
        "allowed_o_auth_flows_user_pool_client": "allowedOAuthFlowsUserPoolClient",
        "allowed_o_auth_scopes": "allowedOAuthScopes",
        "analytics_configuration": "analyticsConfiguration",
        "callback_ur_ls": "callbackUrLs",
        "client_name": "clientName",
        "default_redirect_uri": "defaultRedirectUri",
        "enable_token_revocation": "enableTokenRevocation",
        "explicit_auth_flows": "explicitAuthFlows",
        "generate_secret": "generateSecret",
        "id_token_validity": "idTokenValidity",
        "logout_ur_ls": "logoutUrLs",
        "prevent_user_existence_errors": "preventUserExistenceErrors",
        "read_attributes": "readAttributes",
        "refresh_token_validity": "refreshTokenValidity",
        "supported_identity_providers": "supportedIdentityProviders",
        "token_validity_units": "tokenValidityUnits",
        "write_attributes": "writeAttributes",
    },
)
class CfnUserPoolClientProps:
    def __init__(
        self,
        *,
        user_pool_id: builtins.str,
        access_token_validity: typing.Optional[jsii.Number] = None,
        allowed_o_auth_flows: typing.Optional[typing.Sequence[builtins.str]] = None,
        allowed_o_auth_flows_user_pool_client: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        allowed_o_auth_scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
        analytics_configuration: typing.Optional[typing.Union[CfnUserPoolClient.AnalyticsConfigurationProperty, _IResolvable_da3f097b]] = None,
        callback_ur_ls: typing.Optional[typing.Sequence[builtins.str]] = None,
        client_name: typing.Optional[builtins.str] = None,
        default_redirect_uri: typing.Optional[builtins.str] = None,
        enable_token_revocation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        explicit_auth_flows: typing.Optional[typing.Sequence[builtins.str]] = None,
        generate_secret: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        id_token_validity: typing.Optional[jsii.Number] = None,
        logout_ur_ls: typing.Optional[typing.Sequence[builtins.str]] = None,
        prevent_user_existence_errors: typing.Optional[builtins.str] = None,
        read_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
        refresh_token_validity: typing.Optional[jsii.Number] = None,
        supported_identity_providers: typing.Optional[typing.Sequence[builtins.str]] = None,
        token_validity_units: typing.Optional[typing.Union[CfnUserPoolClient.TokenValidityUnitsProperty, _IResolvable_da3f097b]] = None,
        write_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolClient``.

        :param user_pool_id: The user pool ID for the user pool where you want to create a user pool client.
        :param access_token_validity: The time limit, after which the access token is no longer valid and cannot be used.
        :param allowed_o_auth_flows: The allowed OAuth flows. Set to ``code`` to initiate a code grant flow, which provides an authorization code as the response. This code can be exchanged for access tokens with the token endpoint. Set to ``implicit`` to specify that the client should get the access token (and, optionally, ID token, based on scopes) directly. Set to ``client_credentials`` to specify that the client should get the access token (and, optionally, ID token, based on scopes) from the token endpoint using a combination of client and client_secret.
        :param allowed_o_auth_flows_user_pool_client: Set to true if the client is allowed to follow the OAuth protocol when interacting with Amazon Cognito user pools.
        :param allowed_o_auth_scopes: The allowed OAuth scopes. Possible values provided by OAuth are: ``phone`` , ``email`` , ``openid`` , and ``profile`` . Possible values provided by AWS are: ``aws.cognito.signin.user.admin`` . Custom scopes created in Resource Servers are also supported.
        :param analytics_configuration: The Amazon Pinpoint analytics configuration for collecting metrics for this user pool. .. epigraph:: In AWS Regions where isn't available, User Pools only supports sending events to Amazon Pinpoint projects in AWS Region us-east-1. In Regions where is available, User Pools will support sending events to Amazon Pinpoint projects within that same Region.
        :param callback_ur_ls: A list of allowed redirect (callback) URLs for the identity providers. A redirect URI must: - Be an absolute URI. - Be registered with the authorization server. - Not include a fragment component. See `OAuth 2.0 - Redirection Endpoint <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6749#section-3.1.2>`_ . Amazon Cognito requires HTTPS over HTTP except for http://localhost for testing purposes only. App callback URLs such as myapp://example are also supported.
        :param client_name: The client name for the user pool client you would like to create.
        :param default_redirect_uri: The default redirect URI. Must be in the ``CallbackURLs`` list. A redirect URI must: - Be an absolute URI. - Be registered with the authorization server. - Not include a fragment component. See `OAuth 2.0 - Redirection Endpoint <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6749#section-3.1.2>`_ . Amazon Cognito requires HTTPS over HTTP except for http://localhost for testing purposes only. App callback URLs such as myapp://example are also supported.
        :param enable_token_revocation: Activates or deactivates token revocation. For more information about revoking tokens, see `RevokeToken <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RevokeToken.html>`_ . If you don't include this parameter, token revocation is automatically activated for the new user pool client.
        :param explicit_auth_flows: The authentication flows that are supported by the user pool clients. Flow names without the ``ALLOW_`` prefix are no longer supported, in favor of new names with the ``ALLOW_`` prefix. Note that values with ``ALLOW_`` prefix must be used only along with the ``ALLOW_`` prefix. Valid values include: - ``ALLOW_ADMIN_USER_PASSWORD_AUTH`` : Enable admin based user password authentication flow ``ADMIN_USER_PASSWORD_AUTH`` . This setting replaces the ``ADMIN_NO_SRP_AUTH`` setting. With this authentication flow, Amazon Cognito receives the password in the request instead of using the Secure Remote Password (SRP) protocol to verify passwords. - ``ALLOW_CUSTOM_AUTH`` : Enable AWS Lambda trigger based authentication. - ``ALLOW_USER_PASSWORD_AUTH`` : Enable user password-based authentication. In this flow, Amazon Cognito receives the password in the request instead of using the SRP protocol to verify passwords. - ``ALLOW_USER_SRP_AUTH`` : Enable SRP-based authentication. - ``ALLOW_REFRESH_TOKEN_AUTH`` : Enable authflow to refresh tokens.
        :param generate_secret: Boolean to specify whether you want to generate a secret for the user pool client being created.
        :param id_token_validity: The time limit, after which the ID token is no longer valid and cannot be used.
        :param logout_ur_ls: A list of allowed logout URLs for the identity providers.
        :param prevent_user_existence_errors: Use this setting to choose which errors and responses are returned by Cognito APIs during authentication, account confirmation, and password recovery when the user does not exist in the user pool. When set to ``ENABLED`` and the user does not exist, authentication returns an error indicating either the username or password was incorrect, and account confirmation and password recovery return a response indicating a code was sent to a simulated destination. When set to ``LEGACY`` , those APIs will return a ``UserNotFoundException`` exception if the user does not exist in the user pool.
        :param read_attributes: The read attributes.
        :param refresh_token_validity: The time limit, in days, after which the refresh token is no longer valid and can't be used.
        :param supported_identity_providers: A list of provider names for the identity providers that are supported on this client. The following are supported: ``COGNITO`` , ``Facebook`` , ``SignInWithApple`` , ``Google`` and ``LoginWithAmazon`` .
        :param token_validity_units: The units in which the validity times are represented in. Default for RefreshToken is days, and default for ID and access tokens are hours.
        :param write_attributes: The user pool attributes that the app client can write to. If your app client allows users to sign in through an identity provider, this array must include all attributes that are mapped to identity provider attributes. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If your app client lacks write access to a mapped attribute, Amazon Cognito throws an error when it tries to update the attribute. For more information, see `Specifying Identity Provider Attribute Mappings for Your User Pool <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            cfn_user_pool_client_props = cognito.CfnUserPoolClientProps(
                user_pool_id="userPoolId",
            
                # the properties below are optional
                access_token_validity=123,
                allowed_oAuth_flows=["allowedOAuthFlows"],
                allowed_oAuth_flows_user_pool_client=False,
                allowed_oAuth_scopes=["allowedOAuthScopes"],
                analytics_configuration=cognito.CfnUserPoolClient.AnalyticsConfigurationProperty(
                    application_arn="applicationArn",
                    application_id="applicationId",
                    external_id="externalId",
                    role_arn="roleArn",
                    user_data_shared=False
                ),
                callback_ur_ls=["callbackUrLs"],
                client_name="clientName",
                default_redirect_uri="defaultRedirectUri",
                enable_token_revocation=False,
                explicit_auth_flows=["explicitAuthFlows"],
                generate_secret=False,
                id_token_validity=123,
                logout_ur_ls=["logoutUrLs"],
                prevent_user_existence_errors="preventUserExistenceErrors",
                read_attributes=["readAttributes"],
                refresh_token_validity=123,
                supported_identity_providers=["supportedIdentityProviders"],
                token_validity_units=cognito.CfnUserPoolClient.TokenValidityUnitsProperty(
                    access_token="accessToken",
                    id_token="idToken",
                    refresh_token="refreshToken"
                ),
                write_attributes=["writeAttributes"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool_id": user_pool_id,
        }
        if access_token_validity is not None:
            self._values["access_token_validity"] = access_token_validity
        if allowed_o_auth_flows is not None:
            self._values["allowed_o_auth_flows"] = allowed_o_auth_flows
        if allowed_o_auth_flows_user_pool_client is not None:
            self._values["allowed_o_auth_flows_user_pool_client"] = allowed_o_auth_flows_user_pool_client
        if allowed_o_auth_scopes is not None:
            self._values["allowed_o_auth_scopes"] = allowed_o_auth_scopes
        if analytics_configuration is not None:
            self._values["analytics_configuration"] = analytics_configuration
        if callback_ur_ls is not None:
            self._values["callback_ur_ls"] = callback_ur_ls
        if client_name is not None:
            self._values["client_name"] = client_name
        if default_redirect_uri is not None:
            self._values["default_redirect_uri"] = default_redirect_uri
        if enable_token_revocation is not None:
            self._values["enable_token_revocation"] = enable_token_revocation
        if explicit_auth_flows is not None:
            self._values["explicit_auth_flows"] = explicit_auth_flows
        if generate_secret is not None:
            self._values["generate_secret"] = generate_secret
        if id_token_validity is not None:
            self._values["id_token_validity"] = id_token_validity
        if logout_ur_ls is not None:
            self._values["logout_ur_ls"] = logout_ur_ls
        if prevent_user_existence_errors is not None:
            self._values["prevent_user_existence_errors"] = prevent_user_existence_errors
        if read_attributes is not None:
            self._values["read_attributes"] = read_attributes
        if refresh_token_validity is not None:
            self._values["refresh_token_validity"] = refresh_token_validity
        if supported_identity_providers is not None:
            self._values["supported_identity_providers"] = supported_identity_providers
        if token_validity_units is not None:
            self._values["token_validity_units"] = token_validity_units
        if write_attributes is not None:
            self._values["write_attributes"] = write_attributes

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool where you want to create a user pool client.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def access_token_validity(self) -> typing.Optional[jsii.Number]:
        '''The time limit, after which the access token is no longer valid and cannot be used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-accesstokenvalidity
        '''
        result = self._values.get("access_token_validity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def allowed_o_auth_flows(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The allowed OAuth flows.

        Set to ``code`` to initiate a code grant flow, which provides an authorization code as the response. This code can be exchanged for access tokens with the token endpoint.

        Set to ``implicit`` to specify that the client should get the access token (and, optionally, ID token, based on scopes) directly.

        Set to ``client_credentials`` to specify that the client should get the access token (and, optionally, ID token, based on scopes) from the token endpoint using a combination of client and client_secret.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-allowedoauthflows
        '''
        result = self._values.get("allowed_o_auth_flows")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def allowed_o_auth_flows_user_pool_client(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Set to true if the client is allowed to follow the OAuth protocol when interacting with Amazon Cognito user pools.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-allowedoauthflowsuserpoolclient
        '''
        result = self._values.get("allowed_o_auth_flows_user_pool_client")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def allowed_o_auth_scopes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The allowed OAuth scopes.

        Possible values provided by OAuth are: ``phone`` , ``email`` , ``openid`` , and ``profile`` . Possible values provided by AWS are: ``aws.cognito.signin.user.admin`` . Custom scopes created in Resource Servers are also supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-allowedoauthscopes
        '''
        result = self._values.get("allowed_o_auth_scopes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def analytics_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPoolClient.AnalyticsConfigurationProperty, _IResolvable_da3f097b]]:
        '''The Amazon Pinpoint analytics configuration for collecting metrics for this user pool.

        .. epigraph::

           In AWS Regions where isn't available, User Pools only supports sending events to Amazon Pinpoint projects in AWS Region us-east-1. In Regions where is available, User Pools will support sending events to Amazon Pinpoint projects within that same Region.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-analyticsconfiguration
        '''
        result = self._values.get("analytics_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnUserPoolClient.AnalyticsConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def callback_ur_ls(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of allowed redirect (callback) URLs for the identity providers.

        A redirect URI must:

        - Be an absolute URI.
        - Be registered with the authorization server.
        - Not include a fragment component.

        See `OAuth 2.0 - Redirection Endpoint <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6749#section-3.1.2>`_ .

        Amazon Cognito requires HTTPS over HTTP except for http://localhost for testing purposes only.

        App callback URLs such as myapp://example are also supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-callbackurls
        '''
        result = self._values.get("callback_ur_ls")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def client_name(self) -> typing.Optional[builtins.str]:
        '''The client name for the user pool client you would like to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-clientname
        '''
        result = self._values.get("client_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def default_redirect_uri(self) -> typing.Optional[builtins.str]:
        '''The default redirect URI. Must be in the ``CallbackURLs`` list.

        A redirect URI must:

        - Be an absolute URI.
        - Be registered with the authorization server.
        - Not include a fragment component.

        See `OAuth 2.0 - Redirection Endpoint <https://docs.aws.amazon.com/https://tools.ietf.org/html/rfc6749#section-3.1.2>`_ .

        Amazon Cognito requires HTTPS over HTTP except for http://localhost for testing purposes only.

        App callback URLs such as myapp://example are also supported.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-defaultredirecturi
        '''
        result = self._values.get("default_redirect_uri")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_token_revocation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Activates or deactivates token revocation. For more information about revoking tokens, see `RevokeToken <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RevokeToken.html>`_ .

        If you don't include this parameter, token revocation is automatically activated for the new user pool client.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-enabletokenrevocation
        '''
        result = self._values.get("enable_token_revocation")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def explicit_auth_flows(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The authentication flows that are supported by the user pool clients.

        Flow names without the ``ALLOW_`` prefix are no longer supported, in favor of new names with the ``ALLOW_`` prefix. Note that values with ``ALLOW_`` prefix must be used only along with the ``ALLOW_`` prefix.

        Valid values include:

        - ``ALLOW_ADMIN_USER_PASSWORD_AUTH`` : Enable admin based user password authentication flow ``ADMIN_USER_PASSWORD_AUTH`` . This setting replaces the ``ADMIN_NO_SRP_AUTH`` setting. With this authentication flow, Amazon Cognito receives the password in the request instead of using the Secure Remote Password (SRP) protocol to verify passwords.
        - ``ALLOW_CUSTOM_AUTH`` : Enable AWS Lambda trigger based authentication.
        - ``ALLOW_USER_PASSWORD_AUTH`` : Enable user password-based authentication. In this flow, Amazon Cognito receives the password in the request instead of using the SRP protocol to verify passwords.
        - ``ALLOW_USER_SRP_AUTH`` : Enable SRP-based authentication.
        - ``ALLOW_REFRESH_TOKEN_AUTH`` : Enable authflow to refresh tokens.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-explicitauthflows
        '''
        result = self._values.get("explicit_auth_flows")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def generate_secret(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Boolean to specify whether you want to generate a secret for the user pool client being created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-generatesecret
        '''
        result = self._values.get("generate_secret")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def id_token_validity(self) -> typing.Optional[jsii.Number]:
        '''The time limit, after which the ID token is no longer valid and cannot be used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-idtokenvalidity
        '''
        result = self._values.get("id_token_validity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def logout_ur_ls(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of allowed logout URLs for the identity providers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-logouturls
        '''
        result = self._values.get("logout_ur_ls")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def prevent_user_existence_errors(self) -> typing.Optional[builtins.str]:
        '''Use this setting to choose which errors and responses are returned by Cognito APIs during authentication, account confirmation, and password recovery when the user does not exist in the user pool.

        When set to ``ENABLED`` and the user does not exist, authentication returns an error indicating either the username or password was incorrect, and account confirmation and password recovery return a response indicating a code was sent to a simulated destination. When set to ``LEGACY`` , those APIs will return a ``UserNotFoundException`` exception if the user does not exist in the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-preventuserexistenceerrors
        '''
        result = self._values.get("prevent_user_existence_errors")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def read_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The read attributes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-readattributes
        '''
        result = self._values.get("read_attributes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def refresh_token_validity(self) -> typing.Optional[jsii.Number]:
        '''The time limit, in days, after which the refresh token is no longer valid and can't be used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-refreshtokenvalidity
        '''
        result = self._values.get("refresh_token_validity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def supported_identity_providers(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of provider names for the identity providers that are supported on this client.

        The following are supported: ``COGNITO`` , ``Facebook`` , ``SignInWithApple`` , ``Google`` and ``LoginWithAmazon`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-supportedidentityproviders
        '''
        result = self._values.get("supported_identity_providers")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def token_validity_units(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPoolClient.TokenValidityUnitsProperty, _IResolvable_da3f097b]]:
        '''The units in which the validity times are represented in.

        Default for RefreshToken is days, and default for ID and access tokens are hours.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-tokenvalidityunits
        '''
        result = self._values.get("token_validity_units")
        return typing.cast(typing.Optional[typing.Union[CfnUserPoolClient.TokenValidityUnitsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def write_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The user pool attributes that the app client can write to.

        If your app client allows users to sign in through an identity provider, this array must include all attributes that are mapped to identity provider attributes. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If your app client lacks write access to a mapped attribute, Amazon Cognito throws an error when it tries to update the attribute. For more information, see `Specifying Identity Provider Attribute Mappings for Your User Pool <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-writeattributes
        '''
        result = self._values.get("write_attributes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolClientProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolDomain(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolDomain",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolDomain``.

    The AWS::Cognito::UserPoolDomain resource creates a new domain for a user pool.

    :cloudformationResource: AWS::Cognito::UserPoolDomain
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooldomain.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        cfn_user_pool_domain = cognito.CfnUserPoolDomain(self, "MyCfnUserPoolDomain",
            domain="domain",
            user_pool_id="userPoolId",
        
            # the properties below are optional
            custom_domain_config=cognito.CfnUserPoolDomain.CustomDomainConfigTypeProperty(
                certificate_arn="certificateArn"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain: builtins.str,
        user_pool_id: builtins.str,
        custom_domain_config: typing.Optional[typing.Union["CfnUserPoolDomain.CustomDomainConfigTypeProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolDomain``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param domain: The domain name for the domain that hosts the sign-up and sign-in pages for your application. For example: ``auth.example.com`` . If you're using a prefix domain, this field denotes the first part of the domain before ``.auth.[region].amazoncognito.com`` . This string can include only lowercase letters, numbers, and hyphens. Don't use a hyphen for the first or last character. Use periods to separate subdomain names.
        :param user_pool_id: The user pool ID for the user pool where you want to associate a user pool domain.
        :param custom_domain_config: The configuration for a custom domain that hosts the sign-up and sign-in pages for your application. Use this object to specify an SSL certificate that is managed by ACM.
        '''
        props = CfnUserPoolDomainProps(
            domain=domain,
            user_pool_id=user_pool_id,
            custom_domain_config=custom_domain_config,
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
    @jsii.member(jsii_name="domain")
    def domain(self) -> builtins.str:
        '''The domain name for the domain that hosts the sign-up and sign-in pages for your application.

        For example: ``auth.example.com`` . If you're using a prefix domain, this field denotes the first part of the domain before ``.auth.[region].amazoncognito.com`` .

        This string can include only lowercase letters, numbers, and hyphens. Don't use a hyphen for the first or last character. Use periods to separate subdomain names.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooldomain.html#cfn-cognito-userpooldomain-domain
        '''
        return typing.cast(builtins.str, jsii.get(self, "domain"))

    @domain.setter
    def domain(self, value: builtins.str) -> None:
        jsii.set(self, "domain", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool where you want to associate a user pool domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooldomain.html#cfn-cognito-userpooldomain-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="customDomainConfig")
    def custom_domain_config(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPoolDomain.CustomDomainConfigTypeProperty", _IResolvable_da3f097b]]:
        '''The configuration for a custom domain that hosts the sign-up and sign-in pages for your application.

        Use this object to specify an SSL certificate that is managed by ACM.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooldomain.html#cfn-cognito-userpooldomain-customdomainconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPoolDomain.CustomDomainConfigTypeProperty", _IResolvable_da3f097b]], jsii.get(self, "customDomainConfig"))

    @custom_domain_config.setter
    def custom_domain_config(
        self,
        value: typing.Optional[typing.Union["CfnUserPoolDomain.CustomDomainConfigTypeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "customDomainConfig", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolDomain.CustomDomainConfigTypeProperty",
        jsii_struct_bases=[],
        name_mapping={"certificate_arn": "certificateArn"},
    )
    class CustomDomainConfigTypeProperty:
        def __init__(
            self,
            *,
            certificate_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration for a custom domain that hosts the sign-up and sign-in webpages for your application.

            :param certificate_arn: The Amazon Resource Name (ARN) of an AWS Certificate Manager SSL certificate. You use this certificate for the subdomain of your custom domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpooldomain-customdomainconfigtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                custom_domain_config_type_property = cognito.CfnUserPoolDomain.CustomDomainConfigTypeProperty(
                    certificate_arn="certificateArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if certificate_arn is not None:
                self._values["certificate_arn"] = certificate_arn

        @builtins.property
        def certificate_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of an AWS Certificate Manager SSL certificate.

            You use this certificate for the subdomain of your custom domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpooldomain-customdomainconfigtype.html#cfn-cognito-userpooldomain-customdomainconfigtype-certificatearn
            '''
            result = self._values.get("certificate_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomDomainConfigTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolDomainProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain": "domain",
        "user_pool_id": "userPoolId",
        "custom_domain_config": "customDomainConfig",
    },
)
class CfnUserPoolDomainProps:
    def __init__(
        self,
        *,
        domain: builtins.str,
        user_pool_id: builtins.str,
        custom_domain_config: typing.Optional[typing.Union[CfnUserPoolDomain.CustomDomainConfigTypeProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolDomain``.

        :param domain: The domain name for the domain that hosts the sign-up and sign-in pages for your application. For example: ``auth.example.com`` . If you're using a prefix domain, this field denotes the first part of the domain before ``.auth.[region].amazoncognito.com`` . This string can include only lowercase letters, numbers, and hyphens. Don't use a hyphen for the first or last character. Use periods to separate subdomain names.
        :param user_pool_id: The user pool ID for the user pool where you want to associate a user pool domain.
        :param custom_domain_config: The configuration for a custom domain that hosts the sign-up and sign-in pages for your application. Use this object to specify an SSL certificate that is managed by ACM.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooldomain.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            cfn_user_pool_domain_props = cognito.CfnUserPoolDomainProps(
                domain="domain",
                user_pool_id="userPoolId",
            
                # the properties below are optional
                custom_domain_config=cognito.CfnUserPoolDomain.CustomDomainConfigTypeProperty(
                    certificate_arn="certificateArn"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain": domain,
            "user_pool_id": user_pool_id,
        }
        if custom_domain_config is not None:
            self._values["custom_domain_config"] = custom_domain_config

    @builtins.property
    def domain(self) -> builtins.str:
        '''The domain name for the domain that hosts the sign-up and sign-in pages for your application.

        For example: ``auth.example.com`` . If you're using a prefix domain, this field denotes the first part of the domain before ``.auth.[region].amazoncognito.com`` .

        This string can include only lowercase letters, numbers, and hyphens. Don't use a hyphen for the first or last character. Use periods to separate subdomain names.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooldomain.html#cfn-cognito-userpooldomain-domain
        '''
        result = self._values.get("domain")
        assert result is not None, "Required property 'domain' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool where you want to associate a user pool domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooldomain.html#cfn-cognito-userpooldomain-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def custom_domain_config(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPoolDomain.CustomDomainConfigTypeProperty, _IResolvable_da3f097b]]:
        '''The configuration for a custom domain that hosts the sign-up and sign-in pages for your application.

        Use this object to specify an SSL certificate that is managed by ACM.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooldomain.html#cfn-cognito-userpooldomain-customdomainconfig
        '''
        result = self._values.get("custom_domain_config")
        return typing.cast(typing.Optional[typing.Union[CfnUserPoolDomain.CustomDomainConfigTypeProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolDomainProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolGroup",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolGroup``.

    Specifies a new group in the identified user pool.

    Calling this action requires developer credentials.

    :cloudformationResource: AWS::Cognito::UserPoolGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        cfn_user_pool_group = cognito.CfnUserPoolGroup(self, "MyCfnUserPoolGroup",
            user_pool_id="userPoolId",
        
            # the properties below are optional
            description="description",
            group_name="groupName",
            precedence=123,
            role_arn="roleArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user_pool_id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        group_name: typing.Optional[builtins.str] = None,
        precedence: typing.Optional[jsii.Number] = None,
        role_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param user_pool_id: The user pool ID for the user pool.
        :param description: A string containing the description of the group.
        :param group_name: The name of the group. Must be unique.
        :param precedence: A non-negative integer value that specifies the precedence of this group relative to the other groups that a user can belong to in the user pool. Zero is the highest precedence value. Groups with lower ``Precedence`` values take precedence over groups with higher ornull ``Precedence`` values. If a user belongs to two or more groups, it is the group with the lowest precedence value whose role ARN is given in the user's tokens for the ``cognito:roles`` and ``cognito:preferred_role`` claims. Two groups can have the same ``Precedence`` value. If this happens, neither group takes precedence over the other. If two groups with the same ``Precedence`` have the same role ARN, that role is used in the ``cognito:preferred_role`` claim in tokens for users in each group. If the two groups have different role ARNs, the ``cognito:preferred_role`` claim isn't set in users' tokens. The default ``Precedence`` value is null.
        :param role_arn: The role Amazon Resource Name (ARN) for the group.
        '''
        props = CfnUserPoolGroupProps(
            user_pool_id=user_pool_id,
            description=description,
            group_name=group_name,
            precedence=precedence,
            role_arn=role_arn,
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
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A string containing the description of the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="groupName")
    def group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the group.

        Must be unique.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-groupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "groupName"))

    @group_name.setter
    def group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "groupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="precedence")
    def precedence(self) -> typing.Optional[jsii.Number]:
        '''A non-negative integer value that specifies the precedence of this group relative to the other groups that a user can belong to in the user pool.

        Zero is the highest precedence value. Groups with lower ``Precedence`` values take precedence over groups with higher ornull ``Precedence`` values. If a user belongs to two or more groups, it is the group with the lowest precedence value whose role ARN is given in the user's tokens for the ``cognito:roles`` and ``cognito:preferred_role`` claims.

        Two groups can have the same ``Precedence`` value. If this happens, neither group takes precedence over the other. If two groups with the same ``Precedence`` have the same role ARN, that role is used in the ``cognito:preferred_role`` claim in tokens for users in each group. If the two groups have different role ARNs, the ``cognito:preferred_role`` claim isn't set in users' tokens.

        The default ``Precedence`` value is null.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-precedence
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "precedence"))

    @precedence.setter
    def precedence(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "precedence", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The role Amazon Resource Name (ARN) for the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-rolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "roleArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "user_pool_id": "userPoolId",
        "description": "description",
        "group_name": "groupName",
        "precedence": "precedence",
        "role_arn": "roleArn",
    },
)
class CfnUserPoolGroupProps:
    def __init__(
        self,
        *,
        user_pool_id: builtins.str,
        description: typing.Optional[builtins.str] = None,
        group_name: typing.Optional[builtins.str] = None,
        precedence: typing.Optional[jsii.Number] = None,
        role_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolGroup``.

        :param user_pool_id: The user pool ID for the user pool.
        :param description: A string containing the description of the group.
        :param group_name: The name of the group. Must be unique.
        :param precedence: A non-negative integer value that specifies the precedence of this group relative to the other groups that a user can belong to in the user pool. Zero is the highest precedence value. Groups with lower ``Precedence`` values take precedence over groups with higher ornull ``Precedence`` values. If a user belongs to two or more groups, it is the group with the lowest precedence value whose role ARN is given in the user's tokens for the ``cognito:roles`` and ``cognito:preferred_role`` claims. Two groups can have the same ``Precedence`` value. If this happens, neither group takes precedence over the other. If two groups with the same ``Precedence`` have the same role ARN, that role is used in the ``cognito:preferred_role`` claim in tokens for users in each group. If the two groups have different role ARNs, the ``cognito:preferred_role`` claim isn't set in users' tokens. The default ``Precedence`` value is null.
        :param role_arn: The role Amazon Resource Name (ARN) for the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            cfn_user_pool_group_props = cognito.CfnUserPoolGroupProps(
                user_pool_id="userPoolId",
            
                # the properties below are optional
                description="description",
                group_name="groupName",
                precedence=123,
                role_arn="roleArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool_id": user_pool_id,
        }
        if description is not None:
            self._values["description"] = description
        if group_name is not None:
            self._values["group_name"] = group_name
        if precedence is not None:
            self._values["precedence"] = precedence
        if role_arn is not None:
            self._values["role_arn"] = role_arn

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A string containing the description of the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the group.

        Must be unique.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-groupname
        '''
        result = self._values.get("group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def precedence(self) -> typing.Optional[jsii.Number]:
        '''A non-negative integer value that specifies the precedence of this group relative to the other groups that a user can belong to in the user pool.

        Zero is the highest precedence value. Groups with lower ``Precedence`` values take precedence over groups with higher ornull ``Precedence`` values. If a user belongs to two or more groups, it is the group with the lowest precedence value whose role ARN is given in the user's tokens for the ``cognito:roles`` and ``cognito:preferred_role`` claims.

        Two groups can have the same ``Precedence`` value. If this happens, neither group takes precedence over the other. If two groups with the same ``Precedence`` have the same role ARN, that role is used in the ``cognito:preferred_role`` claim in tokens for users in each group. If the two groups have different role ARNs, the ``cognito:preferred_role`` claim isn't set in users' tokens.

        The default ``Precedence`` value is null.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-precedence
        '''
        result = self._values.get("precedence")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The role Amazon Resource Name (ARN) for the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolgroup.html#cfn-cognito-userpoolgroup-rolearn
        '''
        result = self._values.get("role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolIdentityProvider(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolIdentityProvider",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolIdentityProvider``.

    The ``AWS::Cognito::UserPoolIdentityProvider`` resource creates an identity provider for a user pool.

    :cloudformationResource: AWS::Cognito::UserPoolIdentityProvider
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        # attribute_mapping: Any
        # provider_details: Any
        
        cfn_user_pool_identity_provider = cognito.CfnUserPoolIdentityProvider(self, "MyCfnUserPoolIdentityProvider",
            provider_name="providerName",
            provider_type="providerType",
            user_pool_id="userPoolId",
        
            # the properties below are optional
            attribute_mapping=attribute_mapping,
            idp_identifiers=["idpIdentifiers"],
            provider_details=provider_details
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        provider_name: builtins.str,
        provider_type: builtins.str,
        user_pool_id: builtins.str,
        attribute_mapping: typing.Any = None,
        idp_identifiers: typing.Optional[typing.Sequence[builtins.str]] = None,
        provider_details: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolIdentityProvider``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param provider_name: The identity provider name.
        :param provider_type: The identity provider type.
        :param user_pool_id: The user pool ID.
        :param attribute_mapping: A mapping of identity provider attributes to standard and custom user pool attributes.
        :param idp_identifiers: A list of identity provider identifiers.
        :param provider_details: The identity provider details. The following list describes the provider detail keys for each identity provider type. - For Google and Login with Amazon: - client_id - client_secret - authorize_scopes - For Facebook: - client_id - client_secret - authorize_scopes - api_version - For Sign in with Apple: - client_id - team_id - key_id - private_key - authorize_scopes - For OpenID Connect (OIDC) providers: - client_id - client_secret - attributes_request_method - oidc_issuer - authorize_scopes - authorize_url *if not available from discovery URL specified by oidc_issuer key* - token_url *if not available from discovery URL specified by oidc_issuer key* - attributes_url *if not available from discovery URL specified by oidc_issuer key* - jwks_uri *if not available from discovery URL specified by oidc_issuer key* - attributes_url_add_attributes *a read-only property that is set automatically* - For SAML providers: - MetadataFile OR MetadataURL - IDPSignout (optional)
        '''
        props = CfnUserPoolIdentityProviderProps(
            provider_name=provider_name,
            provider_type=provider_type,
            user_pool_id=user_pool_id,
            attribute_mapping=attribute_mapping,
            idp_identifiers=idp_identifiers,
            provider_details=provider_details,
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
    @jsii.member(jsii_name="attributeMapping")
    def attribute_mapping(self) -> typing.Any:
        '''A mapping of identity provider attributes to standard and custom user pool attributes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-attributemapping
        '''
        return typing.cast(typing.Any, jsii.get(self, "attributeMapping"))

    @attribute_mapping.setter
    def attribute_mapping(self, value: typing.Any) -> None:
        jsii.set(self, "attributeMapping", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerDetails")
    def provider_details(self) -> typing.Any:
        '''The identity provider details. The following list describes the provider detail keys for each identity provider type.

        - For Google and Login with Amazon:
        - client_id
        - client_secret
        - authorize_scopes
        - For Facebook:
        - client_id
        - client_secret
        - authorize_scopes
        - api_version
        - For Sign in with Apple:
        - client_id
        - team_id
        - key_id
        - private_key
        - authorize_scopes
        - For OpenID Connect (OIDC) providers:
        - client_id
        - client_secret
        - attributes_request_method
        - oidc_issuer
        - authorize_scopes
        - authorize_url *if not available from discovery URL specified by oidc_issuer key*
        - token_url *if not available from discovery URL specified by oidc_issuer key*
        - attributes_url *if not available from discovery URL specified by oidc_issuer key*
        - jwks_uri *if not available from discovery URL specified by oidc_issuer key*
        - attributes_url_add_attributes *a read-only property that is set automatically*
        - For SAML providers:
        - MetadataFile OR MetadataURL
        - IDPSignout (optional)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-providerdetails
        '''
        return typing.cast(typing.Any, jsii.get(self, "providerDetails"))

    @provider_details.setter
    def provider_details(self, value: typing.Any) -> None:
        jsii.set(self, "providerDetails", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerName")
    def provider_name(self) -> builtins.str:
        '''The identity provider name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-providername
        '''
        return typing.cast(builtins.str, jsii.get(self, "providerName"))

    @provider_name.setter
    def provider_name(self, value: builtins.str) -> None:
        jsii.set(self, "providerName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerType")
    def provider_type(self) -> builtins.str:
        '''The identity provider type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-providertype
        '''
        return typing.cast(builtins.str, jsii.get(self, "providerType"))

    @provider_type.setter
    def provider_type(self, value: builtins.str) -> None:
        jsii.set(self, "providerType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="idpIdentifiers")
    def idp_identifiers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of identity provider identifiers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-idpidentifiers
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "idpIdentifiers"))

    @idp_identifiers.setter
    def idp_identifiers(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "idpIdentifiers", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolIdentityProviderProps",
    jsii_struct_bases=[],
    name_mapping={
        "provider_name": "providerName",
        "provider_type": "providerType",
        "user_pool_id": "userPoolId",
        "attribute_mapping": "attributeMapping",
        "idp_identifiers": "idpIdentifiers",
        "provider_details": "providerDetails",
    },
)
class CfnUserPoolIdentityProviderProps:
    def __init__(
        self,
        *,
        provider_name: builtins.str,
        provider_type: builtins.str,
        user_pool_id: builtins.str,
        attribute_mapping: typing.Any = None,
        idp_identifiers: typing.Optional[typing.Sequence[builtins.str]] = None,
        provider_details: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolIdentityProvider``.

        :param provider_name: The identity provider name.
        :param provider_type: The identity provider type.
        :param user_pool_id: The user pool ID.
        :param attribute_mapping: A mapping of identity provider attributes to standard and custom user pool attributes.
        :param idp_identifiers: A list of identity provider identifiers.
        :param provider_details: The identity provider details. The following list describes the provider detail keys for each identity provider type. - For Google and Login with Amazon: - client_id - client_secret - authorize_scopes - For Facebook: - client_id - client_secret - authorize_scopes - api_version - For Sign in with Apple: - client_id - team_id - key_id - private_key - authorize_scopes - For OpenID Connect (OIDC) providers: - client_id - client_secret - attributes_request_method - oidc_issuer - authorize_scopes - authorize_url *if not available from discovery URL specified by oidc_issuer key* - token_url *if not available from discovery URL specified by oidc_issuer key* - attributes_url *if not available from discovery URL specified by oidc_issuer key* - jwks_uri *if not available from discovery URL specified by oidc_issuer key* - attributes_url_add_attributes *a read-only property that is set automatically* - For SAML providers: - MetadataFile OR MetadataURL - IDPSignout (optional)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # attribute_mapping: Any
            # provider_details: Any
            
            cfn_user_pool_identity_provider_props = cognito.CfnUserPoolIdentityProviderProps(
                provider_name="providerName",
                provider_type="providerType",
                user_pool_id="userPoolId",
            
                # the properties below are optional
                attribute_mapping=attribute_mapping,
                idp_identifiers=["idpIdentifiers"],
                provider_details=provider_details
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "provider_name": provider_name,
            "provider_type": provider_type,
            "user_pool_id": user_pool_id,
        }
        if attribute_mapping is not None:
            self._values["attribute_mapping"] = attribute_mapping
        if idp_identifiers is not None:
            self._values["idp_identifiers"] = idp_identifiers
        if provider_details is not None:
            self._values["provider_details"] = provider_details

    @builtins.property
    def provider_name(self) -> builtins.str:
        '''The identity provider name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-providername
        '''
        result = self._values.get("provider_name")
        assert result is not None, "Required property 'provider_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def provider_type(self) -> builtins.str:
        '''The identity provider type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-providertype
        '''
        result = self._values.get("provider_type")
        assert result is not None, "Required property 'provider_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def attribute_mapping(self) -> typing.Any:
        '''A mapping of identity provider attributes to standard and custom user pool attributes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-attributemapping
        '''
        result = self._values.get("attribute_mapping")
        return typing.cast(typing.Any, result)

    @builtins.property
    def idp_identifiers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of identity provider identifiers.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-idpidentifiers
        '''
        result = self._values.get("idp_identifiers")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def provider_details(self) -> typing.Any:
        '''The identity provider details. The following list describes the provider detail keys for each identity provider type.

        - For Google and Login with Amazon:
        - client_id
        - client_secret
        - authorize_scopes
        - For Facebook:
        - client_id
        - client_secret
        - authorize_scopes
        - api_version
        - For Sign in with Apple:
        - client_id
        - team_id
        - key_id
        - private_key
        - authorize_scopes
        - For OpenID Connect (OIDC) providers:
        - client_id
        - client_secret
        - attributes_request_method
        - oidc_issuer
        - authorize_scopes
        - authorize_url *if not available from discovery URL specified by oidc_issuer key*
        - token_url *if not available from discovery URL specified by oidc_issuer key*
        - attributes_url *if not available from discovery URL specified by oidc_issuer key*
        - jwks_uri *if not available from discovery URL specified by oidc_issuer key*
        - attributes_url_add_attributes *a read-only property that is set automatically*
        - For SAML providers:
        - MetadataFile OR MetadataURL
        - IDPSignout (optional)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolidentityprovider.html#cfn-cognito-userpoolidentityprovider-providerdetails
        '''
        result = self._values.get("provider_details")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolIdentityProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolProps",
    jsii_struct_bases=[],
    name_mapping={
        "account_recovery_setting": "accountRecoverySetting",
        "admin_create_user_config": "adminCreateUserConfig",
        "alias_attributes": "aliasAttributes",
        "auto_verified_attributes": "autoVerifiedAttributes",
        "device_configuration": "deviceConfiguration",
        "email_configuration": "emailConfiguration",
        "email_verification_message": "emailVerificationMessage",
        "email_verification_subject": "emailVerificationSubject",
        "enabled_mfas": "enabledMfas",
        "lambda_config": "lambdaConfig",
        "mfa_configuration": "mfaConfiguration",
        "policies": "policies",
        "schema": "schema",
        "sms_authentication_message": "smsAuthenticationMessage",
        "sms_configuration": "smsConfiguration",
        "sms_verification_message": "smsVerificationMessage",
        "username_attributes": "usernameAttributes",
        "username_configuration": "usernameConfiguration",
        "user_pool_add_ons": "userPoolAddOns",
        "user_pool_name": "userPoolName",
        "user_pool_tags": "userPoolTags",
        "verification_message_template": "verificationMessageTemplate",
    },
)
class CfnUserPoolProps:
    def __init__(
        self,
        *,
        account_recovery_setting: typing.Optional[typing.Union[CfnUserPool.AccountRecoverySettingProperty, _IResolvable_da3f097b]] = None,
        admin_create_user_config: typing.Optional[typing.Union[CfnUserPool.AdminCreateUserConfigProperty, _IResolvable_da3f097b]] = None,
        alias_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
        auto_verified_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
        device_configuration: typing.Optional[typing.Union[CfnUserPool.DeviceConfigurationProperty, _IResolvable_da3f097b]] = None,
        email_configuration: typing.Optional[typing.Union[CfnUserPool.EmailConfigurationProperty, _IResolvable_da3f097b]] = None,
        email_verification_message: typing.Optional[builtins.str] = None,
        email_verification_subject: typing.Optional[builtins.str] = None,
        enabled_mfas: typing.Optional[typing.Sequence[builtins.str]] = None,
        lambda_config: typing.Optional[typing.Union[CfnUserPool.LambdaConfigProperty, _IResolvable_da3f097b]] = None,
        mfa_configuration: typing.Optional[builtins.str] = None,
        policies: typing.Optional[typing.Union[CfnUserPool.PoliciesProperty, _IResolvable_da3f097b]] = None,
        schema: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnUserPool.SchemaAttributeProperty, _IResolvable_da3f097b]]]] = None,
        sms_authentication_message: typing.Optional[builtins.str] = None,
        sms_configuration: typing.Optional[typing.Union[CfnUserPool.SmsConfigurationProperty, _IResolvable_da3f097b]] = None,
        sms_verification_message: typing.Optional[builtins.str] = None,
        username_attributes: typing.Optional[typing.Sequence[builtins.str]] = None,
        username_configuration: typing.Optional[typing.Union[CfnUserPool.UsernameConfigurationProperty, _IResolvable_da3f097b]] = None,
        user_pool_add_ons: typing.Optional[typing.Union[CfnUserPool.UserPoolAddOnsProperty, _IResolvable_da3f097b]] = None,
        user_pool_name: typing.Optional[builtins.str] = None,
        user_pool_tags: typing.Any = None,
        verification_message_template: typing.Optional[typing.Union[CfnUserPool.VerificationMessageTemplateProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPool``.

        :param account_recovery_setting: Use this setting to define which verified available method a user can use to recover their password when they call ``ForgotPassword`` . It allows you to define a preferred method when a user has more than one method available. With this setting, SMS does not qualify for a valid password recovery mechanism if the user also has SMS MFA enabled. In the absence of this setting, Cognito uses the legacy behavior to determine the recovery method where SMS is preferred over email.
        :param admin_create_user_config: The configuration for creating a new user profile.
        :param alias_attributes: Attributes supported as an alias for this user pool. Possible values: *phone_number* , *email* , or *preferred_username* . .. epigraph:: This user pool property cannot be updated.
        :param auto_verified_attributes: The attributes to be auto-verified. Possible values: *email* , *phone_number* .
        :param device_configuration: The device configuration.
        :param email_configuration: The email configuration.
        :param email_verification_message: A string representing the email verification message. EmailVerificationMessage is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
        :param email_verification_subject: A string representing the email verification subject. EmailVerificationSubject is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.
        :param enabled_mfas: Enables MFA on a specified user pool. To disable all MFAs after it has been enabled, set MfaConfiguration to “OFF” and remove EnabledMfas. MFAs can only be all disabled if MfaConfiguration is OFF. Once SMS_MFA is enabled, SMS_MFA can only be disabled by setting MfaConfiguration to “OFF”. Can be one of the following values: - ``SMS_MFA`` - Enables SMS MFA for the user pool. SMS_MFA can only be enabled if SMS configuration is provided. - ``SOFTWARE_TOKEN_MFA`` - Enables software token MFA for the user pool. Allowed values: ``SMS_MFA`` | ``SOFTWARE_TOKEN_MFA``
        :param lambda_config: The Lambda trigger configuration information for the new user pool. .. epigraph:: In a push model, event sources (such as Amazon S3 and custom applications) need permission to invoke a function. So you must make an extra call to add permission for these event sources to invoke your Lambda function. For more information on using the Lambda API to add permission, see `AddPermission <https://docs.aws.amazon.com/lambda/latest/dg/API_AddPermission.html>`_ . For adding permission using the AWS CLI , see `add-permission <https://docs.aws.amazon.com/cli/latest/reference/lambda/add-permission.html>`_ .
        :param mfa_configuration: The multi-factor (MFA) configuration. Valid values include:. - ``OFF`` MFA won't be used for any users. - ``ON`` MFA is required for all users to sign in. - ``OPTIONAL`` MFA will be required only for individual users who have an MFA factor activated.
        :param policies: The policy associated with a user pool.
        :param schema: The schema attributes for the new user pool. These attributes can be standard or custom attributes. .. epigraph:: During a user pool update, you can add new schema attributes but you cannot modify or delete an existing schema attribute.
        :param sms_authentication_message: A string representing the SMS authentication message.
        :param sms_configuration: The SMS configuration.
        :param sms_verification_message: A string representing the SMS verification message.
        :param username_attributes: Determines whether email addresses or phone numbers can be specified as user names when a user signs up. Possible values: ``phone_number`` or ``email`` . This user pool property cannot be updated.
        :param username_configuration: You can choose to set case sensitivity on the username input for the selected sign-in option. For example, when this is set to ``False`` , users will be able to sign in using either "username" or "Username". This configuration is immutable once it has been set.
        :param user_pool_add_ons: Enables advanced security risk detection. Set the key ``AdvancedSecurityMode`` to the value "AUDIT".
        :param user_pool_name: A string used to name the user pool.
        :param user_pool_tags: The tag keys and values to assign to the user pool. A tag is a label that you can use to categorize and manage user pools in different ways, such as by purpose, owner, environment, or other criteria.
        :param verification_message_template: The template for the verification message that the user sees when the app requests permission to access the user's information.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # user_pool_tags: Any
            
            cfn_user_pool_props = cognito.CfnUserPoolProps(
                account_recovery_setting=cognito.CfnUserPool.AccountRecoverySettingProperty(
                    recovery_mechanisms=[cognito.CfnUserPool.RecoveryOptionProperty(
                        name="name",
                        priority=123
                    )]
                ),
                admin_create_user_config=cognito.CfnUserPool.AdminCreateUserConfigProperty(
                    allow_admin_create_user_only=False,
                    invite_message_template=cognito.CfnUserPool.InviteMessageTemplateProperty(
                        email_message="emailMessage",
                        email_subject="emailSubject",
                        sms_message="smsMessage"
                    ),
                    unused_account_validity_days=123
                ),
                alias_attributes=["aliasAttributes"],
                auto_verified_attributes=["autoVerifiedAttributes"],
                device_configuration=cognito.CfnUserPool.DeviceConfigurationProperty(
                    challenge_required_on_new_device=False,
                    device_only_remembered_on_user_prompt=False
                ),
                email_configuration=cognito.CfnUserPool.EmailConfigurationProperty(
                    configuration_set="configurationSet",
                    email_sending_account="emailSendingAccount",
                    from="from",
                    reply_to_email_address="replyToEmailAddress",
                    source_arn="sourceArn"
                ),
                email_verification_message="emailVerificationMessage",
                email_verification_subject="emailVerificationSubject",
                enabled_mfas=["enabledMfas"],
                lambda_config=cognito.CfnUserPool.LambdaConfigProperty(
                    create_auth_challenge="createAuthChallenge",
                    custom_email_sender=cognito.CfnUserPool.CustomEmailSenderProperty(
                        lambda_arn="lambdaArn",
                        lambda_version="lambdaVersion"
                    ),
                    custom_message="customMessage",
                    custom_sms_sender=cognito.CfnUserPool.CustomSMSSenderProperty(
                        lambda_arn="lambdaArn",
                        lambda_version="lambdaVersion"
                    ),
                    define_auth_challenge="defineAuthChallenge",
                    kms_key_id="kmsKeyId",
                    post_authentication="postAuthentication",
                    post_confirmation="postConfirmation",
                    pre_authentication="preAuthentication",
                    pre_sign_up="preSignUp",
                    pre_token_generation="preTokenGeneration",
                    user_migration="userMigration",
                    verify_auth_challenge_response="verifyAuthChallengeResponse"
                ),
                mfa_configuration="mfaConfiguration",
                policies=cognito.CfnUserPool.PoliciesProperty(
                    password_policy=cognito.CfnUserPool.PasswordPolicyProperty(
                        minimum_length=123,
                        require_lowercase=False,
                        require_numbers=False,
                        require_symbols=False,
                        require_uppercase=False,
                        temporary_password_validity_days=123
                    )
                ),
                schema=[cognito.CfnUserPool.SchemaAttributeProperty(
                    attribute_data_type="attributeDataType",
                    developer_only_attribute=False,
                    mutable=False,
                    name="name",
                    number_attribute_constraints=cognito.CfnUserPool.NumberAttributeConstraintsProperty(
                        max_value="maxValue",
                        min_value="minValue"
                    ),
                    required=False,
                    string_attribute_constraints=cognito.CfnUserPool.StringAttributeConstraintsProperty(
                        max_length="maxLength",
                        min_length="minLength"
                    )
                )],
                sms_authentication_message="smsAuthenticationMessage",
                sms_configuration=cognito.CfnUserPool.SmsConfigurationProperty(
                    external_id="externalId",
                    sns_caller_arn="snsCallerArn",
                    sns_region="snsRegion"
                ),
                sms_verification_message="smsVerificationMessage",
                username_attributes=["usernameAttributes"],
                username_configuration=cognito.CfnUserPool.UsernameConfigurationProperty(
                    case_sensitive=False
                ),
                user_pool_add_ons=cognito.CfnUserPool.UserPoolAddOnsProperty(
                    advanced_security_mode="advancedSecurityMode"
                ),
                user_pool_name="userPoolName",
                user_pool_tags=user_pool_tags,
                verification_message_template=cognito.CfnUserPool.VerificationMessageTemplateProperty(
                    default_email_option="defaultEmailOption",
                    email_message="emailMessage",
                    email_message_by_link="emailMessageByLink",
                    email_subject="emailSubject",
                    email_subject_by_link="emailSubjectByLink",
                    sms_message="smsMessage"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if account_recovery_setting is not None:
            self._values["account_recovery_setting"] = account_recovery_setting
        if admin_create_user_config is not None:
            self._values["admin_create_user_config"] = admin_create_user_config
        if alias_attributes is not None:
            self._values["alias_attributes"] = alias_attributes
        if auto_verified_attributes is not None:
            self._values["auto_verified_attributes"] = auto_verified_attributes
        if device_configuration is not None:
            self._values["device_configuration"] = device_configuration
        if email_configuration is not None:
            self._values["email_configuration"] = email_configuration
        if email_verification_message is not None:
            self._values["email_verification_message"] = email_verification_message
        if email_verification_subject is not None:
            self._values["email_verification_subject"] = email_verification_subject
        if enabled_mfas is not None:
            self._values["enabled_mfas"] = enabled_mfas
        if lambda_config is not None:
            self._values["lambda_config"] = lambda_config
        if mfa_configuration is not None:
            self._values["mfa_configuration"] = mfa_configuration
        if policies is not None:
            self._values["policies"] = policies
        if schema is not None:
            self._values["schema"] = schema
        if sms_authentication_message is not None:
            self._values["sms_authentication_message"] = sms_authentication_message
        if sms_configuration is not None:
            self._values["sms_configuration"] = sms_configuration
        if sms_verification_message is not None:
            self._values["sms_verification_message"] = sms_verification_message
        if username_attributes is not None:
            self._values["username_attributes"] = username_attributes
        if username_configuration is not None:
            self._values["username_configuration"] = username_configuration
        if user_pool_add_ons is not None:
            self._values["user_pool_add_ons"] = user_pool_add_ons
        if user_pool_name is not None:
            self._values["user_pool_name"] = user_pool_name
        if user_pool_tags is not None:
            self._values["user_pool_tags"] = user_pool_tags
        if verification_message_template is not None:
            self._values["verification_message_template"] = verification_message_template

    @builtins.property
    def account_recovery_setting(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.AccountRecoverySettingProperty, _IResolvable_da3f097b]]:
        '''Use this setting to define which verified available method a user can use to recover their password when they call ``ForgotPassword`` .

        It allows you to define a preferred method when a user has more than one method available. With this setting, SMS does not qualify for a valid password recovery mechanism if the user also has SMS MFA enabled. In the absence of this setting, Cognito uses the legacy behavior to determine the recovery method where SMS is preferred over email.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-accountrecoverysetting
        '''
        result = self._values.get("account_recovery_setting")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.AccountRecoverySettingProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def admin_create_user_config(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.AdminCreateUserConfigProperty, _IResolvable_da3f097b]]:
        '''The configuration for creating a new user profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-admincreateuserconfig
        '''
        result = self._values.get("admin_create_user_config")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.AdminCreateUserConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def alias_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Attributes supported as an alias for this user pool. Possible values: *phone_number* , *email* , or *preferred_username* .

        .. epigraph::

           This user pool property cannot be updated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-aliasattributes
        '''
        result = self._values.get("alias_attributes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def auto_verified_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The attributes to be auto-verified.

        Possible values: *email* , *phone_number* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-autoverifiedattributes
        '''
        result = self._values.get("auto_verified_attributes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def device_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.DeviceConfigurationProperty, _IResolvable_da3f097b]]:
        '''The device configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-deviceconfiguration
        '''
        result = self._values.get("device_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.DeviceConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def email_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.EmailConfigurationProperty, _IResolvable_da3f097b]]:
        '''The email configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-emailconfiguration
        '''
        result = self._values.get("email_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.EmailConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def email_verification_message(self) -> typing.Optional[builtins.str]:
        '''A string representing the email verification message.

        EmailVerificationMessage is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-emailverificationmessage
        '''
        result = self._values.get("email_verification_message")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def email_verification_subject(self) -> typing.Optional[builtins.str]:
        '''A string representing the email verification subject.

        EmailVerificationSubject is allowed only if `EmailSendingAccount <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html#CognitoUserPools-Type-EmailConfigurationType-EmailSendingAccount>`_ is DEVELOPER.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-emailverificationsubject
        '''
        result = self._values.get("email_verification_subject")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enabled_mfas(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Enables MFA on a specified user pool.

        To disable all MFAs after it has been enabled, set MfaConfiguration to “OFF” and remove EnabledMfas. MFAs can only be all disabled if MfaConfiguration is OFF. Once SMS_MFA is enabled, SMS_MFA can only be disabled by setting MfaConfiguration to “OFF”. Can be one of the following values:

        - ``SMS_MFA`` - Enables SMS MFA for the user pool. SMS_MFA can only be enabled if SMS configuration is provided.
        - ``SOFTWARE_TOKEN_MFA`` - Enables software token MFA for the user pool.

        Allowed values: ``SMS_MFA`` | ``SOFTWARE_TOKEN_MFA``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-enabledmfas
        '''
        result = self._values.get("enabled_mfas")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def lambda_config(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.LambdaConfigProperty, _IResolvable_da3f097b]]:
        '''The Lambda trigger configuration information for the new user pool.

        .. epigraph::

           In a push model, event sources (such as Amazon S3 and custom applications) need permission to invoke a function. So you must make an extra call to add permission for these event sources to invoke your Lambda function.

           For more information on using the Lambda API to add permission, see `AddPermission <https://docs.aws.amazon.com/lambda/latest/dg/API_AddPermission.html>`_ .

           For adding permission using the AWS CLI , see `add-permission <https://docs.aws.amazon.com/cli/latest/reference/lambda/add-permission.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-lambdaconfig
        '''
        result = self._values.get("lambda_config")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.LambdaConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def mfa_configuration(self) -> typing.Optional[builtins.str]:
        '''The multi-factor (MFA) configuration. Valid values include:.

        - ``OFF`` MFA won't be used for any users.
        - ``ON`` MFA is required for all users to sign in.
        - ``OPTIONAL`` MFA will be required only for individual users who have an MFA factor activated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-mfaconfiguration
        '''
        result = self._values.get("mfa_configuration")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def policies(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.PoliciesProperty, _IResolvable_da3f097b]]:
        '''The policy associated with a user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-policies
        '''
        result = self._values.get("policies")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.PoliciesProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def schema(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUserPool.SchemaAttributeProperty, _IResolvable_da3f097b]]]]:
        '''The schema attributes for the new user pool. These attributes can be standard or custom attributes.

        .. epigraph::

           During a user pool update, you can add new schema attributes but you cannot modify or delete an existing schema attribute.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-schema
        '''
        result = self._values.get("schema")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUserPool.SchemaAttributeProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def sms_authentication_message(self) -> typing.Optional[builtins.str]:
        '''A string representing the SMS authentication message.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-smsauthenticationmessage
        '''
        result = self._values.get("sms_authentication_message")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sms_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.SmsConfigurationProperty, _IResolvable_da3f097b]]:
        '''The SMS configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-smsconfiguration
        '''
        result = self._values.get("sms_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.SmsConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def sms_verification_message(self) -> typing.Optional[builtins.str]:
        '''A string representing the SMS verification message.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-smsverificationmessage
        '''
        result = self._values.get("sms_verification_message")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def username_attributes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Determines whether email addresses or phone numbers can be specified as user names when a user signs up.

        Possible values: ``phone_number`` or ``email`` .

        This user pool property cannot be updated.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-usernameattributes
        '''
        result = self._values.get("username_attributes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def username_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.UsernameConfigurationProperty, _IResolvable_da3f097b]]:
        '''You can choose to set case sensitivity on the username input for the selected sign-in option.

        For example, when this is set to ``False`` , users will be able to sign in using either "username" or "Username". This configuration is immutable once it has been set.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-usernameconfiguration
        '''
        result = self._values.get("username_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.UsernameConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def user_pool_add_ons(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.UserPoolAddOnsProperty, _IResolvable_da3f097b]]:
        '''Enables advanced security risk detection.

        Set the key ``AdvancedSecurityMode`` to the value "AUDIT".

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-userpooladdons
        '''
        result = self._values.get("user_pool_add_ons")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.UserPoolAddOnsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def user_pool_name(self) -> typing.Optional[builtins.str]:
        '''A string used to name the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-userpoolname
        '''
        result = self._values.get("user_pool_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def user_pool_tags(self) -> typing.Any:
        '''The tag keys and values to assign to the user pool.

        A tag is a label that you can use to categorize and manage user pools in different ways, such as by purpose, owner, environment, or other criteria.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-userpooltags
        '''
        result = self._values.get("user_pool_tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def verification_message_template(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPool.VerificationMessageTemplateProperty, _IResolvable_da3f097b]]:
        '''The template for the verification message that the user sees when the app requests permission to access the user's information.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpool.html#cfn-cognito-userpool-verificationmessagetemplate
        '''
        result = self._values.get("verification_message_template")
        return typing.cast(typing.Optional[typing.Union[CfnUserPool.VerificationMessageTemplateProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolResourceServer(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolResourceServer",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolResourceServer``.

    The ``AWS::Cognito::UserPoolResourceServer`` resource creates a new OAuth2.0 resource server and defines custom scopes in it.

    :cloudformationResource: AWS::Cognito::UserPoolResourceServer
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        cfn_user_pool_resource_server = cognito.CfnUserPoolResourceServer(self, "MyCfnUserPoolResourceServer",
            identifier="identifier",
            name="name",
            user_pool_id="userPoolId",
        
            # the properties below are optional
            scopes=[cognito.CfnUserPoolResourceServer.ResourceServerScopeTypeProperty(
                scope_description="scopeDescription",
                scope_name="scopeName"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        identifier: builtins.str,
        name: builtins.str,
        user_pool_id: builtins.str,
        scopes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnUserPoolResourceServer.ResourceServerScopeTypeProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolResourceServer``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param identifier: A unique resource server identifier for the resource server. This could be an HTTPS endpoint where the resource server is located. For example: ``https://my-weather-api.example.com`` .
        :param name: A friendly name for the resource server.
        :param user_pool_id: The user pool ID for the user pool.
        :param scopes: A list of scopes. Each scope is a map with keys ``ScopeName`` and ``ScopeDescription`` .
        '''
        props = CfnUserPoolResourceServerProps(
            identifier=identifier, name=name, user_pool_id=user_pool_id, scopes=scopes
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
    @jsii.member(jsii_name="identifier")
    def identifier(self) -> builtins.str:
        '''A unique resource server identifier for the resource server.

        This could be an HTTPS endpoint where the resource server is located. For example: ``https://my-weather-api.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html#cfn-cognito-userpoolresourceserver-identifier
        '''
        return typing.cast(builtins.str, jsii.get(self, "identifier"))

    @identifier.setter
    def identifier(self, value: builtins.str) -> None:
        jsii.set(self, "identifier", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A friendly name for the resource server.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html#cfn-cognito-userpoolresourceserver-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html#cfn-cognito-userpoolresourceserver-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scopes")
    def scopes(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolResourceServer.ResourceServerScopeTypeProperty", _IResolvable_da3f097b]]]]:
        '''A list of scopes.

        Each scope is a map with keys ``ScopeName`` and ``ScopeDescription`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html#cfn-cognito-userpoolresourceserver-scopes
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolResourceServer.ResourceServerScopeTypeProperty", _IResolvable_da3f097b]]]], jsii.get(self, "scopes"))

    @scopes.setter
    def scopes(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolResourceServer.ResourceServerScopeTypeProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "scopes", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolResourceServer.ResourceServerScopeTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "scope_description": "scopeDescription",
            "scope_name": "scopeName",
        },
    )
    class ResourceServerScopeTypeProperty:
        def __init__(
            self,
            *,
            scope_description: builtins.str,
            scope_name: builtins.str,
        ) -> None:
            '''A resource server scope.

            :param scope_description: A description of the scope.
            :param scope_name: The name of the scope.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolresourceserver-resourceserverscopetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                resource_server_scope_type_property = cognito.CfnUserPoolResourceServer.ResourceServerScopeTypeProperty(
                    scope_description="scopeDescription",
                    scope_name="scopeName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "scope_description": scope_description,
                "scope_name": scope_name,
            }

        @builtins.property
        def scope_description(self) -> builtins.str:
            '''A description of the scope.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolresourceserver-resourceserverscopetype.html#cfn-cognito-userpoolresourceserver-resourceserverscopetype-scopedescription
            '''
            result = self._values.get("scope_description")
            assert result is not None, "Required property 'scope_description' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def scope_name(self) -> builtins.str:
            '''The name of the scope.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolresourceserver-resourceserverscopetype.html#cfn-cognito-userpoolresourceserver-resourceserverscopetype-scopename
            '''
            result = self._values.get("scope_name")
            assert result is not None, "Required property 'scope_name' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceServerScopeTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolResourceServerProps",
    jsii_struct_bases=[],
    name_mapping={
        "identifier": "identifier",
        "name": "name",
        "user_pool_id": "userPoolId",
        "scopes": "scopes",
    },
)
class CfnUserPoolResourceServerProps:
    def __init__(
        self,
        *,
        identifier: builtins.str,
        name: builtins.str,
        user_pool_id: builtins.str,
        scopes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnUserPoolResourceServer.ResourceServerScopeTypeProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolResourceServer``.

        :param identifier: A unique resource server identifier for the resource server. This could be an HTTPS endpoint where the resource server is located. For example: ``https://my-weather-api.example.com`` .
        :param name: A friendly name for the resource server.
        :param user_pool_id: The user pool ID for the user pool.
        :param scopes: A list of scopes. Each scope is a map with keys ``ScopeName`` and ``ScopeDescription`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            cfn_user_pool_resource_server_props = cognito.CfnUserPoolResourceServerProps(
                identifier="identifier",
                name="name",
                user_pool_id="userPoolId",
            
                # the properties below are optional
                scopes=[cognito.CfnUserPoolResourceServer.ResourceServerScopeTypeProperty(
                    scope_description="scopeDescription",
                    scope_name="scopeName"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "identifier": identifier,
            "name": name,
            "user_pool_id": user_pool_id,
        }
        if scopes is not None:
            self._values["scopes"] = scopes

    @builtins.property
    def identifier(self) -> builtins.str:
        '''A unique resource server identifier for the resource server.

        This could be an HTTPS endpoint where the resource server is located. For example: ``https://my-weather-api.example.com`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html#cfn-cognito-userpoolresourceserver-identifier
        '''
        result = self._values.get("identifier")
        assert result is not None, "Required property 'identifier' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''A friendly name for the resource server.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html#cfn-cognito-userpoolresourceserver-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html#cfn-cognito-userpoolresourceserver-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def scopes(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUserPoolResourceServer.ResourceServerScopeTypeProperty, _IResolvable_da3f097b]]]]:
        '''A list of scopes.

        Each scope is a map with keys ``ScopeName`` and ``ScopeDescription`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolresourceserver.html#cfn-cognito-userpoolresourceserver-scopes
        '''
        result = self._values.get("scopes")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUserPoolResourceServer.ResourceServerScopeTypeProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolResourceServerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolRiskConfigurationAttachment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolRiskConfigurationAttachment``.

    The ``AWS::Cognito::UserPoolRiskConfigurationAttachment`` resource sets the risk configuration that is used for Amazon Cognito advanced security features.

    You can specify risk configuration for a single client (with a specific ``clientId`` ) or for all clients (by setting the ``clientId`` to ``ALL`` ). If you specify ``ALL`` , the default configuration is used for every client that has had no risk configuration set previously. If you specify risk configuration for a particular client, it no longer falls back to the ``ALL`` configuration.

    :cloudformationResource: AWS::Cognito::UserPoolRiskConfigurationAttachment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        cfn_user_pool_risk_configuration_attachment = cognito.CfnUserPoolRiskConfigurationAttachment(self, "MyCfnUserPoolRiskConfigurationAttachment",
            client_id="clientId",
            user_pool_id="userPoolId",
        
            # the properties below are optional
            account_takeover_risk_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty(
                actions=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionsTypeProperty(
                    high_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                        event_action="eventAction",
                        notify=False
                    ),
                    low_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                        event_action="eventAction",
                        notify=False
                    ),
                    medium_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                        event_action="eventAction",
                        notify=False
                    )
                ),
        
                # the properties below are optional
                notify_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyConfigurationTypeProperty(
                    source_arn="sourceArn",
        
                    # the properties below are optional
                    block_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                        subject="subject",
        
                        # the properties below are optional
                        html_body="htmlBody",
                        text_body="textBody"
                    ),
                    from="from",
                    mfa_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                        subject="subject",
        
                        # the properties below are optional
                        html_body="htmlBody",
                        text_body="textBody"
                    ),
                    no_action_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                        subject="subject",
        
                        # the properties below are optional
                        html_body="htmlBody",
                        text_body="textBody"
                    ),
                    reply_to="replyTo"
                )
            ),
            compromised_credentials_risk_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty(
                actions=cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsActionsTypeProperty(
                    event_action="eventAction"
                ),
        
                # the properties below are optional
                event_filter=["eventFilter"]
            ),
            risk_exception_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty(
                blocked_ip_range_list=["blockedIpRangeList"],
                skipped_ip_range_list=["skippedIpRangeList"]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        client_id: builtins.str,
        user_pool_id: builtins.str,
        account_takeover_risk_configuration: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty", _IResolvable_da3f097b]] = None,
        compromised_credentials_risk_configuration: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty", _IResolvable_da3f097b]] = None,
        risk_exception_configuration: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolRiskConfigurationAttachment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param client_id: The app client ID. You can specify the risk configuration for a single client (with a specific ClientId) or for all clients (by setting the ClientId to ``ALL`` ).
        :param user_pool_id: The user pool ID.
        :param account_takeover_risk_configuration: The account takeover risk configuration object, including the ``NotifyConfiguration`` object and ``Actions`` to take if there is an account takeover.
        :param compromised_credentials_risk_configuration: The compromised credentials risk configuration object, including the ``EventFilter`` and the ``EventAction`` .
        :param risk_exception_configuration: The configuration to override the risk decision.
        '''
        props = CfnUserPoolRiskConfigurationAttachmentProps(
            client_id=client_id,
            user_pool_id=user_pool_id,
            account_takeover_risk_configuration=account_takeover_risk_configuration,
            compromised_credentials_risk_configuration=compromised_credentials_risk_configuration,
            risk_exception_configuration=risk_exception_configuration,
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
    @jsii.member(jsii_name="clientId")
    def client_id(self) -> builtins.str:
        '''The app client ID.

        You can specify the risk configuration for a single client (with a specific ClientId) or for all clients (by setting the ClientId to ``ALL`` ).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-clientid
        '''
        return typing.cast(builtins.str, jsii.get(self, "clientId"))

    @client_id.setter
    def client_id(self, value: builtins.str) -> None:
        jsii.set(self, "clientId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accountTakeoverRiskConfiguration")
    def account_takeover_risk_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty", _IResolvable_da3f097b]]:
        '''The account takeover risk configuration object, including the ``NotifyConfiguration`` object and ``Actions`` to take if there is an account takeover.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoverriskconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty", _IResolvable_da3f097b]], jsii.get(self, "accountTakeoverRiskConfiguration"))

    @account_takeover_risk_configuration.setter
    def account_takeover_risk_configuration(
        self,
        value: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "accountTakeoverRiskConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="compromisedCredentialsRiskConfiguration")
    def compromised_credentials_risk_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty", _IResolvable_da3f097b]]:
        '''The compromised credentials risk configuration object, including the ``EventFilter`` and the ``EventAction`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-compromisedcredentialsriskconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty", _IResolvable_da3f097b]], jsii.get(self, "compromisedCredentialsRiskConfiguration"))

    @compromised_credentials_risk_configuration.setter
    def compromised_credentials_risk_configuration(
        self,
        value: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "compromisedCredentialsRiskConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="riskExceptionConfiguration")
    def risk_exception_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty", _IResolvable_da3f097b]]:
        '''The configuration to override the risk decision.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-riskexceptionconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty", _IResolvable_da3f097b]], jsii.get(self, "riskExceptionConfiguration"))

    @risk_exception_configuration.setter
    def risk_exception_configuration(
        self,
        value: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "riskExceptionConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty",
        jsii_struct_bases=[],
        name_mapping={"event_action": "eventAction", "notify": "notify"},
    )
    class AccountTakeoverActionTypeProperty:
        def __init__(
            self,
            *,
            event_action: builtins.str,
            notify: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''Account takeover action type.

            :param event_action: The event action. - ``BLOCK`` Choosing this action will block the request. - ``MFA_IF_CONFIGURED`` Present an MFA challenge if user has configured it, else allow the request. - ``MFA_REQUIRED`` Present an MFA challenge if user has configured it, else block the request. - ``NO_ACTION`` Allow the user to sign in.
            :param notify: Flag specifying whether to send a notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoveractiontype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                account_takeover_action_type_property = cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                    event_action="eventAction",
                    notify=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "event_action": event_action,
                "notify": notify,
            }

        @builtins.property
        def event_action(self) -> builtins.str:
            '''The event action.

            - ``BLOCK`` Choosing this action will block the request.
            - ``MFA_IF_CONFIGURED`` Present an MFA challenge if user has configured it, else allow the request.
            - ``MFA_REQUIRED`` Present an MFA challenge if user has configured it, else block the request.
            - ``NO_ACTION`` Allow the user to sign in.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoveractiontype.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoveractiontype-eventaction
            '''
            result = self._values.get("event_action")
            assert result is not None, "Required property 'event_action' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def notify(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Flag specifying whether to send a notification.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoveractiontype.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoveractiontype-notify
            '''
            result = self._values.get("notify")
            assert result is not None, "Required property 'notify' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccountTakeoverActionTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionsTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "high_action": "highAction",
            "low_action": "lowAction",
            "medium_action": "mediumAction",
        },
    )
    class AccountTakeoverActionsTypeProperty:
        def __init__(
            self,
            *,
            high_action: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]] = None,
            low_action: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]] = None,
            medium_action: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Account takeover actions type.

            :param high_action: Action to take for a high risk.
            :param low_action: Action to take for a low risk.
            :param medium_action: Action to take for a medium risk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoveractionstype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                account_takeover_actions_type_property = cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionsTypeProperty(
                    high_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                        event_action="eventAction",
                        notify=False
                    ),
                    low_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                        event_action="eventAction",
                        notify=False
                    ),
                    medium_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                        event_action="eventAction",
                        notify=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if high_action is not None:
                self._values["high_action"] = high_action
            if low_action is not None:
                self._values["low_action"] = low_action
            if medium_action is not None:
                self._values["medium_action"] = medium_action

        @builtins.property
        def high_action(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]]:
            '''Action to take for a high risk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoveractionstype.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoveractionstype-highaction
            '''
            result = self._values.get("high_action")
            return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def low_action(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]]:
            '''Action to take for a low risk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoveractionstype.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoveractionstype-lowaction
            '''
            result = self._values.get("low_action")
            return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def medium_action(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]]:
            '''Action to take for a medium risk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoveractionstype.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoveractionstype-mediumaction
            '''
            result = self._values.get("medium_action")
            return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccountTakeoverActionsTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "actions": "actions",
            "notify_configuration": "notifyConfiguration",
        },
    )
    class AccountTakeoverRiskConfigurationTypeProperty:
        def __init__(
            self,
            *,
            actions: typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionsTypeProperty", _IResolvable_da3f097b],
            notify_configuration: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyConfigurationTypeProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Configuration for mitigation actions and notification for different levels of risk detected for a potential account takeover.

            :param actions: Account takeover risk configuration actions.
            :param notify_configuration: The notify configuration used to construct email notifications.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoverriskconfigurationtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                account_takeover_risk_configuration_type_property = cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty(
                    actions=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionsTypeProperty(
                        high_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                            event_action="eventAction",
                            notify=False
                        ),
                        low_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                            event_action="eventAction",
                            notify=False
                        ),
                        medium_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                            event_action="eventAction",
                            notify=False
                        )
                    ),
                
                    # the properties below are optional
                    notify_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyConfigurationTypeProperty(
                        source_arn="sourceArn",
                
                        # the properties below are optional
                        block_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                            subject="subject",
                
                            # the properties below are optional
                            html_body="htmlBody",
                            text_body="textBody"
                        ),
                        from="from",
                        mfa_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                            subject="subject",
                
                            # the properties below are optional
                            html_body="htmlBody",
                            text_body="textBody"
                        ),
                        no_action_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                            subject="subject",
                
                            # the properties below are optional
                            html_body="htmlBody",
                            text_body="textBody"
                        ),
                        reply_to="replyTo"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "actions": actions,
            }
            if notify_configuration is not None:
                self._values["notify_configuration"] = notify_configuration

        @builtins.property
        def actions(
            self,
        ) -> typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionsTypeProperty", _IResolvable_da3f097b]:
            '''Account takeover risk configuration actions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoverriskconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoverriskconfigurationtype-actions
            '''
            result = self._values.get("actions")
            assert result is not None, "Required property 'actions' is missing"
            return typing.cast(typing.Union["CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionsTypeProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def notify_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyConfigurationTypeProperty", _IResolvable_da3f097b]]:
            '''The notify configuration used to construct email notifications.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-accounttakeoverriskconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoverriskconfigurationtype-notifyconfiguration
            '''
            result = self._values.get("notify_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyConfigurationTypeProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccountTakeoverRiskConfigurationTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsActionsTypeProperty",
        jsii_struct_bases=[],
        name_mapping={"event_action": "eventAction"},
    )
    class CompromisedCredentialsActionsTypeProperty:
        def __init__(self, *, event_action: builtins.str) -> None:
            '''The compromised credentials actions type.

            :param event_action: The event action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-compromisedcredentialsactionstype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                compromised_credentials_actions_type_property = cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsActionsTypeProperty(
                    event_action="eventAction"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "event_action": event_action,
            }

        @builtins.property
        def event_action(self) -> builtins.str:
            '''The event action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-compromisedcredentialsactionstype.html#cfn-cognito-userpoolriskconfigurationattachment-compromisedcredentialsactionstype-eventaction
            '''
            result = self._values.get("event_action")
            assert result is not None, "Required property 'event_action' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CompromisedCredentialsActionsTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty",
        jsii_struct_bases=[],
        name_mapping={"actions": "actions", "event_filter": "eventFilter"},
    )
    class CompromisedCredentialsRiskConfigurationTypeProperty:
        def __init__(
            self,
            *,
            actions: typing.Union["CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsActionsTypeProperty", _IResolvable_da3f097b],
            event_filter: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The compromised credentials risk configuration type.

            :param actions: The compromised credentials risk configuration actions.
            :param event_filter: Perform the action for these events. The default is to perform all events if no event filter is specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-compromisedcredentialsriskconfigurationtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                compromised_credentials_risk_configuration_type_property = cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty(
                    actions=cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsActionsTypeProperty(
                        event_action="eventAction"
                    ),
                
                    # the properties below are optional
                    event_filter=["eventFilter"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "actions": actions,
            }
            if event_filter is not None:
                self._values["event_filter"] = event_filter

        @builtins.property
        def actions(
            self,
        ) -> typing.Union["CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsActionsTypeProperty", _IResolvable_da3f097b]:
            '''The compromised credentials risk configuration actions.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-compromisedcredentialsriskconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-compromisedcredentialsriskconfigurationtype-actions
            '''
            result = self._values.get("actions")
            assert result is not None, "Required property 'actions' is missing"
            return typing.cast(typing.Union["CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsActionsTypeProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def event_filter(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Perform the action for these events.

            The default is to perform all events if no event filter is specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-compromisedcredentialsriskconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-compromisedcredentialsriskconfigurationtype-eventfilter
            '''
            result = self._values.get("event_filter")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CompromisedCredentialsRiskConfigurationTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment.NotifyConfigurationTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "source_arn": "sourceArn",
            "block_email": "blockEmail",
            "from_": "from",
            "mfa_email": "mfaEmail",
            "no_action_email": "noActionEmail",
            "reply_to": "replyTo",
        },
    )
    class NotifyConfigurationTypeProperty:
        def __init__(
            self,
            *,
            source_arn: builtins.str,
            block_email: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]] = None,
            from_: typing.Optional[builtins.str] = None,
            mfa_email: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]] = None,
            no_action_email: typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]] = None,
            reply_to: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The notify configuration type.

            :param source_arn: The Amazon Resource Name (ARN) of the identity that is associated with the sending authorization policy. This identity permits Amazon Cognito to send for the email address specified in the ``From`` parameter.
            :param block_email: Email template used when a detected risk event is blocked.
            :param from_: The email address that is sending the email. The address must be either individually verified with Amazon Simple Email Service, or from a domain that has been verified with Amazon SES.
            :param mfa_email: The multi-factor authentication (MFA) email template used when MFA is challenged as part of a detected risk.
            :param no_action_email: The email template used when a detected risk event is allowed.
            :param reply_to: The destination to which the receiver of an email should reply to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                notify_configuration_type_property = cognito.CfnUserPoolRiskConfigurationAttachment.NotifyConfigurationTypeProperty(
                    source_arn="sourceArn",
                
                    # the properties below are optional
                    block_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                        subject="subject",
                
                        # the properties below are optional
                        html_body="htmlBody",
                        text_body="textBody"
                    ),
                    from="from",
                    mfa_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                        subject="subject",
                
                        # the properties below are optional
                        html_body="htmlBody",
                        text_body="textBody"
                    ),
                    no_action_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                        subject="subject",
                
                        # the properties below are optional
                        html_body="htmlBody",
                        text_body="textBody"
                    ),
                    reply_to="replyTo"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source_arn": source_arn,
            }
            if block_email is not None:
                self._values["block_email"] = block_email
            if from_ is not None:
                self._values["from_"] = from_
            if mfa_email is not None:
                self._values["mfa_email"] = mfa_email
            if no_action_email is not None:
                self._values["no_action_email"] = no_action_email
            if reply_to is not None:
                self._values["reply_to"] = reply_to

        @builtins.property
        def source_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the identity that is associated with the sending authorization policy.

            This identity permits Amazon Cognito to send for the email address specified in the ``From`` parameter.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype-sourcearn
            '''
            result = self._values.get("source_arn")
            assert result is not None, "Required property 'source_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def block_email(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]]:
            '''Email template used when a detected risk event is blocked.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype-blockemail
            '''
            result = self._values.get("block_email")
            return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def from_(self) -> typing.Optional[builtins.str]:
            '''The email address that is sending the email.

            The address must be either individually verified with Amazon Simple Email Service, or from a domain that has been verified with Amazon SES.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype-from
            '''
            result = self._values.get("from_")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def mfa_email(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]]:
            '''The multi-factor authentication (MFA) email template used when MFA is challenged as part of a detected risk.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype-mfaemail
            '''
            result = self._values.get("mfa_email")
            return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def no_action_email(
            self,
        ) -> typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]]:
            '''The email template used when a detected risk event is allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype-noactionemail
            '''
            result = self._values.get("no_action_email")
            return typing.cast(typing.Optional[typing.Union["CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def reply_to(self) -> typing.Optional[builtins.str]:
            '''The destination to which the receiver of an email should reply to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyconfigurationtype-replyto
            '''
            result = self._values.get("reply_to")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotifyConfigurationTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "subject": "subject",
            "html_body": "htmlBody",
            "text_body": "textBody",
        },
    )
    class NotifyEmailTypeProperty:
        def __init__(
            self,
            *,
            subject: builtins.str,
            html_body: typing.Optional[builtins.str] = None,
            text_body: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The notify email type.

            :param subject: The email subject.
            :param html_body: The email HTML body.
            :param text_body: The email text body.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyemailtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                notify_email_type_property = cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                    subject="subject",
                
                    # the properties below are optional
                    html_body="htmlBody",
                    text_body="textBody"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "subject": subject,
            }
            if html_body is not None:
                self._values["html_body"] = html_body
            if text_body is not None:
                self._values["text_body"] = text_body

        @builtins.property
        def subject(self) -> builtins.str:
            '''The email subject.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyemailtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyemailtype-subject
            '''
            result = self._values.get("subject")
            assert result is not None, "Required property 'subject' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def html_body(self) -> typing.Optional[builtins.str]:
            '''The email HTML body.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyemailtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyemailtype-htmlbody
            '''
            result = self._values.get("html_body")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def text_body(self) -> typing.Optional[builtins.str]:
            '''The email text body.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-notifyemailtype.html#cfn-cognito-userpoolriskconfigurationattachment-notifyemailtype-textbody
            '''
            result = self._values.get("text_body")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotifyEmailTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty",
        jsii_struct_bases=[],
        name_mapping={
            "blocked_ip_range_list": "blockedIpRangeList",
            "skipped_ip_range_list": "skippedIpRangeList",
        },
    )
    class RiskExceptionConfigurationTypeProperty:
        def __init__(
            self,
            *,
            blocked_ip_range_list: typing.Optional[typing.Sequence[builtins.str]] = None,
            skipped_ip_range_list: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The type of the configuration to override the risk decision.

            :param blocked_ip_range_list: Overrides the risk decision to always block the pre-authentication requests. The IP range is in CIDR notation, a compact representation of an IP address and its routing prefix.
            :param skipped_ip_range_list: Risk detection isn't performed on the IP addresses in this range list. The IP range is in CIDR notation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-riskexceptionconfigurationtype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                risk_exception_configuration_type_property = cognito.CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty(
                    blocked_ip_range_list=["blockedIpRangeList"],
                    skipped_ip_range_list=["skippedIpRangeList"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if blocked_ip_range_list is not None:
                self._values["blocked_ip_range_list"] = blocked_ip_range_list
            if skipped_ip_range_list is not None:
                self._values["skipped_ip_range_list"] = skipped_ip_range_list

        @builtins.property
        def blocked_ip_range_list(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Overrides the risk decision to always block the pre-authentication requests.

            The IP range is in CIDR notation, a compact representation of an IP address and its routing prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-riskexceptionconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-riskexceptionconfigurationtype-blockediprangelist
            '''
            result = self._values.get("blocked_ip_range_list")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def skipped_ip_range_list(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Risk detection isn't performed on the IP addresses in this range list.

            The IP range is in CIDR notation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpoolriskconfigurationattachment-riskexceptionconfigurationtype.html#cfn-cognito-userpoolriskconfigurationattachment-riskexceptionconfigurationtype-skippediprangelist
            '''
            result = self._values.get("skipped_ip_range_list")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RiskExceptionConfigurationTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolRiskConfigurationAttachmentProps",
    jsii_struct_bases=[],
    name_mapping={
        "client_id": "clientId",
        "user_pool_id": "userPoolId",
        "account_takeover_risk_configuration": "accountTakeoverRiskConfiguration",
        "compromised_credentials_risk_configuration": "compromisedCredentialsRiskConfiguration",
        "risk_exception_configuration": "riskExceptionConfiguration",
    },
)
class CfnUserPoolRiskConfigurationAttachmentProps:
    def __init__(
        self,
        *,
        client_id: builtins.str,
        user_pool_id: builtins.str,
        account_takeover_risk_configuration: typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty, _IResolvable_da3f097b]] = None,
        compromised_credentials_risk_configuration: typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty, _IResolvable_da3f097b]] = None,
        risk_exception_configuration: typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolRiskConfigurationAttachment``.

        :param client_id: The app client ID. You can specify the risk configuration for a single client (with a specific ClientId) or for all clients (by setting the ClientId to ``ALL`` ).
        :param user_pool_id: The user pool ID.
        :param account_takeover_risk_configuration: The account takeover risk configuration object, including the ``NotifyConfiguration`` object and ``Actions`` to take if there is an account takeover.
        :param compromised_credentials_risk_configuration: The compromised credentials risk configuration object, including the ``EventFilter`` and the ``EventAction`` .
        :param risk_exception_configuration: The configuration to override the risk decision.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            cfn_user_pool_risk_configuration_attachment_props = cognito.CfnUserPoolRiskConfigurationAttachmentProps(
                client_id="clientId",
                user_pool_id="userPoolId",
            
                # the properties below are optional
                account_takeover_risk_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty(
                    actions=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionsTypeProperty(
                        high_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                            event_action="eventAction",
                            notify=False
                        ),
                        low_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                            event_action="eventAction",
                            notify=False
                        ),
                        medium_action=cognito.CfnUserPoolRiskConfigurationAttachment.AccountTakeoverActionTypeProperty(
                            event_action="eventAction",
                            notify=False
                        )
                    ),
            
                    # the properties below are optional
                    notify_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyConfigurationTypeProperty(
                        source_arn="sourceArn",
            
                        # the properties below are optional
                        block_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                            subject="subject",
            
                            # the properties below are optional
                            html_body="htmlBody",
                            text_body="textBody"
                        ),
                        from="from",
                        mfa_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                            subject="subject",
            
                            # the properties below are optional
                            html_body="htmlBody",
                            text_body="textBody"
                        ),
                        no_action_email=cognito.CfnUserPoolRiskConfigurationAttachment.NotifyEmailTypeProperty(
                            subject="subject",
            
                            # the properties below are optional
                            html_body="htmlBody",
                            text_body="textBody"
                        ),
                        reply_to="replyTo"
                    )
                ),
                compromised_credentials_risk_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty(
                    actions=cognito.CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsActionsTypeProperty(
                        event_action="eventAction"
                    ),
            
                    # the properties below are optional
                    event_filter=["eventFilter"]
                ),
                risk_exception_configuration=cognito.CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty(
                    blocked_ip_range_list=["blockedIpRangeList"],
                    skipped_ip_range_list=["skippedIpRangeList"]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "client_id": client_id,
            "user_pool_id": user_pool_id,
        }
        if account_takeover_risk_configuration is not None:
            self._values["account_takeover_risk_configuration"] = account_takeover_risk_configuration
        if compromised_credentials_risk_configuration is not None:
            self._values["compromised_credentials_risk_configuration"] = compromised_credentials_risk_configuration
        if risk_exception_configuration is not None:
            self._values["risk_exception_configuration"] = risk_exception_configuration

    @builtins.property
    def client_id(self) -> builtins.str:
        '''The app client ID.

        You can specify the risk configuration for a single client (with a specific ClientId) or for all clients (by setting the ClientId to ``ALL`` ).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-clientid
        '''
        result = self._values.get("client_id")
        assert result is not None, "Required property 'client_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def account_takeover_risk_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty, _IResolvable_da3f097b]]:
        '''The account takeover risk configuration object, including the ``NotifyConfiguration`` object and ``Actions`` to take if there is an account takeover.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-accounttakeoverriskconfiguration
        '''
        result = self._values.get("account_takeover_risk_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationTypeProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def compromised_credentials_risk_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty, _IResolvable_da3f097b]]:
        '''The compromised credentials risk configuration object, including the ``EventFilter`` and the ``EventAction`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-compromisedcredentialsriskconfiguration
        '''
        result = self._values.get("compromised_credentials_risk_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationTypeProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def risk_exception_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty, _IResolvable_da3f097b]]:
        '''The configuration to override the risk decision.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolriskconfigurationattachment.html#cfn-cognito-userpoolriskconfigurationattachment-riskexceptionconfiguration
        '''
        result = self._values.get("risk_exception_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnUserPoolRiskConfigurationAttachment.RiskExceptionConfigurationTypeProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolRiskConfigurationAttachmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolUICustomizationAttachment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolUICustomizationAttachment",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolUICustomizationAttachment``.

    The ``AWS::Cognito::UserPoolUICustomizationAttachment`` resource sets the UI customization information for a user pool's built-in app UI.

    You can specify app UI customization settings for a single client (with a specific ``clientId`` ) or for all clients (by setting the ``clientId`` to ``ALL`` ). If you specify ``ALL`` , the default configuration is used for every client that has had no UI customization set previously. If you specify UI customization settings for a particular client, it no longer falls back to the ``ALL`` configuration.
    .. epigraph::

       Before you create this resource, your user pool must have a domain associated with it. You can create an ``AWS::Cognito::UserPoolDomain`` resource first in this user pool.

    Setting a logo image isn't supported from AWS CloudFormation . Use the Amazon Cognito `SetUICustomization <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUICustomization.html#API_SetUICustomization_RequestSyntax>`_ API operation to set the image.

    :cloudformationResource: AWS::Cognito::UserPoolUICustomizationAttachment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluicustomizationattachment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        cfn_user_pool_uICustomization_attachment = cognito.CfnUserPoolUICustomizationAttachment(self, "MyCfnUserPoolUICustomizationAttachment",
            client_id="clientId",
            user_pool_id="userPoolId",
        
            # the properties below are optional
            css="css"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        client_id: builtins.str,
        user_pool_id: builtins.str,
        css: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolUICustomizationAttachment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param client_id: The client ID for the client app. You can specify the UI customization settings for a single client (with a specific clientId) or for all clients (by setting the clientId to ``ALL`` ).
        :param user_pool_id: The user pool ID for the user pool.
        :param css: The CSS values in the UI customization.
        '''
        props = CfnUserPoolUICustomizationAttachmentProps(
            client_id=client_id, user_pool_id=user_pool_id, css=css
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
    @jsii.member(jsii_name="clientId")
    def client_id(self) -> builtins.str:
        '''The client ID for the client app.

        You can specify the UI customization settings for a single client (with a specific clientId) or for all clients (by setting the clientId to ``ALL`` ).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluicustomizationattachment.html#cfn-cognito-userpooluicustomizationattachment-clientid
        '''
        return typing.cast(builtins.str, jsii.get(self, "clientId"))

    @client_id.setter
    def client_id(self, value: builtins.str) -> None:
        jsii.set(self, "clientId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluicustomizationattachment.html#cfn-cognito-userpooluicustomizationattachment-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="css")
    def css(self) -> typing.Optional[builtins.str]:
        '''The CSS values in the UI customization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluicustomizationattachment.html#cfn-cognito-userpooluicustomizationattachment-css
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "css"))

    @css.setter
    def css(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "css", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolUICustomizationAttachmentProps",
    jsii_struct_bases=[],
    name_mapping={"client_id": "clientId", "user_pool_id": "userPoolId", "css": "css"},
)
class CfnUserPoolUICustomizationAttachmentProps:
    def __init__(
        self,
        *,
        client_id: builtins.str,
        user_pool_id: builtins.str,
        css: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolUICustomizationAttachment``.

        :param client_id: The client ID for the client app. You can specify the UI customization settings for a single client (with a specific clientId) or for all clients (by setting the clientId to ``ALL`` ).
        :param user_pool_id: The user pool ID for the user pool.
        :param css: The CSS values in the UI customization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluicustomizationattachment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            cfn_user_pool_uICustomization_attachment_props = cognito.CfnUserPoolUICustomizationAttachmentProps(
                client_id="clientId",
                user_pool_id="userPoolId",
            
                # the properties below are optional
                css="css"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "client_id": client_id,
            "user_pool_id": user_pool_id,
        }
        if css is not None:
            self._values["css"] = css

    @builtins.property
    def client_id(self) -> builtins.str:
        '''The client ID for the client app.

        You can specify the UI customization settings for a single client (with a specific clientId) or for all clients (by setting the clientId to ``ALL`` ).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluicustomizationattachment.html#cfn-cognito-userpooluicustomizationattachment-clientid
        '''
        result = self._values.get("client_id")
        assert result is not None, "Required property 'client_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluicustomizationattachment.html#cfn-cognito-userpooluicustomizationattachment-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def css(self) -> typing.Optional[builtins.str]:
        '''The CSS values in the UI customization.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluicustomizationattachment.html#cfn-cognito-userpooluicustomizationattachment-css
        '''
        result = self._values.get("css")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolUICustomizationAttachmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolUser(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolUser",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolUser``.

    The ``AWS::Cognito::UserPoolUser`` resource creates an Amazon Cognito user pool user.

    :cloudformationResource: AWS::Cognito::UserPoolUser
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        # client_metadata: Any
        
        cfn_user_pool_user = cognito.CfnUserPoolUser(self, "MyCfnUserPoolUser",
            user_pool_id="userPoolId",
        
            # the properties below are optional
            client_metadata=client_metadata,
            desired_delivery_mediums=["desiredDeliveryMediums"],
            force_alias_creation=False,
            message_action="messageAction",
            user_attributes=[cognito.CfnUserPoolUser.AttributeTypeProperty(
                name="name",
                value="value"
            )],
            username="username",
            validation_data=[cognito.CfnUserPoolUser.AttributeTypeProperty(
                name="name",
                value="value"
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user_pool_id: builtins.str,
        client_metadata: typing.Any = None,
        desired_delivery_mediums: typing.Optional[typing.Sequence[builtins.str]] = None,
        force_alias_creation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        message_action: typing.Optional[builtins.str] = None,
        user_attributes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnUserPoolUser.AttributeTypeProperty", _IResolvable_da3f097b]]]] = None,
        username: typing.Optional[builtins.str] = None,
        validation_data: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnUserPoolUser.AttributeTypeProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolUser``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param user_pool_id: The user pool ID for the user pool where the user will be created.
        :param client_metadata: A map of custom key-value pairs that you can provide as input for the custom workflow that is invoked by the *pre sign-up* trigger. You create custom workflows by assigning AWS Lambda functions to user pool triggers. When you create a ``UserPoolUser`` resource and include the ``ClientMetadata`` property, Amazon Cognito invokes the function that is assigned to the *pre sign-up* trigger. When Amazon Cognito invokes this function, it passes a JSON payload, which the function receives as input. This payload contains a ``clientMetadata`` attribute, which provides the data that you assigned to the ClientMetadata property. In your function code in AWS Lambda , you can process the ``clientMetadata`` value to enhance your workflow for your specific needs. For more information, see `Customizing User Pool Workflows with Lambda Triggers <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html>`_ in the *Amazon Cognito Developer Guide* . .. epigraph:: Take the following limitations into consideration when you use the ClientMetadata parameter: - Amazon Cognito does not store the ClientMetadata value. This data is available only to AWS Lambda triggers that are assigned to a user pool to support custom workflows. If your user pool configuration does not include triggers, the ClientMetadata parameter serves no purpose. - Amazon Cognito does not validate the ClientMetadata value. - Amazon Cognito does not encrypt the the ClientMetadata value, so don't use it to provide sensitive information.
        :param desired_delivery_mediums: Specify ``"EMAIL"`` if email will be used to send the welcome message. Specify ``"SMS"`` if the phone number will be used. The default value is ``"SMS"`` . You can specify more than one value.
        :param force_alias_creation: This parameter is used only if the ``phone_number_verified`` or ``email_verified`` attribute is set to ``True`` . Otherwise, it is ignored. If this parameter is set to ``True`` and the phone number or email address specified in the UserAttributes parameter already exists as an alias with a different user, the API call will migrate the alias from the previous user to the newly created user. The previous user will no longer be able to log in using that alias. If this parameter is set to ``False`` , the API throws an ``AliasExistsException`` error if the alias already exists. The default value is ``False`` .
        :param message_action: Set to ``RESEND`` to resend the invitation message to a user that already exists and reset the expiration limit on the user's account. Set to ``SUPPRESS`` to suppress sending the message. You can specify only one value.
        :param user_attributes: The user attributes and attribute values to be set for the user to be created. These are name-value pairs You can create a user without specifying any attributes other than ``Username`` . However, any attributes that you specify as required (in ` <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>`_ or in the *Attributes* tab of the console) must be supplied either by you (in your call to ``AdminCreateUser`` ) or by the user (when they sign up in response to your welcome message). For custom attributes, you must prepend the ``custom:`` prefix to the attribute name. To send a message inviting the user to sign up, you must specify the user's email address or phone number. This can be done in your call to AdminCreateUser or in the *Users* tab of the Amazon Cognito console for managing your user pools. In your call to ``AdminCreateUser`` , you can set the ``email_verified`` attribute to ``True`` , and you can set the ``phone_number_verified`` attribute to ``True`` . (You can also do this by calling ` <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html>`_ .) - *email* : The email address of the user to whom the message that contains the code and user name will be sent. Required if the ``email_verified`` attribute is set to ``True`` , or if ``"EMAIL"`` is specified in the ``DesiredDeliveryMediums`` parameter. - *phone_number* : The phone number of the user to whom the message that contains the code and user name will be sent. Required if the ``phone_number_verified`` attribute is set to ``True`` , or if ``"SMS"`` is specified in the ``DesiredDeliveryMediums`` parameter.
        :param username: The username for the user. Must be unique within the user pool. Must be a UTF-8 string between 1 and 128 characters. After the user is created, the username can't be changed.
        :param validation_data: The user's validation data. This is an array of name-value pairs that contain user attributes and attribute values that you can use for custom validation, such as restricting the types of user accounts that can be registered. For example, you might choose to allow or disallow user sign-up based on the user's domain. To configure custom validation, you must create a Pre Sign-up AWS Lambda trigger for the user pool as described in the Amazon Cognito Developer Guide. The Lambda trigger receives the validation data and uses it in the validation process. The user's validation data isn't persisted.
        '''
        props = CfnUserPoolUserProps(
            user_pool_id=user_pool_id,
            client_metadata=client_metadata,
            desired_delivery_mediums=desired_delivery_mediums,
            force_alias_creation=force_alias_creation,
            message_action=message_action,
            user_attributes=user_attributes,
            username=username,
            validation_data=validation_data,
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
    @jsii.member(jsii_name="clientMetadata")
    def client_metadata(self) -> typing.Any:
        '''A map of custom key-value pairs that you can provide as input for the custom workflow that is invoked by the *pre sign-up* trigger.

        You create custom workflows by assigning AWS Lambda functions to user pool triggers. When you create a ``UserPoolUser`` resource and include the ``ClientMetadata`` property, Amazon Cognito invokes the function that is assigned to the *pre sign-up* trigger. When Amazon Cognito invokes this function, it passes a JSON payload, which the function receives as input. This payload contains a ``clientMetadata`` attribute, which provides the data that you assigned to the ClientMetadata property. In your function code in AWS Lambda , you can process the ``clientMetadata`` value to enhance your workflow for your specific needs.

        For more information, see `Customizing User Pool Workflows with Lambda Triggers <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html>`_ in the *Amazon Cognito Developer Guide* .
        .. epigraph::

           Take the following limitations into consideration when you use the ClientMetadata parameter:

           - Amazon Cognito does not store the ClientMetadata value. This data is available only to AWS Lambda triggers that are assigned to a user pool to support custom workflows. If your user pool configuration does not include triggers, the ClientMetadata parameter serves no purpose.
           - Amazon Cognito does not validate the ClientMetadata value.
           - Amazon Cognito does not encrypt the the ClientMetadata value, so don't use it to provide sensitive information.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-clientmetadata
        '''
        return typing.cast(typing.Any, jsii.get(self, "clientMetadata"))

    @client_metadata.setter
    def client_metadata(self, value: typing.Any) -> None:
        jsii.set(self, "clientMetadata", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool where the user will be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="desiredDeliveryMediums")
    def desired_delivery_mediums(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specify ``"EMAIL"`` if email will be used to send the welcome message.

        Specify ``"SMS"`` if the phone number will be used. The default value is ``"SMS"`` . You can specify more than one value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-desireddeliverymediums
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "desiredDeliveryMediums"))

    @desired_delivery_mediums.setter
    def desired_delivery_mediums(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "desiredDeliveryMediums", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="forceAliasCreation")
    def force_alias_creation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''This parameter is used only if the ``phone_number_verified`` or ``email_verified`` attribute is set to ``True`` .

        Otherwise, it is ignored.

        If this parameter is set to ``True`` and the phone number or email address specified in the UserAttributes parameter already exists as an alias with a different user, the API call will migrate the alias from the previous user to the newly created user. The previous user will no longer be able to log in using that alias.

        If this parameter is set to ``False`` , the API throws an ``AliasExistsException`` error if the alias already exists. The default value is ``False`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-forcealiascreation
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "forceAliasCreation"))

    @force_alias_creation.setter
    def force_alias_creation(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "forceAliasCreation", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="messageAction")
    def message_action(self) -> typing.Optional[builtins.str]:
        '''Set to ``RESEND`` to resend the invitation message to a user that already exists and reset the expiration limit on the user's account.

        Set to ``SUPPRESS`` to suppress sending the message. You can specify only one value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-messageaction
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "messageAction"))

    @message_action.setter
    def message_action(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "messageAction", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userAttributes")
    def user_attributes(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolUser.AttributeTypeProperty", _IResolvable_da3f097b]]]]:
        '''The user attributes and attribute values to be set for the user to be created.

        These are name-value pairs You can create a user without specifying any attributes other than ``Username`` . However, any attributes that you specify as required (in ` <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>`_ or in the *Attributes* tab of the console) must be supplied either by you (in your call to ``AdminCreateUser`` ) or by the user (when they sign up in response to your welcome message).

        For custom attributes, you must prepend the ``custom:`` prefix to the attribute name.

        To send a message inviting the user to sign up, you must specify the user's email address or phone number. This can be done in your call to AdminCreateUser or in the *Users* tab of the Amazon Cognito console for managing your user pools.

        In your call to ``AdminCreateUser`` , you can set the ``email_verified`` attribute to ``True`` , and you can set the ``phone_number_verified`` attribute to ``True`` . (You can also do this by calling ` <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html>`_ .)

        - *email* : The email address of the user to whom the message that contains the code and user name will be sent. Required if the ``email_verified`` attribute is set to ``True`` , or if ``"EMAIL"`` is specified in the ``DesiredDeliveryMediums`` parameter.
        - *phone_number* : The phone number of the user to whom the message that contains the code and user name will be sent. Required if the ``phone_number_verified`` attribute is set to ``True`` , or if ``"SMS"`` is specified in the ``DesiredDeliveryMediums`` parameter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-userattributes
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolUser.AttributeTypeProperty", _IResolvable_da3f097b]]]], jsii.get(self, "userAttributes"))

    @user_attributes.setter
    def user_attributes(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolUser.AttributeTypeProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "userAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="username")
    def username(self) -> typing.Optional[builtins.str]:
        '''The username for the user.

        Must be unique within the user pool. Must be a UTF-8 string between 1 and 128 characters. After the user is created, the username can't be changed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-username
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "username"))

    @username.setter
    def username(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "username", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="validationData")
    def validation_data(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolUser.AttributeTypeProperty", _IResolvable_da3f097b]]]]:
        '''The user's validation data.

        This is an array of name-value pairs that contain user attributes and attribute values that you can use for custom validation, such as restricting the types of user accounts that can be registered. For example, you might choose to allow or disallow user sign-up based on the user's domain.

        To configure custom validation, you must create a Pre Sign-up AWS Lambda trigger for the user pool as described in the Amazon Cognito Developer Guide. The Lambda trigger receives the validation data and uses it in the validation process.

        The user's validation data isn't persisted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-validationdata
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolUser.AttributeTypeProperty", _IResolvable_da3f097b]]]], jsii.get(self, "validationData"))

    @validation_data.setter
    def validation_data(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnUserPoolUser.AttributeTypeProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "validationData", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolUser.AttributeTypeProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class AttributeTypeProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies whether the attribute is standard or custom.

            :param name: The name of the attribute.
            :param value: The value of the attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpooluser-attributetype.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_cognito as cognito
                
                attribute_type_property = cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="name",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpooluser-attributetype.html#cfn-cognito-userpooluser-attributetype-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value of the attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpooluser-attributetype.html#cfn-cognito-userpooluser-attributetype-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AttributeTypeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolUserProps",
    jsii_struct_bases=[],
    name_mapping={
        "user_pool_id": "userPoolId",
        "client_metadata": "clientMetadata",
        "desired_delivery_mediums": "desiredDeliveryMediums",
        "force_alias_creation": "forceAliasCreation",
        "message_action": "messageAction",
        "user_attributes": "userAttributes",
        "username": "username",
        "validation_data": "validationData",
    },
)
class CfnUserPoolUserProps:
    def __init__(
        self,
        *,
        user_pool_id: builtins.str,
        client_metadata: typing.Any = None,
        desired_delivery_mediums: typing.Optional[typing.Sequence[builtins.str]] = None,
        force_alias_creation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        message_action: typing.Optional[builtins.str] = None,
        user_attributes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnUserPoolUser.AttributeTypeProperty, _IResolvable_da3f097b]]]] = None,
        username: typing.Optional[builtins.str] = None,
        validation_data: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnUserPoolUser.AttributeTypeProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolUser``.

        :param user_pool_id: The user pool ID for the user pool where the user will be created.
        :param client_metadata: A map of custom key-value pairs that you can provide as input for the custom workflow that is invoked by the *pre sign-up* trigger. You create custom workflows by assigning AWS Lambda functions to user pool triggers. When you create a ``UserPoolUser`` resource and include the ``ClientMetadata`` property, Amazon Cognito invokes the function that is assigned to the *pre sign-up* trigger. When Amazon Cognito invokes this function, it passes a JSON payload, which the function receives as input. This payload contains a ``clientMetadata`` attribute, which provides the data that you assigned to the ClientMetadata property. In your function code in AWS Lambda , you can process the ``clientMetadata`` value to enhance your workflow for your specific needs. For more information, see `Customizing User Pool Workflows with Lambda Triggers <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html>`_ in the *Amazon Cognito Developer Guide* . .. epigraph:: Take the following limitations into consideration when you use the ClientMetadata parameter: - Amazon Cognito does not store the ClientMetadata value. This data is available only to AWS Lambda triggers that are assigned to a user pool to support custom workflows. If your user pool configuration does not include triggers, the ClientMetadata parameter serves no purpose. - Amazon Cognito does not validate the ClientMetadata value. - Amazon Cognito does not encrypt the the ClientMetadata value, so don't use it to provide sensitive information.
        :param desired_delivery_mediums: Specify ``"EMAIL"`` if email will be used to send the welcome message. Specify ``"SMS"`` if the phone number will be used. The default value is ``"SMS"`` . You can specify more than one value.
        :param force_alias_creation: This parameter is used only if the ``phone_number_verified`` or ``email_verified`` attribute is set to ``True`` . Otherwise, it is ignored. If this parameter is set to ``True`` and the phone number or email address specified in the UserAttributes parameter already exists as an alias with a different user, the API call will migrate the alias from the previous user to the newly created user. The previous user will no longer be able to log in using that alias. If this parameter is set to ``False`` , the API throws an ``AliasExistsException`` error if the alias already exists. The default value is ``False`` .
        :param message_action: Set to ``RESEND`` to resend the invitation message to a user that already exists and reset the expiration limit on the user's account. Set to ``SUPPRESS`` to suppress sending the message. You can specify only one value.
        :param user_attributes: The user attributes and attribute values to be set for the user to be created. These are name-value pairs You can create a user without specifying any attributes other than ``Username`` . However, any attributes that you specify as required (in ` <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>`_ or in the *Attributes* tab of the console) must be supplied either by you (in your call to ``AdminCreateUser`` ) or by the user (when they sign up in response to your welcome message). For custom attributes, you must prepend the ``custom:`` prefix to the attribute name. To send a message inviting the user to sign up, you must specify the user's email address or phone number. This can be done in your call to AdminCreateUser or in the *Users* tab of the Amazon Cognito console for managing your user pools. In your call to ``AdminCreateUser`` , you can set the ``email_verified`` attribute to ``True`` , and you can set the ``phone_number_verified`` attribute to ``True`` . (You can also do this by calling ` <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html>`_ .) - *email* : The email address of the user to whom the message that contains the code and user name will be sent. Required if the ``email_verified`` attribute is set to ``True`` , or if ``"EMAIL"`` is specified in the ``DesiredDeliveryMediums`` parameter. - *phone_number* : The phone number of the user to whom the message that contains the code and user name will be sent. Required if the ``phone_number_verified`` attribute is set to ``True`` , or if ``"SMS"`` is specified in the ``DesiredDeliveryMediums`` parameter.
        :param username: The username for the user. Must be unique within the user pool. Must be a UTF-8 string between 1 and 128 characters. After the user is created, the username can't be changed.
        :param validation_data: The user's validation data. This is an array of name-value pairs that contain user attributes and attribute values that you can use for custom validation, such as restricting the types of user accounts that can be registered. For example, you might choose to allow or disallow user sign-up based on the user's domain. To configure custom validation, you must create a Pre Sign-up AWS Lambda trigger for the user pool as described in the Amazon Cognito Developer Guide. The Lambda trigger receives the validation data and uses it in the validation process. The user's validation data isn't persisted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # client_metadata: Any
            
            cfn_user_pool_user_props = cognito.CfnUserPoolUserProps(
                user_pool_id="userPoolId",
            
                # the properties below are optional
                client_metadata=client_metadata,
                desired_delivery_mediums=["desiredDeliveryMediums"],
                force_alias_creation=False,
                message_action="messageAction",
                user_attributes=[cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="name",
                    value="value"
                )],
                username="username",
                validation_data=[cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="name",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool_id": user_pool_id,
        }
        if client_metadata is not None:
            self._values["client_metadata"] = client_metadata
        if desired_delivery_mediums is not None:
            self._values["desired_delivery_mediums"] = desired_delivery_mediums
        if force_alias_creation is not None:
            self._values["force_alias_creation"] = force_alias_creation
        if message_action is not None:
            self._values["message_action"] = message_action
        if user_attributes is not None:
            self._values["user_attributes"] = user_attributes
        if username is not None:
            self._values["username"] = username
        if validation_data is not None:
            self._values["validation_data"] = validation_data

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool where the user will be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_metadata(self) -> typing.Any:
        '''A map of custom key-value pairs that you can provide as input for the custom workflow that is invoked by the *pre sign-up* trigger.

        You create custom workflows by assigning AWS Lambda functions to user pool triggers. When you create a ``UserPoolUser`` resource and include the ``ClientMetadata`` property, Amazon Cognito invokes the function that is assigned to the *pre sign-up* trigger. When Amazon Cognito invokes this function, it passes a JSON payload, which the function receives as input. This payload contains a ``clientMetadata`` attribute, which provides the data that you assigned to the ClientMetadata property. In your function code in AWS Lambda , you can process the ``clientMetadata`` value to enhance your workflow for your specific needs.

        For more information, see `Customizing User Pool Workflows with Lambda Triggers <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html>`_ in the *Amazon Cognito Developer Guide* .
        .. epigraph::

           Take the following limitations into consideration when you use the ClientMetadata parameter:

           - Amazon Cognito does not store the ClientMetadata value. This data is available only to AWS Lambda triggers that are assigned to a user pool to support custom workflows. If your user pool configuration does not include triggers, the ClientMetadata parameter serves no purpose.
           - Amazon Cognito does not validate the ClientMetadata value.
           - Amazon Cognito does not encrypt the the ClientMetadata value, so don't use it to provide sensitive information.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-clientmetadata
        '''
        result = self._values.get("client_metadata")
        return typing.cast(typing.Any, result)

    @builtins.property
    def desired_delivery_mediums(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specify ``"EMAIL"`` if email will be used to send the welcome message.

        Specify ``"SMS"`` if the phone number will be used. The default value is ``"SMS"`` . You can specify more than one value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-desireddeliverymediums
        '''
        result = self._values.get("desired_delivery_mediums")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def force_alias_creation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''This parameter is used only if the ``phone_number_verified`` or ``email_verified`` attribute is set to ``True`` .

        Otherwise, it is ignored.

        If this parameter is set to ``True`` and the phone number or email address specified in the UserAttributes parameter already exists as an alias with a different user, the API call will migrate the alias from the previous user to the newly created user. The previous user will no longer be able to log in using that alias.

        If this parameter is set to ``False`` , the API throws an ``AliasExistsException`` error if the alias already exists. The default value is ``False`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-forcealiascreation
        '''
        result = self._values.get("force_alias_creation")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def message_action(self) -> typing.Optional[builtins.str]:
        '''Set to ``RESEND`` to resend the invitation message to a user that already exists and reset the expiration limit on the user's account.

        Set to ``SUPPRESS`` to suppress sending the message. You can specify only one value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-messageaction
        '''
        result = self._values.get("message_action")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def user_attributes(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUserPoolUser.AttributeTypeProperty, _IResolvable_da3f097b]]]]:
        '''The user attributes and attribute values to be set for the user to be created.

        These are name-value pairs You can create a user without specifying any attributes other than ``Username`` . However, any attributes that you specify as required (in ` <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html>`_ or in the *Attributes* tab of the console) must be supplied either by you (in your call to ``AdminCreateUser`` ) or by the user (when they sign up in response to your welcome message).

        For custom attributes, you must prepend the ``custom:`` prefix to the attribute name.

        To send a message inviting the user to sign up, you must specify the user's email address or phone number. This can be done in your call to AdminCreateUser or in the *Users* tab of the Amazon Cognito console for managing your user pools.

        In your call to ``AdminCreateUser`` , you can set the ``email_verified`` attribute to ``True`` , and you can set the ``phone_number_verified`` attribute to ``True`` . (You can also do this by calling ` <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUpdateUserAttributes.html>`_ .)

        - *email* : The email address of the user to whom the message that contains the code and user name will be sent. Required if the ``email_verified`` attribute is set to ``True`` , or if ``"EMAIL"`` is specified in the ``DesiredDeliveryMediums`` parameter.
        - *phone_number* : The phone number of the user to whom the message that contains the code and user name will be sent. Required if the ``phone_number_verified`` attribute is set to ``True`` , or if ``"SMS"`` is specified in the ``DesiredDeliveryMediums`` parameter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-userattributes
        '''
        result = self._values.get("user_attributes")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUserPoolUser.AttributeTypeProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def username(self) -> typing.Optional[builtins.str]:
        '''The username for the user.

        Must be unique within the user pool. Must be a UTF-8 string between 1 and 128 characters. After the user is created, the username can't be changed.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-username
        '''
        result = self._values.get("username")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def validation_data(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUserPoolUser.AttributeTypeProperty, _IResolvable_da3f097b]]]]:
        '''The user's validation data.

        This is an array of name-value pairs that contain user attributes and attribute values that you can use for custom validation, such as restricting the types of user accounts that can be registered. For example, you might choose to allow or disallow user sign-up based on the user's domain.

        To configure custom validation, you must create a Pre Sign-up AWS Lambda trigger for the user pool as described in the Amazon Cognito Developer Guide. The Lambda trigger receives the validation data and uses it in the validation process.

        The user's validation data isn't persisted.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpooluser.html#cfn-cognito-userpooluser-validationdata
        '''
        result = self._values.get("validation_data")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnUserPoolUser.AttributeTypeProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolUserProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnUserPoolUserToGroupAttachment(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolUserToGroupAttachment",
):
    '''A CloudFormation ``AWS::Cognito::UserPoolUserToGroupAttachment``.

    Adds the specified user to the specified group.

    Calling this action requires developer credentials.

    :cloudformationResource: AWS::Cognito::UserPoolUserToGroupAttachment
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolusertogroupattachment.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        cfn_user_pool_user_to_group_attachment = cognito.CfnUserPoolUserToGroupAttachment(self, "MyCfnUserPoolUserToGroupAttachment",
            group_name="groupName",
            username="username",
            user_pool_id="userPoolId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        group_name: builtins.str,
        username: builtins.str,
        user_pool_id: builtins.str,
    ) -> None:
        '''Create a new ``AWS::Cognito::UserPoolUserToGroupAttachment``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param group_name: The group name.
        :param username: The username for the user.
        :param user_pool_id: The user pool ID for the user pool.
        '''
        props = CfnUserPoolUserToGroupAttachmentProps(
            group_name=group_name, username=username, user_pool_id=user_pool_id
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
    @jsii.member(jsii_name="groupName")
    def group_name(self) -> builtins.str:
        '''The group name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolusertogroupattachment.html#cfn-cognito-userpoolusertogroupattachment-groupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "groupName"))

    @group_name.setter
    def group_name(self, value: builtins.str) -> None:
        jsii.set(self, "groupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="username")
    def username(self) -> builtins.str:
        '''The username for the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolusertogroupattachment.html#cfn-cognito-userpoolusertogroupattachment-username
        '''
        return typing.cast(builtins.str, jsii.get(self, "username"))

    @username.setter
    def username(self, value: builtins.str) -> None:
        jsii.set(self, "username", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolusertogroupattachment.html#cfn-cognito-userpoolusertogroupattachment-userpoolid
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @user_pool_id.setter
    def user_pool_id(self, value: builtins.str) -> None:
        jsii.set(self, "userPoolId", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CfnUserPoolUserToGroupAttachmentProps",
    jsii_struct_bases=[],
    name_mapping={
        "group_name": "groupName",
        "username": "username",
        "user_pool_id": "userPoolId",
    },
)
class CfnUserPoolUserToGroupAttachmentProps:
    def __init__(
        self,
        *,
        group_name: builtins.str,
        username: builtins.str,
        user_pool_id: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnUserPoolUserToGroupAttachment``.

        :param group_name: The group name.
        :param username: The username for the user.
        :param user_pool_id: The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolusertogroupattachment.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            cfn_user_pool_user_to_group_attachment_props = cognito.CfnUserPoolUserToGroupAttachmentProps(
                group_name="groupName",
                username="username",
                user_pool_id="userPoolId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "group_name": group_name,
            "username": username,
            "user_pool_id": user_pool_id,
        }

    @builtins.property
    def group_name(self) -> builtins.str:
        '''The group name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolusertogroupattachment.html#cfn-cognito-userpoolusertogroupattachment-groupname
        '''
        result = self._values.get("group_name")
        assert result is not None, "Required property 'group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def username(self) -> builtins.str:
        '''The username for the user.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolusertogroupattachment.html#cfn-cognito-userpoolusertogroupattachment-username
        '''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The user pool ID for the user pool.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolusertogroupattachment.html#cfn-cognito-userpoolusertogroupattachment-userpoolid
        '''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnUserPoolUserToGroupAttachmentProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ClientAttributes(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.ClientAttributes",
):
    '''A set of attributes, useful to set Read and Write attributes.

    :exampleMetadata: infused

    Example::

        pool = cognito.UserPool(self, "Pool")
        
        client_write_attributes = (cognito.ClientAttributes()).with_standard_attributes(fullname=True, email=True).with_custom_attributes("favouritePizza", "favouriteBeverage")
        
        client_read_attributes = client_write_attributes.with_standard_attributes(email_verified=True).with_custom_attributes("pointsEarned")
        
        pool.add_client("app-client",
            # ...
            read_attributes=client_read_attributes,
            write_attributes=client_write_attributes
        )
    '''

    def __init__(self) -> None:
        '''Creates a ClientAttributes with the specified attributes.

        :default: - a ClientAttributes object without any attributes
        '''
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="attributes")
    def attributes(self) -> typing.List[builtins.str]:
        '''The list of attributes represented by this ClientAttributes.'''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "attributes", []))

    @jsii.member(jsii_name="withCustomAttributes")
    def with_custom_attributes(self, *attributes: builtins.str) -> "ClientAttributes":
        '''Creates a custom ClientAttributes with the specified attributes.

        :param attributes: a list of custom attributes to add to the set.
        '''
        return typing.cast("ClientAttributes", jsii.invoke(self, "withCustomAttributes", [*attributes]))

    @jsii.member(jsii_name="withStandardAttributes")
    def with_standard_attributes(
        self,
        *,
        address: typing.Optional[builtins.bool] = None,
        birthdate: typing.Optional[builtins.bool] = None,
        email: typing.Optional[builtins.bool] = None,
        email_verified: typing.Optional[builtins.bool] = None,
        family_name: typing.Optional[builtins.bool] = None,
        fullname: typing.Optional[builtins.bool] = None,
        gender: typing.Optional[builtins.bool] = None,
        given_name: typing.Optional[builtins.bool] = None,
        last_update_time: typing.Optional[builtins.bool] = None,
        locale: typing.Optional[builtins.bool] = None,
        middle_name: typing.Optional[builtins.bool] = None,
        nickname: typing.Optional[builtins.bool] = None,
        phone_number: typing.Optional[builtins.bool] = None,
        phone_number_verified: typing.Optional[builtins.bool] = None,
        preferred_username: typing.Optional[builtins.bool] = None,
        profile_page: typing.Optional[builtins.bool] = None,
        profile_picture: typing.Optional[builtins.bool] = None,
        timezone: typing.Optional[builtins.bool] = None,
        website: typing.Optional[builtins.bool] = None,
    ) -> "ClientAttributes":
        '''Creates a custom ClientAttributes with the specified attributes.

        :param address: The user's postal address. Default: false
        :param birthdate: The user's birthday, represented as an ISO 8601:2004 format. Default: false
        :param email: The user's e-mail address, represented as an RFC 5322 [RFC5322] addr-spec. Default: false
        :param email_verified: Whether the email address has been verified. Default: false
        :param family_name: The surname or last name of the user. Default: false
        :param fullname: The user's full name in displayable form, including all name parts, titles and suffixes. Default: false
        :param gender: The user's gender. Default: false
        :param given_name: The user's first name or give name. Default: false
        :param last_update_time: The time, the user's information was last updated. Default: false
        :param locale: The user's locale, represented as a BCP47 [RFC5646] language tag. Default: false
        :param middle_name: The user's middle name. Default: false
        :param nickname: The user's nickname or casual name. Default: false
        :param phone_number: The user's telephone number. Default: false
        :param phone_number_verified: Whether the phone number has been verified. Default: false
        :param preferred_username: The user's preffered username, different from the immutable user name. Default: false
        :param profile_page: The URL to the user's profile page. Default: false
        :param profile_picture: The URL to the user's profile picture. Default: false
        :param timezone: The user's time zone. Default: false
        :param website: The URL to the user's web page or blog. Default: false
        '''
        attributes = StandardAttributesMask(
            address=address,
            birthdate=birthdate,
            email=email,
            email_verified=email_verified,
            family_name=family_name,
            fullname=fullname,
            gender=gender,
            given_name=given_name,
            last_update_time=last_update_time,
            locale=locale,
            middle_name=middle_name,
            nickname=nickname,
            phone_number=phone_number,
            phone_number_verified=phone_number_verified,
            preferred_username=preferred_username,
            profile_page=profile_page,
            profile_picture=profile_picture,
            timezone=timezone,
            website=website,
        )

        return typing.cast("ClientAttributes", jsii.invoke(self, "withStandardAttributes", [attributes]))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CognitoDomainOptions",
    jsii_struct_bases=[],
    name_mapping={"domain_prefix": "domainPrefix"},
)
class CognitoDomainOptions:
    def __init__(self, *, domain_prefix: builtins.str) -> None:
        '''Options while specifying a cognito prefix domain.

        :param domain_prefix: The prefix to the Cognito hosted domain name that will be associated with the user pool.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain-prefix.html
        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            
            pool.add_domain("CognitoDomain",
                cognito_domain=cognito.CognitoDomainOptions(
                    domain_prefix="my-awesome-app"
                )
            )
            
            certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/11-3336f1-44483d-adc7-9cd375c5169d"
            
            domain_cert = certificatemanager.Certificate.from_certificate_arn(self, "domainCert", certificate_arn)
            pool.add_domain("CustomDomain",
                custom_domain=cognito.CustomDomainOptions(
                    domain_name="user.myapp.com",
                    certificate=domain_cert
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_prefix": domain_prefix,
        }

    @builtins.property
    def domain_prefix(self) -> builtins.str:
        '''The prefix to the Cognito hosted domain name that will be associated with the user pool.'''
        result = self._values.get("domain_prefix")
        assert result is not None, "Required property 'domain_prefix' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CognitoDomainOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CustomAttributeConfig",
    jsii_struct_bases=[],
    name_mapping={
        "data_type": "dataType",
        "mutable": "mutable",
        "number_constraints": "numberConstraints",
        "string_constraints": "stringConstraints",
    },
)
class CustomAttributeConfig:
    def __init__(
        self,
        *,
        data_type: builtins.str,
        mutable: typing.Optional[builtins.bool] = None,
        number_constraints: typing.Optional["NumberAttributeConstraints"] = None,
        string_constraints: typing.Optional["StringAttributeConstraints"] = None,
    ) -> None:
        '''Configuration that will be fed into CloudFormation for any custom attribute type.

        :param data_type: The data type of the custom attribute.
        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: false
        :param number_constraints: The constraints for a custom attribute of the 'Number' data type. Default: - None.
        :param string_constraints: The constraints for a custom attribute of 'String' data type. Default: - None.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            custom_attribute_config = cognito.CustomAttributeConfig(
                data_type="dataType",
            
                # the properties below are optional
                mutable=False,
                number_constraints=cognito.NumberAttributeConstraints(
                    max=123,
                    min=123
                ),
                string_constraints=cognito.StringAttributeConstraints(
                    max_len=123,
                    min_len=123
                )
            )
        '''
        if isinstance(number_constraints, dict):
            number_constraints = NumberAttributeConstraints(**number_constraints)
        if isinstance(string_constraints, dict):
            string_constraints = StringAttributeConstraints(**string_constraints)
        self._values: typing.Dict[str, typing.Any] = {
            "data_type": data_type,
        }
        if mutable is not None:
            self._values["mutable"] = mutable
        if number_constraints is not None:
            self._values["number_constraints"] = number_constraints
        if string_constraints is not None:
            self._values["string_constraints"] = string_constraints

    @builtins.property
    def data_type(self) -> builtins.str:
        '''The data type of the custom attribute.

        :see: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SchemaAttributeType.html#CognitoUserPools-Type-SchemaAttributeType-AttributeDataType
        '''
        result = self._values.get("data_type")
        assert result is not None, "Required property 'data_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def mutable(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the value of the attribute can be changed.

        For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true.
        Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider.
        If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute.

        :default: false
        '''
        result = self._values.get("mutable")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def number_constraints(self) -> typing.Optional["NumberAttributeConstraints"]:
        '''The constraints for a custom attribute of the 'Number' data type.

        :default: - None.
        '''
        result = self._values.get("number_constraints")
        return typing.cast(typing.Optional["NumberAttributeConstraints"], result)

    @builtins.property
    def string_constraints(self) -> typing.Optional["StringAttributeConstraints"]:
        '''The constraints for a custom attribute of 'String' data type.

        :default: - None.
        '''
        result = self._values.get("string_constraints")
        return typing.cast(typing.Optional["StringAttributeConstraints"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CustomAttributeConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CustomAttributeProps",
    jsii_struct_bases=[],
    name_mapping={"mutable": "mutable"},
)
class CustomAttributeProps:
    def __init__(self, *, mutable: typing.Optional[builtins.bool] = None) -> None:
        '''Constraints that can be applied to a custom attribute of any type.

        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: false

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                standard_attributes=cognito.StandardAttributes(
                    fullname=cognito.StandardAttribute(
                        required=True,
                        mutable=False
                    ),
                    address=cognito.StandardAttribute(
                        required=False,
                        mutable=True
                    )
                ),
                custom_attributes={
                    "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                    "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                    "is_employee": cognito.BooleanAttribute(mutable=True),
                    "joined_on": cognito.DateTimeAttribute()
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if mutable is not None:
            self._values["mutable"] = mutable

    @builtins.property
    def mutable(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the value of the attribute can be changed.

        For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true.
        Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider.
        If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute.

        :default: false
        '''
        result = self._values.get("mutable")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CustomAttributeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.CustomDomainOptions",
    jsii_struct_bases=[],
    name_mapping={"certificate": "certificate", "domain_name": "domainName"},
)
class CustomDomainOptions:
    def __init__(
        self,
        *,
        certificate: _ICertificate_c194c70b,
        domain_name: builtins.str,
    ) -> None:
        '''Options while specifying custom domain.

        :param certificate: The certificate to associate with this domain.
        :param domain_name: The custom domain name that you would like to associate with this User Pool.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-add-custom-domain.html
        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            
            pool.add_domain("CognitoDomain",
                cognito_domain=cognito.CognitoDomainOptions(
                    domain_prefix="my-awesome-app"
                )
            )
            
            certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/11-3336f1-44483d-adc7-9cd375c5169d"
            
            domain_cert = certificatemanager.Certificate.from_certificate_arn(self, "domainCert", certificate_arn)
            pool.add_domain("CustomDomain",
                custom_domain=cognito.CustomDomainOptions(
                    domain_name="user.myapp.com",
                    certificate=domain_cert
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "certificate": certificate,
            "domain_name": domain_name,
        }

    @builtins.property
    def certificate(self) -> _ICertificate_c194c70b:
        '''The certificate to associate with this domain.'''
        result = self._values.get("certificate")
        assert result is not None, "Required property 'certificate' is missing"
        return typing.cast(_ICertificate_c194c70b, result)

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The custom domain name that you would like to associate with this User Pool.'''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CustomDomainOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.DeviceTracking",
    jsii_struct_bases=[],
    name_mapping={
        "challenge_required_on_new_device": "challengeRequiredOnNewDevice",
        "device_only_remembered_on_user_prompt": "deviceOnlyRememberedOnUserPrompt",
    },
)
class DeviceTracking:
    def __init__(
        self,
        *,
        challenge_required_on_new_device: builtins.bool,
        device_only_remembered_on_user_prompt: builtins.bool,
    ) -> None:
        '''Device tracking settings.

        :param challenge_required_on_new_device: Indicates whether a challenge is required on a new device. Only applicable to a new device. Default: false
        :param device_only_remembered_on_user_prompt: If true, a device is only remembered on user prompt. Default: false

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-device-tracking.html
        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                device_tracking=cognito.DeviceTracking(
                    challenge_required_on_new_device=True,
                    device_only_remembered_on_user_prompt=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "challenge_required_on_new_device": challenge_required_on_new_device,
            "device_only_remembered_on_user_prompt": device_only_remembered_on_user_prompt,
        }

    @builtins.property
    def challenge_required_on_new_device(self) -> builtins.bool:
        '''Indicates whether a challenge is required on a new device.

        Only applicable to a new device.

        :default: false

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-device-tracking.html
        '''
        result = self._values.get("challenge_required_on_new_device")
        assert result is not None, "Required property 'challenge_required_on_new_device' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def device_only_remembered_on_user_prompt(self) -> builtins.bool:
        '''If true, a device is only remembered on user prompt.

        :default: false

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-device-tracking.html
        '''
        result = self._values.get("device_only_remembered_on_user_prompt")
        assert result is not None, "Required property 'device_only_remembered_on_user_prompt' is missing"
        return typing.cast(builtins.bool, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DeviceTracking(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.EmailSettings",
    jsii_struct_bases=[],
    name_mapping={"from_": "from", "reply_to": "replyTo"},
)
class EmailSettings:
    def __init__(
        self,
        *,
        from_: typing.Optional[builtins.str] = None,
        reply_to: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Email settings for the user pool.

        :param from_: The 'from' address on the emails received by the user. Default: noreply
        :param reply_to: The 'replyTo' address on the emails received by the user as defined by IETF RFC-5322. When set, most email clients recognize to change 'to' line to this address when a reply is drafted. Default: - Not set.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            email_settings = cognito.EmailSettings(
                from="from",
                reply_to="replyTo"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if from_ is not None:
            self._values["from_"] = from_
        if reply_to is not None:
            self._values["reply_to"] = reply_to

    @builtins.property
    def from_(self) -> typing.Optional[builtins.str]:
        '''The 'from' address on the emails received by the user.

        :default: noreply

        :verificationemail: .com
        '''
        result = self._values.get("from_")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def reply_to(self) -> typing.Optional[builtins.str]:
        '''The 'replyTo' address on the emails received by the user as defined by IETF RFC-5322.

        When set, most email clients recognize to change 'to' line to this address when a reply is drafted.

        :default: - Not set.
        '''
        result = self._values.get("reply_to")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EmailSettings(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_cognito.ICustomAttribute")
class ICustomAttribute(typing_extensions.Protocol):
    '''Represents a custom attribute type.'''

    @jsii.member(jsii_name="bind")
    def bind(self) -> CustomAttributeConfig:
        '''Bind this custom attribute type to the values as expected by CloudFormation.'''
        ...


class _ICustomAttributeProxy:
    '''Represents a custom attribute type.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_cognito.ICustomAttribute"

    @jsii.member(jsii_name="bind")
    def bind(self) -> CustomAttributeConfig:
        '''Bind this custom attribute type to the values as expected by CloudFormation.'''
        return typing.cast(CustomAttributeConfig, jsii.invoke(self, "bind", []))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ICustomAttribute).__jsii_proxy_class__ = lambda : _ICustomAttributeProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_cognito.IUserPool")
class IUserPool(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents a Cognito UserPool.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="identityProviders")
    def identity_providers(self) -> typing.List["IUserPoolIdentityProvider"]:
        '''Get all identity providers registered with this user pool.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolArn")
    def user_pool_arn(self) -> builtins.str:
        '''The ARN of this user pool resource.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The physical ID of this user pool resource.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="addClient")
    def add_client(
        self,
        id: builtins.str,
        *,
        access_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        auth_flows: typing.Optional[AuthFlow] = None,
        disable_o_auth: typing.Optional[builtins.bool] = None,
        enable_token_revocation: typing.Optional[builtins.bool] = None,
        generate_secret: typing.Optional[builtins.bool] = None,
        id_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        o_auth: typing.Optional["OAuthSettings"] = None,
        prevent_user_existence_errors: typing.Optional[builtins.bool] = None,
        read_attributes: typing.Optional[ClientAttributes] = None,
        refresh_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        supported_identity_providers: typing.Optional[typing.Sequence["UserPoolClientIdentityProvider"]] = None,
        user_pool_client_name: typing.Optional[builtins.str] = None,
        write_attributes: typing.Optional[ClientAttributes] = None,
    ) -> "UserPoolClient":
        '''Add a new app client to this user pool.

        :param id: -
        :param access_token_validity: Validity of the access token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param auth_flows: The set of OAuth authentication flows to enable on the client. Default: - all auth flows disabled
        :param disable_o_auth: Turns off all OAuth interactions for this client. Default: false
        :param enable_token_revocation: Enable token revocation for this client. Default: true for new user pool clients
        :param generate_secret: Whether to generate a client secret. Default: false
        :param id_token_validity: Validity of the ID token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param o_auth: OAuth settings for this client to interact with the app. An error is thrown when this is specified and ``disableOAuth`` is set. Default: - see defaults in ``OAuthSettings``. meaningless if ``disableOAuth`` is set.
        :param prevent_user_existence_errors: Whether Cognito returns a UserNotFoundException exception when the user does not exist in the user pool (false), or whether it returns another type of error that doesn't reveal the user's absence. Default: false
        :param read_attributes: The set of attributes this client will be able to read. Default: - all standard and custom attributes
        :param refresh_token_validity: Validity of the refresh token. Values between 60 minutes and 10 years are valid. Default: Duration.days(30)
        :param supported_identity_providers: The list of identity providers that users should be able to use to sign in using this client. Default: - supports all identity providers that are registered with the user pool. If the user pool and/or identity providers are imported, either specify this option explicitly or ensure that the identity providers are registered with the user pool using the ``UserPool.registerIdentityProvider()`` API.
        :param user_pool_client_name: Name of the application client. Default: - cloudformation generated name
        :param write_attributes: The set of attributes this client will be able to write. Default: - all standard and custom attributes

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html
        '''
        ...

    @jsii.member(jsii_name="addDomain")
    def add_domain(
        self,
        id: builtins.str,
        *,
        cognito_domain: typing.Optional[CognitoDomainOptions] = None,
        custom_domain: typing.Optional[CustomDomainOptions] = None,
    ) -> "UserPoolDomain":
        '''Associate a domain to this user pool.

        :param id: -
        :param cognito_domain: Associate a cognito prefix domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``customDomain`` is specified, otherwise, throws an error.
        :param custom_domain: Associate a custom domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``cognitoDomain`` is specified, otherwise, throws an error.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html
        '''
        ...

    @jsii.member(jsii_name="addResourceServer")
    def add_resource_server(
        self,
        id: builtins.str,
        *,
        identifier: builtins.str,
        scopes: typing.Optional[typing.Sequence["ResourceServerScope"]] = None,
        user_pool_resource_server_name: typing.Optional[builtins.str] = None,
    ) -> "UserPoolResourceServer":
        '''Add a new resource server to this user pool.

        :param id: -
        :param identifier: A unique resource server identifier for the resource server.
        :param scopes: Oauth scopes. Default: - No scopes will be added
        :param user_pool_resource_server_name: A friendly name for the resource server. Default: - same as ``identifier``

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-resource-servers.html
        '''
        ...

    @jsii.member(jsii_name="registerIdentityProvider")
    def register_identity_provider(self, provider: "IUserPoolIdentityProvider") -> None:
        '''Register an identity provider with this user pool.

        :param provider: -
        '''
        ...


class _IUserPoolProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents a Cognito UserPool.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_cognito.IUserPool"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="identityProviders")
    def identity_providers(self) -> typing.List["IUserPoolIdentityProvider"]:
        '''Get all identity providers registered with this user pool.'''
        return typing.cast(typing.List["IUserPoolIdentityProvider"], jsii.get(self, "identityProviders"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolArn")
    def user_pool_arn(self) -> builtins.str:
        '''The ARN of this user pool resource.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The physical ID of this user pool resource.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @jsii.member(jsii_name="addClient")
    def add_client(
        self,
        id: builtins.str,
        *,
        access_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        auth_flows: typing.Optional[AuthFlow] = None,
        disable_o_auth: typing.Optional[builtins.bool] = None,
        enable_token_revocation: typing.Optional[builtins.bool] = None,
        generate_secret: typing.Optional[builtins.bool] = None,
        id_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        o_auth: typing.Optional["OAuthSettings"] = None,
        prevent_user_existence_errors: typing.Optional[builtins.bool] = None,
        read_attributes: typing.Optional[ClientAttributes] = None,
        refresh_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        supported_identity_providers: typing.Optional[typing.Sequence["UserPoolClientIdentityProvider"]] = None,
        user_pool_client_name: typing.Optional[builtins.str] = None,
        write_attributes: typing.Optional[ClientAttributes] = None,
    ) -> "UserPoolClient":
        '''Add a new app client to this user pool.

        :param id: -
        :param access_token_validity: Validity of the access token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param auth_flows: The set of OAuth authentication flows to enable on the client. Default: - all auth flows disabled
        :param disable_o_auth: Turns off all OAuth interactions for this client. Default: false
        :param enable_token_revocation: Enable token revocation for this client. Default: true for new user pool clients
        :param generate_secret: Whether to generate a client secret. Default: false
        :param id_token_validity: Validity of the ID token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param o_auth: OAuth settings for this client to interact with the app. An error is thrown when this is specified and ``disableOAuth`` is set. Default: - see defaults in ``OAuthSettings``. meaningless if ``disableOAuth`` is set.
        :param prevent_user_existence_errors: Whether Cognito returns a UserNotFoundException exception when the user does not exist in the user pool (false), or whether it returns another type of error that doesn't reveal the user's absence. Default: false
        :param read_attributes: The set of attributes this client will be able to read. Default: - all standard and custom attributes
        :param refresh_token_validity: Validity of the refresh token. Values between 60 minutes and 10 years are valid. Default: Duration.days(30)
        :param supported_identity_providers: The list of identity providers that users should be able to use to sign in using this client. Default: - supports all identity providers that are registered with the user pool. If the user pool and/or identity providers are imported, either specify this option explicitly or ensure that the identity providers are registered with the user pool using the ``UserPool.registerIdentityProvider()`` API.
        :param user_pool_client_name: Name of the application client. Default: - cloudformation generated name
        :param write_attributes: The set of attributes this client will be able to write. Default: - all standard and custom attributes

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html
        '''
        options = UserPoolClientOptions(
            access_token_validity=access_token_validity,
            auth_flows=auth_flows,
            disable_o_auth=disable_o_auth,
            enable_token_revocation=enable_token_revocation,
            generate_secret=generate_secret,
            id_token_validity=id_token_validity,
            o_auth=o_auth,
            prevent_user_existence_errors=prevent_user_existence_errors,
            read_attributes=read_attributes,
            refresh_token_validity=refresh_token_validity,
            supported_identity_providers=supported_identity_providers,
            user_pool_client_name=user_pool_client_name,
            write_attributes=write_attributes,
        )

        return typing.cast("UserPoolClient", jsii.invoke(self, "addClient", [id, options]))

    @jsii.member(jsii_name="addDomain")
    def add_domain(
        self,
        id: builtins.str,
        *,
        cognito_domain: typing.Optional[CognitoDomainOptions] = None,
        custom_domain: typing.Optional[CustomDomainOptions] = None,
    ) -> "UserPoolDomain":
        '''Associate a domain to this user pool.

        :param id: -
        :param cognito_domain: Associate a cognito prefix domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``customDomain`` is specified, otherwise, throws an error.
        :param custom_domain: Associate a custom domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``cognitoDomain`` is specified, otherwise, throws an error.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain.html
        '''
        options = UserPoolDomainOptions(
            cognito_domain=cognito_domain, custom_domain=custom_domain
        )

        return typing.cast("UserPoolDomain", jsii.invoke(self, "addDomain", [id, options]))

    @jsii.member(jsii_name="addResourceServer")
    def add_resource_server(
        self,
        id: builtins.str,
        *,
        identifier: builtins.str,
        scopes: typing.Optional[typing.Sequence["ResourceServerScope"]] = None,
        user_pool_resource_server_name: typing.Optional[builtins.str] = None,
    ) -> "UserPoolResourceServer":
        '''Add a new resource server to this user pool.

        :param id: -
        :param identifier: A unique resource server identifier for the resource server.
        :param scopes: Oauth scopes. Default: - No scopes will be added
        :param user_pool_resource_server_name: A friendly name for the resource server. Default: - same as ``identifier``

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-resource-servers.html
        '''
        options = UserPoolResourceServerOptions(
            identifier=identifier,
            scopes=scopes,
            user_pool_resource_server_name=user_pool_resource_server_name,
        )

        return typing.cast("UserPoolResourceServer", jsii.invoke(self, "addResourceServer", [id, options]))

    @jsii.member(jsii_name="registerIdentityProvider")
    def register_identity_provider(self, provider: "IUserPoolIdentityProvider") -> None:
        '''Register an identity provider with this user pool.

        :param provider: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerIdentityProvider", [provider]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IUserPool).__jsii_proxy_class__ = lambda : _IUserPoolProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_cognito.IUserPoolClient")
class IUserPoolClient(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents a Cognito user pool client.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolClientId")
    def user_pool_client_id(self) -> builtins.str:
        '''Name of the application client.

        :attribute: true
        '''
        ...


class _IUserPoolClientProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents a Cognito user pool client.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_cognito.IUserPoolClient"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolClientId")
    def user_pool_client_id(self) -> builtins.str:
        '''Name of the application client.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolClientId"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IUserPoolClient).__jsii_proxy_class__ = lambda : _IUserPoolClientProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_cognito.IUserPoolDomain")
class IUserPoolDomain(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents a user pool domain.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The domain that was specified to be created.

        If ``customDomain`` was selected, this holds the full domain name that was specified.
        If the ``cognitoDomain`` was used, it contains the prefix to the Cognito hosted domain.

        :attribute: true
        '''
        ...


class _IUserPoolDomainProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents a user pool domain.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_cognito.IUserPoolDomain"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The domain that was specified to be created.

        If ``customDomain`` was selected, this holds the full domain name that was specified.
        If the ``cognitoDomain`` was used, it contains the prefix to the Cognito hosted domain.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IUserPoolDomain).__jsii_proxy_class__ = lambda : _IUserPoolDomainProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_cognito.IUserPoolIdentityProvider")
class IUserPoolIdentityProvider(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents a UserPoolIdentityProvider.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerName")
    def provider_name(self) -> builtins.str:
        '''The primary identifier of this identity provider.

        :attribute: true
        '''
        ...


class _IUserPoolIdentityProviderProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents a UserPoolIdentityProvider.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_cognito.IUserPoolIdentityProvider"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerName")
    def provider_name(self) -> builtins.str:
        '''The primary identifier of this identity provider.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "providerName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IUserPoolIdentityProvider).__jsii_proxy_class__ = lambda : _IUserPoolIdentityProviderProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_cognito.IUserPoolResourceServer")
class IUserPoolResourceServer(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents a Cognito user pool resource server.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolResourceServerId")
    def user_pool_resource_server_id(self) -> builtins.str:
        '''Resource server id.

        :attribute: true
        '''
        ...


class _IUserPoolResourceServerProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents a Cognito user pool resource server.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_cognito.IUserPoolResourceServer"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolResourceServerId")
    def user_pool_resource_server_id(self) -> builtins.str:
        '''Resource server id.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolResourceServerId"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IUserPoolResourceServer).__jsii_proxy_class__ = lambda : _IUserPoolResourceServerProxy


@jsii.enum(jsii_type="aws-cdk-lib.aws_cognito.Mfa")
class Mfa(enum.Enum):
    '''The different ways in which a user pool's MFA enforcement can be configured.

    :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html
    :exampleMetadata: infused

    Example::

        cognito.UserPool(self, "myuserpool",
            # ...
            mfa=cognito.Mfa.REQUIRED,
            mfa_second_factor=cognito.MfaSecondFactor(
                sms=True,
                otp=True
            )
        )
    '''

    OFF = "OFF"
    '''Users are not required to use MFA for sign in, and cannot configure one.'''
    OPTIONAL = "OPTIONAL"
    '''Users are not required to use MFA for sign in, but can configure one if they so choose to.'''
    REQUIRED = "REQUIRED"
    '''Users are required to configure an MFA, and have to use it to sign in.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.MfaSecondFactor",
    jsii_struct_bases=[],
    name_mapping={"otp": "otp", "sms": "sms"},
)
class MfaSecondFactor:
    def __init__(self, *, otp: builtins.bool, sms: builtins.bool) -> None:
        '''The different ways in which a user pool can obtain their MFA token for sign in.

        :param otp: The MFA token is a time-based one time password that is generated by a hardware or software token. Default: false
        :param sms: The MFA token is sent to the user via SMS to their verified phone numbers. Default: true

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html
        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                mfa=cognito.Mfa.REQUIRED,
                mfa_second_factor=cognito.MfaSecondFactor(
                    sms=True,
                    otp=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "otp": otp,
            "sms": sms,
        }

    @builtins.property
    def otp(self) -> builtins.bool:
        '''The MFA token is a time-based one time password that is generated by a hardware or software token.

        :default: false

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html
        '''
        result = self._values.get("otp")
        assert result is not None, "Required property 'otp' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def sms(self) -> builtins.bool:
        '''The MFA token is sent to the user via SMS to their verified phone numbers.

        :default: true

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-sms-text-message.html
        '''
        result = self._values.get("sms")
        assert result is not None, "Required property 'sms' is missing"
        return typing.cast(builtins.bool, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MfaSecondFactor(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(ICustomAttribute)
class NumberAttribute(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.NumberAttribute",
):
    '''The Number custom attribute type.

    :exampleMetadata: infused

    Example::

        cognito.UserPool(self, "myuserpool",
            # ...
            standard_attributes=cognito.StandardAttributes(
                fullname=cognito.StandardAttribute(
                    required=True,
                    mutable=False
                ),
                address=cognito.StandardAttribute(
                    required=False,
                    mutable=True
                )
            ),
            custom_attributes={
                "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                "is_employee": cognito.BooleanAttribute(mutable=True),
                "joined_on": cognito.DateTimeAttribute()
            }
        )
    '''

    def __init__(
        self,
        *,
        max: typing.Optional[jsii.Number] = None,
        min: typing.Optional[jsii.Number] = None,
        mutable: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''
        :param max: Maximum value of this attribute. Default: - no maximum value
        :param min: Minimum value of this attribute. Default: - no minimum value
        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: false
        '''
        props = NumberAttributeProps(max=max, min=min, mutable=mutable)

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="bind")
    def bind(self) -> CustomAttributeConfig:
        '''Bind this custom attribute type to the values as expected by CloudFormation.'''
        return typing.cast(CustomAttributeConfig, jsii.invoke(self, "bind", []))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.NumberAttributeConstraints",
    jsii_struct_bases=[],
    name_mapping={"max": "max", "min": "min"},
)
class NumberAttributeConstraints:
    def __init__(
        self,
        *,
        max: typing.Optional[jsii.Number] = None,
        min: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Constraints that can be applied to a custom attribute of number type.

        :param max: Maximum value of this attribute. Default: - no maximum value
        :param min: Minimum value of this attribute. Default: - no minimum value

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            number_attribute_constraints = cognito.NumberAttributeConstraints(
                max=123,
                min=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if max is not None:
            self._values["max"] = max
        if min is not None:
            self._values["min"] = min

    @builtins.property
    def max(self) -> typing.Optional[jsii.Number]:
        '''Maximum value of this attribute.

        :default: - no maximum value
        '''
        result = self._values.get("max")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min(self) -> typing.Optional[jsii.Number]:
        '''Minimum value of this attribute.

        :default: - no minimum value
        '''
        result = self._values.get("min")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NumberAttributeConstraints(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.NumberAttributeProps",
    jsii_struct_bases=[NumberAttributeConstraints, CustomAttributeProps],
    name_mapping={"max": "max", "min": "min", "mutable": "mutable"},
)
class NumberAttributeProps(NumberAttributeConstraints, CustomAttributeProps):
    def __init__(
        self,
        *,
        max: typing.Optional[jsii.Number] = None,
        min: typing.Optional[jsii.Number] = None,
        mutable: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Props for NumberAttr.

        :param max: Maximum value of this attribute. Default: - no maximum value
        :param min: Minimum value of this attribute. Default: - no minimum value
        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: false

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                standard_attributes=cognito.StandardAttributes(
                    fullname=cognito.StandardAttribute(
                        required=True,
                        mutable=False
                    ),
                    address=cognito.StandardAttribute(
                        required=False,
                        mutable=True
                    )
                ),
                custom_attributes={
                    "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                    "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                    "is_employee": cognito.BooleanAttribute(mutable=True),
                    "joined_on": cognito.DateTimeAttribute()
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if max is not None:
            self._values["max"] = max
        if min is not None:
            self._values["min"] = min
        if mutable is not None:
            self._values["mutable"] = mutable

    @builtins.property
    def max(self) -> typing.Optional[jsii.Number]:
        '''Maximum value of this attribute.

        :default: - no maximum value
        '''
        result = self._values.get("max")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min(self) -> typing.Optional[jsii.Number]:
        '''Minimum value of this attribute.

        :default: - no minimum value
        '''
        result = self._values.get("min")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def mutable(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the value of the attribute can be changed.

        For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true.
        Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider.
        If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute.

        :default: false
        '''
        result = self._values.get("mutable")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NumberAttributeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.OAuthFlows",
    jsii_struct_bases=[],
    name_mapping={
        "authorization_code_grant": "authorizationCodeGrant",
        "client_credentials": "clientCredentials",
        "implicit_code_grant": "implicitCodeGrant",
    },
)
class OAuthFlows:
    def __init__(
        self,
        *,
        authorization_code_grant: typing.Optional[builtins.bool] = None,
        client_credentials: typing.Optional[builtins.bool] = None,
        implicit_code_grant: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Types of OAuth grant flows.

        :param authorization_code_grant: Initiate an authorization code grant flow, which provides an authorization code as the response. Default: false
        :param client_credentials: Client should get the access token and ID token from the token endpoint using a combination of client and client_secret. Default: false
        :param implicit_code_grant: The client should get the access token and ID token directly. Default: false

        :see: - the 'Allowed OAuth Flows' section at https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-idp-settings.html
        :exampleMetadata: infused

        Example::

            userpool = cognito.UserPool(self, "UserPool")
            client = userpool.add_client("Client",
                # ...
                o_auth=cognito.OAuthSettings(
                    flows=cognito.OAuthFlows(
                        implicit_code_grant=True
                    ),
                    callback_urls=["https://myapp.com/home", "https://myapp.com/users"
                    ]
                )
            )
            domain = userpool.add_domain("Domain")
            sign_in_url = domain.sign_in_url(client,
                redirect_uri="https://myapp.com/home"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if authorization_code_grant is not None:
            self._values["authorization_code_grant"] = authorization_code_grant
        if client_credentials is not None:
            self._values["client_credentials"] = client_credentials
        if implicit_code_grant is not None:
            self._values["implicit_code_grant"] = implicit_code_grant

    @builtins.property
    def authorization_code_grant(self) -> typing.Optional[builtins.bool]:
        '''Initiate an authorization code grant flow, which provides an authorization code as the response.

        :default: false
        '''
        result = self._values.get("authorization_code_grant")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def client_credentials(self) -> typing.Optional[builtins.bool]:
        '''Client should get the access token and ID token from the token endpoint using a combination of client and client_secret.

        :default: false
        '''
        result = self._values.get("client_credentials")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def implicit_code_grant(self) -> typing.Optional[builtins.bool]:
        '''The client should get the access token and ID token directly.

        :default: false
        '''
        result = self._values.get("implicit_code_grant")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OAuthFlows(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class OAuthScope(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.OAuthScope",
):
    '''OAuth scopes that are allowed with this client.

    :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-idp-settings.html
    :exampleMetadata: infused

    Example::

        pool = cognito.UserPool(self, "Pool")
        
        read_only_scope = cognito.ResourceServerScope(scope_name="read", scope_description="Read-only access")
        full_access_scope = cognito.ResourceServerScope(scope_name="*", scope_description="Full access")
        
        user_server = pool.add_resource_server("ResourceServer",
            identifier="users",
            scopes=[read_only_scope, full_access_scope]
        )
        
        read_only_client = pool.add_client("read-only-client",
            # ...
            o_auth=cognito.OAuthSettings(
                # ...
                scopes=[cognito.OAuthScope.resource_server(user_server, read_only_scope)]
            )
        )
        
        full_access_client = pool.add_client("full-access-client",
            # ...
            o_auth=cognito.OAuthSettings(
                # ...
                scopes=[cognito.OAuthScope.resource_server(user_server, full_access_scope)]
            )
        )
    '''

    @jsii.member(jsii_name="custom") # type: ignore[misc]
    @builtins.classmethod
    def custom(cls, name: builtins.str) -> "OAuthScope":
        '''Custom scope is one that you define for your own resource server in the Resource Servers.

        The format is 'resource-server-identifier/scope'.

        :param name: -

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html
        '''
        return typing.cast("OAuthScope", jsii.sinvoke(cls, "custom", [name]))

    @jsii.member(jsii_name="resourceServer") # type: ignore[misc]
    @builtins.classmethod
    def resource_server(
        cls,
        server: IUserPoolResourceServer,
        scope: "ResourceServerScope",
    ) -> "OAuthScope":
        '''Adds a custom scope that's tied to a resource server in your stack.

        :param server: -
        :param scope: -
        '''
        return typing.cast("OAuthScope", jsii.sinvoke(cls, "resourceServer", [server, scope]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="COGNITO_ADMIN")
    def COGNITO_ADMIN(cls) -> "OAuthScope":
        '''Grants access to Amazon Cognito User Pool API operations that require access tokens, such as UpdateUserAttributes and VerifyUserAttribute.'''
        return typing.cast("OAuthScope", jsii.sget(cls, "COGNITO_ADMIN"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="EMAIL")
    def EMAIL(cls) -> "OAuthScope":
        '''Grants access to the 'email' and 'email_verified' claims.

        Automatically includes access to ``OAuthScope.OPENID``.
        '''
        return typing.cast("OAuthScope", jsii.sget(cls, "EMAIL"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="OPENID")
    def OPENID(cls) -> "OAuthScope":
        '''Returns all user attributes in the ID token that are readable by the client.'''
        return typing.cast("OAuthScope", jsii.sget(cls, "OPENID"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PHONE")
    def PHONE(cls) -> "OAuthScope":
        '''Grants access to the 'phone_number' and 'phone_number_verified' claims.

        Automatically includes access to ``OAuthScope.OPENID``.
        '''
        return typing.cast("OAuthScope", jsii.sget(cls, "PHONE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PROFILE")
    def PROFILE(cls) -> "OAuthScope":
        '''Grants access to all user attributes that are readable by the client Automatically includes access to ``OAuthScope.OPENID``.'''
        return typing.cast("OAuthScope", jsii.sget(cls, "PROFILE"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scopeName")
    def scope_name(self) -> builtins.str:
        '''The name of this scope as recognized by CloudFormation.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html#cfn-cognito-userpoolclient-allowedoauthscopes
        '''
        return typing.cast(builtins.str, jsii.get(self, "scopeName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.OAuthSettings",
    jsii_struct_bases=[],
    name_mapping={
        "callback_urls": "callbackUrls",
        "flows": "flows",
        "logout_urls": "logoutUrls",
        "scopes": "scopes",
    },
)
class OAuthSettings:
    def __init__(
        self,
        *,
        callback_urls: typing.Optional[typing.Sequence[builtins.str]] = None,
        flows: typing.Optional[OAuthFlows] = None,
        logout_urls: typing.Optional[typing.Sequence[builtins.str]] = None,
        scopes: typing.Optional[typing.Sequence[OAuthScope]] = None,
    ) -> None:
        '''OAuth settings to configure the interaction between the app and this client.

        :param callback_urls: List of allowed redirect URLs for the identity providers. Default: - ['https://example.com'] if either authorizationCodeGrant or implicitCodeGrant flows are enabled, no callback URLs otherwise.
        :param flows: OAuth flows that are allowed with this client. Default: {authorizationCodeGrant:true,implicitCodeGrant:true}
        :param logout_urls: List of allowed logout URLs for the identity providers. Default: - no logout URLs
        :param scopes: OAuth scopes that are allowed with this client. Default: [OAuthScope.PHONE,OAuthScope.EMAIL,OAuthScope.OPENID,OAuthScope.PROFILE,OAuthScope.COGNITO_ADMIN]

        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            
            read_only_scope = cognito.ResourceServerScope(scope_name="read", scope_description="Read-only access")
            full_access_scope = cognito.ResourceServerScope(scope_name="*", scope_description="Full access")
            
            user_server = pool.add_resource_server("ResourceServer",
                identifier="users",
                scopes=[read_only_scope, full_access_scope]
            )
            
            read_only_client = pool.add_client("read-only-client",
                # ...
                o_auth=cognito.OAuthSettings(
                    # ...
                    scopes=[cognito.OAuthScope.resource_server(user_server, read_only_scope)]
                )
            )
            
            full_access_client = pool.add_client("full-access-client",
                # ...
                o_auth=cognito.OAuthSettings(
                    # ...
                    scopes=[cognito.OAuthScope.resource_server(user_server, full_access_scope)]
                )
            )
        '''
        if isinstance(flows, dict):
            flows = OAuthFlows(**flows)
        self._values: typing.Dict[str, typing.Any] = {}
        if callback_urls is not None:
            self._values["callback_urls"] = callback_urls
        if flows is not None:
            self._values["flows"] = flows
        if logout_urls is not None:
            self._values["logout_urls"] = logout_urls
        if scopes is not None:
            self._values["scopes"] = scopes

    @builtins.property
    def callback_urls(self) -> typing.Optional[typing.List[builtins.str]]:
        '''List of allowed redirect URLs for the identity providers.

        :default: - ['https://example.com'] if either authorizationCodeGrant or implicitCodeGrant flows are enabled, no callback URLs otherwise.
        '''
        result = self._values.get("callback_urls")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def flows(self) -> typing.Optional[OAuthFlows]:
        '''OAuth flows that are allowed with this client.

        :default: {authorizationCodeGrant:true,implicitCodeGrant:true}

        :see: - the 'Allowed OAuth Flows' section at https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-idp-settings.html
        '''
        result = self._values.get("flows")
        return typing.cast(typing.Optional[OAuthFlows], result)

    @builtins.property
    def logout_urls(self) -> typing.Optional[typing.List[builtins.str]]:
        '''List of allowed logout URLs for the identity providers.

        :default: - no logout URLs
        '''
        result = self._values.get("logout_urls")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def scopes(self) -> typing.Optional[typing.List[OAuthScope]]:
        '''OAuth scopes that are allowed with this client.

        :default: [OAuthScope.PHONE,OAuthScope.EMAIL,OAuthScope.OPENID,OAuthScope.PROFILE,OAuthScope.COGNITO_ADMIN]

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-idp-settings.html
        '''
        result = self._values.get("scopes")
        return typing.cast(typing.Optional[typing.List[OAuthScope]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OAuthSettings(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.PasswordPolicy",
    jsii_struct_bases=[],
    name_mapping={
        "min_length": "minLength",
        "require_digits": "requireDigits",
        "require_lowercase": "requireLowercase",
        "require_symbols": "requireSymbols",
        "require_uppercase": "requireUppercase",
        "temp_password_validity": "tempPasswordValidity",
    },
)
class PasswordPolicy:
    def __init__(
        self,
        *,
        min_length: typing.Optional[jsii.Number] = None,
        require_digits: typing.Optional[builtins.bool] = None,
        require_lowercase: typing.Optional[builtins.bool] = None,
        require_symbols: typing.Optional[builtins.bool] = None,
        require_uppercase: typing.Optional[builtins.bool] = None,
        temp_password_validity: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Password policy for User Pools.

        :param min_length: Minimum length required for a user's password. Default: 8
        :param require_digits: Whether the user is required to have digits in their password. Default: true
        :param require_lowercase: Whether the user is required to have lowercase characters in their password. Default: true
        :param require_symbols: Whether the user is required to have symbols in their password. Default: true
        :param require_uppercase: Whether the user is required to have uppercase characters in their password. Default: true
        :param temp_password_validity: The length of time the temporary password generated by an admin is valid. This must be provided as whole days, like Duration.days(3) or Duration.hours(48). Fractional days, such as Duration.hours(20), will generate an error. Default: Duration.days(7)

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                password_policy=cognito.PasswordPolicy(
                    min_length=12,
                    require_lowercase=True,
                    require_uppercase=True,
                    require_digits=True,
                    require_symbols=True,
                    temp_password_validity=Duration.days(3)
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if min_length is not None:
            self._values["min_length"] = min_length
        if require_digits is not None:
            self._values["require_digits"] = require_digits
        if require_lowercase is not None:
            self._values["require_lowercase"] = require_lowercase
        if require_symbols is not None:
            self._values["require_symbols"] = require_symbols
        if require_uppercase is not None:
            self._values["require_uppercase"] = require_uppercase
        if temp_password_validity is not None:
            self._values["temp_password_validity"] = temp_password_validity

    @builtins.property
    def min_length(self) -> typing.Optional[jsii.Number]:
        '''Minimum length required for a user's password.

        :default: 8
        '''
        result = self._values.get("min_length")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def require_digits(self) -> typing.Optional[builtins.bool]:
        '''Whether the user is required to have digits in their password.

        :default: true
        '''
        result = self._values.get("require_digits")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def require_lowercase(self) -> typing.Optional[builtins.bool]:
        '''Whether the user is required to have lowercase characters in their password.

        :default: true
        '''
        result = self._values.get("require_lowercase")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def require_symbols(self) -> typing.Optional[builtins.bool]:
        '''Whether the user is required to have symbols in their password.

        :default: true
        '''
        result = self._values.get("require_symbols")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def require_uppercase(self) -> typing.Optional[builtins.bool]:
        '''Whether the user is required to have uppercase characters in their password.

        :default: true
        '''
        result = self._values.get("require_uppercase")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def temp_password_validity(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The length of time the temporary password generated by an admin is valid.

        This must be provided as whole days, like Duration.days(3) or Duration.hours(48).
        Fractional days, such as Duration.hours(20), will generate an error.

        :default: Duration.days(7)
        '''
        result = self._values.get("temp_password_validity")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PasswordPolicy(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ProviderAttribute(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.ProviderAttribute",
):
    '''An attribute available from a third party identity provider.

    :exampleMetadata: infused

    Example::

        userpool = cognito.UserPool(self, "Pool")
        
        cognito.UserPoolIdentityProviderAmazon(self, "Amazon",
            client_id="amzn-client-id",
            client_secret="amzn-client-secret",
            user_pool=userpool,
            attribute_mapping=cognito.AttributeMapping(
                email=cognito.ProviderAttribute.AMAZON_EMAIL,
                website=cognito.ProviderAttribute.other("url"),  # use other() when an attribute is not pre-defined in the CDK
                custom={
                    # custom user pool attributes go here
                    "unique_id": cognito.ProviderAttribute.AMAZON_USER_ID
                }
            )
        )
    '''

    @jsii.member(jsii_name="other") # type: ignore[misc]
    @builtins.classmethod
    def other(cls, attribute_name: builtins.str) -> "ProviderAttribute":
        '''Use this to specify an attribute from the identity provider that is not pre-defined in the CDK.

        :param attribute_name: the attribute value string as recognized by the provider.
        '''
        return typing.cast("ProviderAttribute", jsii.sinvoke(cls, "other", [attribute_name]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AMAZON_EMAIL")
    def AMAZON_EMAIL(cls) -> "ProviderAttribute":
        '''The email attribute provided by Amazon.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "AMAZON_EMAIL"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AMAZON_NAME")
    def AMAZON_NAME(cls) -> "ProviderAttribute":
        '''The name attribute provided by Amazon.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "AMAZON_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AMAZON_POSTAL_CODE")
    def AMAZON_POSTAL_CODE(cls) -> "ProviderAttribute":
        '''The postal code attribute provided by Amazon.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "AMAZON_POSTAL_CODE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AMAZON_USER_ID")
    def AMAZON_USER_ID(cls) -> "ProviderAttribute":
        '''The user id attribute provided by Amazon.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "AMAZON_USER_ID"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="APPLE_EMAIL")
    def APPLE_EMAIL(cls) -> "ProviderAttribute":
        '''The email attribute provided by Apple.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "APPLE_EMAIL"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="APPLE_FIRST_NAME")
    def APPLE_FIRST_NAME(cls) -> "ProviderAttribute":
        '''The first name attribute provided by Apple.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "APPLE_FIRST_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="APPLE_LAST_NAME")
    def APPLE_LAST_NAME(cls) -> "ProviderAttribute":
        '''The last name attribute provided by Apple.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "APPLE_LAST_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="APPLE_NAME")
    def APPLE_NAME(cls) -> "ProviderAttribute":
        '''The name attribute provided by Apple.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "APPLE_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_BIRTHDAY")
    def FACEBOOK_BIRTHDAY(cls) -> "ProviderAttribute":
        '''The birthday attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_BIRTHDAY"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_EMAIL")
    def FACEBOOK_EMAIL(cls) -> "ProviderAttribute":
        '''The email attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_EMAIL"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_FIRST_NAME")
    def FACEBOOK_FIRST_NAME(cls) -> "ProviderAttribute":
        '''The first name attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_FIRST_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_GENDER")
    def FACEBOOK_GENDER(cls) -> "ProviderAttribute":
        '''The gender attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_GENDER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_ID")
    def FACEBOOK_ID(cls) -> "ProviderAttribute":
        '''The user id attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_ID"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_LAST_NAME")
    def FACEBOOK_LAST_NAME(cls) -> "ProviderAttribute":
        '''The last name attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_LAST_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_LOCALE")
    def FACEBOOK_LOCALE(cls) -> "ProviderAttribute":
        '''The locale attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_LOCALE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_MIDDLE_NAME")
    def FACEBOOK_MIDDLE_NAME(cls) -> "ProviderAttribute":
        '''The middle name attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_MIDDLE_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK_NAME")
    def FACEBOOK_NAME(cls) -> "ProviderAttribute":
        '''The name attribute provided by Facebook.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "FACEBOOK_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_BIRTHDAYS")
    def GOOGLE_BIRTHDAYS(cls) -> "ProviderAttribute":
        '''The birthday attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_BIRTHDAYS"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_EMAIL")
    def GOOGLE_EMAIL(cls) -> "ProviderAttribute":
        '''The email attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_EMAIL"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_FAMILY_NAME")
    def GOOGLE_FAMILY_NAME(cls) -> "ProviderAttribute":
        '''The family name attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_FAMILY_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_GENDER")
    def GOOGLE_GENDER(cls) -> "ProviderAttribute":
        '''The gender attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_GENDER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_GIVEN_NAME")
    def GOOGLE_GIVEN_NAME(cls) -> "ProviderAttribute":
        '''The given name attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_GIVEN_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_NAME")
    def GOOGLE_NAME(cls) -> "ProviderAttribute":
        '''The name attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_NAME"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_NAMES")
    def GOOGLE_NAMES(cls) -> "ProviderAttribute":
        '''The name attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_NAMES"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_PHONE_NUMBERS")
    def GOOGLE_PHONE_NUMBERS(cls) -> "ProviderAttribute":
        '''The phone number attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_PHONE_NUMBERS"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE_PICTURE")
    def GOOGLE_PICTURE(cls) -> "ProviderAttribute":
        '''The picture attribute provided by Google.'''
        return typing.cast("ProviderAttribute", jsii.sget(cls, "GOOGLE_PICTURE"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attributeName")
    def attribute_name(self) -> builtins.str:
        '''The attribute value string as recognized by the provider.'''
        return typing.cast(builtins.str, jsii.get(self, "attributeName"))


class ResourceServerScope(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.ResourceServerScope",
):
    '''A scope for ResourceServer.

    :exampleMetadata: infused

    Example::

        pool = cognito.UserPool(self, "Pool")
        
        read_only_scope = cognito.ResourceServerScope(scope_name="read", scope_description="Read-only access")
        full_access_scope = cognito.ResourceServerScope(scope_name="*", scope_description="Full access")
        
        user_server = pool.add_resource_server("ResourceServer",
            identifier="users",
            scopes=[read_only_scope, full_access_scope]
        )
        
        read_only_client = pool.add_client("read-only-client",
            # ...
            o_auth=cognito.OAuthSettings(
                # ...
                scopes=[cognito.OAuthScope.resource_server(user_server, read_only_scope)]
            )
        )
        
        full_access_client = pool.add_client("full-access-client",
            # ...
            o_auth=cognito.OAuthSettings(
                # ...
                scopes=[cognito.OAuthScope.resource_server(user_server, full_access_scope)]
            )
        )
    '''

    def __init__(
        self,
        *,
        scope_description: builtins.str,
        scope_name: builtins.str,
    ) -> None:
        '''
        :param scope_description: A description of the scope.
        :param scope_name: The name of the scope.
        '''
        props = ResourceServerScopeProps(
            scope_description=scope_description, scope_name=scope_name
        )

        jsii.create(self.__class__, self, [props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scopeDescription")
    def scope_description(self) -> builtins.str:
        '''A description of the scope.'''
        return typing.cast(builtins.str, jsii.get(self, "scopeDescription"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scopeName")
    def scope_name(self) -> builtins.str:
        '''The name of the scope.'''
        return typing.cast(builtins.str, jsii.get(self, "scopeName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.ResourceServerScopeProps",
    jsii_struct_bases=[],
    name_mapping={"scope_description": "scopeDescription", "scope_name": "scopeName"},
)
class ResourceServerScopeProps:
    def __init__(
        self,
        *,
        scope_description: builtins.str,
        scope_name: builtins.str,
    ) -> None:
        '''Props to initialize ResourceServerScope.

        :param scope_description: A description of the scope.
        :param scope_name: The name of the scope.

        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            
            read_only_scope = cognito.ResourceServerScope(scope_name="read", scope_description="Read-only access")
            full_access_scope = cognito.ResourceServerScope(scope_name="*", scope_description="Full access")
            
            user_server = pool.add_resource_server("ResourceServer",
                identifier="users",
                scopes=[read_only_scope, full_access_scope]
            )
            
            read_only_client = pool.add_client("read-only-client",
                # ...
                o_auth=cognito.OAuthSettings(
                    # ...
                    scopes=[cognito.OAuthScope.resource_server(user_server, read_only_scope)]
                )
            )
            
            full_access_client = pool.add_client("full-access-client",
                # ...
                o_auth=cognito.OAuthSettings(
                    # ...
                    scopes=[cognito.OAuthScope.resource_server(user_server, full_access_scope)]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "scope_description": scope_description,
            "scope_name": scope_name,
        }

    @builtins.property
    def scope_description(self) -> builtins.str:
        '''A description of the scope.'''
        result = self._values.get("scope_description")
        assert result is not None, "Required property 'scope_description' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def scope_name(self) -> builtins.str:
        '''The name of the scope.'''
        result = self._values.get("scope_name")
        assert result is not None, "Required property 'scope_name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ResourceServerScopeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.SignInAliases",
    jsii_struct_bases=[],
    name_mapping={
        "email": "email",
        "phone": "phone",
        "preferred_username": "preferredUsername",
        "username": "username",
    },
)
class SignInAliases:
    def __init__(
        self,
        *,
        email: typing.Optional[builtins.bool] = None,
        phone: typing.Optional[builtins.bool] = None,
        preferred_username: typing.Optional[builtins.bool] = None,
        username: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''The different ways in which users of this pool can sign up or sign in.

        :param email: Whether a user is allowed to sign up or sign in with an email address. Default: false
        :param phone: Whether a user is allowed to sign up or sign in with a phone number. Default: false
        :param preferred_username: Whether a user is allowed to sign in with a secondary username, that can be set and modified after sign up. Can only be used in conjunction with ``USERNAME``. Default: false
        :param username: Whether user is allowed to sign up or sign in with a username. Default: true

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                # ...
                sign_in_aliases=cognito.SignInAliases(
                    username=True,
                    email=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if email is not None:
            self._values["email"] = email
        if phone is not None:
            self._values["phone"] = phone
        if preferred_username is not None:
            self._values["preferred_username"] = preferred_username
        if username is not None:
            self._values["username"] = username

    @builtins.property
    def email(self) -> typing.Optional[builtins.bool]:
        '''Whether a user is allowed to sign up or sign in with an email address.

        :default: false
        '''
        result = self._values.get("email")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def phone(self) -> typing.Optional[builtins.bool]:
        '''Whether a user is allowed to sign up or sign in with a phone number.

        :default: false
        '''
        result = self._values.get("phone")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def preferred_username(self) -> typing.Optional[builtins.bool]:
        '''Whether a user is allowed to sign in with a secondary username, that can be set and modified after sign up.

        Can only be used in conjunction with ``USERNAME``.

        :default: false
        '''
        result = self._values.get("preferred_username")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def username(self) -> typing.Optional[builtins.bool]:
        '''Whether user is allowed to sign up or sign in with a username.

        :default: true
        '''
        result = self._values.get("username")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SignInAliases(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.SignInUrlOptions",
    jsii_struct_bases=[],
    name_mapping={"redirect_uri": "redirectUri", "sign_in_path": "signInPath"},
)
class SignInUrlOptions:
    def __init__(
        self,
        *,
        redirect_uri: builtins.str,
        sign_in_path: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options to customize the behaviour of ``signInUrl()``.

        :param redirect_uri: Where to redirect to after sign in.
        :param sign_in_path: The path in the URI where the sign-in page is located. Default: '/login'

        :exampleMetadata: infused

        Example::

            userpool = cognito.UserPool(self, "UserPool")
            client = userpool.add_client("Client",
                # ...
                o_auth=cognito.OAuthSettings(
                    flows=cognito.OAuthFlows(
                        implicit_code_grant=True
                    ),
                    callback_urls=["https://myapp.com/home", "https://myapp.com/users"
                    ]
                )
            )
            domain = userpool.add_domain("Domain")
            sign_in_url = domain.sign_in_url(client,
                redirect_uri="https://myapp.com/home"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "redirect_uri": redirect_uri,
        }
        if sign_in_path is not None:
            self._values["sign_in_path"] = sign_in_path

    @builtins.property
    def redirect_uri(self) -> builtins.str:
        '''Where to redirect to after sign in.'''
        result = self._values.get("redirect_uri")
        assert result is not None, "Required property 'redirect_uri' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def sign_in_path(self) -> typing.Optional[builtins.str]:
        '''The path in the URI where the sign-in page is located.

        :default: '/login'
        '''
        result = self._values.get("sign_in_path")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SignInUrlOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.StandardAttribute",
    jsii_struct_bases=[],
    name_mapping={"mutable": "mutable", "required": "required"},
)
class StandardAttribute:
    def __init__(
        self,
        *,
        mutable: typing.Optional[builtins.bool] = None,
        required: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Standard attribute that can be marked as required or mutable.

        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, this must be set to ``true``. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: true
        :param required: Specifies whether the attribute is required upon user registration. If the attribute is required and the user does not provide a value, registration or sign-in will fail. Default: false

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#cognito-user-pools-standard-attributes
        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                standard_attributes=cognito.StandardAttributes(
                    fullname=cognito.StandardAttribute(
                        required=True,
                        mutable=False
                    ),
                    address=cognito.StandardAttribute(
                        required=False,
                        mutable=True
                    )
                ),
                custom_attributes={
                    "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                    "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                    "is_employee": cognito.BooleanAttribute(mutable=True),
                    "joined_on": cognito.DateTimeAttribute()
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if mutable is not None:
            self._values["mutable"] = mutable
        if required is not None:
            self._values["required"] = required

    @builtins.property
    def mutable(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the value of the attribute can be changed.

        For any user pool attribute that's mapped to an identity provider attribute, this must be set to ``true``.
        Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider.
        If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute.

        :default: true
        '''
        result = self._values.get("mutable")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def required(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the attribute is required upon user registration.

        If the attribute is required and the user does not provide a value, registration or sign-in will fail.

        :default: false
        '''
        result = self._values.get("required")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StandardAttribute(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.StandardAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "address": "address",
        "birthdate": "birthdate",
        "email": "email",
        "family_name": "familyName",
        "fullname": "fullname",
        "gender": "gender",
        "given_name": "givenName",
        "last_update_time": "lastUpdateTime",
        "locale": "locale",
        "middle_name": "middleName",
        "nickname": "nickname",
        "phone_number": "phoneNumber",
        "preferred_username": "preferredUsername",
        "profile_page": "profilePage",
        "profile_picture": "profilePicture",
        "timezone": "timezone",
        "website": "website",
    },
)
class StandardAttributes:
    def __init__(
        self,
        *,
        address: typing.Optional[StandardAttribute] = None,
        birthdate: typing.Optional[StandardAttribute] = None,
        email: typing.Optional[StandardAttribute] = None,
        family_name: typing.Optional[StandardAttribute] = None,
        fullname: typing.Optional[StandardAttribute] = None,
        gender: typing.Optional[StandardAttribute] = None,
        given_name: typing.Optional[StandardAttribute] = None,
        last_update_time: typing.Optional[StandardAttribute] = None,
        locale: typing.Optional[StandardAttribute] = None,
        middle_name: typing.Optional[StandardAttribute] = None,
        nickname: typing.Optional[StandardAttribute] = None,
        phone_number: typing.Optional[StandardAttribute] = None,
        preferred_username: typing.Optional[StandardAttribute] = None,
        profile_page: typing.Optional[StandardAttribute] = None,
        profile_picture: typing.Optional[StandardAttribute] = None,
        timezone: typing.Optional[StandardAttribute] = None,
        website: typing.Optional[StandardAttribute] = None,
    ) -> None:
        '''The set of standard attributes that can be marked as required or mutable.

        :param address: The user's postal address. Default: - see the defaults under ``StandardAttribute``
        :param birthdate: The user's birthday, represented as an ISO 8601:2004 format. Default: - see the defaults under ``StandardAttribute``
        :param email: The user's e-mail address, represented as an RFC 5322 [RFC5322] addr-spec. Default: - see the defaults under ``StandardAttribute``
        :param family_name: The surname or last name of the user. Default: - see the defaults under ``StandardAttribute``
        :param fullname: The user's full name in displayable form, including all name parts, titles and suffixes. Default: - see the defaults under ``StandardAttribute``
        :param gender: The user's gender. Default: - see the defaults under ``StandardAttribute``
        :param given_name: The user's first name or give name. Default: - see the defaults under ``StandardAttribute``
        :param last_update_time: The time, the user's information was last updated. Default: - see the defaults under ``StandardAttribute``
        :param locale: The user's locale, represented as a BCP47 [RFC5646] language tag. Default: - see the defaults under ``StandardAttribute``
        :param middle_name: The user's middle name. Default: - see the defaults under ``StandardAttribute``
        :param nickname: The user's nickname or casual name. Default: - see the defaults under ``StandardAttribute``
        :param phone_number: The user's telephone number. Default: - see the defaults under ``StandardAttribute``
        :param preferred_username: The user's preffered username, different from the immutable user name. Default: - see the defaults under ``StandardAttribute``
        :param profile_page: The URL to the user's profile page. Default: - see the defaults under ``StandardAttribute``
        :param profile_picture: The URL to the user's profile picture. Default: - see the defaults under ``StandardAttribute``
        :param timezone: The user's time zone. Default: - see the defaults under ``StandardAttribute``
        :param website: The URL to the user's web page or blog. Default: - see the defaults under ``StandardAttribute``

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#cognito-user-pools-standard-attributes
        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                standard_attributes=cognito.StandardAttributes(
                    fullname=cognito.StandardAttribute(
                        required=True,
                        mutable=False
                    ),
                    address=cognito.StandardAttribute(
                        required=False,
                        mutable=True
                    )
                ),
                custom_attributes={
                    "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                    "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                    "is_employee": cognito.BooleanAttribute(mutable=True),
                    "joined_on": cognito.DateTimeAttribute()
                }
            )
        '''
        if isinstance(address, dict):
            address = StandardAttribute(**address)
        if isinstance(birthdate, dict):
            birthdate = StandardAttribute(**birthdate)
        if isinstance(email, dict):
            email = StandardAttribute(**email)
        if isinstance(family_name, dict):
            family_name = StandardAttribute(**family_name)
        if isinstance(fullname, dict):
            fullname = StandardAttribute(**fullname)
        if isinstance(gender, dict):
            gender = StandardAttribute(**gender)
        if isinstance(given_name, dict):
            given_name = StandardAttribute(**given_name)
        if isinstance(last_update_time, dict):
            last_update_time = StandardAttribute(**last_update_time)
        if isinstance(locale, dict):
            locale = StandardAttribute(**locale)
        if isinstance(middle_name, dict):
            middle_name = StandardAttribute(**middle_name)
        if isinstance(nickname, dict):
            nickname = StandardAttribute(**nickname)
        if isinstance(phone_number, dict):
            phone_number = StandardAttribute(**phone_number)
        if isinstance(preferred_username, dict):
            preferred_username = StandardAttribute(**preferred_username)
        if isinstance(profile_page, dict):
            profile_page = StandardAttribute(**profile_page)
        if isinstance(profile_picture, dict):
            profile_picture = StandardAttribute(**profile_picture)
        if isinstance(timezone, dict):
            timezone = StandardAttribute(**timezone)
        if isinstance(website, dict):
            website = StandardAttribute(**website)
        self._values: typing.Dict[str, typing.Any] = {}
        if address is not None:
            self._values["address"] = address
        if birthdate is not None:
            self._values["birthdate"] = birthdate
        if email is not None:
            self._values["email"] = email
        if family_name is not None:
            self._values["family_name"] = family_name
        if fullname is not None:
            self._values["fullname"] = fullname
        if gender is not None:
            self._values["gender"] = gender
        if given_name is not None:
            self._values["given_name"] = given_name
        if last_update_time is not None:
            self._values["last_update_time"] = last_update_time
        if locale is not None:
            self._values["locale"] = locale
        if middle_name is not None:
            self._values["middle_name"] = middle_name
        if nickname is not None:
            self._values["nickname"] = nickname
        if phone_number is not None:
            self._values["phone_number"] = phone_number
        if preferred_username is not None:
            self._values["preferred_username"] = preferred_username
        if profile_page is not None:
            self._values["profile_page"] = profile_page
        if profile_picture is not None:
            self._values["profile_picture"] = profile_picture
        if timezone is not None:
            self._values["timezone"] = timezone
        if website is not None:
            self._values["website"] = website

    @builtins.property
    def address(self) -> typing.Optional[StandardAttribute]:
        '''The user's postal address.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("address")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def birthdate(self) -> typing.Optional[StandardAttribute]:
        '''The user's birthday, represented as an ISO 8601:2004 format.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("birthdate")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def email(self) -> typing.Optional[StandardAttribute]:
        '''The user's e-mail address, represented as an RFC 5322 [RFC5322] addr-spec.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("email")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def family_name(self) -> typing.Optional[StandardAttribute]:
        '''The surname or last name of the user.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("family_name")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def fullname(self) -> typing.Optional[StandardAttribute]:
        '''The user's full name in displayable form, including all name parts, titles and suffixes.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("fullname")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def gender(self) -> typing.Optional[StandardAttribute]:
        '''The user's gender.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("gender")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def given_name(self) -> typing.Optional[StandardAttribute]:
        '''The user's first name or give name.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("given_name")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def last_update_time(self) -> typing.Optional[StandardAttribute]:
        '''The time, the user's information was last updated.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("last_update_time")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def locale(self) -> typing.Optional[StandardAttribute]:
        '''The user's locale, represented as a BCP47 [RFC5646] language tag.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("locale")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def middle_name(self) -> typing.Optional[StandardAttribute]:
        '''The user's middle name.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("middle_name")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def nickname(self) -> typing.Optional[StandardAttribute]:
        '''The user's nickname or casual name.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("nickname")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def phone_number(self) -> typing.Optional[StandardAttribute]:
        '''The user's telephone number.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("phone_number")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def preferred_username(self) -> typing.Optional[StandardAttribute]:
        '''The user's preffered username, different from the immutable user name.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("preferred_username")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def profile_page(self) -> typing.Optional[StandardAttribute]:
        '''The URL to the user's profile page.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("profile_page")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def profile_picture(self) -> typing.Optional[StandardAttribute]:
        '''The URL to the user's profile picture.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("profile_picture")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def timezone(self) -> typing.Optional[StandardAttribute]:
        '''The user's time zone.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("timezone")
        return typing.cast(typing.Optional[StandardAttribute], result)

    @builtins.property
    def website(self) -> typing.Optional[StandardAttribute]:
        '''The URL to the user's web page or blog.

        :default: - see the defaults under ``StandardAttribute``
        '''
        result = self._values.get("website")
        return typing.cast(typing.Optional[StandardAttribute], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StandardAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.StandardAttributesMask",
    jsii_struct_bases=[],
    name_mapping={
        "address": "address",
        "birthdate": "birthdate",
        "email": "email",
        "email_verified": "emailVerified",
        "family_name": "familyName",
        "fullname": "fullname",
        "gender": "gender",
        "given_name": "givenName",
        "last_update_time": "lastUpdateTime",
        "locale": "locale",
        "middle_name": "middleName",
        "nickname": "nickname",
        "phone_number": "phoneNumber",
        "phone_number_verified": "phoneNumberVerified",
        "preferred_username": "preferredUsername",
        "profile_page": "profilePage",
        "profile_picture": "profilePicture",
        "timezone": "timezone",
        "website": "website",
    },
)
class StandardAttributesMask:
    def __init__(
        self,
        *,
        address: typing.Optional[builtins.bool] = None,
        birthdate: typing.Optional[builtins.bool] = None,
        email: typing.Optional[builtins.bool] = None,
        email_verified: typing.Optional[builtins.bool] = None,
        family_name: typing.Optional[builtins.bool] = None,
        fullname: typing.Optional[builtins.bool] = None,
        gender: typing.Optional[builtins.bool] = None,
        given_name: typing.Optional[builtins.bool] = None,
        last_update_time: typing.Optional[builtins.bool] = None,
        locale: typing.Optional[builtins.bool] = None,
        middle_name: typing.Optional[builtins.bool] = None,
        nickname: typing.Optional[builtins.bool] = None,
        phone_number: typing.Optional[builtins.bool] = None,
        phone_number_verified: typing.Optional[builtins.bool] = None,
        preferred_username: typing.Optional[builtins.bool] = None,
        profile_page: typing.Optional[builtins.bool] = None,
        profile_picture: typing.Optional[builtins.bool] = None,
        timezone: typing.Optional[builtins.bool] = None,
        website: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''This interface contains standard attributes recognized by Cognito from https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html including built-in attributes ``email_verified`` and ``phone_number_verified``.

        :param address: The user's postal address. Default: false
        :param birthdate: The user's birthday, represented as an ISO 8601:2004 format. Default: false
        :param email: The user's e-mail address, represented as an RFC 5322 [RFC5322] addr-spec. Default: false
        :param email_verified: Whether the email address has been verified. Default: false
        :param family_name: The surname or last name of the user. Default: false
        :param fullname: The user's full name in displayable form, including all name parts, titles and suffixes. Default: false
        :param gender: The user's gender. Default: false
        :param given_name: The user's first name or give name. Default: false
        :param last_update_time: The time, the user's information was last updated. Default: false
        :param locale: The user's locale, represented as a BCP47 [RFC5646] language tag. Default: false
        :param middle_name: The user's middle name. Default: false
        :param nickname: The user's nickname or casual name. Default: false
        :param phone_number: The user's telephone number. Default: false
        :param phone_number_verified: Whether the phone number has been verified. Default: false
        :param preferred_username: The user's preffered username, different from the immutable user name. Default: false
        :param profile_page: The URL to the user's profile page. Default: false
        :param profile_picture: The URL to the user's profile picture. Default: false
        :param timezone: The user's time zone. Default: false
        :param website: The URL to the user's web page or blog. Default: false

        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            
            client_write_attributes = (cognito.ClientAttributes()).with_standard_attributes(fullname=True, email=True).with_custom_attributes("favouritePizza", "favouriteBeverage")
            
            client_read_attributes = client_write_attributes.with_standard_attributes(email_verified=True).with_custom_attributes("pointsEarned")
            
            pool.add_client("app-client",
                # ...
                read_attributes=client_read_attributes,
                write_attributes=client_write_attributes
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if address is not None:
            self._values["address"] = address
        if birthdate is not None:
            self._values["birthdate"] = birthdate
        if email is not None:
            self._values["email"] = email
        if email_verified is not None:
            self._values["email_verified"] = email_verified
        if family_name is not None:
            self._values["family_name"] = family_name
        if fullname is not None:
            self._values["fullname"] = fullname
        if gender is not None:
            self._values["gender"] = gender
        if given_name is not None:
            self._values["given_name"] = given_name
        if last_update_time is not None:
            self._values["last_update_time"] = last_update_time
        if locale is not None:
            self._values["locale"] = locale
        if middle_name is not None:
            self._values["middle_name"] = middle_name
        if nickname is not None:
            self._values["nickname"] = nickname
        if phone_number is not None:
            self._values["phone_number"] = phone_number
        if phone_number_verified is not None:
            self._values["phone_number_verified"] = phone_number_verified
        if preferred_username is not None:
            self._values["preferred_username"] = preferred_username
        if profile_page is not None:
            self._values["profile_page"] = profile_page
        if profile_picture is not None:
            self._values["profile_picture"] = profile_picture
        if timezone is not None:
            self._values["timezone"] = timezone
        if website is not None:
            self._values["website"] = website

    @builtins.property
    def address(self) -> typing.Optional[builtins.bool]:
        '''The user's postal address.

        :default: false
        '''
        result = self._values.get("address")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def birthdate(self) -> typing.Optional[builtins.bool]:
        '''The user's birthday, represented as an ISO 8601:2004 format.

        :default: false
        '''
        result = self._values.get("birthdate")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def email(self) -> typing.Optional[builtins.bool]:
        '''The user's e-mail address, represented as an RFC 5322 [RFC5322] addr-spec.

        :default: false
        '''
        result = self._values.get("email")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def email_verified(self) -> typing.Optional[builtins.bool]:
        '''Whether the email address has been verified.

        :default: false
        '''
        result = self._values.get("email_verified")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def family_name(self) -> typing.Optional[builtins.bool]:
        '''The surname or last name of the user.

        :default: false
        '''
        result = self._values.get("family_name")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def fullname(self) -> typing.Optional[builtins.bool]:
        '''The user's full name in displayable form, including all name parts, titles and suffixes.

        :default: false
        '''
        result = self._values.get("fullname")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def gender(self) -> typing.Optional[builtins.bool]:
        '''The user's gender.

        :default: false
        '''
        result = self._values.get("gender")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def given_name(self) -> typing.Optional[builtins.bool]:
        '''The user's first name or give name.

        :default: false
        '''
        result = self._values.get("given_name")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def last_update_time(self) -> typing.Optional[builtins.bool]:
        '''The time, the user's information was last updated.

        :default: false
        '''
        result = self._values.get("last_update_time")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def locale(self) -> typing.Optional[builtins.bool]:
        '''The user's locale, represented as a BCP47 [RFC5646] language tag.

        :default: false
        '''
        result = self._values.get("locale")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def middle_name(self) -> typing.Optional[builtins.bool]:
        '''The user's middle name.

        :default: false
        '''
        result = self._values.get("middle_name")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def nickname(self) -> typing.Optional[builtins.bool]:
        '''The user's nickname or casual name.

        :default: false
        '''
        result = self._values.get("nickname")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def phone_number(self) -> typing.Optional[builtins.bool]:
        '''The user's telephone number.

        :default: false
        '''
        result = self._values.get("phone_number")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def phone_number_verified(self) -> typing.Optional[builtins.bool]:
        '''Whether the phone number has been verified.

        :default: false
        '''
        result = self._values.get("phone_number_verified")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def preferred_username(self) -> typing.Optional[builtins.bool]:
        '''The user's preffered username, different from the immutable user name.

        :default: false
        '''
        result = self._values.get("preferred_username")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def profile_page(self) -> typing.Optional[builtins.bool]:
        '''The URL to the user's profile page.

        :default: false
        '''
        result = self._values.get("profile_page")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def profile_picture(self) -> typing.Optional[builtins.bool]:
        '''The URL to the user's profile picture.

        :default: false
        '''
        result = self._values.get("profile_picture")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def timezone(self) -> typing.Optional[builtins.bool]:
        '''The user's time zone.

        :default: false
        '''
        result = self._values.get("timezone")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def website(self) -> typing.Optional[builtins.bool]:
        '''The URL to the user's web page or blog.

        :default: false
        '''
        result = self._values.get("website")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StandardAttributesMask(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(ICustomAttribute)
class StringAttribute(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.StringAttribute",
):
    '''The String custom attribute type.

    :exampleMetadata: infused

    Example::

        cognito.UserPool(self, "myuserpool",
            # ...
            standard_attributes=cognito.StandardAttributes(
                fullname=cognito.StandardAttribute(
                    required=True,
                    mutable=False
                ),
                address=cognito.StandardAttribute(
                    required=False,
                    mutable=True
                )
            ),
            custom_attributes={
                "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                "is_employee": cognito.BooleanAttribute(mutable=True),
                "joined_on": cognito.DateTimeAttribute()
            }
        )
    '''

    def __init__(
        self,
        *,
        max_len: typing.Optional[jsii.Number] = None,
        min_len: typing.Optional[jsii.Number] = None,
        mutable: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''
        :param max_len: Maximum length of this attribute. Default: 2048
        :param min_len: Minimum length of this attribute. Default: 0
        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: false
        '''
        props = StringAttributeProps(max_len=max_len, min_len=min_len, mutable=mutable)

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="bind")
    def bind(self) -> CustomAttributeConfig:
        '''Bind this custom attribute type to the values as expected by CloudFormation.'''
        return typing.cast(CustomAttributeConfig, jsii.invoke(self, "bind", []))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.StringAttributeConstraints",
    jsii_struct_bases=[],
    name_mapping={"max_len": "maxLen", "min_len": "minLen"},
)
class StringAttributeConstraints:
    def __init__(
        self,
        *,
        max_len: typing.Optional[jsii.Number] = None,
        min_len: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Constraints that can be applied to a custom attribute of string type.

        :param max_len: Maximum length of this attribute. Default: 2048
        :param min_len: Minimum length of this attribute. Default: 0

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            string_attribute_constraints = cognito.StringAttributeConstraints(
                max_len=123,
                min_len=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if max_len is not None:
            self._values["max_len"] = max_len
        if min_len is not None:
            self._values["min_len"] = min_len

    @builtins.property
    def max_len(self) -> typing.Optional[jsii.Number]:
        '''Maximum length of this attribute.

        :default: 2048
        '''
        result = self._values.get("max_len")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_len(self) -> typing.Optional[jsii.Number]:
        '''Minimum length of this attribute.

        :default: 0
        '''
        result = self._values.get("min_len")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StringAttributeConstraints(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.StringAttributeProps",
    jsii_struct_bases=[StringAttributeConstraints, CustomAttributeProps],
    name_mapping={"max_len": "maxLen", "min_len": "minLen", "mutable": "mutable"},
)
class StringAttributeProps(StringAttributeConstraints, CustomAttributeProps):
    def __init__(
        self,
        *,
        max_len: typing.Optional[jsii.Number] = None,
        min_len: typing.Optional[jsii.Number] = None,
        mutable: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Props for constructing a StringAttr.

        :param max_len: Maximum length of this attribute. Default: 2048
        :param min_len: Minimum length of this attribute. Default: 0
        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: false

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                standard_attributes=cognito.StandardAttributes(
                    fullname=cognito.StandardAttribute(
                        required=True,
                        mutable=False
                    ),
                    address=cognito.StandardAttribute(
                        required=False,
                        mutable=True
                    )
                ),
                custom_attributes={
                    "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                    "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                    "is_employee": cognito.BooleanAttribute(mutable=True),
                    "joined_on": cognito.DateTimeAttribute()
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if max_len is not None:
            self._values["max_len"] = max_len
        if min_len is not None:
            self._values["min_len"] = min_len
        if mutable is not None:
            self._values["mutable"] = mutable

    @builtins.property
    def max_len(self) -> typing.Optional[jsii.Number]:
        '''Maximum length of this attribute.

        :default: 2048
        '''
        result = self._values.get("max_len")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_len(self) -> typing.Optional[jsii.Number]:
        '''Minimum length of this attribute.

        :default: 0
        '''
        result = self._values.get("min_len")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def mutable(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the value of the attribute can be changed.

        For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true.
        Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider.
        If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute.

        :default: false
        '''
        result = self._values.get("mutable")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StringAttributeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserInvitationConfig",
    jsii_struct_bases=[],
    name_mapping={
        "email_body": "emailBody",
        "email_subject": "emailSubject",
        "sms_message": "smsMessage",
    },
)
class UserInvitationConfig:
    def __init__(
        self,
        *,
        email_body: typing.Optional[builtins.str] = None,
        email_subject: typing.Optional[builtins.str] = None,
        sms_message: typing.Optional[builtins.str] = None,
    ) -> None:
        '''User pool configuration when administrators sign users up.

        :param email_body: The template to the email body that is sent to the user when an administrator signs them up to the user pool. Default: 'Your username is {username} and temporary password is {####}.'
        :param email_subject: The template to the email subject that is sent to the user when an administrator signs them up to the user pool. Default: 'Your temporary password'
        :param sms_message: The template to the SMS message that is sent to the user when an administrator signs them up to the user pool. Default: 'Your username is {username} and temporary password is {####}'

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                user_invitation=cognito.UserInvitationConfig(
                    email_subject="Invite to join our awesome app!",
                    email_body="Hello {username}, you have been invited to join our awesome app! Your temporary password is {####}",
                    sms_message="Hello {username}, your temporary password for our awesome app is {####}"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if email_body is not None:
            self._values["email_body"] = email_body
        if email_subject is not None:
            self._values["email_subject"] = email_subject
        if sms_message is not None:
            self._values["sms_message"] = sms_message

    @builtins.property
    def email_body(self) -> typing.Optional[builtins.str]:
        '''The template to the email body that is sent to the user when an administrator signs them up to the user pool.

        :default: 'Your username is {username} and temporary password is {####}.'
        '''
        result = self._values.get("email_body")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def email_subject(self) -> typing.Optional[builtins.str]:
        '''The template to the email subject that is sent to the user when an administrator signs them up to the user pool.

        :default: 'Your temporary password'
        '''
        result = self._values.get("email_subject")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sms_message(self) -> typing.Optional[builtins.str]:
        '''The template to the SMS message that is sent to the user when an administrator signs them up to the user pool.

        :default: 'Your username is {username} and temporary password is {####}'
        '''
        result = self._values.get("sms_message")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserInvitationConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IUserPool)
class UserPool(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPool",
):
    '''Define a Cognito User Pool.

    :exampleMetadata: infused

    Example::

        pool = cognito.UserPool(self, "Pool")
        pool.add_client("app-client",
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True
                ),
                scopes=[cognito.OAuthScope.OPENID],
                callback_urls=["https://my-app-domain.com/welcome"],
                logout_urls=["https://my-app-domain.com/signin"]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        account_recovery: typing.Optional[AccountRecovery] = None,
        auto_verify: typing.Optional[AutoVerifiedAttrs] = None,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, ICustomAttribute]] = None,
        custom_sender_kms_key: typing.Optional[_IKey_5f11635f] = None,
        device_tracking: typing.Optional[DeviceTracking] = None,
        email: typing.Optional["UserPoolEmail"] = None,
        enable_sms_role: typing.Optional[builtins.bool] = None,
        lambda_triggers: typing.Optional["UserPoolTriggers"] = None,
        mfa: typing.Optional[Mfa] = None,
        mfa_message: typing.Optional[builtins.str] = None,
        mfa_second_factor: typing.Optional[MfaSecondFactor] = None,
        password_policy: typing.Optional[PasswordPolicy] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        self_sign_up_enabled: typing.Optional[builtins.bool] = None,
        sign_in_aliases: typing.Optional[SignInAliases] = None,
        sign_in_case_sensitive: typing.Optional[builtins.bool] = None,
        sms_role: typing.Optional[_IRole_235f5d8e] = None,
        sms_role_external_id: typing.Optional[builtins.str] = None,
        standard_attributes: typing.Optional[StandardAttributes] = None,
        user_invitation: typing.Optional[UserInvitationConfig] = None,
        user_pool_name: typing.Optional[builtins.str] = None,
        user_verification: typing.Optional["UserVerificationConfig"] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param account_recovery: How will a user be able to recover their account? Default: AccountRecovery.PHONE_WITHOUT_MFA_AND_EMAIL
        :param auto_verify: Attributes which Cognito will look to verify automatically upon user sign up. EMAIL and PHONE are the only available options. Default: - If ``signInAlias`` includes email and/or phone, they will be included in ``autoVerifiedAttributes`` by default. If absent, no attributes will be auto-verified.
        :param custom_attributes: Define a set of custom attributes that can be configured for each user in the user pool. Default: - No custom attributes.
        :param custom_sender_kms_key: This key will be used to encrypt temporary passwords and authorization codes that Amazon Cognito generates. Default: - no key ID configured
        :param device_tracking: Device tracking settings. Default: - see defaults on each property of DeviceTracking.
        :param email: Email settings for a user pool. Default: - cognito will use the default email configuration
        :param enable_sms_role: Setting this would explicitly enable or disable SMS role creation. When left unspecified, CDK will determine based on other properties if a role is needed or not. Default: - CDK will determine based on other properties of the user pool if an SMS role should be created or not.
        :param lambda_triggers: Lambda functions to use for supported Cognito triggers. Default: - No Lambda triggers.
        :param mfa: Configure whether users of this user pool can or are required use MFA to sign in. Default: Mfa.OFF
        :param mfa_message: The SMS message template sent during MFA verification. Use '{####}' in the template where Cognito should insert the verification code. Default: 'Your authentication code is {####}.'
        :param mfa_second_factor: Configure the MFA types that users can use in this user pool. Ignored if ``mfa`` is set to ``OFF``. Default: - { sms: true, oneTimePassword: false }, if ``mfa`` is set to ``OPTIONAL`` or ``REQUIRED``. { sms: false, oneTimePassword: false }, otherwise
        :param password_policy: Password policy for this user pool. Default: - see defaults on each property of PasswordPolicy.
        :param removal_policy: Policy to apply when the user pool is removed from the stack. Default: RemovalPolicy.RETAIN
        :param self_sign_up_enabled: Whether self sign up should be enabled. This can be further configured via the ``selfSignUp`` property. Default: false
        :param sign_in_aliases: Methods in which a user registers or signs in to a user pool. Allows either username with aliases OR sign in with email, phone, or both. Read the sections on usernames and aliases to learn more - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html To match with 'Option 1' in the above link, with a verified email, this property should be set to ``{ username: true, email: true }``. To match with 'Option 2' in the above link with both a verified email and phone number, this property should be set to ``{ email: true, phone: true }``. Default: { username: true }
        :param sign_in_case_sensitive: Whether sign-in aliases should be evaluated with case sensitivity. For example, when this option is set to false, users will be able to sign in using either ``MyUsername`` or ``myusername``. Default: true
        :param sms_role: The IAM role that Cognito will assume while sending SMS messages. Default: - a new IAM role is created
        :param sms_role_external_id: The 'ExternalId' that Cognito service must using when assuming the ``smsRole``, if the role is restricted with an 'sts:ExternalId' conditional. Learn more about ExternalId here - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html This property will be ignored if ``smsRole`` is not specified. Default: - No external id will be configured
        :param standard_attributes: The set of attributes that are required for every user in the user pool. Read more on attributes here - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html Default: - All standard attributes are optional and mutable.
        :param user_invitation: Configuration around admins signing up users into a user pool. Default: - see defaults in UserInvitationConfig
        :param user_pool_name: Name of the user pool. Default: - automatically generated name by CloudFormation at deploy time
        :param user_verification: Configuration around users signing themselves up to the user pool. Enable or disable self sign-up via the ``selfSignUpEnabled`` property. Default: - see defaults in UserVerificationConfig
        '''
        props = UserPoolProps(
            account_recovery=account_recovery,
            auto_verify=auto_verify,
            custom_attributes=custom_attributes,
            custom_sender_kms_key=custom_sender_kms_key,
            device_tracking=device_tracking,
            email=email,
            enable_sms_role=enable_sms_role,
            lambda_triggers=lambda_triggers,
            mfa=mfa,
            mfa_message=mfa_message,
            mfa_second_factor=mfa_second_factor,
            password_policy=password_policy,
            removal_policy=removal_policy,
            self_sign_up_enabled=self_sign_up_enabled,
            sign_in_aliases=sign_in_aliases,
            sign_in_case_sensitive=sign_in_case_sensitive,
            sms_role=sms_role,
            sms_role_external_id=sms_role_external_id,
            standard_attributes=standard_attributes,
            user_invitation=user_invitation,
            user_pool_name=user_pool_name,
            user_verification=user_verification,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromUserPoolArn") # type: ignore[misc]
    @builtins.classmethod
    def from_user_pool_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        user_pool_arn: builtins.str,
    ) -> IUserPool:
        '''Import an existing user pool based on its ARN.

        :param scope: -
        :param id: -
        :param user_pool_arn: -
        '''
        return typing.cast(IUserPool, jsii.sinvoke(cls, "fromUserPoolArn", [scope, id, user_pool_arn]))

    @jsii.member(jsii_name="fromUserPoolId") # type: ignore[misc]
    @builtins.classmethod
    def from_user_pool_id(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        user_pool_id: builtins.str,
    ) -> IUserPool:
        '''Import an existing user pool based on its id.

        :param scope: -
        :param id: -
        :param user_pool_id: -
        '''
        return typing.cast(IUserPool, jsii.sinvoke(cls, "fromUserPoolId", [scope, id, user_pool_id]))

    @jsii.member(jsii_name="addClient")
    def add_client(
        self,
        id: builtins.str,
        *,
        access_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        auth_flows: typing.Optional[AuthFlow] = None,
        disable_o_auth: typing.Optional[builtins.bool] = None,
        enable_token_revocation: typing.Optional[builtins.bool] = None,
        generate_secret: typing.Optional[builtins.bool] = None,
        id_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        o_auth: typing.Optional[OAuthSettings] = None,
        prevent_user_existence_errors: typing.Optional[builtins.bool] = None,
        read_attributes: typing.Optional[ClientAttributes] = None,
        refresh_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        supported_identity_providers: typing.Optional[typing.Sequence["UserPoolClientIdentityProvider"]] = None,
        user_pool_client_name: typing.Optional[builtins.str] = None,
        write_attributes: typing.Optional[ClientAttributes] = None,
    ) -> "UserPoolClient":
        '''Add a new app client to this user pool.

        :param id: -
        :param access_token_validity: Validity of the access token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param auth_flows: The set of OAuth authentication flows to enable on the client. Default: - all auth flows disabled
        :param disable_o_auth: Turns off all OAuth interactions for this client. Default: false
        :param enable_token_revocation: Enable token revocation for this client. Default: true for new user pool clients
        :param generate_secret: Whether to generate a client secret. Default: false
        :param id_token_validity: Validity of the ID token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param o_auth: OAuth settings for this client to interact with the app. An error is thrown when this is specified and ``disableOAuth`` is set. Default: - see defaults in ``OAuthSettings``. meaningless if ``disableOAuth`` is set.
        :param prevent_user_existence_errors: Whether Cognito returns a UserNotFoundException exception when the user does not exist in the user pool (false), or whether it returns another type of error that doesn't reveal the user's absence. Default: false
        :param read_attributes: The set of attributes this client will be able to read. Default: - all standard and custom attributes
        :param refresh_token_validity: Validity of the refresh token. Values between 60 minutes and 10 years are valid. Default: Duration.days(30)
        :param supported_identity_providers: The list of identity providers that users should be able to use to sign in using this client. Default: - supports all identity providers that are registered with the user pool. If the user pool and/or identity providers are imported, either specify this option explicitly or ensure that the identity providers are registered with the user pool using the ``UserPool.registerIdentityProvider()`` API.
        :param user_pool_client_name: Name of the application client. Default: - cloudformation generated name
        :param write_attributes: The set of attributes this client will be able to write. Default: - all standard and custom attributes
        '''
        options = UserPoolClientOptions(
            access_token_validity=access_token_validity,
            auth_flows=auth_flows,
            disable_o_auth=disable_o_auth,
            enable_token_revocation=enable_token_revocation,
            generate_secret=generate_secret,
            id_token_validity=id_token_validity,
            o_auth=o_auth,
            prevent_user_existence_errors=prevent_user_existence_errors,
            read_attributes=read_attributes,
            refresh_token_validity=refresh_token_validity,
            supported_identity_providers=supported_identity_providers,
            user_pool_client_name=user_pool_client_name,
            write_attributes=write_attributes,
        )

        return typing.cast("UserPoolClient", jsii.invoke(self, "addClient", [id, options]))

    @jsii.member(jsii_name="addDomain")
    def add_domain(
        self,
        id: builtins.str,
        *,
        cognito_domain: typing.Optional[CognitoDomainOptions] = None,
        custom_domain: typing.Optional[CustomDomainOptions] = None,
    ) -> "UserPoolDomain":
        '''Associate a domain to this user pool.

        :param id: -
        :param cognito_domain: Associate a cognito prefix domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``customDomain`` is specified, otherwise, throws an error.
        :param custom_domain: Associate a custom domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``cognitoDomain`` is specified, otherwise, throws an error.
        '''
        options = UserPoolDomainOptions(
            cognito_domain=cognito_domain, custom_domain=custom_domain
        )

        return typing.cast("UserPoolDomain", jsii.invoke(self, "addDomain", [id, options]))

    @jsii.member(jsii_name="addResourceServer")
    def add_resource_server(
        self,
        id: builtins.str,
        *,
        identifier: builtins.str,
        scopes: typing.Optional[typing.Sequence[ResourceServerScope]] = None,
        user_pool_resource_server_name: typing.Optional[builtins.str] = None,
    ) -> "UserPoolResourceServer":
        '''Add a new resource server to this user pool.

        :param id: -
        :param identifier: A unique resource server identifier for the resource server.
        :param scopes: Oauth scopes. Default: - No scopes will be added
        :param user_pool_resource_server_name: A friendly name for the resource server. Default: - same as ``identifier``
        '''
        options = UserPoolResourceServerOptions(
            identifier=identifier,
            scopes=scopes,
            user_pool_resource_server_name=user_pool_resource_server_name,
        )

        return typing.cast("UserPoolResourceServer", jsii.invoke(self, "addResourceServer", [id, options]))

    @jsii.member(jsii_name="addTrigger")
    def add_trigger(
        self,
        operation: "UserPoolOperation",
        fn: _IFunction_6adb0ab8,
    ) -> None:
        '''Add a lambda trigger to a user pool operation.

        :param operation: -
        :param fn: -

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html
        '''
        return typing.cast(None, jsii.invoke(self, "addTrigger", [operation, fn]))

    @jsii.member(jsii_name="registerIdentityProvider")
    def register_identity_provider(self, provider: IUserPoolIdentityProvider) -> None:
        '''Register an identity provider with this user pool.

        :param provider: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerIdentityProvider", [provider]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="identityProviders")
    def identity_providers(self) -> typing.List[IUserPoolIdentityProvider]:
        '''Get all identity providers registered with this user pool.'''
        return typing.cast(typing.List[IUserPoolIdentityProvider], jsii.get(self, "identityProviders"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolArn")
    def user_pool_arn(self) -> builtins.str:
        '''The ARN of the user pool.'''
        return typing.cast(builtins.str, jsii.get(self, "userPoolArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolId")
    def user_pool_id(self) -> builtins.str:
        '''The physical ID of this user pool resource.'''
        return typing.cast(builtins.str, jsii.get(self, "userPoolId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolProviderName")
    def user_pool_provider_name(self) -> builtins.str:
        '''User pool provider name.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolProviderName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolProviderUrl")
    def user_pool_provider_url(self) -> builtins.str:
        '''User pool provider URL.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "userPoolProviderUrl"))


@jsii.implements(IUserPoolClient)
class UserPoolClient(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolClient",
):
    '''Define a UserPool App Client.

    :exampleMetadata: infused

    Example::

        pool = cognito.UserPool(self, "Pool")
        provider = cognito.UserPoolIdentityProviderAmazon(self, "Amazon",
            user_pool=pool,
            client_id="amzn-client-id",
            client_secret="amzn-client-secret"
        )
        
        client = pool.add_client("app-client",
            # ...
            supported_identity_providers=[cognito.UserPoolClientIdentityProvider.AMAZON
            ]
        )
        
        client.node.add_dependency(provider)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user_pool: IUserPool,
        access_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        auth_flows: typing.Optional[AuthFlow] = None,
        disable_o_auth: typing.Optional[builtins.bool] = None,
        enable_token_revocation: typing.Optional[builtins.bool] = None,
        generate_secret: typing.Optional[builtins.bool] = None,
        id_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        o_auth: typing.Optional[OAuthSettings] = None,
        prevent_user_existence_errors: typing.Optional[builtins.bool] = None,
        read_attributes: typing.Optional[ClientAttributes] = None,
        refresh_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        supported_identity_providers: typing.Optional[typing.Sequence["UserPoolClientIdentityProvider"]] = None,
        user_pool_client_name: typing.Optional[builtins.str] = None,
        write_attributes: typing.Optional[ClientAttributes] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param user_pool: The UserPool resource this client will have access to.
        :param access_token_validity: Validity of the access token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param auth_flows: The set of OAuth authentication flows to enable on the client. Default: - all auth flows disabled
        :param disable_o_auth: Turns off all OAuth interactions for this client. Default: false
        :param enable_token_revocation: Enable token revocation for this client. Default: true for new user pool clients
        :param generate_secret: Whether to generate a client secret. Default: false
        :param id_token_validity: Validity of the ID token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param o_auth: OAuth settings for this client to interact with the app. An error is thrown when this is specified and ``disableOAuth`` is set. Default: - see defaults in ``OAuthSettings``. meaningless if ``disableOAuth`` is set.
        :param prevent_user_existence_errors: Whether Cognito returns a UserNotFoundException exception when the user does not exist in the user pool (false), or whether it returns another type of error that doesn't reveal the user's absence. Default: false
        :param read_attributes: The set of attributes this client will be able to read. Default: - all standard and custom attributes
        :param refresh_token_validity: Validity of the refresh token. Values between 60 minutes and 10 years are valid. Default: Duration.days(30)
        :param supported_identity_providers: The list of identity providers that users should be able to use to sign in using this client. Default: - supports all identity providers that are registered with the user pool. If the user pool and/or identity providers are imported, either specify this option explicitly or ensure that the identity providers are registered with the user pool using the ``UserPool.registerIdentityProvider()`` API.
        :param user_pool_client_name: Name of the application client. Default: - cloudformation generated name
        :param write_attributes: The set of attributes this client will be able to write. Default: - all standard and custom attributes
        '''
        props = UserPoolClientProps(
            user_pool=user_pool,
            access_token_validity=access_token_validity,
            auth_flows=auth_flows,
            disable_o_auth=disable_o_auth,
            enable_token_revocation=enable_token_revocation,
            generate_secret=generate_secret,
            id_token_validity=id_token_validity,
            o_auth=o_auth,
            prevent_user_existence_errors=prevent_user_existence_errors,
            read_attributes=read_attributes,
            refresh_token_validity=refresh_token_validity,
            supported_identity_providers=supported_identity_providers,
            user_pool_client_name=user_pool_client_name,
            write_attributes=write_attributes,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromUserPoolClientId") # type: ignore[misc]
    @builtins.classmethod
    def from_user_pool_client_id(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        user_pool_client_id: builtins.str,
    ) -> IUserPoolClient:
        '''Import a user pool client given its id.

        :param scope: -
        :param id: -
        :param user_pool_client_id: -
        '''
        return typing.cast(IUserPoolClient, jsii.sinvoke(cls, "fromUserPoolClientId", [scope, id, user_pool_client_id]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="oAuthFlows")
    def o_auth_flows(self) -> OAuthFlows:
        '''The OAuth flows enabled for this client.'''
        return typing.cast(OAuthFlows, jsii.get(self, "oAuthFlows"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolClientId")
    def user_pool_client_id(self) -> builtins.str:
        '''Name of the application client.'''
        return typing.cast(builtins.str, jsii.get(self, "userPoolClientId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolClientName")
    def user_pool_client_name(self) -> builtins.str:
        '''The client name that was specified via the ``userPoolClientName`` property during initialization, throws an error otherwise.'''
        return typing.cast(builtins.str, jsii.get(self, "userPoolClientName"))


class UserPoolClientIdentityProvider(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolClientIdentityProvider",
):
    '''Identity providers supported by the UserPoolClient.

    :exampleMetadata: infused

    Example::

        pool = cognito.UserPool(self, "Pool")
        pool.add_client("app-client",
            # ...
            supported_identity_providers=[cognito.UserPoolClientIdentityProvider.AMAZON, cognito.UserPoolClientIdentityProvider.COGNITO
            ]
        )
    '''

    @jsii.member(jsii_name="custom") # type: ignore[misc]
    @builtins.classmethod
    def custom(cls, name: builtins.str) -> "UserPoolClientIdentityProvider":
        '''Specify a provider not yet supported by the CDK.

        :param name: name of the identity provider as recognized by CloudFormation property ``SupportedIdentityProviders``.
        '''
        return typing.cast("UserPoolClientIdentityProvider", jsii.sinvoke(cls, "custom", [name]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AMAZON")
    def AMAZON(cls) -> "UserPoolClientIdentityProvider":
        '''Allow users to sign in using 'Login With Amazon'.

        A ``UserPoolIdentityProviderAmazon`` must be attached to the user pool.
        '''
        return typing.cast("UserPoolClientIdentityProvider", jsii.sget(cls, "AMAZON"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="APPLE")
    def APPLE(cls) -> "UserPoolClientIdentityProvider":
        '''Allow users to sign in using 'Sign In With Apple'.

        A ``UserPoolIdentityProviderApple`` must be attached to the user pool.
        '''
        return typing.cast("UserPoolClientIdentityProvider", jsii.sget(cls, "APPLE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="COGNITO")
    def COGNITO(cls) -> "UserPoolClientIdentityProvider":
        '''Allow users to sign in directly as a user of the User Pool.'''
        return typing.cast("UserPoolClientIdentityProvider", jsii.sget(cls, "COGNITO"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="FACEBOOK")
    def FACEBOOK(cls) -> "UserPoolClientIdentityProvider":
        '''Allow users to sign in using 'Facebook Login'.

        A ``UserPoolIdentityProviderFacebook`` must be attached to the user pool.
        '''
        return typing.cast("UserPoolClientIdentityProvider", jsii.sget(cls, "FACEBOOK"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GOOGLE")
    def GOOGLE(cls) -> "UserPoolClientIdentityProvider":
        '''Allow users to sign in using 'Google Login'.

        A ``UserPoolIdentityProviderGoogle`` must be attached to the user pool.
        '''
        return typing.cast("UserPoolClientIdentityProvider", jsii.sget(cls, "GOOGLE"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the identity provider as recognized by CloudFormation property ``SupportedIdentityProviders``.'''
        return typing.cast(builtins.str, jsii.get(self, "name"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolClientOptions",
    jsii_struct_bases=[],
    name_mapping={
        "access_token_validity": "accessTokenValidity",
        "auth_flows": "authFlows",
        "disable_o_auth": "disableOAuth",
        "enable_token_revocation": "enableTokenRevocation",
        "generate_secret": "generateSecret",
        "id_token_validity": "idTokenValidity",
        "o_auth": "oAuth",
        "prevent_user_existence_errors": "preventUserExistenceErrors",
        "read_attributes": "readAttributes",
        "refresh_token_validity": "refreshTokenValidity",
        "supported_identity_providers": "supportedIdentityProviders",
        "user_pool_client_name": "userPoolClientName",
        "write_attributes": "writeAttributes",
    },
)
class UserPoolClientOptions:
    def __init__(
        self,
        *,
        access_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        auth_flows: typing.Optional[AuthFlow] = None,
        disable_o_auth: typing.Optional[builtins.bool] = None,
        enable_token_revocation: typing.Optional[builtins.bool] = None,
        generate_secret: typing.Optional[builtins.bool] = None,
        id_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        o_auth: typing.Optional[OAuthSettings] = None,
        prevent_user_existence_errors: typing.Optional[builtins.bool] = None,
        read_attributes: typing.Optional[ClientAttributes] = None,
        refresh_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        supported_identity_providers: typing.Optional[typing.Sequence[UserPoolClientIdentityProvider]] = None,
        user_pool_client_name: typing.Optional[builtins.str] = None,
        write_attributes: typing.Optional[ClientAttributes] = None,
    ) -> None:
        '''Options to create a UserPoolClient.

        :param access_token_validity: Validity of the access token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param auth_flows: The set of OAuth authentication flows to enable on the client. Default: - all auth flows disabled
        :param disable_o_auth: Turns off all OAuth interactions for this client. Default: false
        :param enable_token_revocation: Enable token revocation for this client. Default: true for new user pool clients
        :param generate_secret: Whether to generate a client secret. Default: false
        :param id_token_validity: Validity of the ID token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param o_auth: OAuth settings for this client to interact with the app. An error is thrown when this is specified and ``disableOAuth`` is set. Default: - see defaults in ``OAuthSettings``. meaningless if ``disableOAuth`` is set.
        :param prevent_user_existence_errors: Whether Cognito returns a UserNotFoundException exception when the user does not exist in the user pool (false), or whether it returns another type of error that doesn't reveal the user's absence. Default: false
        :param read_attributes: The set of attributes this client will be able to read. Default: - all standard and custom attributes
        :param refresh_token_validity: Validity of the refresh token. Values between 60 minutes and 10 years are valid. Default: Duration.days(30)
        :param supported_identity_providers: The list of identity providers that users should be able to use to sign in using this client. Default: - supports all identity providers that are registered with the user pool. If the user pool and/or identity providers are imported, either specify this option explicitly or ensure that the identity providers are registered with the user pool using the ``UserPool.registerIdentityProvider()`` API.
        :param user_pool_client_name: Name of the application client. Default: - cloudformation generated name
        :param write_attributes: The set of attributes this client will be able to write. Default: - all standard and custom attributes

        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            pool.add_client("app-client",
                o_auth=cognito.OAuthSettings(
                    flows=cognito.OAuthFlows(
                        authorization_code_grant=True
                    ),
                    scopes=[cognito.OAuthScope.OPENID],
                    callback_urls=["https://my-app-domain.com/welcome"],
                    logout_urls=["https://my-app-domain.com/signin"]
                )
            )
        '''
        if isinstance(auth_flows, dict):
            auth_flows = AuthFlow(**auth_flows)
        if isinstance(o_auth, dict):
            o_auth = OAuthSettings(**o_auth)
        self._values: typing.Dict[str, typing.Any] = {}
        if access_token_validity is not None:
            self._values["access_token_validity"] = access_token_validity
        if auth_flows is not None:
            self._values["auth_flows"] = auth_flows
        if disable_o_auth is not None:
            self._values["disable_o_auth"] = disable_o_auth
        if enable_token_revocation is not None:
            self._values["enable_token_revocation"] = enable_token_revocation
        if generate_secret is not None:
            self._values["generate_secret"] = generate_secret
        if id_token_validity is not None:
            self._values["id_token_validity"] = id_token_validity
        if o_auth is not None:
            self._values["o_auth"] = o_auth
        if prevent_user_existence_errors is not None:
            self._values["prevent_user_existence_errors"] = prevent_user_existence_errors
        if read_attributes is not None:
            self._values["read_attributes"] = read_attributes
        if refresh_token_validity is not None:
            self._values["refresh_token_validity"] = refresh_token_validity
        if supported_identity_providers is not None:
            self._values["supported_identity_providers"] = supported_identity_providers
        if user_pool_client_name is not None:
            self._values["user_pool_client_name"] = user_pool_client_name
        if write_attributes is not None:
            self._values["write_attributes"] = write_attributes

    @builtins.property
    def access_token_validity(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Validity of the access token.

        Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity.

        :default: Duration.minutes(60)

        :see: https://docs.aws.amazon.com/en_us/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-access-token
        '''
        result = self._values.get("access_token_validity")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def auth_flows(self) -> typing.Optional[AuthFlow]:
        '''The set of OAuth authentication flows to enable on the client.

        :default: - all auth flows disabled

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html
        '''
        result = self._values.get("auth_flows")
        return typing.cast(typing.Optional[AuthFlow], result)

    @builtins.property
    def disable_o_auth(self) -> typing.Optional[builtins.bool]:
        '''Turns off all OAuth interactions for this client.

        :default: false
        '''
        result = self._values.get("disable_o_auth")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def enable_token_revocation(self) -> typing.Optional[builtins.bool]:
        '''Enable token revocation for this client.

        :default: true for new user pool clients

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html#enable-token-revocation
        '''
        result = self._values.get("enable_token_revocation")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def generate_secret(self) -> typing.Optional[builtins.bool]:
        '''Whether to generate a client secret.

        :default: false
        '''
        result = self._values.get("generate_secret")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def id_token_validity(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Validity of the ID token.

        Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity.

        :default: Duration.minutes(60)

        :see: https://docs.aws.amazon.com/en_us/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-id-token
        '''
        result = self._values.get("id_token_validity")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def o_auth(self) -> typing.Optional[OAuthSettings]:
        '''OAuth settings for this client to interact with the app.

        An error is thrown when this is specified and ``disableOAuth`` is set.

        :default: - see defaults in ``OAuthSettings``. meaningless if ``disableOAuth`` is set.
        '''
        result = self._values.get("o_auth")
        return typing.cast(typing.Optional[OAuthSettings], result)

    @builtins.property
    def prevent_user_existence_errors(self) -> typing.Optional[builtins.bool]:
        '''Whether Cognito returns a UserNotFoundException exception when the user does not exist in the user pool (false), or whether it returns another type of error that doesn't reveal the user's absence.

        :default: false

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html
        '''
        result = self._values.get("prevent_user_existence_errors")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def read_attributes(self) -> typing.Optional[ClientAttributes]:
        '''The set of attributes this client will be able to read.

        :default: - all standard and custom attributes

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-attribute-permissions-and-scopes
        '''
        result = self._values.get("read_attributes")
        return typing.cast(typing.Optional[ClientAttributes], result)

    @builtins.property
    def refresh_token_validity(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Validity of the refresh token.

        Values between 60 minutes and 10 years are valid.

        :default: Duration.days(30)

        :see: https://docs.aws.amazon.com/en_us/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-refresh-token
        '''
        result = self._values.get("refresh_token_validity")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def supported_identity_providers(
        self,
    ) -> typing.Optional[typing.List[UserPoolClientIdentityProvider]]:
        '''The list of identity providers that users should be able to use to sign in using this client.

        :default:

        - supports all identity providers that are registered with the user pool. If the user pool and/or
        identity providers are imported, either specify this option explicitly or ensure that the identity providers are
        registered with the user pool using the ``UserPool.registerIdentityProvider()`` API.
        '''
        result = self._values.get("supported_identity_providers")
        return typing.cast(typing.Optional[typing.List[UserPoolClientIdentityProvider]], result)

    @builtins.property
    def user_pool_client_name(self) -> typing.Optional[builtins.str]:
        '''Name of the application client.

        :default: - cloudformation generated name
        '''
        result = self._values.get("user_pool_client_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def write_attributes(self) -> typing.Optional[ClientAttributes]:
        '''The set of attributes this client will be able to write.

        :default: - all standard and custom attributes

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-attribute-permissions-and-scopes
        '''
        result = self._values.get("write_attributes")
        return typing.cast(typing.Optional[ClientAttributes], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolClientOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolClientProps",
    jsii_struct_bases=[UserPoolClientOptions],
    name_mapping={
        "access_token_validity": "accessTokenValidity",
        "auth_flows": "authFlows",
        "disable_o_auth": "disableOAuth",
        "enable_token_revocation": "enableTokenRevocation",
        "generate_secret": "generateSecret",
        "id_token_validity": "idTokenValidity",
        "o_auth": "oAuth",
        "prevent_user_existence_errors": "preventUserExistenceErrors",
        "read_attributes": "readAttributes",
        "refresh_token_validity": "refreshTokenValidity",
        "supported_identity_providers": "supportedIdentityProviders",
        "user_pool_client_name": "userPoolClientName",
        "write_attributes": "writeAttributes",
        "user_pool": "userPool",
    },
)
class UserPoolClientProps(UserPoolClientOptions):
    def __init__(
        self,
        *,
        access_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        auth_flows: typing.Optional[AuthFlow] = None,
        disable_o_auth: typing.Optional[builtins.bool] = None,
        enable_token_revocation: typing.Optional[builtins.bool] = None,
        generate_secret: typing.Optional[builtins.bool] = None,
        id_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        o_auth: typing.Optional[OAuthSettings] = None,
        prevent_user_existence_errors: typing.Optional[builtins.bool] = None,
        read_attributes: typing.Optional[ClientAttributes] = None,
        refresh_token_validity: typing.Optional[_Duration_4839e8c3] = None,
        supported_identity_providers: typing.Optional[typing.Sequence[UserPoolClientIdentityProvider]] = None,
        user_pool_client_name: typing.Optional[builtins.str] = None,
        write_attributes: typing.Optional[ClientAttributes] = None,
        user_pool: IUserPool,
    ) -> None:
        '''Properties for the UserPoolClient construct.

        :param access_token_validity: Validity of the access token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param auth_flows: The set of OAuth authentication flows to enable on the client. Default: - all auth flows disabled
        :param disable_o_auth: Turns off all OAuth interactions for this client. Default: false
        :param enable_token_revocation: Enable token revocation for this client. Default: true for new user pool clients
        :param generate_secret: Whether to generate a client secret. Default: false
        :param id_token_validity: Validity of the ID token. Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity. Default: Duration.minutes(60)
        :param o_auth: OAuth settings for this client to interact with the app. An error is thrown when this is specified and ``disableOAuth`` is set. Default: - see defaults in ``OAuthSettings``. meaningless if ``disableOAuth`` is set.
        :param prevent_user_existence_errors: Whether Cognito returns a UserNotFoundException exception when the user does not exist in the user pool (false), or whether it returns another type of error that doesn't reveal the user's absence. Default: false
        :param read_attributes: The set of attributes this client will be able to read. Default: - all standard and custom attributes
        :param refresh_token_validity: Validity of the refresh token. Values between 60 minutes and 10 years are valid. Default: Duration.days(30)
        :param supported_identity_providers: The list of identity providers that users should be able to use to sign in using this client. Default: - supports all identity providers that are registered with the user pool. If the user pool and/or identity providers are imported, either specify this option explicitly or ensure that the identity providers are registered with the user pool using the ``UserPool.registerIdentityProvider()`` API.
        :param user_pool_client_name: Name of the application client. Default: - cloudformation generated name
        :param write_attributes: The set of attributes this client will be able to write. Default: - all standard and custom attributes
        :param user_pool: The UserPool resource this client will have access to.

        :exampleMetadata: infused

        Example::

            imported_pool = cognito.UserPool.from_user_pool_id(self, "imported-pool", "us-east-1_oiuR12Abd")
            cognito.UserPoolClient(self, "customer-app-client",
                user_pool=imported_pool
            )
        '''
        if isinstance(auth_flows, dict):
            auth_flows = AuthFlow(**auth_flows)
        if isinstance(o_auth, dict):
            o_auth = OAuthSettings(**o_auth)
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool": user_pool,
        }
        if access_token_validity is not None:
            self._values["access_token_validity"] = access_token_validity
        if auth_flows is not None:
            self._values["auth_flows"] = auth_flows
        if disable_o_auth is not None:
            self._values["disable_o_auth"] = disable_o_auth
        if enable_token_revocation is not None:
            self._values["enable_token_revocation"] = enable_token_revocation
        if generate_secret is not None:
            self._values["generate_secret"] = generate_secret
        if id_token_validity is not None:
            self._values["id_token_validity"] = id_token_validity
        if o_auth is not None:
            self._values["o_auth"] = o_auth
        if prevent_user_existence_errors is not None:
            self._values["prevent_user_existence_errors"] = prevent_user_existence_errors
        if read_attributes is not None:
            self._values["read_attributes"] = read_attributes
        if refresh_token_validity is not None:
            self._values["refresh_token_validity"] = refresh_token_validity
        if supported_identity_providers is not None:
            self._values["supported_identity_providers"] = supported_identity_providers
        if user_pool_client_name is not None:
            self._values["user_pool_client_name"] = user_pool_client_name
        if write_attributes is not None:
            self._values["write_attributes"] = write_attributes

    @builtins.property
    def access_token_validity(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Validity of the access token.

        Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity.

        :default: Duration.minutes(60)

        :see: https://docs.aws.amazon.com/en_us/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-access-token
        '''
        result = self._values.get("access_token_validity")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def auth_flows(self) -> typing.Optional[AuthFlow]:
        '''The set of OAuth authentication flows to enable on the client.

        :default: - all auth flows disabled

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html
        '''
        result = self._values.get("auth_flows")
        return typing.cast(typing.Optional[AuthFlow], result)

    @builtins.property
    def disable_o_auth(self) -> typing.Optional[builtins.bool]:
        '''Turns off all OAuth interactions for this client.

        :default: false
        '''
        result = self._values.get("disable_o_auth")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def enable_token_revocation(self) -> typing.Optional[builtins.bool]:
        '''Enable token revocation for this client.

        :default: true for new user pool clients

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html#enable-token-revocation
        '''
        result = self._values.get("enable_token_revocation")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def generate_secret(self) -> typing.Optional[builtins.bool]:
        '''Whether to generate a client secret.

        :default: false
        '''
        result = self._values.get("generate_secret")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def id_token_validity(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Validity of the ID token.

        Values between 5 minutes and 1 day are valid. The duration can not be longer than the refresh token validity.

        :default: Duration.minutes(60)

        :see: https://docs.aws.amazon.com/en_us/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-id-token
        '''
        result = self._values.get("id_token_validity")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def o_auth(self) -> typing.Optional[OAuthSettings]:
        '''OAuth settings for this client to interact with the app.

        An error is thrown when this is specified and ``disableOAuth`` is set.

        :default: - see defaults in ``OAuthSettings``. meaningless if ``disableOAuth`` is set.
        '''
        result = self._values.get("o_auth")
        return typing.cast(typing.Optional[OAuthSettings], result)

    @builtins.property
    def prevent_user_existence_errors(self) -> typing.Optional[builtins.bool]:
        '''Whether Cognito returns a UserNotFoundException exception when the user does not exist in the user pool (false), or whether it returns another type of error that doesn't reveal the user's absence.

        :default: false

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html
        '''
        result = self._values.get("prevent_user_existence_errors")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def read_attributes(self) -> typing.Optional[ClientAttributes]:
        '''The set of attributes this client will be able to read.

        :default: - all standard and custom attributes

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-attribute-permissions-and-scopes
        '''
        result = self._values.get("read_attributes")
        return typing.cast(typing.Optional[ClientAttributes], result)

    @builtins.property
    def refresh_token_validity(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Validity of the refresh token.

        Values between 60 minutes and 10 years are valid.

        :default: Duration.days(30)

        :see: https://docs.aws.amazon.com/en_us/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-refresh-token
        '''
        result = self._values.get("refresh_token_validity")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def supported_identity_providers(
        self,
    ) -> typing.Optional[typing.List[UserPoolClientIdentityProvider]]:
        '''The list of identity providers that users should be able to use to sign in using this client.

        :default:

        - supports all identity providers that are registered with the user pool. If the user pool and/or
        identity providers are imported, either specify this option explicitly or ensure that the identity providers are
        registered with the user pool using the ``UserPool.registerIdentityProvider()`` API.
        '''
        result = self._values.get("supported_identity_providers")
        return typing.cast(typing.Optional[typing.List[UserPoolClientIdentityProvider]], result)

    @builtins.property
    def user_pool_client_name(self) -> typing.Optional[builtins.str]:
        '''Name of the application client.

        :default: - cloudformation generated name
        '''
        result = self._values.get("user_pool_client_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def write_attributes(self) -> typing.Optional[ClientAttributes]:
        '''The set of attributes this client will be able to write.

        :default: - all standard and custom attributes

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html#user-pool-settings-attribute-permissions-and-scopes
        '''
        result = self._values.get("write_attributes")
        return typing.cast(typing.Optional[ClientAttributes], result)

    @builtins.property
    def user_pool(self) -> IUserPool:
        '''The UserPool resource this client will have access to.'''
        result = self._values.get("user_pool")
        assert result is not None, "Required property 'user_pool' is missing"
        return typing.cast(IUserPool, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolClientProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IUserPoolDomain)
class UserPoolDomain(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolDomain",
):
    '''Define a user pool domain.

    :exampleMetadata: infused

    Example::

        userpool = cognito.UserPool(self, "UserPool")
        client = userpool.add_client("Client",
            # ...
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    implicit_code_grant=True
                ),
                callback_urls=["https://myapp.com/home", "https://myapp.com/users"
                ]
            )
        )
        domain = userpool.add_domain("Domain")
        sign_in_url = domain.sign_in_url(client,
            redirect_uri="https://myapp.com/home"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user_pool: IUserPool,
        cognito_domain: typing.Optional[CognitoDomainOptions] = None,
        custom_domain: typing.Optional[CustomDomainOptions] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param user_pool: The user pool to which this domain should be associated.
        :param cognito_domain: Associate a cognito prefix domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``customDomain`` is specified, otherwise, throws an error.
        :param custom_domain: Associate a custom domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``cognitoDomain`` is specified, otherwise, throws an error.
        '''
        props = UserPoolDomainProps(
            user_pool=user_pool,
            cognito_domain=cognito_domain,
            custom_domain=custom_domain,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromDomainName") # type: ignore[misc]
    @builtins.classmethod
    def from_domain_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        user_pool_domain_name: builtins.str,
    ) -> IUserPoolDomain:
        '''Import a UserPoolDomain given its domain name.

        :param scope: -
        :param id: -
        :param user_pool_domain_name: -
        '''
        return typing.cast(IUserPoolDomain, jsii.sinvoke(cls, "fromDomainName", [scope, id, user_pool_domain_name]))

    @jsii.member(jsii_name="baseUrl")
    def base_url(self) -> builtins.str:
        '''The URL to the hosted UI associated with this domain.'''
        return typing.cast(builtins.str, jsii.invoke(self, "baseUrl", []))

    @jsii.member(jsii_name="signInUrl")
    def sign_in_url(
        self,
        client: UserPoolClient,
        *,
        redirect_uri: builtins.str,
        sign_in_path: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''The URL to the sign in page in this domain using a specific UserPoolClient.

        :param client: [disable-awslint:ref-via-interface] the user pool client that the UI will use to interact with the UserPool.
        :param redirect_uri: Where to redirect to after sign in.
        :param sign_in_path: The path in the URI where the sign-in page is located. Default: '/login'
        '''
        options = SignInUrlOptions(
            redirect_uri=redirect_uri, sign_in_path=sign_in_path
        )

        return typing.cast(builtins.str, jsii.invoke(self, "signInUrl", [client, options]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cloudFrontDomainName")
    def cloud_front_domain_name(self) -> builtins.str:
        '''The domain name of the CloudFront distribution associated with the user pool domain.'''
        return typing.cast(builtins.str, jsii.get(self, "cloudFrontDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The domain that was specified to be created.

        If ``customDomain`` was selected, this holds the full domain name that was specified.
        If the ``cognitoDomain`` was used, it contains the prefix to the Cognito hosted domain.
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolDomainOptions",
    jsii_struct_bases=[],
    name_mapping={"cognito_domain": "cognitoDomain", "custom_domain": "customDomain"},
)
class UserPoolDomainOptions:
    def __init__(
        self,
        *,
        cognito_domain: typing.Optional[CognitoDomainOptions] = None,
        custom_domain: typing.Optional[CustomDomainOptions] = None,
    ) -> None:
        '''Options to create a UserPoolDomain.

        :param cognito_domain: Associate a cognito prefix domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``customDomain`` is specified, otherwise, throws an error.
        :param custom_domain: Associate a custom domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``cognitoDomain`` is specified, otherwise, throws an error.

        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            
            pool.add_domain("CognitoDomain",
                cognito_domain=cognito.CognitoDomainOptions(
                    domain_prefix="my-awesome-app"
                )
            )
            
            certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/11-3336f1-44483d-adc7-9cd375c5169d"
            
            domain_cert = certificatemanager.Certificate.from_certificate_arn(self, "domainCert", certificate_arn)
            pool.add_domain("CustomDomain",
                custom_domain=cognito.CustomDomainOptions(
                    domain_name="user.myapp.com",
                    certificate=domain_cert
                )
            )
        '''
        if isinstance(cognito_domain, dict):
            cognito_domain = CognitoDomainOptions(**cognito_domain)
        if isinstance(custom_domain, dict):
            custom_domain = CustomDomainOptions(**custom_domain)
        self._values: typing.Dict[str, typing.Any] = {}
        if cognito_domain is not None:
            self._values["cognito_domain"] = cognito_domain
        if custom_domain is not None:
            self._values["custom_domain"] = custom_domain

    @builtins.property
    def cognito_domain(self) -> typing.Optional[CognitoDomainOptions]:
        '''Associate a cognito prefix domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified.

        :default: - not set if ``customDomain`` is specified, otherwise, throws an error.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain-prefix.html
        '''
        result = self._values.get("cognito_domain")
        return typing.cast(typing.Optional[CognitoDomainOptions], result)

    @builtins.property
    def custom_domain(self) -> typing.Optional[CustomDomainOptions]:
        '''Associate a custom domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified.

        :default: - not set if ``cognitoDomain`` is specified, otherwise, throws an error.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-add-custom-domain.html
        '''
        result = self._values.get("custom_domain")
        return typing.cast(typing.Optional[CustomDomainOptions], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolDomainOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolDomainProps",
    jsii_struct_bases=[UserPoolDomainOptions],
    name_mapping={
        "cognito_domain": "cognitoDomain",
        "custom_domain": "customDomain",
        "user_pool": "userPool",
    },
)
class UserPoolDomainProps(UserPoolDomainOptions):
    def __init__(
        self,
        *,
        cognito_domain: typing.Optional[CognitoDomainOptions] = None,
        custom_domain: typing.Optional[CustomDomainOptions] = None,
        user_pool: IUserPool,
    ) -> None:
        '''Props for UserPoolDomain construct.

        :param cognito_domain: Associate a cognito prefix domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``customDomain`` is specified, otherwise, throws an error.
        :param custom_domain: Associate a custom domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified. Default: - not set if ``cognitoDomain`` is specified, otherwise, throws an error.
        :param user_pool: The user pool to which this domain should be associated.

        :exampleMetadata: lit=aws-elasticloadbalancingv2-actions/test/integ.cognito.lit.ts infused

        Example::

            import aws_cdk.aws_cognito as cognito
            import aws_cdk.aws_ec2 as ec2
            import aws_cdk.aws_elasticloadbalancingv2 as elbv2
            from aws_cdk import App, CfnOutput, Stack
            from constructs import Construct
            import aws_cdk as actions
            
            Stack): lb = elbv2.ApplicationLoadBalancer(self, "LB",
                vpc=vpc,
                internet_facing=True
            )
            
            user_pool = cognito.UserPool(self, "UserPool")
            user_pool_client = cognito.UserPoolClient(self, "Client",
                user_pool=user_pool,
            
                # Required minimal configuration for use with an ELB
                generate_secret=True,
                auth_flows=cognito.AuthFlow(
                    user_password=True
                ),
                o_auth=cognito.OAuthSettings(
                    flows=cognito.OAuthFlows(
                        authorization_code_grant=True
                    ),
                    scopes=[cognito.OAuthScope.EMAIL],
                    callback_urls=[f"https://{lb.loadBalancerDnsName}/oauth2/idpresponse"
                    ]
                )
            )
            cfn_client = user_pool_client.node.default_child
            cfn_client.add_property_override("RefreshTokenValidity", 1)
            cfn_client.add_property_override("SupportedIdentityProviders", ["COGNITO"])
            
            user_pool_domain = cognito.UserPoolDomain(self, "Domain",
                user_pool=user_pool,
                cognito_domain=cognito.CognitoDomainOptions(
                    domain_prefix="test-cdk-prefix"
                )
            )
            
            lb.add_listener("Listener",
                port=443,
                certificates=[certificate],
                default_action=actions.AuthenticateCognitoAction(
                    user_pool=user_pool,
                    user_pool_client=user_pool_client,
                    user_pool_domain=user_pool_domain,
                    next=elbv2.ListenerAction.fixed_response(200,
                        content_type="text/plain",
                        message_body="Authenticated"
                    )
                )
            )
            
            CfnOutput(self, "DNS",
                value=lb.load_balancer_dns_name
            )
            
            app = App()
            CognitoStack(app, "integ-cognito")
            app.synth()
        '''
        if isinstance(cognito_domain, dict):
            cognito_domain = CognitoDomainOptions(**cognito_domain)
        if isinstance(custom_domain, dict):
            custom_domain = CustomDomainOptions(**custom_domain)
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool": user_pool,
        }
        if cognito_domain is not None:
            self._values["cognito_domain"] = cognito_domain
        if custom_domain is not None:
            self._values["custom_domain"] = custom_domain

    @builtins.property
    def cognito_domain(self) -> typing.Optional[CognitoDomainOptions]:
        '''Associate a cognito prefix domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified.

        :default: - not set if ``customDomain`` is specified, otherwise, throws an error.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain-prefix.html
        '''
        result = self._values.get("cognito_domain")
        return typing.cast(typing.Optional[CognitoDomainOptions], result)

    @builtins.property
    def custom_domain(self) -> typing.Optional[CustomDomainOptions]:
        '''Associate a custom domain with your user pool Either ``customDomain`` or ``cognitoDomain`` must be specified.

        :default: - not set if ``cognitoDomain`` is specified, otherwise, throws an error.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-add-custom-domain.html
        '''
        result = self._values.get("custom_domain")
        return typing.cast(typing.Optional[CustomDomainOptions], result)

    @builtins.property
    def user_pool(self) -> IUserPool:
        '''The user pool to which this domain should be associated.'''
        result = self._values.get("user_pool")
        assert result is not None, "Required property 'user_pool' is missing"
        return typing.cast(IUserPool, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolDomainProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class UserPoolEmail(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolEmail",
):
    '''Configure how Cognito sends emails.

    :exampleMetadata: infused

    Example::

        cognito.UserPool(self, "myuserpool",
            email=cognito.UserPoolEmail.with_sES(
                from_email="noreply@myawesomeapp.com",
                from_name="Awesome App",
                reply_to="support@myawesomeapp.com"
            )
        )
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="withCognito") # type: ignore[misc]
    @builtins.classmethod
    def with_cognito(
        cls,
        reply_to: typing.Optional[builtins.str] = None,
    ) -> "UserPoolEmail":
        '''Send email using Cognito.

        :param reply_to: -
        '''
        return typing.cast("UserPoolEmail", jsii.sinvoke(cls, "withCognito", [reply_to]))

    @jsii.member(jsii_name="withSES") # type: ignore[misc]
    @builtins.classmethod
    def with_ses(
        cls,
        *,
        from_email: builtins.str,
        configuration_set_name: typing.Optional[builtins.str] = None,
        from_name: typing.Optional[builtins.str] = None,
        reply_to: typing.Optional[builtins.str] = None,
        ses_region: typing.Optional[builtins.str] = None,
    ) -> "UserPoolEmail":
        '''Send email using SES.

        :param from_email: The verified Amazon SES email address that Cognito should use to send emails. The email address used must be a verified email address in Amazon SES and must be configured to allow Cognito to send emails.
        :param configuration_set_name: The name of a configuration set in Amazon SES that should be applied to emails sent via Cognito. Default: - no configuration set
        :param from_name: An optional name that should be used as the sender's name along with the email. Default: - no name
        :param reply_to: The destination to which the receiver of the email should reploy to. Default: - same as the fromEmail
        :param ses_region: Required if the UserPool region is different than the SES region. If sending emails with a Amazon SES verified email address, and the region that SES is configured is different than the region in which the UserPool is deployed, you must specify that region here. Must be 'us-east-1', 'us-west-2', or 'eu-west-1' Default: - The same region as the Cognito UserPool
        '''
        options = UserPoolSESOptions(
            from_email=from_email,
            configuration_set_name=configuration_set_name,
            from_name=from_name,
            reply_to=reply_to,
            ses_region=ses_region,
        )

        return typing.cast("UserPoolEmail", jsii.sinvoke(cls, "withSES", [options]))


class _UserPoolEmailProxy(UserPoolEmail):
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, UserPoolEmail).__jsii_proxy_class__ = lambda : _UserPoolEmailProxy


class UserPoolIdentityProvider(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProvider",
):
    '''User pool third-party identity providers.'''

    @jsii.member(jsii_name="fromProviderName") # type: ignore[misc]
    @builtins.classmethod
    def from_provider_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        provider_name: builtins.str,
    ) -> IUserPoolIdentityProvider:
        '''Import an existing UserPoolIdentityProvider.

        :param scope: -
        :param id: -
        :param provider_name: -
        '''
        return typing.cast(IUserPoolIdentityProvider, jsii.sinvoke(cls, "fromProviderName", [scope, id, provider_name]))


@jsii.implements(IUserPoolIdentityProvider)
class UserPoolIdentityProviderAmazon(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderAmazon",
):
    '''Represents a identity provider that integrates with 'Login with Amazon'.

    :exampleMetadata: infused
    :resource: AWS::Cognito::UserPoolIdentityProvider

    Example::

        pool = cognito.UserPool(self, "Pool")
        provider = cognito.UserPoolIdentityProviderAmazon(self, "Amazon",
            user_pool=pool,
            client_id="amzn-client-id",
            client_secret="amzn-client-secret"
        )
        
        client = pool.add_client("app-client",
            # ...
            supported_identity_providers=[cognito.UserPoolClientIdentityProvider.AMAZON
            ]
        )
        
        client.node.add_dependency(provider)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        client_id: builtins.str,
        client_secret: builtins.str,
        scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param client_id: The client id recognized by 'Login with Amazon' APIs.
        :param client_secret: The client secret to be accompanied with clientId for 'Login with Amazon' APIs to authenticate the client.
        :param scopes: The types of user profile data to obtain for the Amazon profile. Default: [ profile ]
        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping
        '''
        props = UserPoolIdentityProviderAmazonProps(
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            user_pool=user_pool,
            attribute_mapping=attribute_mapping,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="configureAttributeMapping")
    def _configure_attribute_mapping(self) -> typing.Any:
        return typing.cast(typing.Any, jsii.invoke(self, "configureAttributeMapping", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerName")
    def provider_name(self) -> builtins.str:
        '''The primary identifier of this identity provider.'''
        return typing.cast(builtins.str, jsii.get(self, "providerName"))


@jsii.implements(IUserPoolIdentityProvider)
class UserPoolIdentityProviderApple(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderApple",
):
    '''Represents a identity provider that integrates with 'Apple'.

    :resource: AWS::Cognito::UserPoolIdentityProvider
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        # provider_attribute: cognito.ProviderAttribute
        # user_pool: cognito.UserPool
        
        user_pool_identity_provider_apple = cognito.UserPoolIdentityProviderApple(self, "MyUserPoolIdentityProviderApple",
            client_id="clientId",
            key_id="keyId",
            private_key="privateKey",
            team_id="teamId",
            user_pool=user_pool,
        
            # the properties below are optional
            attribute_mapping=cognito.AttributeMapping(
                address=provider_attribute,
                birthdate=provider_attribute,
                custom={
                    "custom_key": provider_attribute
                },
                email=provider_attribute,
                family_name=provider_attribute,
                fullname=provider_attribute,
                gender=provider_attribute,
                given_name=provider_attribute,
                last_update_time=provider_attribute,
                locale=provider_attribute,
                middle_name=provider_attribute,
                nickname=provider_attribute,
                phone_number=provider_attribute,
                preferred_username=provider_attribute,
                profile_page=provider_attribute,
                profile_picture=provider_attribute,
                timezone=provider_attribute,
                website=provider_attribute
            ),
            scopes=["scopes"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        client_id: builtins.str,
        key_id: builtins.str,
        private_key: builtins.str,
        team_id: builtins.str,
        scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param client_id: The client id recognized by Apple APIs.
        :param key_id: The keyId (of the same key, which content has to be later supplied as ``privateKey``) for Apple APIs to authenticate the client.
        :param private_key: The privateKey content for Apple APIs to authenticate the client.
        :param team_id: The teamId for Apple APIs to authenticate the client.
        :param scopes: The list of apple permissions to obtain for getting access to the apple profile. Default: [ name ]
        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping
        '''
        props = UserPoolIdentityProviderAppleProps(
            client_id=client_id,
            key_id=key_id,
            private_key=private_key,
            team_id=team_id,
            scopes=scopes,
            user_pool=user_pool,
            attribute_mapping=attribute_mapping,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="configureAttributeMapping")
    def _configure_attribute_mapping(self) -> typing.Any:
        return typing.cast(typing.Any, jsii.invoke(self, "configureAttributeMapping", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerName")
    def provider_name(self) -> builtins.str:
        '''The primary identifier of this identity provider.'''
        return typing.cast(builtins.str, jsii.get(self, "providerName"))


@jsii.implements(IUserPoolIdentityProvider)
class UserPoolIdentityProviderFacebook(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderFacebook",
):
    '''Represents a identity provider that integrates with 'Facebook Login'.

    :resource: AWS::Cognito::UserPoolIdentityProvider
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        # provider_attribute: cognito.ProviderAttribute
        # user_pool: cognito.UserPool
        
        user_pool_identity_provider_facebook = cognito.UserPoolIdentityProviderFacebook(self, "MyUserPoolIdentityProviderFacebook",
            client_id="clientId",
            client_secret="clientSecret",
            user_pool=user_pool,
        
            # the properties below are optional
            api_version="apiVersion",
            attribute_mapping=cognito.AttributeMapping(
                address=provider_attribute,
                birthdate=provider_attribute,
                custom={
                    "custom_key": provider_attribute
                },
                email=provider_attribute,
                family_name=provider_attribute,
                fullname=provider_attribute,
                gender=provider_attribute,
                given_name=provider_attribute,
                last_update_time=provider_attribute,
                locale=provider_attribute,
                middle_name=provider_attribute,
                nickname=provider_attribute,
                phone_number=provider_attribute,
                preferred_username=provider_attribute,
                profile_page=provider_attribute,
                profile_picture=provider_attribute,
                timezone=provider_attribute,
                website=provider_attribute
            ),
            scopes=["scopes"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        client_id: builtins.str,
        client_secret: builtins.str,
        api_version: typing.Optional[builtins.str] = None,
        scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param client_id: The client id recognized by Facebook APIs.
        :param client_secret: The client secret to be accompanied with clientUd for Facebook to authenticate the client.
        :param api_version: The Facebook API version to use. Default: - to the oldest version supported by Facebook
        :param scopes: The list of facebook permissions to obtain for getting access to the Facebook profile. Default: [ public_profile ]
        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping
        '''
        props = UserPoolIdentityProviderFacebookProps(
            client_id=client_id,
            client_secret=client_secret,
            api_version=api_version,
            scopes=scopes,
            user_pool=user_pool,
            attribute_mapping=attribute_mapping,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="configureAttributeMapping")
    def _configure_attribute_mapping(self) -> typing.Any:
        return typing.cast(typing.Any, jsii.invoke(self, "configureAttributeMapping", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerName")
    def provider_name(self) -> builtins.str:
        '''The primary identifier of this identity provider.'''
        return typing.cast(builtins.str, jsii.get(self, "providerName"))


@jsii.implements(IUserPoolIdentityProvider)
class UserPoolIdentityProviderGoogle(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderGoogle",
):
    '''Represents a identity provider that integrates with 'Google'.

    :resource: AWS::Cognito::UserPoolIdentityProvider
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_cognito as cognito
        
        # provider_attribute: cognito.ProviderAttribute
        # user_pool: cognito.UserPool
        
        user_pool_identity_provider_google = cognito.UserPoolIdentityProviderGoogle(self, "MyUserPoolIdentityProviderGoogle",
            client_id="clientId",
            client_secret="clientSecret",
            user_pool=user_pool,
        
            # the properties below are optional
            attribute_mapping=cognito.AttributeMapping(
                address=provider_attribute,
                birthdate=provider_attribute,
                custom={
                    "custom_key": provider_attribute
                },
                email=provider_attribute,
                family_name=provider_attribute,
                fullname=provider_attribute,
                gender=provider_attribute,
                given_name=provider_attribute,
                last_update_time=provider_attribute,
                locale=provider_attribute,
                middle_name=provider_attribute,
                nickname=provider_attribute,
                phone_number=provider_attribute,
                preferred_username=provider_attribute,
                profile_page=provider_attribute,
                profile_picture=provider_attribute,
                timezone=provider_attribute,
                website=provider_attribute
            ),
            scopes=["scopes"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        client_id: builtins.str,
        client_secret: builtins.str,
        scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param client_id: The client id recognized by Google APIs.
        :param client_secret: The client secret to be accompanied with clientId for Google APIs to authenticate the client.
        :param scopes: The list of google permissions to obtain for getting access to the google profile. Default: [ profile ]
        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping
        '''
        props = UserPoolIdentityProviderGoogleProps(
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            user_pool=user_pool,
            attribute_mapping=attribute_mapping,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="configureAttributeMapping")
    def _configure_attribute_mapping(self) -> typing.Any:
        return typing.cast(typing.Any, jsii.invoke(self, "configureAttributeMapping", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="providerName")
    def provider_name(self) -> builtins.str:
        '''The primary identifier of this identity provider.'''
        return typing.cast(builtins.str, jsii.get(self, "providerName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderProps",
    jsii_struct_bases=[],
    name_mapping={"user_pool": "userPool", "attribute_mapping": "attributeMapping"},
)
class UserPoolIdentityProviderProps:
    def __init__(
        self,
        *,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
    ) -> None:
        '''Properties to create a new instance of UserPoolIdentityProvider.

        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # provider_attribute: cognito.ProviderAttribute
            # user_pool: cognito.UserPool
            
            user_pool_identity_provider_props = cognito.UserPoolIdentityProviderProps(
                user_pool=user_pool,
            
                # the properties below are optional
                attribute_mapping=cognito.AttributeMapping(
                    address=provider_attribute,
                    birthdate=provider_attribute,
                    custom={
                        "custom_key": provider_attribute
                    },
                    email=provider_attribute,
                    family_name=provider_attribute,
                    fullname=provider_attribute,
                    gender=provider_attribute,
                    given_name=provider_attribute,
                    last_update_time=provider_attribute,
                    locale=provider_attribute,
                    middle_name=provider_attribute,
                    nickname=provider_attribute,
                    phone_number=provider_attribute,
                    preferred_username=provider_attribute,
                    profile_page=provider_attribute,
                    profile_picture=provider_attribute,
                    timezone=provider_attribute,
                    website=provider_attribute
                )
            )
        '''
        if isinstance(attribute_mapping, dict):
            attribute_mapping = AttributeMapping(**attribute_mapping)
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool": user_pool,
        }
        if attribute_mapping is not None:
            self._values["attribute_mapping"] = attribute_mapping

    @builtins.property
    def user_pool(self) -> IUserPool:
        '''The user pool to which this construct provides identities.'''
        result = self._values.get("user_pool")
        assert result is not None, "Required property 'user_pool' is missing"
        return typing.cast(IUserPool, result)

    @builtins.property
    def attribute_mapping(self) -> typing.Optional[AttributeMapping]:
        '''Mapping attributes from the identity provider to standard and custom attributes of the user pool.

        :default: - no attribute mapping
        '''
        result = self._values.get("attribute_mapping")
        return typing.cast(typing.Optional[AttributeMapping], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolIdentityProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class UserPoolOperation(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolOperation",
):
    '''User pool operations to which lambda triggers can be attached.

    :exampleMetadata: infused

    Example::

        auth_challenge_fn = lambda_.Function(self, "authChallengeFn",
            runtime=lambda_.Runtime.NODEJS_12_X,
            handler="index.handler",
            code=lambda_.Code.from_asset(path.join(__dirname, "path/to/asset"))
        )
        
        userpool = cognito.UserPool(self, "myuserpool",
            # ...
            lambda_triggers=cognito.UserPoolTriggers(
                create_auth_challenge=auth_challenge_fn
            )
        )
        
        userpool.add_trigger(cognito.UserPoolOperation.USER_MIGRATION, lambda_.Function(self, "userMigrationFn",
            runtime=lambda_.Runtime.NODEJS_12_X,
            handler="index.handler",
            code=lambda_.Code.from_asset(path.join(__dirname, "path/to/asset"))
        ))
    '''

    @jsii.member(jsii_name="of") # type: ignore[misc]
    @builtins.classmethod
    def of(cls, name: builtins.str) -> "UserPoolOperation":
        '''A custom user pool operation.

        :param name: -
        '''
        return typing.cast("UserPoolOperation", jsii.sinvoke(cls, "of", [name]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CREATE_AUTH_CHALLENGE")
    def CREATE_AUTH_CHALLENGE(cls) -> "UserPoolOperation":
        '''Creates a challenge in a custom auth flow.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-create-auth-challenge.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "CREATE_AUTH_CHALLENGE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CUSTOM_EMAIL_SENDER")
    def CUSTOM_EMAIL_SENDER(cls) -> "UserPoolOperation":
        '''Amazon Cognito invokes this trigger to send email notifications to users.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-email-sender.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "CUSTOM_EMAIL_SENDER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CUSTOM_MESSAGE")
    def CUSTOM_MESSAGE(cls) -> "UserPoolOperation":
        '''Advanced customization and localization of messages.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-message.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "CUSTOM_MESSAGE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="CUSTOM_SMS_SENDER")
    def CUSTOM_SMS_SENDER(cls) -> "UserPoolOperation":
        '''Amazon Cognito invokes this trigger to send email notifications to users.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-sms-sender.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "CUSTOM_SMS_SENDER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="DEFINE_AUTH_CHALLENGE")
    def DEFINE_AUTH_CHALLENGE(cls) -> "UserPoolOperation":
        '''Determines the next challenge in a custom auth flow.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-define-auth-challenge.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "DEFINE_AUTH_CHALLENGE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="POST_AUTHENTICATION")
    def POST_AUTHENTICATION(cls) -> "UserPoolOperation":
        '''Event logging for custom analytics.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-authentication.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "POST_AUTHENTICATION"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="POST_CONFIRMATION")
    def POST_CONFIRMATION(cls) -> "UserPoolOperation":
        '''Custom welcome messages or event logging for custom analytics.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-confirmation.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "POST_CONFIRMATION"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PRE_AUTHENTICATION")
    def PRE_AUTHENTICATION(cls) -> "UserPoolOperation":
        '''Custom validation to accept or deny the sign-in request.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-authentication.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "PRE_AUTHENTICATION"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PRE_SIGN_UP")
    def PRE_SIGN_UP(cls) -> "UserPoolOperation":
        '''Custom validation to accept or deny the sign-up request.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-sign-up.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "PRE_SIGN_UP"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PRE_TOKEN_GENERATION")
    def PRE_TOKEN_GENERATION(cls) -> "UserPoolOperation":
        '''Add or remove attributes in Id tokens.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "PRE_TOKEN_GENERATION"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="USER_MIGRATION")
    def USER_MIGRATION(cls) -> "UserPoolOperation":
        '''Migrate a user from an existing user directory to user pools.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "USER_MIGRATION"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="VERIFY_AUTH_CHALLENGE_RESPONSE")
    def VERIFY_AUTH_CHALLENGE_RESPONSE(cls) -> "UserPoolOperation":
        '''Determines if a response is correct in a custom auth flow.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-verify-auth-challenge-response.html
        '''
        return typing.cast("UserPoolOperation", jsii.sget(cls, "VERIFY_AUTH_CHALLENGE_RESPONSE"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="operationName")
    def operation_name(self) -> builtins.str:
        '''The key to use in ``CfnUserPool.LambdaConfigProperty``.'''
        return typing.cast(builtins.str, jsii.get(self, "operationName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolProps",
    jsii_struct_bases=[],
    name_mapping={
        "account_recovery": "accountRecovery",
        "auto_verify": "autoVerify",
        "custom_attributes": "customAttributes",
        "custom_sender_kms_key": "customSenderKmsKey",
        "device_tracking": "deviceTracking",
        "email": "email",
        "enable_sms_role": "enableSmsRole",
        "lambda_triggers": "lambdaTriggers",
        "mfa": "mfa",
        "mfa_message": "mfaMessage",
        "mfa_second_factor": "mfaSecondFactor",
        "password_policy": "passwordPolicy",
        "removal_policy": "removalPolicy",
        "self_sign_up_enabled": "selfSignUpEnabled",
        "sign_in_aliases": "signInAliases",
        "sign_in_case_sensitive": "signInCaseSensitive",
        "sms_role": "smsRole",
        "sms_role_external_id": "smsRoleExternalId",
        "standard_attributes": "standardAttributes",
        "user_invitation": "userInvitation",
        "user_pool_name": "userPoolName",
        "user_verification": "userVerification",
    },
)
class UserPoolProps:
    def __init__(
        self,
        *,
        account_recovery: typing.Optional[AccountRecovery] = None,
        auto_verify: typing.Optional[AutoVerifiedAttrs] = None,
        custom_attributes: typing.Optional[typing.Mapping[builtins.str, ICustomAttribute]] = None,
        custom_sender_kms_key: typing.Optional[_IKey_5f11635f] = None,
        device_tracking: typing.Optional[DeviceTracking] = None,
        email: typing.Optional[UserPoolEmail] = None,
        enable_sms_role: typing.Optional[builtins.bool] = None,
        lambda_triggers: typing.Optional["UserPoolTriggers"] = None,
        mfa: typing.Optional[Mfa] = None,
        mfa_message: typing.Optional[builtins.str] = None,
        mfa_second_factor: typing.Optional[MfaSecondFactor] = None,
        password_policy: typing.Optional[PasswordPolicy] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        self_sign_up_enabled: typing.Optional[builtins.bool] = None,
        sign_in_aliases: typing.Optional[SignInAliases] = None,
        sign_in_case_sensitive: typing.Optional[builtins.bool] = None,
        sms_role: typing.Optional[_IRole_235f5d8e] = None,
        sms_role_external_id: typing.Optional[builtins.str] = None,
        standard_attributes: typing.Optional[StandardAttributes] = None,
        user_invitation: typing.Optional[UserInvitationConfig] = None,
        user_pool_name: typing.Optional[builtins.str] = None,
        user_verification: typing.Optional["UserVerificationConfig"] = None,
    ) -> None:
        '''Props for the UserPool construct.

        :param account_recovery: How will a user be able to recover their account? Default: AccountRecovery.PHONE_WITHOUT_MFA_AND_EMAIL
        :param auto_verify: Attributes which Cognito will look to verify automatically upon user sign up. EMAIL and PHONE are the only available options. Default: - If ``signInAlias`` includes email and/or phone, they will be included in ``autoVerifiedAttributes`` by default. If absent, no attributes will be auto-verified.
        :param custom_attributes: Define a set of custom attributes that can be configured for each user in the user pool. Default: - No custom attributes.
        :param custom_sender_kms_key: This key will be used to encrypt temporary passwords and authorization codes that Amazon Cognito generates. Default: - no key ID configured
        :param device_tracking: Device tracking settings. Default: - see defaults on each property of DeviceTracking.
        :param email: Email settings for a user pool. Default: - cognito will use the default email configuration
        :param enable_sms_role: Setting this would explicitly enable or disable SMS role creation. When left unspecified, CDK will determine based on other properties if a role is needed or not. Default: - CDK will determine based on other properties of the user pool if an SMS role should be created or not.
        :param lambda_triggers: Lambda functions to use for supported Cognito triggers. Default: - No Lambda triggers.
        :param mfa: Configure whether users of this user pool can or are required use MFA to sign in. Default: Mfa.OFF
        :param mfa_message: The SMS message template sent during MFA verification. Use '{####}' in the template where Cognito should insert the verification code. Default: 'Your authentication code is {####}.'
        :param mfa_second_factor: Configure the MFA types that users can use in this user pool. Ignored if ``mfa`` is set to ``OFF``. Default: - { sms: true, oneTimePassword: false }, if ``mfa`` is set to ``OPTIONAL`` or ``REQUIRED``. { sms: false, oneTimePassword: false }, otherwise
        :param password_policy: Password policy for this user pool. Default: - see defaults on each property of PasswordPolicy.
        :param removal_policy: Policy to apply when the user pool is removed from the stack. Default: RemovalPolicy.RETAIN
        :param self_sign_up_enabled: Whether self sign up should be enabled. This can be further configured via the ``selfSignUp`` property. Default: false
        :param sign_in_aliases: Methods in which a user registers or signs in to a user pool. Allows either username with aliases OR sign in with email, phone, or both. Read the sections on usernames and aliases to learn more - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html To match with 'Option 1' in the above link, with a verified email, this property should be set to ``{ username: true, email: true }``. To match with 'Option 2' in the above link with both a verified email and phone number, this property should be set to ``{ email: true, phone: true }``. Default: { username: true }
        :param sign_in_case_sensitive: Whether sign-in aliases should be evaluated with case sensitivity. For example, when this option is set to false, users will be able to sign in using either ``MyUsername`` or ``myusername``. Default: true
        :param sms_role: The IAM role that Cognito will assume while sending SMS messages. Default: - a new IAM role is created
        :param sms_role_external_id: The 'ExternalId' that Cognito service must using when assuming the ``smsRole``, if the role is restricted with an 'sts:ExternalId' conditional. Learn more about ExternalId here - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html This property will be ignored if ``smsRole`` is not specified. Default: - No external id will be configured
        :param standard_attributes: The set of attributes that are required for every user in the user pool. Read more on attributes here - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html Default: - All standard attributes are optional and mutable.
        :param user_invitation: Configuration around admins signing up users into a user pool. Default: - see defaults in UserInvitationConfig
        :param user_pool_name: Name of the user pool. Default: - automatically generated name by CloudFormation at deploy time
        :param user_verification: Configuration around users signing themselves up to the user pool. Enable or disable self sign-up via the ``selfSignUpEnabled`` property. Default: - see defaults in UserVerificationConfig

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                self_sign_up_enabled=True,
                user_verification=cognito.UserVerificationConfig(
                    email_subject="Verify your email for our awesome app!",
                    email_body="Thanks for signing up to our awesome app! Your verification code is {####}",
                    email_style=cognito.VerificationEmailStyle.CODE,
                    sms_message="Thanks for signing up to our awesome app! Your verification code is {####}"
                )
            )
        '''
        if isinstance(auto_verify, dict):
            auto_verify = AutoVerifiedAttrs(**auto_verify)
        if isinstance(device_tracking, dict):
            device_tracking = DeviceTracking(**device_tracking)
        if isinstance(lambda_triggers, dict):
            lambda_triggers = UserPoolTriggers(**lambda_triggers)
        if isinstance(mfa_second_factor, dict):
            mfa_second_factor = MfaSecondFactor(**mfa_second_factor)
        if isinstance(password_policy, dict):
            password_policy = PasswordPolicy(**password_policy)
        if isinstance(sign_in_aliases, dict):
            sign_in_aliases = SignInAliases(**sign_in_aliases)
        if isinstance(standard_attributes, dict):
            standard_attributes = StandardAttributes(**standard_attributes)
        if isinstance(user_invitation, dict):
            user_invitation = UserInvitationConfig(**user_invitation)
        if isinstance(user_verification, dict):
            user_verification = UserVerificationConfig(**user_verification)
        self._values: typing.Dict[str, typing.Any] = {}
        if account_recovery is not None:
            self._values["account_recovery"] = account_recovery
        if auto_verify is not None:
            self._values["auto_verify"] = auto_verify
        if custom_attributes is not None:
            self._values["custom_attributes"] = custom_attributes
        if custom_sender_kms_key is not None:
            self._values["custom_sender_kms_key"] = custom_sender_kms_key
        if device_tracking is not None:
            self._values["device_tracking"] = device_tracking
        if email is not None:
            self._values["email"] = email
        if enable_sms_role is not None:
            self._values["enable_sms_role"] = enable_sms_role
        if lambda_triggers is not None:
            self._values["lambda_triggers"] = lambda_triggers
        if mfa is not None:
            self._values["mfa"] = mfa
        if mfa_message is not None:
            self._values["mfa_message"] = mfa_message
        if mfa_second_factor is not None:
            self._values["mfa_second_factor"] = mfa_second_factor
        if password_policy is not None:
            self._values["password_policy"] = password_policy
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if self_sign_up_enabled is not None:
            self._values["self_sign_up_enabled"] = self_sign_up_enabled
        if sign_in_aliases is not None:
            self._values["sign_in_aliases"] = sign_in_aliases
        if sign_in_case_sensitive is not None:
            self._values["sign_in_case_sensitive"] = sign_in_case_sensitive
        if sms_role is not None:
            self._values["sms_role"] = sms_role
        if sms_role_external_id is not None:
            self._values["sms_role_external_id"] = sms_role_external_id
        if standard_attributes is not None:
            self._values["standard_attributes"] = standard_attributes
        if user_invitation is not None:
            self._values["user_invitation"] = user_invitation
        if user_pool_name is not None:
            self._values["user_pool_name"] = user_pool_name
        if user_verification is not None:
            self._values["user_verification"] = user_verification

    @builtins.property
    def account_recovery(self) -> typing.Optional[AccountRecovery]:
        '''How will a user be able to recover their account?

        :default: AccountRecovery.PHONE_WITHOUT_MFA_AND_EMAIL
        '''
        result = self._values.get("account_recovery")
        return typing.cast(typing.Optional[AccountRecovery], result)

    @builtins.property
    def auto_verify(self) -> typing.Optional[AutoVerifiedAttrs]:
        '''Attributes which Cognito will look to verify automatically upon user sign up.

        EMAIL and PHONE are the only available options.

        :default:

        - If ``signInAlias`` includes email and/or phone, they will be included in ``autoVerifiedAttributes`` by default.
        If absent, no attributes will be auto-verified.
        '''
        result = self._values.get("auto_verify")
        return typing.cast(typing.Optional[AutoVerifiedAttrs], result)

    @builtins.property
    def custom_attributes(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, ICustomAttribute]]:
        '''Define a set of custom attributes that can be configured for each user in the user pool.

        :default: - No custom attributes.
        '''
        result = self._values.get("custom_attributes")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, ICustomAttribute]], result)

    @builtins.property
    def custom_sender_kms_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''This key will be used to encrypt temporary passwords and authorization codes that Amazon Cognito generates.

        :default: - no key ID configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-sender-triggers.html
        '''
        result = self._values.get("custom_sender_kms_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def device_tracking(self) -> typing.Optional[DeviceTracking]:
        '''Device tracking settings.

        :default: - see defaults on each property of DeviceTracking.
        '''
        result = self._values.get("device_tracking")
        return typing.cast(typing.Optional[DeviceTracking], result)

    @builtins.property
    def email(self) -> typing.Optional[UserPoolEmail]:
        '''Email settings for a user pool.

        :default: - cognito will use the default email configuration
        '''
        result = self._values.get("email")
        return typing.cast(typing.Optional[UserPoolEmail], result)

    @builtins.property
    def enable_sms_role(self) -> typing.Optional[builtins.bool]:
        '''Setting this would explicitly enable or disable SMS role creation.

        When left unspecified, CDK will determine based on other properties if a role is needed or not.

        :default: - CDK will determine based on other properties of the user pool if an SMS role should be created or not.
        '''
        result = self._values.get("enable_sms_role")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def lambda_triggers(self) -> typing.Optional["UserPoolTriggers"]:
        '''Lambda functions to use for supported Cognito triggers.

        :default: - No Lambda triggers.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html
        '''
        result = self._values.get("lambda_triggers")
        return typing.cast(typing.Optional["UserPoolTriggers"], result)

    @builtins.property
    def mfa(self) -> typing.Optional[Mfa]:
        '''Configure whether users of this user pool can or are required use MFA to sign in.

        :default: Mfa.OFF
        '''
        result = self._values.get("mfa")
        return typing.cast(typing.Optional[Mfa], result)

    @builtins.property
    def mfa_message(self) -> typing.Optional[builtins.str]:
        '''The SMS message template sent during MFA verification.

        Use '{####}' in the template where Cognito should insert the verification code.

        :default: 'Your authentication code is {####}.'
        '''
        result = self._values.get("mfa_message")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def mfa_second_factor(self) -> typing.Optional[MfaSecondFactor]:
        '''Configure the MFA types that users can use in this user pool.

        Ignored if ``mfa`` is set to ``OFF``.

        :default:

        - { sms: true, oneTimePassword: false }, if ``mfa`` is set to ``OPTIONAL`` or ``REQUIRED``.
        { sms: false, oneTimePassword: false }, otherwise
        '''
        result = self._values.get("mfa_second_factor")
        return typing.cast(typing.Optional[MfaSecondFactor], result)

    @builtins.property
    def password_policy(self) -> typing.Optional[PasswordPolicy]:
        '''Password policy for this user pool.

        :default: - see defaults on each property of PasswordPolicy.
        '''
        result = self._values.get("password_policy")
        return typing.cast(typing.Optional[PasswordPolicy], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Policy to apply when the user pool is removed from the stack.

        :default: RemovalPolicy.RETAIN
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def self_sign_up_enabled(self) -> typing.Optional[builtins.bool]:
        '''Whether self sign up should be enabled.

        This can be further configured via the ``selfSignUp`` property.

        :default: false
        '''
        result = self._values.get("self_sign_up_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def sign_in_aliases(self) -> typing.Optional[SignInAliases]:
        '''Methods in which a user registers or signs in to a user pool.

        Allows either username with aliases OR sign in with email, phone, or both.

        Read the sections on usernames and aliases to learn more -
        https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html

        To match with 'Option 1' in the above link, with a verified email, this property should be set to
        ``{ username: true, email: true }``. To match with 'Option 2' in the above link with both a verified email and phone
        number, this property should be set to ``{ email: true, phone: true }``.

        :default: { username: true }
        '''
        result = self._values.get("sign_in_aliases")
        return typing.cast(typing.Optional[SignInAliases], result)

    @builtins.property
    def sign_in_case_sensitive(self) -> typing.Optional[builtins.bool]:
        '''Whether sign-in aliases should be evaluated with case sensitivity.

        For example, when this option is set to false, users will be able to sign in using either ``MyUsername`` or ``myusername``.

        :default: true
        '''
        result = self._values.get("sign_in_case_sensitive")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def sms_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The IAM role that Cognito will assume while sending SMS messages.

        :default: - a new IAM role is created
        '''
        result = self._values.get("sms_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def sms_role_external_id(self) -> typing.Optional[builtins.str]:
        '''The 'ExternalId' that Cognito service must using when assuming the ``smsRole``, if the role is restricted with an 'sts:ExternalId' conditional.

        Learn more about ExternalId here - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html

        This property will be ignored if ``smsRole`` is not specified.

        :default: - No external id will be configured
        '''
        result = self._values.get("sms_role_external_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def standard_attributes(self) -> typing.Optional[StandardAttributes]:
        '''The set of attributes that are required for every user in the user pool.

        Read more on attributes here - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html

        :default: - All standard attributes are optional and mutable.
        '''
        result = self._values.get("standard_attributes")
        return typing.cast(typing.Optional[StandardAttributes], result)

    @builtins.property
    def user_invitation(self) -> typing.Optional[UserInvitationConfig]:
        '''Configuration around admins signing up users into a user pool.

        :default: - see defaults in UserInvitationConfig
        '''
        result = self._values.get("user_invitation")
        return typing.cast(typing.Optional[UserInvitationConfig], result)

    @builtins.property
    def user_pool_name(self) -> typing.Optional[builtins.str]:
        '''Name of the user pool.

        :default: - automatically generated name by CloudFormation at deploy time
        '''
        result = self._values.get("user_pool_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def user_verification(self) -> typing.Optional["UserVerificationConfig"]:
        '''Configuration around users signing themselves up to the user pool.

        Enable or disable self sign-up via the ``selfSignUpEnabled`` property.

        :default: - see defaults in UserVerificationConfig
        '''
        result = self._values.get("user_verification")
        return typing.cast(typing.Optional["UserVerificationConfig"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IUserPoolResourceServer)
class UserPoolResourceServer(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolResourceServer",
):
    '''Defines a User Pool OAuth2.0 Resource Server.

    :exampleMetadata: infused

    Example::

        pool = cognito.UserPool(self, "Pool")
        
        read_only_scope = cognito.ResourceServerScope(scope_name="read", scope_description="Read-only access")
        full_access_scope = cognito.ResourceServerScope(scope_name="*", scope_description="Full access")
        
        user_server = pool.add_resource_server("ResourceServer",
            identifier="users",
            scopes=[read_only_scope, full_access_scope]
        )
        
        read_only_client = pool.add_client("read-only-client",
            # ...
            o_auth=cognito.OAuthSettings(
                # ...
                scopes=[cognito.OAuthScope.resource_server(user_server, read_only_scope)]
            )
        )
        
        full_access_client = pool.add_client("full-access-client",
            # ...
            o_auth=cognito.OAuthSettings(
                # ...
                scopes=[cognito.OAuthScope.resource_server(user_server, full_access_scope)]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        user_pool: IUserPool,
        identifier: builtins.str,
        scopes: typing.Optional[typing.Sequence[ResourceServerScope]] = None,
        user_pool_resource_server_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param user_pool: The user pool to add this resource server to.
        :param identifier: A unique resource server identifier for the resource server.
        :param scopes: Oauth scopes. Default: - No scopes will be added
        :param user_pool_resource_server_name: A friendly name for the resource server. Default: - same as ``identifier``
        '''
        props = UserPoolResourceServerProps(
            user_pool=user_pool,
            identifier=identifier,
            scopes=scopes,
            user_pool_resource_server_name=user_pool_resource_server_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromUserPoolResourceServerId") # type: ignore[misc]
    @builtins.classmethod
    def from_user_pool_resource_server_id(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        user_pool_resource_server_id: builtins.str,
    ) -> IUserPoolResourceServer:
        '''Import a user pool resource client given its id.

        :param scope: -
        :param id: -
        :param user_pool_resource_server_id: -
        '''
        return typing.cast(IUserPoolResourceServer, jsii.sinvoke(cls, "fromUserPoolResourceServerId", [scope, id, user_pool_resource_server_id]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userPoolResourceServerId")
    def user_pool_resource_server_id(self) -> builtins.str:
        '''Resource server id.'''
        return typing.cast(builtins.str, jsii.get(self, "userPoolResourceServerId"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolResourceServerOptions",
    jsii_struct_bases=[],
    name_mapping={
        "identifier": "identifier",
        "scopes": "scopes",
        "user_pool_resource_server_name": "userPoolResourceServerName",
    },
)
class UserPoolResourceServerOptions:
    def __init__(
        self,
        *,
        identifier: builtins.str,
        scopes: typing.Optional[typing.Sequence[ResourceServerScope]] = None,
        user_pool_resource_server_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options to create a UserPoolResourceServer.

        :param identifier: A unique resource server identifier for the resource server.
        :param scopes: Oauth scopes. Default: - No scopes will be added
        :param user_pool_resource_server_name: A friendly name for the resource server. Default: - same as ``identifier``

        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            
            read_only_scope = cognito.ResourceServerScope(scope_name="read", scope_description="Read-only access")
            full_access_scope = cognito.ResourceServerScope(scope_name="*", scope_description="Full access")
            
            user_server = pool.add_resource_server("ResourceServer",
                identifier="users",
                scopes=[read_only_scope, full_access_scope]
            )
            
            read_only_client = pool.add_client("read-only-client",
                # ...
                o_auth=cognito.OAuthSettings(
                    # ...
                    scopes=[cognito.OAuthScope.resource_server(user_server, read_only_scope)]
                )
            )
            
            full_access_client = pool.add_client("full-access-client",
                # ...
                o_auth=cognito.OAuthSettings(
                    # ...
                    scopes=[cognito.OAuthScope.resource_server(user_server, full_access_scope)]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "identifier": identifier,
        }
        if scopes is not None:
            self._values["scopes"] = scopes
        if user_pool_resource_server_name is not None:
            self._values["user_pool_resource_server_name"] = user_pool_resource_server_name

    @builtins.property
    def identifier(self) -> builtins.str:
        '''A unique resource server identifier for the resource server.'''
        result = self._values.get("identifier")
        assert result is not None, "Required property 'identifier' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def scopes(self) -> typing.Optional[typing.List[ResourceServerScope]]:
        '''Oauth scopes.

        :default: - No scopes will be added
        '''
        result = self._values.get("scopes")
        return typing.cast(typing.Optional[typing.List[ResourceServerScope]], result)

    @builtins.property
    def user_pool_resource_server_name(self) -> typing.Optional[builtins.str]:
        '''A friendly name for the resource server.

        :default: - same as ``identifier``
        '''
        result = self._values.get("user_pool_resource_server_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolResourceServerOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolResourceServerProps",
    jsii_struct_bases=[UserPoolResourceServerOptions],
    name_mapping={
        "identifier": "identifier",
        "scopes": "scopes",
        "user_pool_resource_server_name": "userPoolResourceServerName",
        "user_pool": "userPool",
    },
)
class UserPoolResourceServerProps(UserPoolResourceServerOptions):
    def __init__(
        self,
        *,
        identifier: builtins.str,
        scopes: typing.Optional[typing.Sequence[ResourceServerScope]] = None,
        user_pool_resource_server_name: typing.Optional[builtins.str] = None,
        user_pool: IUserPool,
    ) -> None:
        '''Properties for the UserPoolResourceServer construct.

        :param identifier: A unique resource server identifier for the resource server.
        :param scopes: Oauth scopes. Default: - No scopes will be added
        :param user_pool_resource_server_name: A friendly name for the resource server. Default: - same as ``identifier``
        :param user_pool: The user pool to add this resource server to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # resource_server_scope: cognito.ResourceServerScope
            # user_pool: cognito.UserPool
            
            user_pool_resource_server_props = cognito.UserPoolResourceServerProps(
                identifier="identifier",
                user_pool=user_pool,
            
                # the properties below are optional
                scopes=[resource_server_scope],
                user_pool_resource_server_name="userPoolResourceServerName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "identifier": identifier,
            "user_pool": user_pool,
        }
        if scopes is not None:
            self._values["scopes"] = scopes
        if user_pool_resource_server_name is not None:
            self._values["user_pool_resource_server_name"] = user_pool_resource_server_name

    @builtins.property
    def identifier(self) -> builtins.str:
        '''A unique resource server identifier for the resource server.'''
        result = self._values.get("identifier")
        assert result is not None, "Required property 'identifier' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def scopes(self) -> typing.Optional[typing.List[ResourceServerScope]]:
        '''Oauth scopes.

        :default: - No scopes will be added
        '''
        result = self._values.get("scopes")
        return typing.cast(typing.Optional[typing.List[ResourceServerScope]], result)

    @builtins.property
    def user_pool_resource_server_name(self) -> typing.Optional[builtins.str]:
        '''A friendly name for the resource server.

        :default: - same as ``identifier``
        '''
        result = self._values.get("user_pool_resource_server_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def user_pool(self) -> IUserPool:
        '''The user pool to add this resource server to.'''
        result = self._values.get("user_pool")
        assert result is not None, "Required property 'user_pool' is missing"
        return typing.cast(IUserPool, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolResourceServerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolSESOptions",
    jsii_struct_bases=[],
    name_mapping={
        "from_email": "fromEmail",
        "configuration_set_name": "configurationSetName",
        "from_name": "fromName",
        "reply_to": "replyTo",
        "ses_region": "sesRegion",
    },
)
class UserPoolSESOptions:
    def __init__(
        self,
        *,
        from_email: builtins.str,
        configuration_set_name: typing.Optional[builtins.str] = None,
        from_name: typing.Optional[builtins.str] = None,
        reply_to: typing.Optional[builtins.str] = None,
        ses_region: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Configuration for Cognito sending emails via Amazon SES.

        :param from_email: The verified Amazon SES email address that Cognito should use to send emails. The email address used must be a verified email address in Amazon SES and must be configured to allow Cognito to send emails.
        :param configuration_set_name: The name of a configuration set in Amazon SES that should be applied to emails sent via Cognito. Default: - no configuration set
        :param from_name: An optional name that should be used as the sender's name along with the email. Default: - no name
        :param reply_to: The destination to which the receiver of the email should reploy to. Default: - same as the fromEmail
        :param ses_region: Required if the UserPool region is different than the SES region. If sending emails with a Amazon SES verified email address, and the region that SES is configured is different than the region in which the UserPool is deployed, you must specify that region here. Must be 'us-east-1', 'us-west-2', or 'eu-west-1' Default: - The same region as the Cognito UserPool

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                email=cognito.UserPoolEmail.with_sES(
                    from_email="noreply@myawesomeapp.com",
                    from_name="Awesome App",
                    reply_to="support@myawesomeapp.com"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "from_email": from_email,
        }
        if configuration_set_name is not None:
            self._values["configuration_set_name"] = configuration_set_name
        if from_name is not None:
            self._values["from_name"] = from_name
        if reply_to is not None:
            self._values["reply_to"] = reply_to
        if ses_region is not None:
            self._values["ses_region"] = ses_region

    @builtins.property
    def from_email(self) -> builtins.str:
        '''The verified Amazon SES email address that Cognito should use to send emails.

        The email address used must be a verified email address
        in Amazon SES and must be configured to allow Cognito to
        send emails.

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-email.html
        '''
        result = self._values.get("from_email")
        assert result is not None, "Required property 'from_email' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def configuration_set_name(self) -> typing.Optional[builtins.str]:
        '''The name of a configuration set in Amazon SES that should be applied to emails sent via Cognito.

        :default: - no configuration set

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-userpool-emailconfiguration.html#cfn-cognito-userpool-emailconfiguration-configurationset
        '''
        result = self._values.get("configuration_set_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def from_name(self) -> typing.Optional[builtins.str]:
        '''An optional name that should be used as the sender's name along with the email.

        :default: - no name
        '''
        result = self._values.get("from_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def reply_to(self) -> typing.Optional[builtins.str]:
        '''The destination to which the receiver of the email should reploy to.

        :default: - same as the fromEmail
        '''
        result = self._values.get("reply_to")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ses_region(self) -> typing.Optional[builtins.str]:
        '''Required if the UserPool region is different than the SES region.

        If sending emails with a Amazon SES verified email address,
        and the region that SES is configured is different than the
        region in which the UserPool is deployed, you must specify that
        region here.

        Must be 'us-east-1', 'us-west-2', or 'eu-west-1'

        :default: - The same region as the Cognito UserPool
        '''
        result = self._values.get("ses_region")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolSESOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolTriggers",
    jsii_struct_bases=[],
    name_mapping={
        "create_auth_challenge": "createAuthChallenge",
        "custom_email_sender": "customEmailSender",
        "custom_message": "customMessage",
        "custom_sms_sender": "customSmsSender",
        "define_auth_challenge": "defineAuthChallenge",
        "post_authentication": "postAuthentication",
        "post_confirmation": "postConfirmation",
        "pre_authentication": "preAuthentication",
        "pre_sign_up": "preSignUp",
        "pre_token_generation": "preTokenGeneration",
        "user_migration": "userMigration",
        "verify_auth_challenge_response": "verifyAuthChallengeResponse",
    },
)
class UserPoolTriggers:
    def __init__(
        self,
        *,
        create_auth_challenge: typing.Optional[_IFunction_6adb0ab8] = None,
        custom_email_sender: typing.Optional[_IFunction_6adb0ab8] = None,
        custom_message: typing.Optional[_IFunction_6adb0ab8] = None,
        custom_sms_sender: typing.Optional[_IFunction_6adb0ab8] = None,
        define_auth_challenge: typing.Optional[_IFunction_6adb0ab8] = None,
        post_authentication: typing.Optional[_IFunction_6adb0ab8] = None,
        post_confirmation: typing.Optional[_IFunction_6adb0ab8] = None,
        pre_authentication: typing.Optional[_IFunction_6adb0ab8] = None,
        pre_sign_up: typing.Optional[_IFunction_6adb0ab8] = None,
        pre_token_generation: typing.Optional[_IFunction_6adb0ab8] = None,
        user_migration: typing.Optional[_IFunction_6adb0ab8] = None,
        verify_auth_challenge_response: typing.Optional[_IFunction_6adb0ab8] = None,
    ) -> None:
        '''Triggers for a user pool.

        :param create_auth_challenge: Creates an authentication challenge. Default: - no trigger configured
        :param custom_email_sender: Amazon Cognito invokes this trigger to send email notifications to users. Default: - no trigger configured
        :param custom_message: A custom Message AWS Lambda trigger. Default: - no trigger configured
        :param custom_sms_sender: Amazon Cognito invokes this trigger to send SMS notifications to users. Default: - no trigger configured
        :param define_auth_challenge: Defines the authentication challenge. Default: - no trigger configured
        :param post_authentication: A post-authentication AWS Lambda trigger. Default: - no trigger configured
        :param post_confirmation: A post-confirmation AWS Lambda trigger. Default: - no trigger configured
        :param pre_authentication: A pre-authentication AWS Lambda trigger. Default: - no trigger configured
        :param pre_sign_up: A pre-registration AWS Lambda trigger. Default: - no trigger configured
        :param pre_token_generation: A pre-token-generation AWS Lambda trigger. Default: - no trigger configured
        :param user_migration: A user-migration AWS Lambda trigger. Default: - no trigger configured
        :param verify_auth_challenge_response: Verifies the authentication challenge response. Default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html
        :exampleMetadata: infused

        Example::

            auth_challenge_fn = lambda_.Function(self, "authChallengeFn",
                runtime=lambda_.Runtime.NODEJS_12_X,
                handler="index.handler",
                code=lambda_.Code.from_asset(path.join(__dirname, "path/to/asset"))
            )
            
            userpool = cognito.UserPool(self, "myuserpool",
                # ...
                lambda_triggers=cognito.UserPoolTriggers(
                    create_auth_challenge=auth_challenge_fn
                )
            )
            
            userpool.add_trigger(cognito.UserPoolOperation.USER_MIGRATION, lambda_.Function(self, "userMigrationFn",
                runtime=lambda_.Runtime.NODEJS_12_X,
                handler="index.handler",
                code=lambda_.Code.from_asset(path.join(__dirname, "path/to/asset"))
            ))
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if create_auth_challenge is not None:
            self._values["create_auth_challenge"] = create_auth_challenge
        if custom_email_sender is not None:
            self._values["custom_email_sender"] = custom_email_sender
        if custom_message is not None:
            self._values["custom_message"] = custom_message
        if custom_sms_sender is not None:
            self._values["custom_sms_sender"] = custom_sms_sender
        if define_auth_challenge is not None:
            self._values["define_auth_challenge"] = define_auth_challenge
        if post_authentication is not None:
            self._values["post_authentication"] = post_authentication
        if post_confirmation is not None:
            self._values["post_confirmation"] = post_confirmation
        if pre_authentication is not None:
            self._values["pre_authentication"] = pre_authentication
        if pre_sign_up is not None:
            self._values["pre_sign_up"] = pre_sign_up
        if pre_token_generation is not None:
            self._values["pre_token_generation"] = pre_token_generation
        if user_migration is not None:
            self._values["user_migration"] = user_migration
        if verify_auth_challenge_response is not None:
            self._values["verify_auth_challenge_response"] = verify_auth_challenge_response

    @builtins.property
    def create_auth_challenge(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''Creates an authentication challenge.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-create-auth-challenge.html
        '''
        result = self._values.get("create_auth_challenge")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def custom_email_sender(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''Amazon Cognito invokes this trigger to send email notifications to users.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-email-sender.html
        '''
        result = self._values.get("custom_email_sender")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def custom_message(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A custom Message AWS Lambda trigger.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-message.html
        '''
        result = self._values.get("custom_message")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def custom_sms_sender(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''Amazon Cognito invokes this trigger to send SMS notifications to users.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-sms-sender.html
        '''
        result = self._values.get("custom_sms_sender")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def define_auth_challenge(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''Defines the authentication challenge.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-define-auth-challenge.html
        '''
        result = self._values.get("define_auth_challenge")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def post_authentication(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A post-authentication AWS Lambda trigger.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-authentication.html
        '''
        result = self._values.get("post_authentication")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def post_confirmation(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A post-confirmation AWS Lambda trigger.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-confirmation.html
        '''
        result = self._values.get("post_confirmation")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def pre_authentication(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A pre-authentication AWS Lambda trigger.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-authentication.html
        '''
        result = self._values.get("pre_authentication")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def pre_sign_up(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A pre-registration AWS Lambda trigger.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-sign-up.html
        '''
        result = self._values.get("pre_sign_up")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def pre_token_generation(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A pre-token-generation AWS Lambda trigger.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
        '''
        result = self._values.get("pre_token_generation")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def user_migration(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''A user-migration AWS Lambda trigger.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html
        '''
        result = self._values.get("user_migration")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    @builtins.property
    def verify_auth_challenge_response(self) -> typing.Optional[_IFunction_6adb0ab8]:
        '''Verifies the authentication challenge response.

        :default: - no trigger configured

        :see: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-verify-auth-challenge-response.html
        '''
        result = self._values.get("verify_auth_challenge_response")
        return typing.cast(typing.Optional[_IFunction_6adb0ab8], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolTriggers(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserVerificationConfig",
    jsii_struct_bases=[],
    name_mapping={
        "email_body": "emailBody",
        "email_style": "emailStyle",
        "email_subject": "emailSubject",
        "sms_message": "smsMessage",
    },
)
class UserVerificationConfig:
    def __init__(
        self,
        *,
        email_body: typing.Optional[builtins.str] = None,
        email_style: typing.Optional["VerificationEmailStyle"] = None,
        email_subject: typing.Optional[builtins.str] = None,
        sms_message: typing.Optional[builtins.str] = None,
    ) -> None:
        '''User pool configuration for user self sign up.

        :param email_body: The email body template for the verification email sent to the user upon sign up. See https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-templates.html to learn more about message templates. Default: - 'The verification code to your new account is {####}' if VerificationEmailStyle.CODE is chosen, 'Verify your account by clicking on {##Verify Email##}' if VerificationEmailStyle.LINK is chosen.
        :param email_style: Emails can be verified either using a code or a link. Learn more at https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-email-verification-message-customization.html Default: VerificationEmailStyle.CODE
        :param email_subject: The email subject template for the verification email sent to the user upon sign up. See https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-templates.html to learn more about message templates. Default: 'Verify your new account'
        :param sms_message: The message template for the verification SMS sent to the user upon sign up. See https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-templates.html to learn more about message templates. Default: - 'The verification code to your new account is {####}' if VerificationEmailStyle.CODE is chosen, not configured if VerificationEmailStyle.LINK is chosen

        :exampleMetadata: infused

        Example::

            cognito.UserPool(self, "myuserpool",
                # ...
                self_sign_up_enabled=True,
                user_verification=cognito.UserVerificationConfig(
                    email_subject="Verify your email for our awesome app!",
                    email_body="Thanks for signing up to our awesome app! Your verification code is {####}",
                    email_style=cognito.VerificationEmailStyle.CODE,
                    sms_message="Thanks for signing up to our awesome app! Your verification code is {####}"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if email_body is not None:
            self._values["email_body"] = email_body
        if email_style is not None:
            self._values["email_style"] = email_style
        if email_subject is not None:
            self._values["email_subject"] = email_subject
        if sms_message is not None:
            self._values["sms_message"] = sms_message

    @builtins.property
    def email_body(self) -> typing.Optional[builtins.str]:
        '''The email body template for the verification email sent to the user upon sign up.

        See https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-templates.html to
        learn more about message templates.

        :default:

        - 'The verification code to your new account is {####}' if VerificationEmailStyle.CODE is chosen,
        'Verify your account by clicking on {##Verify Email##}' if VerificationEmailStyle.LINK is chosen.
        '''
        result = self._values.get("email_body")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def email_style(self) -> typing.Optional["VerificationEmailStyle"]:
        '''Emails can be verified either using a code or a link.

        Learn more at https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-email-verification-message-customization.html

        :default: VerificationEmailStyle.CODE
        '''
        result = self._values.get("email_style")
        return typing.cast(typing.Optional["VerificationEmailStyle"], result)

    @builtins.property
    def email_subject(self) -> typing.Optional[builtins.str]:
        '''The email subject template for the verification email sent to the user upon sign up.

        See https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-templates.html to
        learn more about message templates.

        :default: 'Verify your new account'
        '''
        result = self._values.get("email_subject")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sms_message(self) -> typing.Optional[builtins.str]:
        '''The message template for the verification SMS sent to the user upon sign up.

        See https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-message-templates.html to
        learn more about message templates.

        :default:

        - 'The verification code to your new account is {####}' if VerificationEmailStyle.CODE is chosen,
        not configured if VerificationEmailStyle.LINK is chosen
        '''
        result = self._values.get("sms_message")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserVerificationConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_cognito.VerificationEmailStyle")
class VerificationEmailStyle(enum.Enum):
    '''The email verification style.

    :exampleMetadata: infused

    Example::

        cognito.UserPool(self, "myuserpool",
            # ...
            self_sign_up_enabled=True,
            user_verification=cognito.UserVerificationConfig(
                email_subject="Verify your email for our awesome app!",
                email_body="Thanks for signing up to our awesome app! Your verification code is {####}",
                email_style=cognito.VerificationEmailStyle.CODE,
                sms_message="Thanks for signing up to our awesome app! Your verification code is {####}"
            )
        )
    '''

    CODE = "CODE"
    '''Verify email via code.'''
    LINK = "LINK"
    '''Verify email via link.'''


@jsii.implements(ICustomAttribute)
class BooleanAttribute(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.BooleanAttribute",
):
    '''The Boolean custom attribute type.

    :exampleMetadata: infused

    Example::

        cognito.UserPool(self, "myuserpool",
            # ...
            standard_attributes=cognito.StandardAttributes(
                fullname=cognito.StandardAttribute(
                    required=True,
                    mutable=False
                ),
                address=cognito.StandardAttribute(
                    required=False,
                    mutable=True
                )
            ),
            custom_attributes={
                "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                "is_employee": cognito.BooleanAttribute(mutable=True),
                "joined_on": cognito.DateTimeAttribute()
            }
        )
    '''

    def __init__(self, *, mutable: typing.Optional[builtins.bool] = None) -> None:
        '''
        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: false
        '''
        props = CustomAttributeProps(mutable=mutable)

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="bind")
    def bind(self) -> CustomAttributeConfig:
        '''Bind this custom attribute type to the values as expected by CloudFormation.'''
        return typing.cast(CustomAttributeConfig, jsii.invoke(self, "bind", []))


@jsii.implements(ICustomAttribute)
class DateTimeAttribute(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_cognito.DateTimeAttribute",
):
    '''The DateTime custom attribute type.

    :exampleMetadata: infused

    Example::

        cognito.UserPool(self, "myuserpool",
            # ...
            standard_attributes=cognito.StandardAttributes(
                fullname=cognito.StandardAttribute(
                    required=True,
                    mutable=False
                ),
                address=cognito.StandardAttribute(
                    required=False,
                    mutable=True
                )
            ),
            custom_attributes={
                "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
                "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
                "is_employee": cognito.BooleanAttribute(mutable=True),
                "joined_on": cognito.DateTimeAttribute()
            }
        )
    '''

    def __init__(self, *, mutable: typing.Optional[builtins.bool] = None) -> None:
        '''
        :param mutable: Specifies whether the value of the attribute can be changed. For any user pool attribute that's mapped to an identity provider attribute, you must set this parameter to true. Amazon Cognito updates mapped attributes when users sign in to your application through an identity provider. If an attribute is immutable, Amazon Cognito throws an error when it attempts to update the attribute. Default: false
        '''
        props = CustomAttributeProps(mutable=mutable)

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="bind")
    def bind(self) -> CustomAttributeConfig:
        '''Bind this custom attribute type to the values as expected by CloudFormation.'''
        return typing.cast(CustomAttributeConfig, jsii.invoke(self, "bind", []))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderAmazonProps",
    jsii_struct_bases=[UserPoolIdentityProviderProps],
    name_mapping={
        "user_pool": "userPool",
        "attribute_mapping": "attributeMapping",
        "client_id": "clientId",
        "client_secret": "clientSecret",
        "scopes": "scopes",
    },
)
class UserPoolIdentityProviderAmazonProps(UserPoolIdentityProviderProps):
    def __init__(
        self,
        *,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
        client_id: builtins.str,
        client_secret: builtins.str,
        scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties to initialize UserPoolAmazonIdentityProvider.

        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping
        :param client_id: The client id recognized by 'Login with Amazon' APIs.
        :param client_secret: The client secret to be accompanied with clientId for 'Login with Amazon' APIs to authenticate the client.
        :param scopes: The types of user profile data to obtain for the Amazon profile. Default: [ profile ]

        :exampleMetadata: infused

        Example::

            pool = cognito.UserPool(self, "Pool")
            provider = cognito.UserPoolIdentityProviderAmazon(self, "Amazon",
                user_pool=pool,
                client_id="amzn-client-id",
                client_secret="amzn-client-secret"
            )
            
            client = pool.add_client("app-client",
                # ...
                supported_identity_providers=[cognito.UserPoolClientIdentityProvider.AMAZON
                ]
            )
            
            client.node.add_dependency(provider)
        '''
        if isinstance(attribute_mapping, dict):
            attribute_mapping = AttributeMapping(**attribute_mapping)
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool": user_pool,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if attribute_mapping is not None:
            self._values["attribute_mapping"] = attribute_mapping
        if scopes is not None:
            self._values["scopes"] = scopes

    @builtins.property
    def user_pool(self) -> IUserPool:
        '''The user pool to which this construct provides identities.'''
        result = self._values.get("user_pool")
        assert result is not None, "Required property 'user_pool' is missing"
        return typing.cast(IUserPool, result)

    @builtins.property
    def attribute_mapping(self) -> typing.Optional[AttributeMapping]:
        '''Mapping attributes from the identity provider to standard and custom attributes of the user pool.

        :default: - no attribute mapping
        '''
        result = self._values.get("attribute_mapping")
        return typing.cast(typing.Optional[AttributeMapping], result)

    @builtins.property
    def client_id(self) -> builtins.str:
        '''The client id recognized by 'Login with Amazon' APIs.

        :see: https://developer.amazon.com/docs/login-with-amazon/security-profile.html#client-identifier
        '''
        result = self._values.get("client_id")
        assert result is not None, "Required property 'client_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_secret(self) -> builtins.str:
        '''The client secret to be accompanied with clientId for 'Login with Amazon' APIs to authenticate the client.

        :see: https://developer.amazon.com/docs/login-with-amazon/security-profile.html#client-identifier
        '''
        result = self._values.get("client_secret")
        assert result is not None, "Required property 'client_secret' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def scopes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The types of user profile data to obtain for the Amazon profile.

        :default: [ profile ]

        :see: https://developer.amazon.com/docs/login-with-amazon/customer-profile.html
        '''
        result = self._values.get("scopes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolIdentityProviderAmazonProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderAppleProps",
    jsii_struct_bases=[UserPoolIdentityProviderProps],
    name_mapping={
        "user_pool": "userPool",
        "attribute_mapping": "attributeMapping",
        "client_id": "clientId",
        "key_id": "keyId",
        "private_key": "privateKey",
        "team_id": "teamId",
        "scopes": "scopes",
    },
)
class UserPoolIdentityProviderAppleProps(UserPoolIdentityProviderProps):
    def __init__(
        self,
        *,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
        client_id: builtins.str,
        key_id: builtins.str,
        private_key: builtins.str,
        team_id: builtins.str,
        scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties to initialize UserPoolAppleIdentityProvider.

        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping
        :param client_id: The client id recognized by Apple APIs.
        :param key_id: The keyId (of the same key, which content has to be later supplied as ``privateKey``) for Apple APIs to authenticate the client.
        :param private_key: The privateKey content for Apple APIs to authenticate the client.
        :param team_id: The teamId for Apple APIs to authenticate the client.
        :param scopes: The list of apple permissions to obtain for getting access to the apple profile. Default: [ name ]

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # provider_attribute: cognito.ProviderAttribute
            # user_pool: cognito.UserPool
            
            user_pool_identity_provider_apple_props = cognito.UserPoolIdentityProviderAppleProps(
                client_id="clientId",
                key_id="keyId",
                private_key="privateKey",
                team_id="teamId",
                user_pool=user_pool,
            
                # the properties below are optional
                attribute_mapping=cognito.AttributeMapping(
                    address=provider_attribute,
                    birthdate=provider_attribute,
                    custom={
                        "custom_key": provider_attribute
                    },
                    email=provider_attribute,
                    family_name=provider_attribute,
                    fullname=provider_attribute,
                    gender=provider_attribute,
                    given_name=provider_attribute,
                    last_update_time=provider_attribute,
                    locale=provider_attribute,
                    middle_name=provider_attribute,
                    nickname=provider_attribute,
                    phone_number=provider_attribute,
                    preferred_username=provider_attribute,
                    profile_page=provider_attribute,
                    profile_picture=provider_attribute,
                    timezone=provider_attribute,
                    website=provider_attribute
                ),
                scopes=["scopes"]
            )
        '''
        if isinstance(attribute_mapping, dict):
            attribute_mapping = AttributeMapping(**attribute_mapping)
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool": user_pool,
            "client_id": client_id,
            "key_id": key_id,
            "private_key": private_key,
            "team_id": team_id,
        }
        if attribute_mapping is not None:
            self._values["attribute_mapping"] = attribute_mapping
        if scopes is not None:
            self._values["scopes"] = scopes

    @builtins.property
    def user_pool(self) -> IUserPool:
        '''The user pool to which this construct provides identities.'''
        result = self._values.get("user_pool")
        assert result is not None, "Required property 'user_pool' is missing"
        return typing.cast(IUserPool, result)

    @builtins.property
    def attribute_mapping(self) -> typing.Optional[AttributeMapping]:
        '''Mapping attributes from the identity provider to standard and custom attributes of the user pool.

        :default: - no attribute mapping
        '''
        result = self._values.get("attribute_mapping")
        return typing.cast(typing.Optional[AttributeMapping], result)

    @builtins.property
    def client_id(self) -> builtins.str:
        '''The client id recognized by Apple APIs.

        :see: https://developer.apple.com/documentation/sign_in_with_apple/clientconfigi/3230948-clientid
        '''
        result = self._values.get("client_id")
        assert result is not None, "Required property 'client_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def key_id(self) -> builtins.str:
        '''The keyId (of the same key, which content has to be later supplied as ``privateKey``) for Apple APIs to authenticate the client.'''
        result = self._values.get("key_id")
        assert result is not None, "Required property 'key_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def private_key(self) -> builtins.str:
        '''The privateKey content for Apple APIs to authenticate the client.'''
        result = self._values.get("private_key")
        assert result is not None, "Required property 'private_key' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def team_id(self) -> builtins.str:
        '''The teamId for Apple APIs to authenticate the client.'''
        result = self._values.get("team_id")
        assert result is not None, "Required property 'team_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def scopes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of apple permissions to obtain for getting access to the apple profile.

        :default: [ name ]

        :see: https://developer.apple.com/documentation/sign_in_with_apple/clientconfigi/3230955-scope
        '''
        result = self._values.get("scopes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolIdentityProviderAppleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderFacebookProps",
    jsii_struct_bases=[UserPoolIdentityProviderProps],
    name_mapping={
        "user_pool": "userPool",
        "attribute_mapping": "attributeMapping",
        "client_id": "clientId",
        "client_secret": "clientSecret",
        "api_version": "apiVersion",
        "scopes": "scopes",
    },
)
class UserPoolIdentityProviderFacebookProps(UserPoolIdentityProviderProps):
    def __init__(
        self,
        *,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
        client_id: builtins.str,
        client_secret: builtins.str,
        api_version: typing.Optional[builtins.str] = None,
        scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties to initialize UserPoolFacebookIdentityProvider.

        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping
        :param client_id: The client id recognized by Facebook APIs.
        :param client_secret: The client secret to be accompanied with clientUd for Facebook to authenticate the client.
        :param api_version: The Facebook API version to use. Default: - to the oldest version supported by Facebook
        :param scopes: The list of facebook permissions to obtain for getting access to the Facebook profile. Default: [ public_profile ]

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # provider_attribute: cognito.ProviderAttribute
            # user_pool: cognito.UserPool
            
            user_pool_identity_provider_facebook_props = cognito.UserPoolIdentityProviderFacebookProps(
                client_id="clientId",
                client_secret="clientSecret",
                user_pool=user_pool,
            
                # the properties below are optional
                api_version="apiVersion",
                attribute_mapping=cognito.AttributeMapping(
                    address=provider_attribute,
                    birthdate=provider_attribute,
                    custom={
                        "custom_key": provider_attribute
                    },
                    email=provider_attribute,
                    family_name=provider_attribute,
                    fullname=provider_attribute,
                    gender=provider_attribute,
                    given_name=provider_attribute,
                    last_update_time=provider_attribute,
                    locale=provider_attribute,
                    middle_name=provider_attribute,
                    nickname=provider_attribute,
                    phone_number=provider_attribute,
                    preferred_username=provider_attribute,
                    profile_page=provider_attribute,
                    profile_picture=provider_attribute,
                    timezone=provider_attribute,
                    website=provider_attribute
                ),
                scopes=["scopes"]
            )
        '''
        if isinstance(attribute_mapping, dict):
            attribute_mapping = AttributeMapping(**attribute_mapping)
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool": user_pool,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if attribute_mapping is not None:
            self._values["attribute_mapping"] = attribute_mapping
        if api_version is not None:
            self._values["api_version"] = api_version
        if scopes is not None:
            self._values["scopes"] = scopes

    @builtins.property
    def user_pool(self) -> IUserPool:
        '''The user pool to which this construct provides identities.'''
        result = self._values.get("user_pool")
        assert result is not None, "Required property 'user_pool' is missing"
        return typing.cast(IUserPool, result)

    @builtins.property
    def attribute_mapping(self) -> typing.Optional[AttributeMapping]:
        '''Mapping attributes from the identity provider to standard and custom attributes of the user pool.

        :default: - no attribute mapping
        '''
        result = self._values.get("attribute_mapping")
        return typing.cast(typing.Optional[AttributeMapping], result)

    @builtins.property
    def client_id(self) -> builtins.str:
        '''The client id recognized by Facebook APIs.'''
        result = self._values.get("client_id")
        assert result is not None, "Required property 'client_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_secret(self) -> builtins.str:
        '''The client secret to be accompanied with clientUd for Facebook to authenticate the client.

        :see: https://developers.facebook.com/docs/facebook-login/security#appsecret
        '''
        result = self._values.get("client_secret")
        assert result is not None, "Required property 'client_secret' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def api_version(self) -> typing.Optional[builtins.str]:
        '''The Facebook API version to use.

        :default: - to the oldest version supported by Facebook
        '''
        result = self._values.get("api_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def scopes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of facebook permissions to obtain for getting access to the Facebook profile.

        :default: [ public_profile ]

        :see: https://developers.facebook.com/docs/facebook-login/permissions
        '''
        result = self._values.get("scopes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolIdentityProviderFacebookProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_cognito.UserPoolIdentityProviderGoogleProps",
    jsii_struct_bases=[UserPoolIdentityProviderProps],
    name_mapping={
        "user_pool": "userPool",
        "attribute_mapping": "attributeMapping",
        "client_id": "clientId",
        "client_secret": "clientSecret",
        "scopes": "scopes",
    },
)
class UserPoolIdentityProviderGoogleProps(UserPoolIdentityProviderProps):
    def __init__(
        self,
        *,
        user_pool: IUserPool,
        attribute_mapping: typing.Optional[AttributeMapping] = None,
        client_id: builtins.str,
        client_secret: builtins.str,
        scopes: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties to initialize UserPoolGoogleIdentityProvider.

        :param user_pool: The user pool to which this construct provides identities.
        :param attribute_mapping: Mapping attributes from the identity provider to standard and custom attributes of the user pool. Default: - no attribute mapping
        :param client_id: The client id recognized by Google APIs.
        :param client_secret: The client secret to be accompanied with clientId for Google APIs to authenticate the client.
        :param scopes: The list of google permissions to obtain for getting access to the google profile. Default: [ profile ]

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_cognito as cognito
            
            # provider_attribute: cognito.ProviderAttribute
            # user_pool: cognito.UserPool
            
            user_pool_identity_provider_google_props = cognito.UserPoolIdentityProviderGoogleProps(
                client_id="clientId",
                client_secret="clientSecret",
                user_pool=user_pool,
            
                # the properties below are optional
                attribute_mapping=cognito.AttributeMapping(
                    address=provider_attribute,
                    birthdate=provider_attribute,
                    custom={
                        "custom_key": provider_attribute
                    },
                    email=provider_attribute,
                    family_name=provider_attribute,
                    fullname=provider_attribute,
                    gender=provider_attribute,
                    given_name=provider_attribute,
                    last_update_time=provider_attribute,
                    locale=provider_attribute,
                    middle_name=provider_attribute,
                    nickname=provider_attribute,
                    phone_number=provider_attribute,
                    preferred_username=provider_attribute,
                    profile_page=provider_attribute,
                    profile_picture=provider_attribute,
                    timezone=provider_attribute,
                    website=provider_attribute
                ),
                scopes=["scopes"]
            )
        '''
        if isinstance(attribute_mapping, dict):
            attribute_mapping = AttributeMapping(**attribute_mapping)
        self._values: typing.Dict[str, typing.Any] = {
            "user_pool": user_pool,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if attribute_mapping is not None:
            self._values["attribute_mapping"] = attribute_mapping
        if scopes is not None:
            self._values["scopes"] = scopes

    @builtins.property
    def user_pool(self) -> IUserPool:
        '''The user pool to which this construct provides identities.'''
        result = self._values.get("user_pool")
        assert result is not None, "Required property 'user_pool' is missing"
        return typing.cast(IUserPool, result)

    @builtins.property
    def attribute_mapping(self) -> typing.Optional[AttributeMapping]:
        '''Mapping attributes from the identity provider to standard and custom attributes of the user pool.

        :default: - no attribute mapping
        '''
        result = self._values.get("attribute_mapping")
        return typing.cast(typing.Optional[AttributeMapping], result)

    @builtins.property
    def client_id(self) -> builtins.str:
        '''The client id recognized by Google APIs.

        :see: https://developers.google.com/identity/sign-in/web/sign-in#specify_your_apps_client_id
        '''
        result = self._values.get("client_id")
        assert result is not None, "Required property 'client_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_secret(self) -> builtins.str:
        '''The client secret to be accompanied with clientId for Google APIs to authenticate the client.

        :see: https://developers.google.com/identity/sign-in/web/sign-in
        '''
        result = self._values.get("client_secret")
        assert result is not None, "Required property 'client_secret' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def scopes(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The list of google permissions to obtain for getting access to the google profile.

        :default: [ profile ]

        :see: https://developers.google.com/identity/sign-in/web/sign-in
        '''
        result = self._values.get("scopes")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UserPoolIdentityProviderGoogleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "AccountRecovery",
    "AttributeMapping",
    "AuthFlow",
    "AutoVerifiedAttrs",
    "BooleanAttribute",
    "CfnIdentityPool",
    "CfnIdentityPoolProps",
    "CfnIdentityPoolRoleAttachment",
    "CfnIdentityPoolRoleAttachmentProps",
    "CfnUserPool",
    "CfnUserPoolClient",
    "CfnUserPoolClientProps",
    "CfnUserPoolDomain",
    "CfnUserPoolDomainProps",
    "CfnUserPoolGroup",
    "CfnUserPoolGroupProps",
    "CfnUserPoolIdentityProvider",
    "CfnUserPoolIdentityProviderProps",
    "CfnUserPoolProps",
    "CfnUserPoolResourceServer",
    "CfnUserPoolResourceServerProps",
    "CfnUserPoolRiskConfigurationAttachment",
    "CfnUserPoolRiskConfigurationAttachmentProps",
    "CfnUserPoolUICustomizationAttachment",
    "CfnUserPoolUICustomizationAttachmentProps",
    "CfnUserPoolUser",
    "CfnUserPoolUserProps",
    "CfnUserPoolUserToGroupAttachment",
    "CfnUserPoolUserToGroupAttachmentProps",
    "ClientAttributes",
    "CognitoDomainOptions",
    "CustomAttributeConfig",
    "CustomAttributeProps",
    "CustomDomainOptions",
    "DateTimeAttribute",
    "DeviceTracking",
    "EmailSettings",
    "ICustomAttribute",
    "IUserPool",
    "IUserPoolClient",
    "IUserPoolDomain",
    "IUserPoolIdentityProvider",
    "IUserPoolResourceServer",
    "Mfa",
    "MfaSecondFactor",
    "NumberAttribute",
    "NumberAttributeConstraints",
    "NumberAttributeProps",
    "OAuthFlows",
    "OAuthScope",
    "OAuthSettings",
    "PasswordPolicy",
    "ProviderAttribute",
    "ResourceServerScope",
    "ResourceServerScopeProps",
    "SignInAliases",
    "SignInUrlOptions",
    "StandardAttribute",
    "StandardAttributes",
    "StandardAttributesMask",
    "StringAttribute",
    "StringAttributeConstraints",
    "StringAttributeProps",
    "UserInvitationConfig",
    "UserPool",
    "UserPoolClient",
    "UserPoolClientIdentityProvider",
    "UserPoolClientOptions",
    "UserPoolClientProps",
    "UserPoolDomain",
    "UserPoolDomainOptions",
    "UserPoolDomainProps",
    "UserPoolEmail",
    "UserPoolIdentityProvider",
    "UserPoolIdentityProviderAmazon",
    "UserPoolIdentityProviderAmazonProps",
    "UserPoolIdentityProviderApple",
    "UserPoolIdentityProviderAppleProps",
    "UserPoolIdentityProviderFacebook",
    "UserPoolIdentityProviderFacebookProps",
    "UserPoolIdentityProviderGoogle",
    "UserPoolIdentityProviderGoogleProps",
    "UserPoolIdentityProviderProps",
    "UserPoolOperation",
    "UserPoolProps",
    "UserPoolResourceServer",
    "UserPoolResourceServerOptions",
    "UserPoolResourceServerProps",
    "UserPoolSESOptions",
    "UserPoolTriggers",
    "UserVerificationConfig",
    "VerificationEmailStyle",
]

publication.publish()
